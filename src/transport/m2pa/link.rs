//! M2PA link state control, without I/O.
//!
//! One [`Link`] is the level-2 state of one signalling link: the alignment
//! procedure of ITU-T Q.703 clause 7 as RFC 4165 4.1.3 maps it onto Link Status
//! messages, the sequence numbering and acknowledgement of User Data (RFC 4165
//! 2.2, 4.2.1), the retransmission buffer kept for changeover (4.2.3), remote
//! processor outage (4.1.4) and remote congestion (4.1.5).
//!
//! It owns no socket and no clock. The caller feeds it what happened (a message
//! from the peer, a timer that ran out, an MSU to send) together with the
//! current instant, and gets back a list of [`Action`]s: frames to put on an
//! SCTP stream, timers to start and stop, MSUs to hand to level 3, and the
//! in-service / out-of-service indications. That is what lets the state table be
//! tested row by row with no association and no waiting.
//!
//! What it does **not** do, because nothing in this node can cause it: local
//! processor outage and local receive congestion (Link Status Processor Outage
//! and Busy are handled when *received*, never originated; level 3 lives in the
//! same process, and SCTP's own receive window is the back-pressure).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use m2pa::{LinkState as Status, LinkStatusMessage, M2paMessage, UserDataMessage};

/// Sequence numbers are 24 bits (RFC 4165 2.2: "range from 0 to 16,777,215").
const SEQ_MASK: u32 = 0x00FF_FFFF;

/// SCTP stream for Link Status (RFC 4165 4.1.2).
pub const STATUS_STREAM: u16 = 0;
/// SCTP stream for User Data, and for the Link Status messages that must stay
/// in sequence with it (RFC 4165 4.1.2).
pub const DATA_STREAM: u16 = 1;

/// The distance from `from` forward to `to` on the 24-bit sequence circle.
fn seq_distance(from: u32, to: u32) -> u32 {
    to.wrapping_sub(from) & SEQ_MASK
}

/// Which proving period the local end asks for (Q.703 7.1: decided at level 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proving {
    /// The normal proving period, T4 = Pn.
    Normal,
    /// The emergency proving period, T4 = Pe.
    Emergency,
}

/// The timers of one link. Names and defaults are those of Q.703 12.3 for a
/// 64 kbit/s link, which RFC 4165 clause 4 has M2PA use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTimers {
    /// T1, "alignment ready": how long to wait in Aligned Ready for the peer.
    pub t1: Duration,
    /// T2, "not aligned": how long to wait for the peer to start alignment.
    pub t2: Duration,
    /// T3, "aligned": how long to wait for the peer to start proving.
    pub t3: Duration,
    /// T4 for the normal proving period (Pn).
    pub t4_normal: Duration,
    /// T4 for the emergency proving period (Pe).
    pub t4_emergency: Duration,
    /// T6, "remote congestion": how long the peer may stay busy.
    pub t6: Duration,
    /// T7, "excessive delay of acknowledgement".
    pub t7: Duration,
    /// The interval between Link Status Proving messages while T4 runs
    /// (RFC 4165 4.1.3, `Proving_Interval`).
    pub proving_interval: Duration,
}

impl Default for LinkTimers {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(45_000),
            t2: Duration::from_millis(30_000),
            t3: Duration::from_millis(1_500),
            t4_normal: Duration::from_millis(8_200),
            t4_emergency: Duration::from_millis(500),
            t6: Duration::from_millis(4_500),
            t7: Duration::from_millis(2_000),
            proving_interval: Duration::from_millis(100),
        }
    }
}

/// The link state (Q.703 Figure 8, link state control, with the three initial
/// alignment states of Figure 9 in place of "initial alignment").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not started, or failed. Nothing is sent or accepted.
    OutOfService,
    /// Alignment started, the peer has not answered. T2 runs.
    NotAligned,
    /// The peer is aligning too; waiting for it to prove. T3 runs.
    Aligned,
    /// Proving. T4 runs.
    Proving,
    /// Proving done here, waiting for the peer to finish. T1 runs.
    AlignedReady,
    /// Carrying MSUs.
    InService,
    /// The peer reported processor outage: nothing is sent until it recovers.
    ProcessorOutage,
}

impl State {
    /// A short name for logs.
    pub fn label(self) -> &'static str {
        match self {
            Self::OutOfService => "out-of-service",
            Self::NotAligned => "not-aligned",
            Self::Aligned => "aligned",
            Self::Proving => "proving",
            Self::AlignedReady => "aligned-ready",
            Self::InService => "in-service",
            Self::ProcessorOutage => "processor-outage",
        }
    }
}

/// A timer of the link. The caller keeps one deadline per value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    /// Alignment ready.
    T1,
    /// Not aligned.
    T2,
    /// Aligned.
    T3,
    /// Proving period.
    T4,
    /// Remote congestion.
    T6,
    /// Excessive delay of acknowledgement.
    T7,
    /// The next Link Status Proving is due.
    Proving,
}

impl Timer {
    /// Every timer, in index order.
    pub const ALL: [Timer; 7] = [
        Self::T1,
        Self::T2,
        Self::T3,
        Self::T4,
        Self::T6,
        Self::T7,
        Self::Proving,
    ];

    /// A dense index, for a deadline array.
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Why a link left service or could not be aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// T1 ran out in Aligned Ready: the peer never finished proving.
    T1,
    /// T2 ran out: the peer never started alignment.
    T2,
    /// T3 ran out: the peer never started proving.
    T3,
    /// T6 ran out: the peer stayed busy too long.
    T6,
    /// T7 ran out: a User Data message was not acknowledged in time.
    T7,
    /// The peer sent a status that is a link failure in this state (Alignment,
    /// Proving or Out of Service while in service; Out of Service during
    /// alignment).
    PeerStatus,
    /// Two abnormal backward sequence numbers in three messages (Q.703 5.3.1).
    AbnormalBsn,
    /// The signalling link test failed twice (Q.707 2.2).
    LinkTest,
    /// The SCTP association is gone (RFC 4165 4.1.7).
    Association,
    /// Stopped by level 3.
    Stopped,
}

impl Failure {
    /// The `reason` label of `sigtran_m2pa_link_failures_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::T1 => "t1",
            Self::T2 => "t2",
            Self::T3 => "t3",
            Self::T6 => "t6",
            Self::T7 => "t7",
            Self::PeerStatus => "peer-status",
            Self::AbnormalBsn => "abnormal-bsn",
            Self::LinkTest => "link-test",
            Self::Association => "association",
            Self::Stopped => "stopped",
        }
    }

    /// Every value, for the metrics rendering.
    pub const ALL: [Failure; 10] = [
        Self::T1,
        Self::T2,
        Self::T3,
        Self::T6,
        Self::T7,
        Self::PeerStatus,
        Self::AbnormalBsn,
        Self::LinkTest,
        Self::Association,
        Self::Stopped,
    ];
}

/// Why something received on, or handed to, a link was not carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// Received User Data whose FSN is not the next one (RFC 4165 4.2.1:
    /// "M2PA SHALL discard the message").
    RxOutOfSequence,
    /// Received User Data while the link is not in service.
    RxNotInService,
    /// A received backward sequence number that acknowledges nothing we sent.
    RxAbnormalBsn,
    /// An MSU handed to a link that is not in service.
    TxNotInService,
    /// The transmit queue is full (transmit congestion, Q.704 3.8).
    TxCongestion,
    /// Sent or queued, not acknowledged, and lost with the link: it failed and
    /// nothing retrieved the buffers before alignment started again.
    TxLostOnFailure,
    /// Sent, and discarded by a peer that flushed after processor outage.
    TxFlushedByPeer,
    /// A frame that could not be encoded.
    Encode,
}

impl Discard {
    /// The `reason` label of `sigtran_m2pa_discarded_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::RxOutOfSequence => "rx-out-of-sequence",
            Self::RxNotInService => "rx-not-in-service",
            Self::RxAbnormalBsn => "rx-abnormal-bsn",
            Self::TxNotInService => "tx-not-in-service",
            Self::TxCongestion => "tx-congestion",
            Self::TxLostOnFailure => "tx-lost-on-failure",
            Self::TxFlushedByPeer => "tx-flushed-by-peer",
            Self::Encode => "encode",
        }
    }

    /// Every value, for the metrics rendering.
    pub const ALL: [Discard; 8] = [
        Self::RxOutOfSequence,
        Self::RxNotInService,
        Self::RxAbnormalBsn,
        Self::TxNotInService,
        Self::TxCongestion,
        Self::TxLostOnFailure,
        Self::TxFlushedByPeer,
        Self::Encode,
    ];

    /// A dense index, for a counter array.
    pub fn index(self) -> usize {
        self as usize
    }
}

/// What the caller has to do after an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this encoded M2PA message on this SCTP stream. `si` is the service
    /// indicator of the MSU inside a User Data message, `None` for a Link
    /// Status or an acknowledgement.
    Send {
        frame: Vec<u8>,
        stream: u16,
        si: Option<u8>,
    },
    /// Hand this received MSU (SIO and SIF) to level 3.
    Deliver { msu: Vec<u8> },
    /// Start, or restart, a timer.
    Start(Timer, Duration),
    /// Stop a timer.
    Stop(Timer),
    /// The link is in service at level 2.
    InService,
    /// The link is out of service.
    OutOfService(Failure),
    /// The peer's processor outage began (`true`) or ended (`false`).
    RemoteProcessorOutage(bool),
    /// `count` messages were not carried, for `reason`.
    Discarded { reason: Discard, count: usize },
}

/// A sent User Data message that the peer has not acknowledged.
#[derive(Debug, Clone)]
struct Unacked {
    fsn: u32,
    sent_at: Instant,
    msu: Vec<u8>,
}

/// What a failed link still holds, for the changeover procedure (RFC 4165
/// 4.2.3): the last FSN accepted from the peer, and what the peer may not have.
#[derive(Debug, Clone, Default)]
struct Retrievable {
    /// The FSN of the last message accepted from the peer (the BSNT).
    bsnt: u32,
    /// The last of our FSNs the peer acknowledged before the failure.
    acked: u32,
    /// Sent, not acknowledged, oldest first.
    unacked: VecDeque<(u32, Vec<u8>)>,
    /// Never sent.
    unsent: VecDeque<Vec<u8>>,
}

/// Level 2 of one M2PA link.
#[derive(Debug)]
pub struct Link {
    timers: LinkTimers,
    proving: Proving,
    tx_queue: usize,
    state: State,
    /// The emergency proving period is in use (ours, or the peer asked).
    use_emergency: bool,
    /// The peer's Ready arrived while we were still proving.
    peer_ready: bool,
    /// FSN of the last User Data message sent.
    fsn_out: u32,
    /// FSN of the last User Data message accepted: the BSN we send.
    fsn_in: u32,
    /// The last of our FSNs the peer acknowledged.
    acked: u32,
    /// A second abnormal BSN within this many received messages fails the link.
    bsn_watch: u8,
    remote_busy: bool,
    /// A received message has not been acknowledged yet.
    ack_due: bool,
    unacked: VecDeque<Unacked>,
    unsent: VecDeque<Vec<u8>>,
    retrievable: Option<Retrievable>,
}

impl Link {
    /// A link that has not been started. `tx_queue` bounds the MSUs held while
    /// the peer is busy or in processor outage.
    pub fn new(timers: LinkTimers, proving: Proving, tx_queue: usize) -> Self {
        Self {
            timers,
            proving,
            tx_queue,
            state: State::OutOfService,
            use_emergency: proving == Proving::Emergency,
            peer_ready: false,
            fsn_out: SEQ_MASK,
            fsn_in: SEQ_MASK,
            acked: SEQ_MASK,
            bsn_watch: 0,
            remote_busy: false,
            ack_due: false,
            unacked: VecDeque::new(),
            unsent: VecDeque::new(),
            retrievable: None,
        }
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether level 2 is in service (processor outage at the peer included:
    /// the link is aligned, level 3 decides what that means for traffic).
    pub fn is_aligned(&self) -> bool {
        matches!(self.state, State::InService | State::ProcessorOutage)
    }

    /// User Data messages sent and not yet acknowledged.
    pub fn unacknowledged(&self) -> usize {
        self.unacked.len()
    }

    /// The association is up: say so to the peer. RFC 4165 4.1.3: "After the
    /// association is established, M2PA SHALL send a Link Status Out of Service
    /// message to its peer."
    pub fn established(&mut self, out: &mut Vec<Action>) {
        self.send_status(Status::OutOfService, STATUS_STREAM, out);
    }

    /// Start initial alignment (the Start request of level 3). A no-op unless
    /// the link is out of service.
    pub fn start(&mut self, out: &mut Vec<Action>) {
        if self.state != State::OutOfService {
            return;
        }
        // Anything a failure left behind that nobody retrieved is lost now:
        // alignment restarts the sequence numbers.
        let count = self.abandon();
        if count > 0 {
            out.push(Action::Discarded {
                reason: Discard::TxLostOnFailure,
                count,
            });
        }
        self.fsn_out = SEQ_MASK;
        self.fsn_in = SEQ_MASK;
        self.acked = SEQ_MASK;
        self.bsn_watch = 0;
        self.remote_busy = false;
        self.ack_due = false;
        self.peer_ready = false;
        self.use_emergency = self.proving == Proving::Emergency;
        self.state = State::NotAligned;
        self.send_status(Status::Alignment, STATUS_STREAM, out);
        out.push(Action::Start(Timer::T2, self.timers.t2));
    }

    /// Take the link out of service for a reason outside level 2 (a failed
    /// signalling link test, a lost association, a stop from level 3).
    pub fn fail(&mut self, reason: Failure, out: &mut Vec<Action>) {
        if self.state == State::OutOfService {
            return;
        }
        for timer in Timer::ALL {
            out.push(Action::Stop(timer));
        }
        // RFC 4165 4.1.6: send Out of Service where MTP2 would send SIOS. There
        // is nothing to send it on when the association is what failed.
        if reason != Failure::Association {
            self.send_status(Status::OutOfService, STATUS_STREAM, out);
        }
        self.retrievable = Some(Retrievable {
            bsnt: self.fsn_in,
            acked: self.acked,
            unacked: self.unacked.drain(..).map(|u| (u.fsn, u.msu)).collect(),
            unsent: std::mem::take(&mut self.unsent),
        });
        self.state = State::OutOfService;
        self.remote_busy = false;
        self.ack_due = false;
        self.peer_ready = false;
        out.push(Action::OutOfService(reason));
    }

    /// The FSN of the last User Data message accepted from the peer: the BSNT
    /// that level 3 puts in a changeover order (RFC 4165 4.2.3). While the link
    /// is up it is the live value; after a failure, the value at the failure.
    pub fn bsnt(&self) -> u32 {
        match &self.retrievable {
            Some(r) => r.bsnt,
            None => self.fsn_in,
        }
    }

    /// Retrieval after a failure (RFC 4165 4.2.3). With `fsnc`, the FSN the far
    /// end last accepted: "any transmitted User Data messages beginning with the
    /// first unacknowledged message with FSN greater than FSNC", then "any
    /// untransmitted User Data messages". Without one, or with one that is not
    /// an FSN we sent and still hold ("no FSNC value, or with an invalid FSNC"):
    /// the untransmitted ones only. Each MSU is SIO and SIF, in order. The
    /// buffers are emptied: a second call returns nothing.
    pub fn retrieve(&mut self, fsnc: Option<u32>) -> Vec<Vec<u8>> {
        let Some(mut held) = self.retrievable.take() else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(held.unacked.len() + held.unsent.len());
        let last_sent = held.unacked.back().map_or(held.acked, |(fsn, _)| *fsn);
        let valid = fsnc.filter(|f| {
            seq_distance(held.acked, f & SEQ_MASK) <= seq_distance(held.acked, last_sent)
        });
        if let Some(fsnc) = valid {
            let accepted = seq_distance(held.acked, fsnc & SEQ_MASK);
            for (fsn, msu) in held.unacked.drain(..) {
                if seq_distance(held.acked, fsn) > accepted {
                    out.push(msu);
                }
            }
        }
        out.extend(held.unsent.drain(..));
        out
    }

    /// Give up what a failure left for retrieval. Returns how many messages
    /// that was.
    pub fn abandon(&mut self) -> usize {
        self.retrievable
            .take()
            .map_or(0, |left| left.unacked.len() + left.unsent.len())
    }

    /// An MSU (SIO and SIF) from level 3 for transmission.
    pub fn send(&mut self, msu: Vec<u8>, now: Instant, out: &mut Vec<Action>) {
        match self.state {
            State::InService if !self.remote_busy => self.transmit(msu, now, out),
            // RFC 4165 4.1.5: "MUST NOT send User Data messages after receiving
            // Link Status Busy and before receiving Link Status Busy Ended";
            // and nothing is sent into a processor outage.
            State::InService | State::ProcessorOutage => {
                if self.unsent.len() >= self.tx_queue {
                    out.push(Action::Discarded {
                        reason: Discard::TxCongestion,
                        count: 1,
                    });
                } else {
                    self.unsent.push_back(msu);
                }
            }
            _ => out.push(Action::Discarded {
                reason: Discard::TxNotInService,
                count: 1,
            }),
        }
    }

    /// A timer ran out.
    pub fn timeout(&mut self, timer: Timer, now: Instant, out: &mut Vec<Action>) {
        match (timer, self.state) {
            (Timer::T2, State::NotAligned) => self.fail(Failure::T2, out),
            (Timer::T3, State::Aligned) => self.fail(Failure::T3, out),
            (Timer::T4, State::Proving) => {
                // Proving period over: alignment complete (Q.703 7.3). RFC 4165
                // 4.1.3: "When M2PA starts timer T1, it SHALL send a Link Status
                // Ready message".
                out.push(Action::Stop(Timer::Proving));
                self.send_status(Status::Ready, STATUS_STREAM, out);
                if self.peer_ready {
                    self.enter_service(out);
                } else {
                    self.state = State::AlignedReady;
                    out.push(Action::Start(Timer::T1, self.timers.t1));
                }
            }
            (Timer::Proving, State::Proving) => {
                self.send_status(self.proving_status(), STATUS_STREAM, out);
                out.push(Action::Start(Timer::Proving, self.timers.proving_interval));
            }
            (Timer::T1, State::AlignedReady) => self.fail(Failure::T1, out),
            (Timer::T6, State::InService | State::ProcessorOutage) if self.remote_busy => {
                self.fail(Failure::T6, out)
            }
            (Timer::T7, State::InService) => {
                // RFC 4165 4.2.1: "If any message is unacknowledged after a
                // period equal to the T7 value, the T7 timer SHALL expire."
                match self.unacked.front() {
                    Some(oldest) if now.duration_since(oldest.sent_at) >= self.timers.t7 => {
                        self.fail(Failure::T7, out)
                    }
                    Some(_) => self.arm_t7(now, out),
                    None => {}
                }
            }
            // A timer of a state the link has left: nothing to do.
            _ => {}
        }
    }

    /// A Link Status message from the peer.
    pub fn on_status(&mut self, status: Status, bsn: u32, now: Instant, out: &mut Vec<Action>) {
        use State as S;
        match (self.state, status) {
            (S::OutOfService, _) => {}

            // Q.703 Figure 9, not aligned: O, N or E from the peer means it is
            // aligning; answer with our own proving status and wait for its.
            (
                S::NotAligned,
                Status::Alignment | Status::ProvingNormal | Status::ProvingEmergency,
            ) => {
                if status == Status::ProvingEmergency {
                    self.use_emergency = true;
                }
                out.push(Action::Stop(Timer::T2));
                self.state = S::Aligned;
                self.send_status(self.proving_status(), STATUS_STREAM, out);
                out.push(Action::Start(Timer::T3, self.timers.t3));
            }
            (S::NotAligned, _) => {}

            // Aligned: the peer's N or E starts proving; E shortens it.
            (S::Aligned, Status::ProvingNormal | Status::ProvingEmergency) => {
                if status == Status::ProvingEmergency {
                    self.use_emergency = true;
                }
                out.push(Action::Stop(Timer::T3));
                self.state = S::Proving;
                out.push(Action::Start(Timer::T4, self.t4()));
                out.push(Action::Start(Timer::Proving, self.timers.proving_interval));
            }
            (S::Aligned | S::Proving, Status::OutOfService) => self.fail(Failure::PeerStatus, out),
            // The peer repeats Alignment until it is answered (RFC 4165 4.1.3):
            // not an event in Aligned.
            (S::Aligned, _) => {}

            // Proving: O from the peer means it started over, so back to
            // Aligned; E while proving normally restarts with the short period.
            (S::Proving, Status::Alignment) => {
                out.push(Action::Stop(Timer::T4));
                out.push(Action::Stop(Timer::Proving));
                self.state = S::Aligned;
                out.push(Action::Start(Timer::T3, self.timers.t3));
            }
            (S::Proving, Status::ProvingEmergency) if !self.use_emergency => {
                self.use_emergency = true;
                out.push(Action::Start(Timer::T4, self.t4()));
            }
            // The peer finished proving first. It says so once, so remember.
            (S::Proving, Status::Ready) => self.peer_ready = true,
            (S::Proving, _) => {}

            // Aligned ready: the peer's Ready puts the link in service. Ours may
            // have reached it while it was still proving, so say it again.
            (S::AlignedReady, Status::Ready) => {
                self.send_status(Status::Ready, STATUS_STREAM, out);
                self.enter_service(out);
            }
            (S::AlignedReady | S::InService, Status::ProcessorOutage) => {
                out.push(Action::Stop(Timer::T1));
                out.push(Action::Stop(Timer::T7));
                self.state = S::ProcessorOutage;
                out.push(Action::RemoteProcessorOutage(true));
            }
            (S::AlignedReady, Status::Alignment | Status::OutOfService) => {
                self.fail(Failure::PeerStatus, out)
            }
            // The peer is still proving, or says something that has no meaning
            // before the link is in service.
            (S::AlignedReady, _) => {}

            // In service: O, N, E and OS are a link failure (Q.703 Figure 8).
            (
                S::InService | S::ProcessorOutage,
                Status::Alignment
                | Status::ProvingNormal
                | Status::ProvingEmergency
                | Status::OutOfService,
            ) => self.fail(Failure::PeerStatus, out),
            (S::InService | S::ProcessorOutage, Status::Busy) => {
                // RFC 4165 4.1.5: T6 starts on the first Busy if messages await
                // acknowledgement, and T7 stops; further Busy change nothing.
                if !self.remote_busy {
                    self.remote_busy = true;
                    out.push(Action::Stop(Timer::T7));
                    if !self.unacked.is_empty() {
                        out.push(Action::Start(Timer::T6, self.timers.t6));
                    }
                }
            }
            (S::InService | S::ProcessorOutage, Status::BusyEnded) => {
                if self.remote_busy {
                    self.remote_busy = false;
                    out.push(Action::Stop(Timer::T6));
                    if self.state == S::InService {
                        self.restart_t7(now, out);
                        self.flush_unsent(now, out);
                    }
                }
            }
            // A Ready in service is the last step of a processor outage
            // recovery (RFC 4165 4.1.4), or a repeat of the one that brought the
            // link up. Its BSN acknowledges; nothing else follows.
            (S::InService, Status::Ready) => {
                self.acknowledge(bsn, false, now, out);
            }
            (S::InService, Status::ProcessorRecovered) => {}
            (S::ProcessorOutage, Status::ProcessorRecovered) => {
                // RFC 4165 4.1.4: answer with Ready on the User Data stream; the
                // BSN of the Recovered is the last message the peer kept. What
                // we sent after that, it discarded: those are gone at level 2.
                self.acknowledge(bsn, false, now, out);
                if !self.unacked.is_empty() {
                    out.push(Action::Discarded {
                        reason: Discard::TxFlushedByPeer,
                        count: self.unacked.len(),
                    });
                    self.unacked.clear();
                }
                self.fsn_out = self.acked;
                self.state = S::InService;
                self.send_status(Status::Ready, DATA_STREAM, out);
                out.push(Action::RemoteProcessorOutage(false));
                if !self.remote_busy {
                    self.flush_unsent(now, out);
                }
            }
            (S::ProcessorOutage, Status::Ready | Status::ProcessorOutage) => {}
        }
    }

    /// A User Data message from the peer. An empty one is an acknowledgement.
    pub fn on_data(
        &mut self,
        bsn: u32,
        fsn: u32,
        message: UserDataMessage,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        match self.state {
            // Q.703 Figure 8, aligned ready: a signal unit from the peer means
            // it is in service.
            State::AlignedReady => self.enter_service(out),
            State::InService | State::ProcessorOutage => {}
            _ => {
                if !message.is_empty() {
                    out.push(Action::Discarded {
                        reason: Discard::RxNotInService,
                        count: 1,
                    });
                }
                return;
            }
        }
        if !self.acknowledge(bsn, true, now, out) {
            return;
        }
        if message.is_empty() {
            // RFC 4165 4.2.1: "If M2PA receives an empty User Data message, it
            // SHALL NOT send an acknowledgement of that message."
            return;
        }
        if fsn & SEQ_MASK != (self.fsn_in + 1) & SEQ_MASK {
            // RFC 4165 4.2.1: "If M2PA receives a User Data message with an FSN
            // that is out of order, M2PA SHALL discard the message."
            out.push(Action::Discarded {
                reason: Discard::RxOutOfSequence,
                count: 1,
            });
            return;
        }
        self.fsn_in = fsn & SEQ_MASK;
        self.ack_due = true;
        out.push(Action::Deliver { msu: message.msu });
    }

    /// Acknowledge what was received, if nothing sent since has done so. To be
    /// called once level 3 has dealt with the delivered MSU: RFC 4165 4.2.1,
    /// "M2PA MUST acknowledge the message with the next User Data message sent.
    /// If there is no User Data message available to be sent ... M2PA SHOULD
    /// generate and send a User Data message with no data payload, without
    /// delay", with "the same FSN as the most recently sent User Data message
    /// that contains data".
    pub fn flush_ack(&mut self, out: &mut Vec<Action>) {
        if !std::mem::take(&mut self.ack_due) || !self.is_aligned() {
            return;
        }
        self.send_frame(
            M2paMessage::UserData {
                bsn: self.fsn_in,
                fsn: self.fsn_out,
                message: UserDataMessage::empty(),
            },
            DATA_STREAM,
            None,
            out,
        );
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn proving_status(&self) -> Status {
        // Q.703 7.2: N and E "indicate the status of the transmitting signalling
        // link terminal; this is not changed by reception of status indications
        // indicating a different status at the remote" end.
        match self.proving {
            Proving::Normal => Status::ProvingNormal,
            Proving::Emergency => Status::ProvingEmergency,
        }
    }

    fn t4(&self) -> Duration {
        if self.use_emergency {
            self.timers.t4_emergency
        } else {
            self.timers.t4_normal
        }
    }

    fn enter_service(&mut self, out: &mut Vec<Action>) {
        out.push(Action::Stop(Timer::T1));
        self.state = State::InService;
        self.peer_ready = false;
        out.push(Action::InService);
    }

    fn send_status(&self, status: Status, stream: u16, out: &mut Vec<Action>) {
        // RFC 4165 4.2.1: "For message types other than User Data, the Forward
        // Sequence Number is set to the FSN of the last User Data message sent."
        self.send_frame(
            M2paMessage::LinkStatus {
                bsn: self.fsn_in,
                fsn: self.fsn_out,
                message: LinkStatusMessage::new(status),
            },
            stream,
            None,
            out,
        );
    }

    fn send_frame(&self, message: M2paMessage, stream: u16, si: Option<u8>, out: &mut Vec<Action>) {
        match message.encode() {
            Ok(frame) => out.push(Action::Send { frame, stream, si }),
            Err(_) => out.push(Action::Discarded {
                reason: Discard::Encode,
                count: 1,
            }),
        }
    }

    /// Number, send and keep one MSU.
    fn transmit(&mut self, msu: Vec<u8>, now: Instant, out: &mut Vec<Action>) {
        let fsn = (self.fsn_out + 1) & SEQ_MASK;
        let si = msu.first().map(|sio| sio & 0x0F);
        // The priority field is spare outside the national MTP that defines it
        // (RFC 4165 2.3.1), and this link frames the ITU variant only.
        let message = M2paMessage::UserData {
            bsn: self.fsn_in,
            fsn,
            message: UserDataMessage::new(0, msu),
        };
        let encoded = message.encode();
        let M2paMessage::UserData { message, .. } = message else {
            return;
        };
        match encoded {
            Ok(frame) => {
                self.fsn_out = fsn;
                // This message carries the BSN: it is the acknowledgement.
                self.ack_due = false;
                let first = self.unacked.is_empty();
                self.unacked.push_back(Unacked {
                    fsn,
                    sent_at: now,
                    msu: message.msu,
                });
                out.push(Action::Send {
                    frame,
                    stream: DATA_STREAM,
                    si,
                });
                if first {
                    out.push(Action::Start(Timer::T7, self.timers.t7));
                }
            }
            Err(_) => out.push(Action::Discarded {
                reason: Discard::Encode,
                count: 1,
            }),
        }
    }

    fn flush_unsent(&mut self, now: Instant, out: &mut Vec<Action>) {
        while let Some(msu) = self.unsent.pop_front() {
            self.transmit(msu, now, out);
        }
    }

    /// (Re)start T7 for the oldest unacknowledged message, or stop it.
    fn arm_t7(&self, now: Instant, out: &mut Vec<Action>) {
        match self.unacked.front() {
            Some(oldest) => {
                let deadline = oldest.sent_at + self.timers.t7;
                out.push(Action::Start(
                    Timer::T7,
                    deadline.saturating_duration_since(now),
                ));
            }
            None => out.push(Action::Stop(Timer::T7)),
        }
    }

    /// T7 afresh for everything still unacknowledged, after a pause in which
    /// no acknowledgement could come (the peer was busy).
    fn restart_t7(&mut self, now: Instant, out: &mut Vec<Action>) {
        for u in &mut self.unacked {
            u.sent_at = now;
        }
        if !self.unacked.is_empty() {
            out.push(Action::Start(Timer::T7, self.timers.t7));
        }
    }

    /// Apply a received BSN: release what it acknowledges. Returns `false` when
    /// the message that carried it is to be discarded (an abnormal BSN) or the
    /// link failed on it. `strict` is for User Data, where Q.703 5.3.1 applies;
    /// a Link Status with a BSN that acknowledges nothing is just not an
    /// acknowledgement.
    fn acknowledge(&mut self, bsn: u32, strict: bool, now: Instant, out: &mut Vec<Action>) -> bool {
        let bsn = bsn & SEQ_MASK;
        let outstanding = seq_distance(self.acked, self.fsn_out);
        let step = seq_distance(self.acked, bsn);
        if step > outstanding {
            if !strict {
                return true;
            }
            out.push(Action::Discarded {
                reason: Discard::RxAbnormalBsn,
                count: 1,
            });
            // Q.703 5.3.1: "If any two backward sequence number values in three
            // consecutively received message signal units or fill-in signal
            // units are not the same as the previous one or any of the forward
            // sequence number values of the signal units in the retransmission
            // buffer ... level 3 is informed that the link is faulty."
            if self.bsn_watch > 0 {
                self.fail(Failure::AbnormalBsn, out);
            } else {
                self.bsn_watch = 2;
            }
            return false;
        }
        if strict {
            self.bsn_watch = self.bsn_watch.saturating_sub(1);
        }
        if step > 0 {
            self.acked = bsn;
            while self
                .unacked
                .front()
                .is_some_and(|u| seq_distance(u.fsn, bsn) < SEQ_MASK / 2)
            {
                self.unacked.pop_front();
            }
            if self.state == State::InService && !self.remote_busy {
                self.arm_t7(now, out);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn timers() -> LinkTimers {
        LinkTimers {
            t1: 400 * MS,
            t2: 300 * MS,
            t3: 100 * MS,
            t4_normal: 80 * MS,
            t4_emergency: 20 * MS,
            t6: 60 * MS,
            t7: 50 * MS,
            proving_interval: 10 * MS,
        }
    }

    fn link() -> Link {
        Link::new(timers(), Proving::Normal, 4)
    }

    /// A sent frame, read back by hand from RFC 4165 2.1 to 2.3: type at octet
    /// 3, BSN in octets 9..12, FSN in 13..16, then the state or the data.
    #[derive(Debug, PartialEq, Eq)]
    enum Sent {
        Status {
            state: u32,
            stream: u16,
            bsn: u32,
            fsn: u32,
        },
        Data {
            bsn: u32,
            fsn: u32,
            data: Vec<u8>,
        },
    }

    fn sent(actions: &[Action]) -> Vec<Sent> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send { frame, stream, .. } => {
                    assert_eq!(&frame[..3], [1, 0, 11], "version, spare, class");
                    assert_eq!(
                        u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize,
                        frame.len(),
                        "message length"
                    );
                    let bsn = u32::from_be_bytes([0, frame[9], frame[10], frame[11]]);
                    let fsn = u32::from_be_bytes([0, frame[13], frame[14], frame[15]]);
                    Some(match frame[3] {
                        2 => Sent::Status {
                            state: u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]),
                            stream: *stream,
                            bsn,
                            fsn,
                        },
                        1 => {
                            assert_eq!(*stream, DATA_STREAM, "user data rides stream 1");
                            Sent::Data {
                                bsn,
                                fsn,
                                data: frame[16..].to_vec(),
                            }
                        }
                        other => panic!("message type {other}"),
                    })
                }
                _ => None,
            })
            .collect()
    }

    fn statuses(actions: &[Action]) -> Vec<u32> {
        sent(actions)
            .into_iter()
            .filter_map(|s| match s {
                Sent::Status { state, .. } => Some(state),
                Sent::Data { .. } => None,
            })
            .collect()
    }

    fn has(actions: &[Action], wanted: &Action) -> bool {
        actions.iter().any(|a| a == wanted)
    }

    const INITIAL: u32 = 0x00FF_FFFF;

    /// Drive a link into the wanted state by the shortest path.
    fn link_in(state: State) -> Link {
        let now = Instant::now();
        let mut l = link();
        let mut out = Vec::new();
        if state == State::OutOfService {
            return l;
        }
        l.start(&mut out);
        if state == State::NotAligned {
            return l;
        }
        l.on_status(Status::Alignment, INITIAL, now, &mut out);
        if state == State::Aligned {
            return l;
        }
        l.on_status(Status::ProvingNormal, INITIAL, now, &mut out);
        if state == State::Proving {
            return l;
        }
        l.timeout(Timer::T4, now, &mut out);
        if state == State::AlignedReady {
            return l;
        }
        l.on_status(Status::Ready, INITIAL, now, &mut out);
        if state == State::InService {
            return l;
        }
        l.on_status(Status::ProcessorOutage, INITIAL, now, &mut out);
        assert_eq!(l.state(), state);
        l
    }

    fn msu(tag: u8) -> Vec<u8> {
        // SIO (national, SCCP), a routing label, one octet of user part.
        vec![0x83, 0xB8, 0x0B, 0xFA, 0x00, tag]
    }

    #[test]
    fn the_association_coming_up_is_announced_with_out_of_service() {
        let mut l = link();
        let mut out = Vec::new();
        l.established(&mut out);
        assert_eq!(
            sent(&out),
            [Sent::Status {
                state: 9,
                stream: 0,
                bsn: INITIAL,
                fsn: INITIAL
            }]
        );
    }

    #[test]
    fn start_sends_alignment_and_runs_t2() {
        let mut l = link();
        let mut out = Vec::new();
        l.start(&mut out);
        assert_eq!(l.state(), State::NotAligned);
        assert_eq!(statuses(&out), [1]);
        assert!(has(&out, &Action::Start(Timer::T2, timers().t2)));
        // A second start changes nothing.
        let mut again = Vec::new();
        l.start(&mut again);
        assert!(again.is_empty());
    }

    /// The state table: for every state and every Link Status the peer can
    /// send, the state that follows and the Link Status sent in answer.
    /// Q.703 Figures 8 and 9 with the RFC 4165 4.1.3 mapping (SIO Alignment,
    /// SIN / SIE Proving Normal / Emergency, SIOS Out of Service, the FISU at
    /// the end of proving Ready).
    #[test]
    fn the_link_status_state_table() {
        use State as S;
        use Status::*;
        const OOS: Status = Status::OutOfService;
        // (state, received, next state, statuses sent)
        let table: &[(S, Status, S, &[u32])] = &[
            // Out of service: nothing is an event.
            (S::OutOfService, Alignment, S::OutOfService, &[]),
            (S::OutOfService, ProvingNormal, S::OutOfService, &[]),
            (S::OutOfService, Ready, S::OutOfService, &[]),
            (S::OutOfService, OOS, S::OutOfService, &[]),
            // Not aligned: O, N, E -> aligned, sending N.
            (S::NotAligned, Alignment, S::Aligned, &[2]),
            (S::NotAligned, ProvingNormal, S::Aligned, &[2]),
            (S::NotAligned, ProvingEmergency, S::Aligned, &[2]),
            (S::NotAligned, OOS, S::NotAligned, &[]),
            (S::NotAligned, Ready, S::NotAligned, &[]),
            (S::NotAligned, Busy, S::NotAligned, &[]),
            (S::NotAligned, ProcessorOutage, S::NotAligned, &[]),
            // Aligned: N, E -> proving; OS -> alignment not possible; a
            // repeated O is tolerated.
            (S::Aligned, Alignment, S::Aligned, &[]),
            (S::Aligned, ProvingNormal, S::Proving, &[]),
            (S::Aligned, ProvingEmergency, S::Proving, &[]),
            (S::Aligned, OOS, S::OutOfService, &[9]),
            (S::Aligned, Ready, S::Aligned, &[]),
            // Proving: O -> aligned; OS -> alignment not possible.
            (S::Proving, Alignment, S::Aligned, &[]),
            (S::Proving, ProvingNormal, S::Proving, &[]),
            (S::Proving, ProvingEmergency, S::Proving, &[]),
            (S::Proving, Ready, S::Proving, &[]),
            (S::Proving, OOS, S::OutOfService, &[9]),
            // Aligned ready: Ready -> in service (and said once more); O, OS
            // -> failure; the peer still proving is not an event.
            (S::AlignedReady, Ready, S::InService, &[4]),
            (S::AlignedReady, ProvingNormal, S::AlignedReady, &[]),
            (S::AlignedReady, ProvingEmergency, S::AlignedReady, &[]),
            (S::AlignedReady, Alignment, S::OutOfService, &[9]),
            (S::AlignedReady, OOS, S::OutOfService, &[9]),
            (S::AlignedReady, ProcessorOutage, S::ProcessorOutage, &[]),
            // In service: O, N, E, OS -> failure. A repeated Ready is not.
            (S::InService, Ready, S::InService, &[]),
            (S::InService, Alignment, S::OutOfService, &[9]),
            (S::InService, ProvingNormal, S::OutOfService, &[9]),
            (S::InService, ProvingEmergency, S::OutOfService, &[9]),
            (S::InService, OOS, S::OutOfService, &[9]),
            (S::InService, ProcessorOutage, S::ProcessorOutage, &[]),
            (S::InService, ProcessorRecovered, S::InService, &[]),
            (S::InService, Busy, S::InService, &[]),
            (S::InService, BusyEnded, S::InService, &[]),
            // Processor outage at the peer: Recovered -> in service, answered
            // with Ready; a status of alignment is still a failure.
            (S::ProcessorOutage, ProcessorRecovered, S::InService, &[4]),
            (S::ProcessorOutage, ProcessorOutage, S::ProcessorOutage, &[]),
            (S::ProcessorOutage, Ready, S::ProcessorOutage, &[]),
            (S::ProcessorOutage, Alignment, S::OutOfService, &[9]),
            (S::ProcessorOutage, OOS, S::OutOfService, &[9]),
        ];
        for (state, received, next, answers) in table {
            let mut l = link_in(*state);
            let mut out = Vec::new();
            l.on_status(*received, INITIAL, Instant::now(), &mut out);
            assert_eq!(l.state(), *next, "{state:?} + {received}");
            assert_eq!(statuses(&out), *answers, "{state:?} + {received}");
        }
    }

    /// The same for timers: which state each one ends, and how.
    #[test]
    fn the_timer_state_table() {
        use State as S;
        let table: &[(S, Timer, S, &[u32])] = &[
            (S::NotAligned, Timer::T2, S::OutOfService, &[9]),
            (S::Aligned, Timer::T3, S::OutOfService, &[9]),
            (S::Proving, Timer::T4, S::AlignedReady, &[4]),
            (S::Proving, Timer::Proving, S::Proving, &[2]),
            (S::AlignedReady, Timer::T1, S::OutOfService, &[9]),
            // A timer that belongs to a state the link has left does nothing.
            (S::Aligned, Timer::T2, S::Aligned, &[]),
            (S::Proving, Timer::T3, S::Proving, &[]),
            (S::InService, Timer::T1, S::InService, &[]),
            (S::InService, Timer::T4, S::InService, &[]),
            (S::InService, Timer::T6, S::InService, &[]),
            (S::InService, Timer::T7, S::InService, &[]),
            (S::OutOfService, Timer::T2, S::OutOfService, &[]),
        ];
        for (state, timer, next, answers) in table {
            let mut l = link_in(*state);
            let mut out = Vec::new();
            l.timeout(*timer, Instant::now(), &mut out);
            assert_eq!(l.state(), *next, "{state:?} + {timer:?}");
            assert_eq!(statuses(&out), *answers, "{state:?} + {timer:?}");
        }
    }

    #[test]
    fn the_timers_of_alignment_start_and_stop_with_their_states() {
        let now = Instant::now();
        let mut l = link();
        let mut out = Vec::new();
        l.start(&mut out);
        out.clear();
        l.on_status(Status::Alignment, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Stop(Timer::T2)));
        assert!(has(&out, &Action::Start(Timer::T3, timers().t3)));
        out.clear();
        l.on_status(Status::ProvingNormal, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Stop(Timer::T3)));
        assert!(has(&out, &Action::Start(Timer::T4, timers().t4_normal)));
        assert!(has(
            &out,
            &Action::Start(Timer::Proving, timers().proving_interval)
        ));
        out.clear();
        l.timeout(Timer::T4, now, &mut out);
        assert!(has(&out, &Action::Stop(Timer::Proving)));
        assert!(has(&out, &Action::Start(Timer::T1, timers().t1)));
        out.clear();
        l.on_status(Status::Ready, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Stop(Timer::T1)));
        assert!(has(&out, &Action::InService));
    }

    #[test]
    fn emergency_from_either_end_shortens_proving() {
        let now = Instant::now();
        // Ours: we send Proving Emergency and use Pe.
        let mut l = Link::new(timers(), Proving::Emergency, 4);
        let mut out = Vec::new();
        l.start(&mut out);
        out.clear();
        l.on_status(Status::Alignment, INITIAL, now, &mut out);
        assert_eq!(statuses(&out), [3]);
        out.clear();
        l.on_status(Status::ProvingNormal, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Start(Timer::T4, timers().t4_emergency)));

        // The peer's: Q.703 7.2, "it continues to send status indication N but
        // initiates the short emergency proving period".
        let mut l = link_in(State::Aligned);
        let mut out = Vec::new();
        l.on_status(Status::ProvingEmergency, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Start(Timer::T4, timers().t4_emergency)));
        out.clear();
        l.timeout(Timer::Proving, now, &mut out);
        assert_eq!(statuses(&out), [2]);

        // And when it turns to emergency while we prove normally.
        let mut l = link_in(State::Proving);
        let mut out = Vec::new();
        l.on_status(Status::ProvingEmergency, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Start(Timer::T4, timers().t4_emergency)));
    }

    #[test]
    fn a_ready_that_arrives_during_proving_is_not_lost() {
        // The peer proves for a shorter time and says Ready once. When our T4
        // runs out the link goes straight into service.
        let now = Instant::now();
        let mut l = link_in(State::Proving);
        let mut out = Vec::new();
        l.on_status(Status::Ready, INITIAL, now, &mut out);
        assert_eq!(l.state(), State::Proving);
        l.timeout(Timer::T4, now, &mut out);
        assert_eq!(l.state(), State::InService);
        assert_eq!(statuses(&out), [4]);
        assert!(has(&out, &Action::InService));
    }

    #[test]
    fn user_data_in_aligned_ready_puts_the_link_in_service() {
        let now = Instant::now();
        let mut l = link_in(State::AlignedReady);
        let mut out = Vec::new();
        l.on_data(INITIAL, 0, UserDataMessage::new(0, msu(1)), now, &mut out);
        assert_eq!(l.state(), State::InService);
        assert!(has(&out, &Action::Deliver { msu: msu(1) }));
    }

    #[test]
    fn user_data_is_numbered_from_zero_and_carries_the_last_fsn_received() {
        // RFC 4165 2.2.2: the FSN "is the M2PA sequence number of the User Data
        // message being sent"; 2.2.1: the BSN "is the FSN of the message last
        // received from the peer". Q.703 has both start at the all-ones value,
        // so the first message is FSN 0.
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        l.send(msu(2), now, &mut out);
        l.on_data(1, 0, UserDataMessage::new(0, msu(9)), now, &mut out);
        l.flush_ack(&mut out);
        l.flush_ack(&mut out);
        l.send(msu(3), now, &mut out);
        // A message received just before one is sent is acknowledged by it:
        // no empty message follows.
        l.on_data(2, 1, UserDataMessage::new(0, msu(8)), now, &mut out);
        l.send(msu(4), now, &mut out);
        l.flush_ack(&mut out);
        let mut data = vec![0u8];
        data.extend(msu(1));
        assert_eq!(
            sent(&out)[0],
            Sent::Data {
                bsn: INITIAL,
                fsn: 0,
                data
            }
        );
        let numbers: Vec<(u32, u32, bool)> = sent(&out)
            .iter()
            .map(|s| match s {
                Sent::Data { bsn, fsn, data } => (*bsn, *fsn, data.is_empty()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            numbers,
            [
                (INITIAL, 0, false),
                (INITIAL, 1, false),
                // The acknowledgement of the peer's FSN 0: empty, once, and with
                // the FSN of our last message that carried data.
                (0, 1, true),
                (0, 2, false),
                (1, 3, false),
            ]
        );
        assert!(has(&out, &Action::Deliver { msu: msu(9) }));
    }

    #[test]
    fn an_acknowledgement_releases_the_retransmission_buffer() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        for tag in 0..4 {
            l.send(msu(tag), now, &mut out);
        }
        assert_eq!(l.unacknowledged(), 4);
        assert!(has(&out, &Action::Start(Timer::T7, timers().t7)));
        out.clear();
        // An empty User Data acknowledging FSN 1: two released, T7 now runs
        // for the oldest of the rest, and the empty message is not answered.
        l.on_data(
            1,
            INITIAL,
            UserDataMessage::empty(),
            now + 10 * MS,
            &mut out,
        );
        assert_eq!(l.unacknowledged(), 2);
        assert!(
            sent(&out).is_empty(),
            "an empty message is not acknowledged"
        );
        assert!(has(&out, &Action::Start(Timer::T7, 40 * MS)));
        out.clear();
        l.on_data(3, INITIAL, UserDataMessage::empty(), now, &mut out);
        assert_eq!(l.unacknowledged(), 0);
        assert!(has(&out, &Action::Stop(Timer::T7)));
    }

    #[test]
    fn t7_takes_the_link_out_when_a_message_stays_unacknowledged() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        out.clear();
        // Fired early (a restarted timer): re-armed for what is left.
        l.timeout(Timer::T7, now + 20 * MS, &mut out);
        assert_eq!(l.state(), State::InService);
        assert!(has(&out, &Action::Start(Timer::T7, 30 * MS)));
        out.clear();
        l.timeout(Timer::T7, now + 50 * MS, &mut out);
        assert_eq!(l.state(), State::OutOfService);
        assert!(has(&out, &Action::OutOfService(Failure::T7)));
        assert_eq!(statuses(&out), [9]);
    }

    #[test]
    fn user_data_out_of_sequence_is_discarded_and_not_acknowledged() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.on_data(INITIAL, 1, UserDataMessage::new(0, msu(1)), now, &mut out);
        l.flush_ack(&mut out);
        assert!(has(
            &out,
            &Action::Discarded {
                reason: Discard::RxOutOfSequence,
                count: 1
            }
        ));
        assert!(sent(&out).is_empty());
        out.clear();
        l.on_data(INITIAL, 0, UserDataMessage::new(0, msu(1)), now, &mut out);
        assert!(has(&out, &Action::Deliver { msu: msu(1) }));
        out.clear();
        // The same FSN again: a duplicate, discarded.
        l.on_data(INITIAL, 0, UserDataMessage::new(0, msu(1)), now, &mut out);
        assert!(!out.iter().any(|a| matches!(a, Action::Deliver { .. })));
    }

    #[test]
    fn two_abnormal_backward_sequence_numbers_in_three_fail_the_link() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        // BSN 5 acknowledges a message that was never sent.
        l.on_data(5, INITIAL, UserDataMessage::empty(), now, &mut out);
        assert_eq!(l.state(), State::InService);
        // One normal message in between does not clear the watch...
        l.on_data(INITIAL, INITIAL, UserDataMessage::empty(), now, &mut out);
        l.on_data(5, INITIAL, UserDataMessage::empty(), now, &mut out);
        assert_eq!(l.state(), State::OutOfService);
        assert!(has(&out, &Action::OutOfService(Failure::AbnormalBsn)));

        // ...two do.
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.on_data(5, INITIAL, UserDataMessage::empty(), now, &mut out);
        l.on_data(INITIAL, INITIAL, UserDataMessage::empty(), now, &mut out);
        l.on_data(INITIAL, INITIAL, UserDataMessage::empty(), now, &mut out);
        l.on_data(5, INITIAL, UserDataMessage::empty(), now, &mut out);
        assert_eq!(l.state(), State::InService);
    }

    #[test]
    fn the_sequence_numbers_wrap_at_24_bits() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        l.fsn_out = SEQ_MASK - 1;
        l.acked = SEQ_MASK - 1;
        l.fsn_in = SEQ_MASK - 1;
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        l.send(msu(2), now, &mut out);
        let fsns: Vec<u32> = sent(&out)
            .iter()
            .map(|s| match s {
                Sent::Data { fsn, .. } => *fsn,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(fsns, [SEQ_MASK, 0]);
        out.clear();
        l.on_data(0, SEQ_MASK, UserDataMessage::new(0, msu(7)), now, &mut out);
        assert_eq!(l.unacknowledged(), 0);
        assert!(has(&out, &Action::Deliver { msu: msu(7) }));
        out.clear();
        l.on_data(0, 0, UserDataMessage::new(0, msu(8)), now, &mut out);
        assert!(has(&out, &Action::Deliver { msu: msu(8) }));
        assert_eq!(l.bsnt(), 0);
    }

    #[test]
    fn a_busy_peer_is_not_sent_user_data_and_is_given_t6() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        out.clear();
        l.on_status(Status::Busy, INITIAL, now, &mut out);
        assert!(has(&out, &Action::Stop(Timer::T7)));
        assert!(has(&out, &Action::Start(Timer::T6, timers().t6)));
        out.clear();
        // "Additional Link Status Busy messages received while T6 is running do
        // not cause T6 to be reset".
        l.on_status(Status::Busy, INITIAL, now, &mut out);
        assert!(out.is_empty());
        l.send(msu(2), now, &mut out);
        assert!(sent(&out).is_empty(), "held while the peer is busy");
        // The peer's own traffic is still acknowledged.
        l.on_data(INITIAL, 0, UserDataMessage::new(0, msu(9)), now, &mut out);
        l.flush_ack(&mut out);
        assert_eq!(sent(&out).len(), 1);
        out.clear();
        l.on_status(Status::BusyEnded, INITIAL, now + 5 * MS, &mut out);
        assert!(has(&out, &Action::Stop(Timer::T6)));
        assert!(has(&out, &Action::Start(Timer::T7, timers().t7)));
        assert_eq!(sent(&out).len(), 1, "the held message goes out");

        // T6 running out is a link failure.
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        l.on_status(Status::Busy, INITIAL, now, &mut out);
        l.timeout(Timer::T6, now + timers().t6, &mut out);
        assert!(has(&out, &Action::OutOfService(Failure::T6)));
    }

    #[test]
    fn the_transmit_queue_is_bounded() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.on_status(Status::Busy, INITIAL, now, &mut out);
        for tag in 0..5 {
            l.send(msu(tag), now, &mut out);
        }
        assert!(has(
            &out,
            &Action::Discarded {
                reason: Discard::TxCongestion,
                count: 1
            }
        ));
    }

    #[test]
    fn processor_outage_at_the_peer_holds_traffic_until_it_recovers() {
        let now = Instant::now();
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.send(msu(1), now, &mut out);
        l.send(msu(2), now, &mut out);
        out.clear();
        l.on_status(Status::ProcessorOutage, INITIAL, now, &mut out);
        assert!(has(&out, &Action::RemoteProcessorOutage(true)));
        assert!(has(&out, &Action::Stop(Timer::T7)));
        l.send(msu(3), now, &mut out);
        assert!(sent(&out).is_empty());
        out.clear();
        // Recovered, having kept our FSN 0 and discarded FSN 1.
        l.on_status(Status::ProcessorRecovered, 0, now, &mut out);
        assert_eq!(l.state(), State::InService);
        assert!(has(
            &out,
            &Action::Discarded {
                reason: Discard::TxFlushedByPeer,
                count: 1
            }
        ));
        assert!(has(&out, &Action::RemoteProcessorOutage(false)));
        // Ready on the User Data stream, then the held message with the FSN
        // that follows the last one the peer kept.
        let frames = sent(&out);
        assert_eq!(
            frames[0],
            Sent::Status {
                state: 4,
                stream: 1,
                bsn: INITIAL,
                fsn: 0
            }
        );
        assert!(matches!(frames[1], Sent::Data { fsn: 1, .. }));
    }

    #[test]
    fn an_msu_for_a_link_that_is_not_in_service_is_counted() {
        let now = Instant::now();
        for state in [State::OutOfService, State::NotAligned, State::Proving] {
            let mut l = link_in(state);
            let mut out = Vec::new();
            l.send(msu(1), now, &mut out);
            assert_eq!(
                out,
                [Action::Discarded {
                    reason: Discard::TxNotInService,
                    count: 1
                }]
            );
            out.clear();
            l.on_data(INITIAL, 0, UserDataMessage::new(0, msu(1)), now, &mut out);
            assert_eq!(
                out,
                [Action::Discarded {
                    reason: Discard::RxNotInService,
                    count: 1
                }]
            );
        }
    }

    #[test]
    fn a_failed_link_gives_up_its_buffers_for_changeover() {
        // RFC 4165 4.2.3: with the FSNC of the far end, the transmitted
        // messages after it and then the untransmitted ones; without, the
        // untransmitted ones only.
        let now = Instant::now();
        let failed = || {
            let mut l = link_in(State::InService);
            let mut out = Vec::new();
            for tag in 0..3 {
                l.send(msu(tag), now, &mut out);
            }
            l.on_data(0, 0, UserDataMessage::new(0, msu(9)), now, &mut out);
            l.on_status(Status::Busy, INITIAL, now, &mut out);
            l.send(msu(3), now, &mut out);
            l.fail(Failure::Association, &mut out);
            assert!(
                !statuses(&out).contains(&9),
                "nothing is sent on a lost association"
            );
            l
        };
        let mut l = failed();
        assert_eq!(l.bsnt(), 0, "the last FSN accepted from the peer");
        assert_eq!(l.retrieve(Some(1)), [msu(2), msu(3)]);
        assert!(l.retrieve(Some(1)).is_empty(), "retrieved once");

        let mut l = failed();
        assert_eq!(l.retrieve(Some(0)), [msu(1), msu(2), msu(3)]);
        let mut l = failed();
        assert_eq!(l.retrieve(Some(2)), [msu(3)]);
        let mut l = failed();
        assert_eq!(l.retrieve(None), [msu(3)]);
        // An FSNC that is not one of ours: as if there were none.
        let mut l = failed();
        assert_eq!(l.retrieve(Some(77)), [msu(3)]);

        // Not retrieved before alignment starts again: counted as lost.
        let mut l = failed();
        let mut out = Vec::new();
        l.start(&mut out);
        assert!(has(
            &out,
            &Action::Discarded {
                reason: Discard::TxLostOnFailure,
                count: 3
            }
        ));
        assert_eq!(l.bsnt(), INITIAL);
    }

    #[test]
    fn a_failure_stops_every_timer() {
        let mut l = link_in(State::InService);
        let mut out = Vec::new();
        l.fail(Failure::LinkTest, &mut out);
        for timer in Timer::ALL {
            assert!(has(&out, &Action::Stop(timer)));
        }
        assert_eq!(statuses(&out), [9]);
        // Failing a link that is already out changes nothing.
        let mut again = Vec::new();
        l.fail(Failure::Stopped, &mut again);
        assert!(again.is_empty());
    }
}
