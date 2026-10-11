//! M2PA per-link task (RFC 4165).
//!
//! One task per SCTP association runs one signalling link. The protocol is in
//! two state machines that do no I/O, [`link::Link`] (level 2: alignment,
//! sequence numbers, acknowledgement, the retransmission buffer) and
//! [`slt::LinkTest`] (the signalling link test of ITU-T Q.707); this module is
//! what connects them to the association, to the clock, and to level 3.
//!
//! * **Receive.** Every message is decoded once and handed to the link. An MSU
//!   the link delivers is a signalling link test message (answered or checked
//!   here, never routed) or goes to the router.
//! * **Send.** Nobody writes User Data to the association but this task: an MSU
//!   for the link arrives on the link's queue ([`LinkPort::offer`]), is numbered
//!   by the link and sent on stream 1. Link Status goes out on stream 0, except
//!   the ones RFC 4165 4.1.2 puts on stream 1.
//! * **Timers.** One deadline per timer of the two machines, one sleep until
//!   the earliest. All of them come from the configuration, in milliseconds.
//! * **Availability.** The link is an egress for routing only while level 2 is
//!   in service **and** the link test has passed (Q.707 2.2: "The signalling
//!   link becomes available only if the test is successful"). MSUs the peer
//!   sends are accepted as soon as level 2 is in service.
//! * **Failure.** A link that fails, or cannot be aligned, starts alignment
//!   again after `restart_ms` (Q.704 12.2.2, T17), for as long as the
//!   association lasts.
//!
//! SCTP hands messages over in the order they arrived on the association, so
//! the "SHOULD give higher priority to reading the Link Status stream" of
//! RFC 4165 4.1.8 is not something this task can do.

use std::sync::Arc;
use std::time::Instant;

use ::m2pa::M2paMessage;
use async_sctp::SctpAssociation;
use mtp3::mgmt::TestMessage;
use mtp3::{Mtp3Msu, NetworkIndicator, PointCode, ServiceIndicator, Variant};
use tokio::sync::watch;

use self::link::{Action, Discard, Failure, Link, State, Timer};
use self::slt::{LinkTest, TestAction, TestTimer};
use super::forward::dispatch;
use super::framing::Msu;
use super::registry::{AssocSlot, LinkPort, LinkSettings};
use super::{discard, TaskCtx};
use crate::metrics::{self, LinkTestResult, RxDiscard};

pub mod link;
pub mod slt;

const PPID_M2PA: u32 = 5;

/// Kept for callers of the 3.0 API. The link no longer answers one status with
/// another: see [`link::Link`].
#[deprecated(
    since = "3.1.0",
    note = "alignment is driven by timers in `transport::M2paLink`, not by answering statuses"
)]
pub fn next_status(state: ::m2pa::M2paState) -> Option<::m2pa::LinkState> {
    use ::m2pa::{LinkState, M2paState};
    match state {
        M2paState::Aligned => Some(LinkState::ProvingNormal),
        M2paState::Proving | M2paState::AlignedReady => Some(LinkState::Ready),
        _ => None,
    }
}

/// The deadlines of every timer of one link.
#[derive(Default)]
struct Deadlines {
    link: [Option<Instant>; 7],
    test: [Option<Instant>; 2],
    /// When alignment is to be started again.
    restart: Option<Instant>,
}

impl Deadlines {
    fn earliest(&self) -> Option<Instant> {
        self.link
            .iter()
            .chain(self.test.iter())
            .chain(std::iter::once(&self.restart))
            .flatten()
            .min()
            .copied()
    }
}

/// One link while its association lasts.
struct Runner<'a> {
    assoc: &'a SctpAssociation,
    slot: &'a AssocSlot,
    port: &'a LinkPort,
    ctx: &'a TaskCtx,
    link: Link,
    test: Option<LinkTest>,
    deadlines: Deadlines,
    /// The association refused a send: it is gone.
    lost: bool,
    /// Whether the slot is currently an egress for routing.
    available: bool,
}

impl Runner<'_> {
    fn settings(&self) -> &LinkSettings {
        &self.port.settings
    }

    /// Carry out what the link asked for, and whatever follows from it.
    async fn apply(&mut self, mut actions: Vec<Action>) {
        loop {
            while !actions.is_empty() {
                let batch = std::mem::take(&mut actions);
                for action in batch {
                    self.apply_one(action, &mut actions).await;
                }
            }
            // Level 3 has dealt with what was delivered: acknowledge it now,
            // unless something sent in the meantime already did.
            self.link.flush_ack(&mut actions);
            if actions.is_empty() {
                break;
            }
        }
        self.refresh_availability();
    }

    async fn apply_one(&mut self, action: Action, more: &mut Vec<Action>) {
        match action {
            Action::Send { frame, stream, si } => {
                if self.lost {
                    return;
                }
                match self.assoc.send(&frame, stream, PPID_M2PA).await {
                    Ok(_) => {
                        if let Some(si) = si {
                            metrics::msu(metrics::Dir::Tx, si);
                        }
                    }
                    // RFC 4165 4.1.7: a send failure makes the association
                    // unusable, and the link goes out of service.
                    Err(error) => {
                        eprintln!(
                            "siphon-sigtran: m2pa link `{}`: send failed ({error}), link out of service",
                            self.slot.id
                        );
                        self.lost = true;
                        self.link.fail(Failure::Association, more);
                    }
                }
            }
            Action::Deliver { msu } => self.deliver(msu, more).await,
            Action::Start(timer, after) => {
                self.deadlines.link[timer.index()] = Some(Instant::now() + after);
            }
            Action::Stop(timer) => self.deadlines.link[timer.index()] = None,
            Action::InService => {
                eprintln!(
                    "siphon-sigtran: m2pa link `{}` is in service at level 2",
                    self.slot.id
                );
                match self.test.as_mut() {
                    Some(test) => {
                        let mut out = Vec::new();
                        test.begin(&mut out);
                        self.apply_test(out, more);
                    }
                    None => eprintln!(
                        "siphon-sigtran: m2pa link `{}` is available without a signalling link test",
                        self.slot.id
                    ),
                }
            }
            Action::OutOfService(reason) => {
                metrics::m2pa_link_failure(reason);
                eprintln!(
                    "siphon-sigtran: m2pa link `{}` is out of service ({})",
                    self.slot.id,
                    reason.label()
                );
                if let Some(test) = self.test.as_mut() {
                    let mut out = Vec::new();
                    test.stop(&mut out);
                    self.apply_test(out, more);
                }
                // Q.704 12.2.2: alignment is tried again after T17.
                self.deadlines.restart = Some(Instant::now() + self.settings().restart);
            }
            Action::RemoteProcessorOutage(on) => eprintln!(
                "siphon-sigtran: m2pa link `{}`: remote processor outage {}",
                self.slot.id,
                if on { "began" } else { "ended" }
            ),
            Action::Discarded { reason, count } => {
                metrics::m2pa_discard(reason, count as u64);
                eprintln!(
                    "siphon-sigtran: m2pa link `{}` did not carry {count} message(s) ({})",
                    self.slot.id,
                    reason.label()
                );
            }
        }
    }

    /// Carry out what the link test asked for.
    fn apply_test(&mut self, test_actions: Vec<TestAction>, more: &mut Vec<Action>) {
        for action in test_actions {
            match action {
                TestAction::SendTest => self.send_test(more),
                TestAction::Start(timer, after) => {
                    self.deadlines.test[timer.index()] = Some(Instant::now() + after);
                }
                TestAction::Stop(timer) => self.deadlines.test[timer.index()] = None,
                TestAction::Available => {
                    metrics::link_test(LinkTestResult::Passed);
                    eprintln!(
                        "siphon-sigtran: m2pa link `{}` passed its signalling link test, available",
                        self.slot.id
                    );
                }
                TestAction::AttemptFailed => {
                    metrics::link_test(LinkTestResult::Failed);
                    eprintln!(
                        "siphon-sigtran: m2pa link `{}`: signalling link test not acknowledged correctly",
                        self.slot.id
                    );
                }
                // Q.707 2.2: "the link is put out of service, restoration is
                // attempted and a management system must be informed".
                TestAction::Failed => {
                    eprintln!(
                        "siphon-sigtran: m2pa link `{}` failed its signalling link test twice",
                        self.slot.id
                    );
                    self.link.fail(Failure::LinkTest, more);
                }
            }
        }
    }

    /// Send our signalling link test message on the link.
    fn send_test(&mut self, more: &mut Vec<Action>) {
        let port = self.port;
        let settings = &port.settings;
        let (Some(test), Some(adjacent)) = (&settings.test, settings.adjacent_pc) else {
            return;
        };
        let message = TestMessage::Sltm {
            pattern: test.pattern.clone(),
        };
        if let Some(msu) = test_msu(settings, adjacent, settings.slc, &message) {
            metrics::link_test(LinkTestResult::Sent);
            self.link.send(msu, Instant::now(), more);
        }
    }

    /// An MSU the link accepted: a signalling link test message is handled
    /// here, everything else is routed.
    async fn deliver(&mut self, raw: Vec<u8>, more: &mut Vec<Action>) {
        let msu = match Mtp3Msu::decode(&raw, Variant::Itu) {
            Ok(msu) => msu,
            Err(error) => {
                discard(RxDiscard::Undecodable, &self.slot.id, error);
                return;
            }
        };
        if msu.si == ServiceIndicator::SNT {
            metrics::msu(metrics::Dir::Rx, msu.si.0);
            self.link_test_message(&msu, more);
            return;
        }
        let msu = Msu {
            opc: msu.opc.value(),
            dpc: msu.dpc.value(),
            si: msu.si.0,
            ni: msu.ni.bits(),
            mp: msu.mp,
            sls: msu.sls,
            payload: msu.data,
        };
        dispatch(msu, self.ctx, &self.slot.id).await;
    }

    /// A signalling network testing message (service indicator 1).
    fn link_test_message(&mut self, msu: &Mtp3Msu, more: &mut Vec<Action>) {
        let settings = self.port.settings.clone();
        let message = match TestMessage::decode(&msu.data, Variant::Itu) {
            Ok(message) => message,
            Err(error) => {
                discard(RxDiscard::Undecodable, &self.slot.id, error);
                return;
            }
        };
        if msu.dpc.value() != settings.own_pc {
            discard(
                RxDiscard::LinkTest,
                &self.slot.id,
                format_args!(
                    "{} for point code {}, not this node",
                    message.name(),
                    msu.dpc.value()
                ),
            );
            return;
        }
        match message {
            // Q.707 2.2: answer "on the signalling link identified by the SLS
            // contained in the signalling link test message", with the pattern
            // "identical to the test pattern received".
            TestMessage::Sltm { pattern } => {
                let answer = TestMessage::Slta { pattern };
                let Some(reply) = test_msu(&settings, msu.opc.value(), msu.sls, &answer) else {
                    return;
                };
                if msu.sls == settings.slc {
                    self.link.send(reply, Instant::now(), more);
                    return;
                }
                let other = self
                    .ctx
                    .registry
                    .link_by_slc(&self.slot.id, msu.sls)
                    .and_then(|slot| slot.link());
                match other {
                    Some(port) => {
                        port.offer(reply);
                    }
                    None => discard(
                        RxDiscard::LinkTest,
                        &self.slot.id,
                        format_args!(
                            "SLTM names link code {}, which this linkset does not have (this link is {})",
                            msu.sls, settings.slc
                        ),
                    ),
                }
            }
            TestMessage::Slta { pattern } => {
                let Some(test) = self.test.as_mut().filter(|t| t.is_waiting()) else {
                    discard(
                        RxDiscard::LinkTest,
                        &self.slot.id,
                        "SLTA while no signalling link test is running",
                    );
                    return;
                };
                // Q.707 2.2, the three criteria: the link code names this link,
                // the originating point is the other end of it, the pattern is
                // the one sent.
                let expected = settings.test.as_ref().map(|t| t.pattern.as_slice());
                let correct = msu.sls == settings.slc
                    && Some(msu.opc.value()) == settings.adjacent_pc
                    && Some(pattern.as_slice()) == expected;
                let mut out = Vec::new();
                test.acknowledged(correct, &mut out);
                self.apply_test(out, more);
            }
        }
    }

    /// A timer of the link, of its test, or the restart delay ran out.
    async fn fire(&mut self) {
        let now = Instant::now();
        let mut actions = Vec::new();
        for timer in Timer::ALL {
            if self.deadlines.link[timer.index()].is_some_and(|at| at <= now) {
                self.deadlines.link[timer.index()] = None;
                self.link.timeout(timer, now, &mut actions);
            }
        }
        for timer in TestTimer::ALL {
            if self.deadlines.test[timer.index()].is_some_and(|at| at <= now) {
                self.deadlines.test[timer.index()] = None;
                if let Some(test) = self.test.as_mut() {
                    let mut out = Vec::new();
                    test.timeout(timer, &mut out);
                    self.apply_test(out, &mut actions);
                }
            }
        }
        if self.deadlines.restart.is_some_and(|at| at <= now) {
            self.deadlines.restart = None;
            self.link.start(&mut actions);
        }
        self.apply(actions).await;
    }

    /// One message from the association.
    async fn received(&mut self, data: &[u8], ppid: u32) {
        if ppid != PPID_M2PA {
            discard(
                RxDiscard::Ppid,
                &self.slot.id,
                format_args!("payload protocol identifier {ppid}, not M2PA"),
            );
            return;
        }
        let now = Instant::now();
        let mut actions = Vec::new();
        match M2paMessage::decode(data) {
            Ok(M2paMessage::LinkStatus { bsn, message, .. }) => {
                self.link.on_status(message.state, bsn, now, &mut actions);
            }
            Ok(M2paMessage::UserData { bsn, fsn, message }) => {
                self.link.on_data(bsn, fsn, message, now, &mut actions);
            }
            // RFC 4165 4.2.1: "an invalid Message Class or unsupported Message
            // Type in the Common Message Header, M2PA SHALL discard".
            Err(error) => discard(RxDiscard::Undecodable, &self.slot.id, error),
        }
        self.apply(actions).await;
    }

    /// Make the slot an egress exactly while the link is in service and tested.
    fn refresh_availability(&mut self) {
        let aligned = self.link.is_aligned();
        let tested = !self.test.as_ref().is_some_and(|t| !t.is_available());
        let available = self.link.state() == State::InService && tested && !self.lost;
        self.port.set_aligned(aligned);
        if available != self.available {
            self.available = available;
            self.slot.set_active(available);
        }
        self.ctx.registry.recompute(&self.ctx.router);
    }
}

/// Build the MSU of a signalling link test message from this node to `dpc`,
/// about link code `slc`.
fn test_msu(settings: &LinkSettings, dpc: u32, slc: u8, message: &TestMessage) -> Option<Vec<u8>> {
    let pc = |value: u32| PointCode::from_value(value & 0x3FFF, Variant::Itu).ok();
    Some(
        Mtp3Msu {
            si: ServiceIndicator::SNT,
            ni: NetworkIndicator::from_bits(settings.ni),
            mp: 0,
            opc: pc(settings.own_pc)?,
            dpc: pc(dpc)?,
            sls: slc,
            data: message.encode(Variant::Itu).ok()?,
        }
        .encode(Variant::Itu),
    )
}

/// Drive one M2PA link for as long as its association lasts.
pub async fn run_link(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(port) = slot.link() else {
        eprintln!(
            "siphon-sigtran: `{}` is not an m2pa link, association not served",
            slot.id
        );
        return;
    };
    // A link is one association (RFC 4165 4.1.2). A new one for the same link
    // takes it over: tell the task that runs it, then wait for its queue.
    port.generation.send_modify(|generation| *generation += 1);
    let mut superseded = port.generation.subscribe();
    let mut queue = port.rx.lock().await;
    let mut stale = 0;
    while queue.try_recv().is_ok() {
        stale += 1;
    }
    if stale > 0 {
        metrics::m2pa_discard(Discard::TxNotInService, stale);
        eprintln!(
            "siphon-sigtran: m2pa link `{}`: {stale} message(s) queued for the previous association dropped",
            slot.id
        );
    }

    let settings = &port.settings;
    if settings.test.is_none() {
        eprintln!(
            "siphon-sigtran: WARNING: m2pa link `{}` runs without a signalling link test \
             (switched off, in no linkset, or no adjacent_pc): it is available as soon as it is aligned",
            slot.id
        );
    }
    let mut runner = Runner {
        assoc: &assoc,
        slot: &slot,
        port,
        ctx: &ctx,
        link: Link::new(settings.timers.clone(), settings.proving, settings.tx_queue),
        test: settings.test.as_ref().map(|t| LinkTest::new(t.t1, t.t2)),
        deadlines: Deadlines::default(),
        lost: false,
        available: false,
    };

    let mut actions = Vec::new();
    runner.link.established(&mut actions);
    runner.link.start(&mut actions);
    runner.apply(actions).await;

    let mut taken_over = false;
    while !runner.lost {
        let wake = runner.deadlines.earliest();
        let sleep = async {
            match wake {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = superseded.changed() => {
                taken_over = true;
                eprintln!(
                    "siphon-sigtran: m2pa link `{}`: a new association took the link over",
                    slot.id
                );
                break;
            }
            received = assoc.recv() => match received {
                Ok((data, info)) => runner.received(&data, info.ppid).await,
                Err(_) => {
                    runner.lost = true;
                }
            },
            Some(msu) = queue.recv() => {
                let mut actions = Vec::new();
                runner.link.send(msu, Instant::now(), &mut actions);
                runner.apply(actions).await;
            }
            _ = sleep => runner.fire().await,
        }
    }

    // RFC 4165 4.1.7: without its association the link is out of service.
    let reason = if runner.lost {
        Failure::Association
    } else {
        Failure::Stopped
    };
    let mut actions = Vec::new();
    runner.link.fail(reason, &mut actions);
    runner.apply(actions).await;
    runner.deadlines = Deadlines::default();
    // What the failed link still holds goes with the association: nothing
    // retrieves it yet (changeover is level 3's, RFC 4165 4.2.3).
    let lost = runner.link.abandon();
    if lost > 0 {
        metrics::m2pa_discard(Discard::TxLostOnFailure, lost as u64);
        eprintln!(
            "siphon-sigtran: m2pa link `{}`: {lost} unacknowledged or unsent message(s) lost with the link",
            slot.id
        );
    }
    port.set_aligned(false);
    slot.set_active(false);
    // Only the task that still owns the link clears its sender: after a
    // take-over the slot already holds the new association.
    if !taken_over {
        slot.clear_sender();
    }
    ctx.registry.recompute(&ctx.router);
    drop(queue);
}
