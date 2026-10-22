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
//! * **Level 3.** The task reports the link available or unavailable to
//!   signalling network management ([`crate::mtp3::management`]) and hands it
//!   every management message for this node (service indicator 0). What it
//!   does with the traffic it is handed is level 3's decision
//!   ([`traffic::LinkTraffic`]): send it, buffer it while a changeover or a
//!   changeback runs, or pass it on to the alternative links. When the link
//!   fails, what level 2 still holds is kept until the changeover says what
//!   the far end has (RFC 4165 4.2.3), and goes out on the alternatives.
//!   Between associations a task without one ([`idle_link`]) serves the queue
//!   the same way, so nothing handed to a link waits for it to come back.
//!
//! SCTP hands messages over in the order they arrived on the association, so
//! the "SHOULD give higher priority to reading the Link Status stream" of
//! RFC 4165 4.1.8 is not something this task can do.

use std::sync::Arc;
use std::time::Instant;

use ::m2pa::M2paMessage;
use async_sctp::SctpAssociation;
use mtp3::mgmt::{ManagementMessage, TestMessage};
use mtp3::{Mtp3Msu, NetworkIndicator, PointCode, ServiceIndicator, Variant};
use tokio::sync::watch;

use self::link::{Action, Discard, Failure, Link, State, Timer};
use self::slt::{LinkTest, TestAction, TestTimer};
use self::traffic::{LinkTraffic, Offer};
use super::forward::{dispatch, reroute};
use super::framing::Msu;
use super::registry::{AssocSlot, LinkCommand, LinkPort, LinkQueues, LinkSettings};
use super::{discard, TaskCtx};
use crate::metrics::{self, LinkTestResult, Mtp3Discard, Retrieved, RxDiscard};
use crate::mtp3::management::Input;

pub mod link;
pub mod slt;
pub mod traffic;

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
    /// Whether the link is available to level 3: in service and tested.
    available: bool,
    /// What level 3 has the link do with traffic.
    traffic: &'a mut LinkTraffic,
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
        // Q.704 2.4.2: a message for this point is delivered by its service
        // indicator, "to the corresponding User Part (or to the Message
        // Transfer Part level 3)". Signalling network management is level 3's.
        if msu.si == ServiceIndicator::SNM && msu.dpc.value() == self.port.settings.own_pc {
            metrics::msu(metrics::Dir::Rx, msu.si.0);
            self.management_message(&msu);
            return;
        }
        // 9.6.6: "All messages to another destination received at a
        // signalling point whose MTP is restarting are discarded", and so are
        // those for a local user.
        if self.ctx.registry.is_restarting() {
            metrics::msu(metrics::Dir::Rx, msu.si.0);
            metrics::mtp3_discard(Mtp3Discard::Restarting, 1);
            eprintln!(
                "siphon-sigtran: dropped a message received on `{}` for dpc {} (SI {}): this node's MTP is restarting",
                self.slot.id,
                msu.dpc.value(),
                msu.si.0
            );
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

    /// A signalling network management message for this node (service
    /// indicator 0): decoded here, acted on by signalling network management.
    fn management_message(&mut self, msu: &Mtp3Msu) {
        let message = match ManagementMessage::decode(&msu.data, Variant::Itu) {
            Ok(message) => message,
            Err(error) => {
                discard(RxDiscard::Undecodable, &self.slot.id, error);
                return;
            }
        };
        metrics::mtp3_management(metrics::Dir::Rx, message.name());
        match self.port.settings.index {
            Some(link) => self.ctx.registry.manage(Input::Received {
                link,
                opc: msu.opc.value(),
                slc: msu.sls,
                message,
            }),
            None => {
                metrics::mtp3_discard(Mtp3Discard::Management, 1);
                eprintln!(
                    "siphon-sigtran: {} received on `{}`, a link in no linkset: not acted on",
                    message.name(),
                    self.slot.id
                );
            }
        }
    }

    /// An MSU handed to the link for transmission: sent, buffered or passed
    /// on, as level 3 has it.
    async fn carry(&mut self, msu: Vec<u8>) {
        let can_send = self.link.is_aligned() && !self.lost;
        match self.traffic.offer(msu, can_send) {
            Offer::Send(msu) => {
                let mut actions = Vec::new();
                self.link.send(msu, Instant::now(), &mut actions);
                self.apply(actions).await;
            }
            Offer::Held => {}
            Offer::Divert(msu) => reroute(msu, self.ctx, self.slot).await,
            Offer::Full => buffer_full(&self.slot.id),
        }
    }

    /// What level 3 wants of the link.
    async fn command(&mut self, command: LinkCommand) {
        let mut actions = Vec::new();
        match command {
            LinkCommand::Hold { done } => hold(self.traffic, self.port, self.ctx, done),
            LinkCommand::Divert { fsnc } => {
                divert_all(self.traffic, fsnc, self.ctx, self.slot, self.port).await;
            }
            LinkCommand::Open => {
                let (buffered, lost) = self.traffic.open();
                route_to(self.port, self.ctx, true);
                lost_with_the_link(&self.slot.id, lost);
                let can_send = self.link.is_aligned() && !self.lost;
                for msu in buffered {
                    match self.traffic.offer(msu, can_send) {
                        Offer::Send(msu) => self.link.send(msu, Instant::now(), &mut actions),
                        Offer::Full => buffer_full(&self.slot.id),
                        Offer::Held | Offer::Divert(_) => {}
                    }
                }
            }
            // Q.704 3.2.2: the far end ordered a changeover from a link that
            // was available here.
            LinkCommand::Fail => self.link.fail(Failure::Stopped, &mut actions),
            LinkCommand::Direct(msu) => self.link.send(msu, Instant::now(), &mut actions),
        }
        self.apply(actions).await;
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
                    // On that link and no other, whatever it carries.
                    Some(port) => port.command(LinkCommand::Direct(reply)),
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

    /// Tell level 3 when the link becomes available (in service and tested)
    /// or stops being it. Whether it then carries traffic is level 3's call.
    fn refresh_availability(&mut self) {
        let aligned = self.link.is_aligned();
        let tested = !self.test.as_ref().is_some_and(|t| !t.is_available());
        let available = self.link.state() == State::InService && tested && !self.lost;
        let realigned = self.port.set_aligned(aligned);
        if available == self.available {
            if realigned {
                self.ctx.registry.recompute(&self.ctx.router);
            }
            return;
        }
        self.available = available;
        self.slot.set_active(available);
        if available {
            if let Some(link) = self.port.settings.index {
                self.ctx.registry.manage(Input::LinkUp { link });
            }
        } else {
            // Q.704 5.3.1: the sequence number of the last message accepted
            // goes into the changeover order, and what the link still holds
            // is kept for the retrieval that follows.
            let bsnt = self.link.bsnt();
            let lost = self.traffic.failed(self.link.detach());
            lost_with_the_link(&self.slot.id, lost);
            if let Some(link) = self.port.settings.index {
                self.ctx.registry.manage(Input::LinkDown { link, bsnt });
            }
        }
        self.ctx.registry.recompute(&self.ctx.router);
    }
}

/// Count what a failure took with it and nothing will send again.
fn lost_with_the_link(link: &str, count: usize) {
    if count > 0 {
        metrics::m2pa_discard(Discard::TxLostOnFailure, count as u64);
        eprintln!(
            "siphon-sigtran: m2pa link `{link}`: {count} unacknowledged message(s) lost with the link"
        );
    }
}

fn buffer_full(link: &str) {
    metrics::mtp3_discard(Mtp3Discard::BufferFull, 1);
    eprintln!("siphon-sigtran: m2pa link `{link}`: changeover buffer full, message dropped");
}

/// Say whether routing leads to the link, and have the route state follow.
/// The task that serves the link is the one that says so: it knows what it
/// does with the traffic before any arrives, and has passed on what it held
/// before none does.
fn route_to(port: &LinkPort, ctx: &TaskCtx, on: bool) {
    port.set_routable(on);
    ctx.registry.recompute(&ctx.router);
}

/// Buffer the traffic of the link, and route to it (Q.704 5.3.1 a, 6.3.1 i).
fn hold(
    traffic: &mut LinkTraffic,
    port: &LinkPort,
    ctx: &TaskCtx,
    done: Option<tokio::sync::oneshot::Sender<()>>,
) {
    traffic.hold();
    route_to(port, ctx, true);
    if let Some(done) = done {
        let _ = done.send(());
    }
}

/// The changeover of a link is complete (Q.704 5.5): send what it holds by the
/// alternatives, in order, say what became of the rest, and only then have
/// routing pass the link by. What is handed to the link meanwhile waits in its
/// queue and follows.
async fn divert_all(
    traffic: &mut LinkTraffic,
    fsnc: Option<u32>,
    ctx: &TaskCtx,
    slot: &AssocSlot,
    port: &LinkPort,
) {
    let diverted = traffic.divert(fsnc);
    metrics::mtp3_retrieved(Retrieved::Resent, diverted.resent as u64);
    metrics::mtp3_retrieved(Retrieved::Confirmed, diverted.confirmed as u64);
    metrics::mtp3_retrieved(Retrieved::LinkTest, diverted.link_tests as u64);
    eprintln!(
        "siphon-sigtran: m2pa link `{}`: changeover, {} message(s) to the alternative ({} of them sent before), {} accepted by the far end",
        slot.id,
        diverted.messages.len(),
        diverted.resent,
        diverted.confirmed
    );
    // Sent, not acknowledged, and not to be sent again without the far end's
    // word on them: possibly lost, and counted as that.
    lost_with_the_link(&slot.id, diverted.unconfirmed);
    for msu in diverted.messages {
        reroute(msu, ctx, slot).await;
    }
    route_to(port, ctx, false);
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
    // takes it over: tell the task that serves it, then wait for its queues.
    let mut mine = 0;
    port.generation.send_modify(|generation| {
        *generation += 1;
        mine = *generation;
    });
    let mut superseded = port.generation.subscribe();
    let mut queues = port.rx.lock().await;
    let LinkQueues {
        msus,
        commands,
        traffic,
    } = &mut *queues;

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
        traffic,
    };

    let mut actions = Vec::new();
    runner.link.established(&mut actions);
    runner.link.start(&mut actions);
    runner.apply(actions).await;

    let mut taken_over = false;
    let mut stopping = false;
    while !runner.lost {
        let wake = runner.deadlines.earliest();
        let sleep = async {
            match wake {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = shutdown.changed() => {
                stopping = true;
                break;
            }
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
            Some(command) = commands.recv() => runner.command(command).await,
            Some(msu) = msus.recv() => {
                // What level 3 said before it routed this message here comes
                // first.
                while let Ok(command) = commands.try_recv() {
                    runner.command(command).await;
                }
                runner.carry(msu).await;
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
    // Level 3 hears of it here, and what the link held is kept for the
    // changeover.
    runner.apply(actions).await;
    runner.deadlines = Deadlines::default();
    // A link that was not available carried nothing of level 3's: what it
    // still holds (its own link test) goes with it.
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
    drop(queues);
    // Until another association takes the link, its queue is still served:
    // traffic routed to it during a changeover is buffered and diverted.
    if !taken_over && !stopping {
        tokio::spawn(idle_link(slot.clone(), ctx.clone(), shutdown, mine));
    }
}

/// Serve the queues of a link that has no association: buffer or pass on what
/// it is handed, as level 3 has it, until an association takes the link.
/// `seen` is the generation of the link when this task was asked for: if a
/// newer association exists already, there is nothing to do.
pub async fn idle_link(
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
    seen: u64,
) {
    let Some(port) = slot.link() else {
        return;
    };
    let mut superseded = port.generation.subscribe();
    if *superseded.borrow_and_update() != seen {
        return;
    }
    let mut queues = tokio::select! {
        queues = port.rx.lock() => queues,
        _ = superseded.changed() => return,
        _ = shutdown.changed() => return,
    };
    let LinkQueues {
        msus,
        commands,
        traffic,
    } = &mut *queues;
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = superseded.changed() => break,
            Some(command) = commands.recv() => idle_command(command, traffic, &ctx, &slot).await,
            Some(msu) = msus.recv() => {
                while let Ok(command) = commands.try_recv() {
                    idle_command(command, traffic, &ctx, &slot).await;
                }
                match traffic.offer(msu, false) {
                    Offer::Divert(msu) => reroute(msu, &ctx, &slot).await,
                    Offer::Full => buffer_full(&slot.id),
                    Offer::Held | Offer::Send(_) => {}
                }
            }
        }
    }
}

/// What level 3 wants of a link that has no association.
async fn idle_command(
    command: LinkCommand,
    traffic: &mut LinkTraffic,
    ctx: &TaskCtx,
    slot: &AssocSlot,
) {
    let Some(port) = slot.link() else { return };
    match command {
        LinkCommand::Hold { done } => hold(traffic, port, ctx, done),
        LinkCommand::Divert { fsnc } => divert_all(traffic, fsnc, ctx, slot, port).await,
        // The link is not up: level 3 has not heard yet. It buffers until the
        // changeover that follows.
        LinkCommand::Open => hold(traffic, port, ctx, None),
        LinkCommand::Fail => {}
        LinkCommand::Direct(_) => {
            metrics::m2pa_discard(Discard::TxNotInService, 1);
            eprintln!(
                "siphon-sigtran: m2pa link `{}` has no association: a message bound to it was not sent",
                slot.id
            );
        }
    }
}
