//! M3UA (RFC 4666): the task of each association, and the task that runs ASP
//! state maintenance for the routing domain.
//!
//! An association is served by one task, in either role:
//!
//! * [`run_sg`], the **signalling gateway side** of a `server` association: a
//!   peer ASP connects and asks to come up and to become active. Every such
//!   request goes to ASP state maintenance, which answers it.
//! * [`run_asp`], the **ASP side** of a `client` association: this node sends
//!   ASP Up and, for every Application Server the association is configured
//!   in, ASP Active, again after T(ack) while they are not acknowledged, and
//!   again when the gateway says the server needs an ASP.
//!
//! [`run_layer`] is the one task that decides about ASP and Application Server
//! state ([`aspm::Aspm`] is the state machine). It also tells the ASPs what
//! level 3 found out about the SS7 destinations: it follows
//! [`Registry::destination_changes`](super::registry::Registry::destination_changes)
//! and sends DUNA, DAVA, DRST and SCON to every active ASP (RFC 4666 4.5.1),
//! which is the interworking of 1.4.3.2 in the direction of the ASPs. The
//! other direction is in the association task: a DUNA or DAVA from an ASP
//! goes to signalling route management, which sends transfer-prohibited and
//! transfer-allowed to the adjacent points.
//!
//! Nothing on the per-message path waits for the layer task. A DATA message
//! is admitted by one atomic per Application Server of the association
//! ([`Registry::admits`](super::registry::Registry::admits)).
//!
//! ## Not done
//!
//! Routing Key Management (REG REQ and DEREG REQ are answered with Error,
//! "Unsupported Message Class"), the Network Appearance parameter (read past),
//! the IPSP models, and more than one ASP on one SCTP association.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::m3ua::{error_code, CommonHeader, M3uaError, M3uaMessage, MessageClass, MessageType};
use async_sctp::SctpAssociation;
use mtp3::mgmt::ManagementMessage;
use mtp3::{Mtp3Event, Mtp3Status, PointCode};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, oneshot, watch};

use self::aspm::{Action, AsState, AspState, Aspm, Input, Message, Status, Timer};
use super::forward::{self, dispatch};
use super::framing::Msu;
use super::registry::{Admission, AssocSlot, DestinationChange, Registry};
use super::{discard, TaskCtx};
use crate::config::Role;
use crate::metrics::{self, Dir, Mtp3Discard, RxDiscard};
use crate::mtp3::management::Input as RouteInput;
use crate::mtp3::route::Destination;

pub mod aspm;

const CTRL_STREAM: u16 = 0;
const PPID_M3UA: u32 = 3;
/// The service indicator of signalling network management (Q.704 14.2.1).
const SI_MANAGEMENT: u8 = 0;
/// How long a management message waits for room in the send buffer of an
/// association before it is given up. One peer that does not read must not
/// hold up what every other peer is told.
const SEND_WAIT: Duration = Duration::from_millis(250);
/// Octets of an offending message that go into the Diagnostic Information of
/// an Error (RFC 4666 3.8.1: "the first 40 octets of the offending message").
const DIAGNOSTIC: usize = 40;
/// Affected point codes in one DUNA, DAVA or DRST.
const AFFECTED_PER_MESSAGE: usize = 128;

/// Why the M3UA layer did not send a message to an Application Server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// The server is pending and its queue is full.
    PendingFull,
    /// It was queued for a pending server, and T(r) ran out before an ASP
    /// became active (RFC 4666 4.3.2).
    PendingExpired,
    /// A signalling network management message for the point code of a
    /// server, which is not transferred in a DATA message (RFC 4666 1.4.3.2)
    /// and has no M3UA message of its own.
    Management,
    /// A management message that did not fit the send buffer of the
    /// association in time, or that the association refused.
    NotSent,
}

impl Discard {
    /// Every value, for the metrics rendering.
    pub const ALL: [Discard; 4] = [
        Self::PendingFull,
        Self::PendingExpired,
        Self::Management,
        Self::NotSent,
    ];

    /// The `reason` label of `sigtran_m3ua_discarded_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::PendingFull => "pending-full",
            Self::PendingExpired => "pending-expired",
            Self::Management => "management",
            Self::NotSent => "not-sent",
        }
    }
}

/// Something M3UA management did, or noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Nothing arrived from a peer for twice T(beat): the association was
    /// aborted (RFC 4666 4.3.4.6).
    BeatTimeout,
    /// A Heartbeat Ack that does not return the Heartbeat Data last sent.
    BeatMismatch,
    /// T(ack) ran out and an ASP Up or ASP Active was sent again.
    AckTimeout,
    /// T(r) ran out for a pending Application Server.
    RecoveryExpired,
    /// An ASP took over an Override server from the one that was active.
    Takeover,
    /// Destination changes arrived faster than they were read: the ASPs were
    /// brought up to date from the routing state instead.
    ChangesLagged,
    /// A DATA message on SCTP stream 0, accepted (RFC 4666 1.4.7).
    DataOnStream0,
}

impl Event {
    /// Every value, for the metrics rendering.
    pub const ALL: [Event; 7] = [
        Self::BeatTimeout,
        Self::BeatMismatch,
        Self::AckTimeout,
        Self::RecoveryExpired,
        Self::Takeover,
        Self::ChangesLagged,
        Self::DataOnStream0,
    ];

    /// The `event` label of `sigtran_m3ua_events_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::BeatTimeout => "beat-timeout",
            Self::BeatMismatch => "beat-mismatch",
            Self::AckTimeout => "ack-timeout",
            Self::RecoveryExpired => "recovery-expired",
            Self::Takeover => "takeover",
            Self::ChangesLagged => "changes-lagged",
            Self::DataOnStream0 => "data-on-stream-0",
        }
    }
}

/// The abbreviation of a message type in RFC 4666 3.1.2, for the counters.
fn type_name(message_type: MessageType) -> &'static str {
    match message_type {
        MessageType::Error => "ERR",
        MessageType::Notify => "NTFY",
        MessageType::Data => "DATA",
        MessageType::Duna => "DUNA",
        MessageType::Dava => "DAVA",
        MessageType::Daud => "DAUD",
        MessageType::Scon => "SCON",
        MessageType::Dupu => "DUPU",
        MessageType::Drst => "DRST",
        MessageType::AspUp => "ASPUP",
        MessageType::AspDown => "ASPDN",
        MessageType::Heartbeat => "BEAT",
        MessageType::AspUpAck => "ASPUP_ACK",
        MessageType::AspDownAck => "ASPDN_ACK",
        MessageType::HeartbeatAck => "BEAT_ACK",
        MessageType::AspActive => "ASPAC",
        MessageType::AspInactive => "ASPIA",
        MessageType::AspActiveAck => "ASPAC_ACK",
        MessageType::AspInactiveAck => "ASPIA_ACK",
        MessageType::RegReq => "REG_REQ",
        MessageType::RegRsp => "REG_RSP",
        MessageType::DeregReq => "DEREG_REQ",
        MessageType::DeregRsp => "DEREG_RSP",
    }
}

/// An Error Code as the name RFC 4666 3.8.1 gives it, for the counters and
/// the log.
pub fn error_name(code: u32) -> &'static str {
    match code {
        error_code::INVALID_VERSION => "invalid-version",
        error_code::UNSUPPORTED_MESSAGE_CLASS => "unsupported-message-class",
        error_code::UNSUPPORTED_MESSAGE_TYPE => "unsupported-message-type",
        error_code::UNSUPPORTED_TRAFFIC_MODE_TYPE => "unsupported-traffic-mode-type",
        error_code::UNEXPECTED_MESSAGE => "unexpected-message",
        error_code::PROTOCOL_ERROR => "protocol-error",
        error_code::INVALID_STREAM_IDENTIFIER => "invalid-stream-identifier",
        error_code::REFUSED_MANAGEMENT_BLOCKING => "refused-management-blocking",
        error_code::ASP_IDENTIFIER_REQUIRED => "asp-identifier-required",
        error_code::INVALID_ASP_IDENTIFIER => "invalid-asp-identifier",
        error_code::INVALID_PARAMETER_VALUE => "invalid-parameter-value",
        error_code::PARAMETER_FIELD_ERROR => "parameter-field-error",
        error_code::UNEXPECTED_PARAMETER => "unexpected-parameter",
        error_code::DESTINATION_STATUS_UNKNOWN => "destination-status-unknown",
        error_code::INVALID_NETWORK_APPEARANCE => "invalid-network-appearance",
        error_code::MISSING_PARAMETER => "missing-parameter",
        error_code::INVALID_ROUTING_CONTEXT => "invalid-routing-context",
        error_code::NO_CONFIGURED_AS_FOR_ASP => "no-configured-as-for-asp",
        _ => "other",
    }
}

/// Count a management message in one direction, and what it says when it is
/// an Error or a Notify.
fn count(dir: Dir, message: &M3uaMessage) {
    metrics::m3ua_management(dir, type_name(message.message_type));
    match message.message_type {
        MessageType::Error => {
            metrics::m3ua_error(dir, error_name(message.error_code().unwrap_or(0)));
        }
        MessageType::Notify => {
            let status = message.status().and_then(Status::from_code);
            metrics::m3ua_notify(dir, status.map_or("other", Status::label));
        }
        _ => {}
    }
}

/// Send a management message on an association. One that cannot be sent is
/// counted and logged.
pub(super) async fn send_management(assoc: &SctpAssociation, id: &str, message: &M3uaMessage) {
    let name = type_name(message.message_type);
    let octets = message.encode();
    let sending = assoc.send(&octets, CTRL_STREAM, PPID_M3UA);
    match tokio::time::timeout(SEND_WAIT, sending).await {
        Ok(Ok(_)) => count(Dir::Tx, message),
        Ok(Err(error)) => {
            metrics::m3ua_discard(Discard::NotSent, 1);
            eprintln!("siphon-sigtran: m3ua `{id}`: {name} not sent: {error}");
        }
        Err(_) => {
            metrics::m3ua_discard(Discard::NotSent, 1);
            eprintln!(
                "siphon-sigtran: m3ua `{id}`: {name} not sent, the association does not take it"
            );
        }
    }
}

/// The Diagnostic Information for an offending message.
fn diagnostic(offending: &[u8]) -> Option<Vec<u8>> {
    (!offending.is_empty()).then(|| offending[..offending.len().min(DIAGNOSTIC)].to_vec())
}

/// The M3UA message for what ASP state maintenance sends.
fn encode(message: &Message, offending: &[u8]) -> M3uaMessage {
    match message {
        Message::UpAck => M3uaMessage::asp_up_ack(None),
        Message::DownAck => M3uaMessage::asp_down_ack(None),
        Message::ActiveAck { mode, contexts } => {
            M3uaMessage::asp_active_ack(*mode, None).with_routing_contexts(contexts)
        }
        Message::InactiveAck { contexts } => {
            M3uaMessage::asp_inactive_ack(None).with_routing_contexts(contexts)
        }
        Message::Notify {
            status,
            asp_identifier,
            context,
        } => {
            let (status_type, information) = status.code();
            M3uaMessage::notify_status(status_type, information, *asp_identifier, Some(*context))
        }
        Message::Error { code, contexts } => {
            M3uaMessage::error(*code, None, diagnostic(offending)).with_routing_contexts(contexts)
        }
    }
}

// ── ASP state maintenance, the task ──────────────────────────────────────────

/// One event for ASP state maintenance, from the task of an association.
pub(crate) struct Request {
    input: Input,
    /// The message the event is, for the Diagnostic Information of an Error.
    offending: Vec<u8>,
    /// Told once everything the event calls for has been done.
    done: Option<oneshot::Sender<()>>,
}

/// Report an event to ASP state maintenance and wait until it has been acted
/// on: what the association receives next finds the state it leaves.
async fn submit(ctx: &TaskCtx, input: Input, offending: &[u8]) {
    let (done, acted) = oneshot::channel();
    let request = Request {
        input,
        offending: offending.to_vec(),
        done: Some(done),
    };
    if ctx.registry.request(request) {
        let _ = acted.await;
    }
}

/// What the ASPs have been told about a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Told {
    Unavailable,
    Available,
    Restricted,
}

struct Layer {
    machine: Aspm,
    ctx: TaskCtx,
    deadlines: BTreeMap<Timer, Instant>,
    /// What signalling route management last said about each destination.
    known: BTreeMap<u32, Told>,
    /// What the active ASPs were last told about it.
    told: BTreeMap<u32, Told>,
    /// This node's MTP restart runs.
    restarting: bool,
}

impl Layer {
    async fn serve(&mut self, request: Request) {
        let actions = self.machine.handle(request.input);
        self.perform(actions, &request.offending).await;
        if let Some(done) = request.done {
            let _ = done.send(());
        }
    }

    async fn perform(&mut self, actions: Vec<Action>, offending: &[u8]) {
        let registry = self.ctx.registry.clone();
        let mut changed = false;
        for action in actions {
            match action {
                Action::Send { asp, message } => {
                    let Some(slot) = registry.asp_slot(asp) else {
                        continue;
                    };
                    let Some(assoc) = slot.sender() else {
                        continue;
                    };
                    if matches!(
                        message,
                        Message::Notify {
                            status: Status::AlternateAspActive,
                            ..
                        }
                    ) {
                        metrics::m3ua_event(Event::Takeover);
                    }
                    send_management(&assoc, &slot.id, &encode(&message, offending)).await;
                }
                Action::Start(timer, after) => {
                    self.deadlines.insert(timer, Instant::now() + after);
                }
                Action::Stop(timer) => {
                    self.deadlines.remove(&timer);
                }
                Action::Asp { asp, server, state } => {
                    if let Some(slot) = registry.asp_slot(asp) {
                        registry.set_asp_active(slot, server, state == AspState::Active);
                        changed = true;
                    }
                }
                Action::Server { server, state } => {
                    let queued = registry.set_server_state(server, state);
                    // The routing state before what was queued is sent by it.
                    registry.recompute(&self.ctx.router);
                    changed = false;
                    let Some((name, _)) = registry.server(server) else {
                        continue;
                    };
                    eprintln!(
                        "siphon-sigtran: m3ua: application server `{name}` is {}",
                        state.label()
                    );
                    if state == AsState::Active {
                        let via = Destination::ApplicationServer(name.to_string());
                        for msu in &queued {
                            let sending = forward::send_via(&via, msu, &registry);
                            if tokio::time::timeout(SEND_WAIT, sending).await.is_err() {
                                metrics::m3ua_discard(Discard::NotSent, 1);
                            }
                        }
                    } else if !queued.is_empty() {
                        metrics::m3ua_discard(Discard::PendingExpired, queued.len() as u64);
                        eprintln!(
                            "siphon-sigtran: m3ua: {} messages queued for `{name}` dropped, no ASP became active",
                            queued.len()
                        );
                    }
                }
                Action::Activated { asp, server } => self.brief(asp, server).await,
            }
        }
        if changed {
            registry.recompute(&self.ctx.router);
        }
    }

    /// Whether a destination is reached through an Application Server now:
    /// this node's MTP restart does not concern it.
    fn by_server(&self, dpc: u32) -> bool {
        self.ctx
            .router
            .egress_for(&self.ctx.tenant, dpc, 0, None)
            .is_some_and(|via| via.is_application_server())
    }

    /// What the ASPs are to believe about a destination. RFC 4666 4.6: while
    /// the MTP restart runs a destination is unavailable to them, "even if it
    /// received an indication that the destination became available".
    fn wanted(&self, dpc: u32) -> Told {
        let known = self.known.get(&dpc).copied().unwrap_or(Told::Unavailable);
        if self.restarting && known != Told::Unavailable && !self.by_server(dpc) {
            Told::Unavailable
        } else {
            known
        }
    }

    /// Bring what the ASPs were told about these destinations in line with
    /// what is, in the order given.
    async fn settle(&mut self, dpcs: impl IntoIterator<Item = u32>) {
        let mut changes: Vec<(Told, u32)> = Vec::new();
        for dpc in dpcs {
            let wanted = self.wanted(dpc);
            let told = self.told.insert(dpc, wanted).unwrap_or(Told::Unavailable);
            if told != wanted {
                changes.push((wanted, dpc));
            }
        }
        // Destinations that changed the same way, one after another, share a
        // message (3.4.1: "Including multiple Affected PCs may be useful when
        // ... a linkset event simultaneously affects the availability status
        // of a list of destinations").
        let mut rest = changes.as_slice();
        while let Some((what, _)) = rest.first().copied() {
            let run = rest
                .iter()
                .take(AFFECTED_PER_MESSAGE)
                .take_while(|(other, _)| *other == what)
                .count();
            let dpcs: Vec<u32> = rest[..run].iter().map(|(_, dpc)| *dpc).collect();
            rest = &rest[run..];
            self.tell(what, &dpcs).await;
        }
    }

    /// Send a DUNA, DAVA or DRST about `dpcs` to every ASP that is active
    /// (RFC 4666 4.6: "all concerned available ASPs (i.e., ASPs in the
    /// ASP-ACTIVE state)"), except those of a server that is itself a route
    /// to the destination.
    async fn tell(&self, what: Told, dpcs: &[u32]) {
        let registry = &self.ctx.registry;
        for server in 0..registry.server_count() {
            let Some((_, context)) = registry.server(server) else {
                continue;
            };
            let concerned: Vec<u32> = dpcs
                .iter()
                .copied()
                .filter(|dpc| registry.destinations().get(dpc).is_none_or_absent(server))
                .collect();
            if concerned.is_empty() {
                continue;
            }
            let message = availability(what, context, concerned);
            for slot in registry.active_asps(server) {
                // Only an ASP is told: as an ASP itself, this node has no
                // such message to send to its gateway.
                if slot.role != Role::Server {
                    continue;
                }
                if let Some(assoc) = slot.sender() {
                    send_management(&assoc, &slot.id, &message).await;
                }
            }
        }
    }

    /// RFC 4666 4.5.1: "For the particular case that an ASP becomes active
    /// for an AS and destinations normally accessible to the AS are
    /// inaccessible, restricted, or congested, the SG MAY send DUNA, DRST, or
    /// SCON messages ... to the ASP newly active for the AS". This node does:
    /// it is how the ASP learns what the others were told before it came.
    async fn brief(&self, asp: usize, server: usize) {
        let registry = &self.ctx.registry;
        let (Some(slot), Some((_, context))) = (registry.asp_slot(asp), registry.server(server))
        else {
            return;
        };
        if slot.role != Role::Server {
            return;
        }
        let Some(assoc) = slot.sender() else {
            return;
        };
        for what in [Told::Unavailable, Told::Restricted] {
            let dpcs: Vec<u32> = registry
                .destinations()
                .iter()
                .filter(|(dpc, servers)| !servers.contains(&server) && self.wanted(**dpc) == what)
                .map(|(dpc, _)| *dpc)
                .collect();
            for chunk in dpcs.chunks(AFFECTED_PER_MESSAGE) {
                let message = availability(what, context, chunk.to_vec());
                send_management(&assoc, &slot.id, &message).await;
            }
        }
    }

    /// Changes that arrived together: what they say about availability is
    /// settled in one go, so that destinations that changed the same way
    /// share a message.
    async fn changed(&mut self, changes: Vec<DestinationChange>) {
        let mut dpcs = Vec::new();
        for change in changes {
            let (dpc, known) = match change {
                DestinationChange::Accessible { dpc } => (dpc, Told::Available),
                DestinationChange::Inaccessible { dpc } => (dpc, Told::Unavailable),
                DestinationChange::Restricted { dpc } => (dpc, Told::Restricted),
                DestinationChange::Congested { .. } => {
                    self.settle(std::mem::take(&mut dpcs)).await;
                    self.congested(change).await;
                    continue;
                }
            };
            self.known.insert(dpc, known);
            dpcs.push(dpc);
        }
        self.settle(dpcs).await;
    }

    async fn congested(&mut self, change: DestinationChange) {
        match change {
            DestinationChange::Accessible { .. }
            | DestinationChange::Inaccessible { .. }
            | DestinationChange::Restricted { .. } => {}
            // RFC 4666 4.5.1: an MTP-STATUS indication becomes a SCON. The
            // level is left out when the transfer-controlled had none (the
            // international method, 3.4.4).
            DestinationChange::Congested { dpc, status } => {
                let registry = &self.ctx.registry;
                for server in 0..registry.server_count() {
                    let Some((_, context)) = registry.server(server) else {
                        continue;
                    };
                    let message = M3uaMessage::scon(
                        Some(context),
                        vec![dpc],
                        None,
                        (status != 0).then_some(status),
                    );
                    for slot in registry.active_asps(server) {
                        if slot.role != Role::Server {
                            continue;
                        }
                        if let Some(assoc) = slot.sender() {
                            send_management(&assoc, &slot.id, &message).await;
                        }
                    }
                }
            }
        }
    }

    /// Changes were missed: take the state of every destination from the
    /// routing tables instead.
    async fn resync(&mut self) {
        let dpcs: Vec<u32> = self.ctx.registry.destinations().keys().copied().collect();
        for dpc in &dpcs {
            let known = destination_status(&self.ctx, *dpc, false);
            self.known.insert(*dpc, known);
        }
        self.settle(dpcs).await;
    }

    /// This node's MTP restart began or ended (RFC 4666 4.6).
    async fn restart(&mut self, on: bool) {
        if self.restarting == on {
            return;
        }
        self.restarting = on;
        let dpcs: Vec<u32> = self.ctx.registry.destinations().keys().copied().collect();
        self.settle(dpcs).await;
    }

    fn due(&mut self, now: Instant) -> Vec<Timer> {
        let due: Vec<Timer> = self
            .deadlines
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(timer, _)| *timer)
            .collect();
        for timer in &due {
            self.deadlines.remove(timer);
        }
        due
    }
}

/// `Option::is_none_or` came after the minimum toolchain of this crate.
trait NotARoute {
    fn is_none_or_absent(&self, server: usize) -> bool;
}

impl NotARoute for Option<&Vec<usize>> {
    fn is_none_or_absent(&self, server: usize) -> bool {
        match self {
            None => true,
            Some(servers) => !servers.contains(&server),
        }
    }
}

/// The DUNA, DAVA or DRST for a list of destinations.
fn availability(what: Told, context: u32, dpcs: Vec<u32>) -> M3uaMessage {
    match what {
        Told::Unavailable => M3uaMessage::duna(Some(context), dpcs),
        Told::Available => M3uaMessage::dava(Some(context), dpcs),
        Told::Restricted => M3uaMessage::drst(Some(context), dpcs),
    }
}

/// The state of a destination from the routing tables as they are. With
/// `audit`, as an ASP that asks is to be answered: unavailable while this
/// node's MTP restart runs (RFC 4666 4.6).
fn destination_status(ctx: &TaskCtx, dpc: u32, audit: bool) -> Told {
    match ctx.router.egress_for(&ctx.tenant, dpc, 0, None) {
        None => Told::Unavailable,
        Some(Destination::Linkset(_)) if audit && ctx.registry.is_restarting() => Told::Unavailable,
        Some(_) if ctx.router.is_restricted(&ctx.tenant, dpc) => Told::Restricted,
        Some(_) => Told::Available,
    }
}

/// Run ASP state maintenance of one domain until shutdown.
pub(super) async fn run_layer(
    machine: Aspm,
    mut requests: mpsc::UnboundedReceiver<Request>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut changes = ctx.registry.destination_changes();
    let mut restart = ctx.registry.restart_changes();
    let mut layer = Layer {
        machine,
        ctx,
        deadlines: BTreeMap::new(),
        known: BTreeMap::new(),
        told: BTreeMap::new(),
        restarting: false,
    };
    loop {
        let wake = layer.deadlines.values().min().copied();
        let sleep = async {
            match wake {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(request) = requests.recv() => layer.serve(request).await,
            change = changes.recv() => match change {
                Ok(change) => {
                    let mut together = vec![change];
                    while let Ok(next) = changes.try_recv() {
                        together.push(next);
                    }
                    layer.changed(together).await;
                }
                Err(RecvError::Lagged(missed)) => {
                    metrics::m3ua_event(Event::ChangesLagged);
                    eprintln!(
                        "siphon-sigtran: m3ua: {missed} destination changes missed, the ASPs are told the state as it is"
                    );
                    layer.resync().await;
                }
                Err(RecvError::Closed) => break,
            },
            Ok(()) = restart.changed() => {
                let on = *restart.borrow_and_update();
                layer.restart(on).await;
            }
            _ = sleep => {
                for timer in layer.due(Instant::now()) {
                    let Timer::Recovery(server) = timer;
                    metrics::m3ua_event(Event::RecoveryExpired);
                    if let Some((name, _)) = layer.ctx.registry.server(server) {
                        eprintln!("siphon-sigtran: m3ua: T(r) of application server `{name}` ran out");
                    }
                    let actions = layer.machine.handle(Input::Timeout(timer));
                    layer.perform(actions, &[]).await;
                }
            }
        }
    }
}

// ── One association ──────────────────────────────────────────────────────────

/// The ASP side of an association: what this node has asked for and is still
/// waiting to have acknowledged.
struct Asking {
    /// ASP Up was acknowledged.
    up: bool,
    /// The Routing Contexts whose ASP Active is not acknowledged.
    contexts: Vec<u32>,
    /// When T(ack) runs out.
    at: Option<Instant>,
}

struct Peer {
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    asp: usize,
    /// The far end is the ASP and this node its signalling gateway.
    gateway: bool,
    /// Something arrived since the last Heartbeat was sent.
    heard: bool,
    /// Heartbeat intervals in a row in which nothing arrived.
    silent: u8,
    /// The Heartbeat Data last sent.
    beat: u64,
    asking: Asking,
}

/// What is to become of the association after a message.
#[derive(PartialEq, Eq)]
enum Next {
    Continue,
    /// Another association has taken the slot over.
    Superseded,
}

impl Peer {
    fn id(&self) -> &str {
        &self.slot.id
    }

    async fn send(&self, message: &M3uaMessage) {
        send_management(&self.assoc, self.id(), message).await;
    }

    /// Answer a message with an Error and count it as dropped. Nothing is
    /// sent to a peer that is not there to be told (`code` is `None`).
    async fn refuse(
        &self,
        code: Option<u32>,
        contexts: &[u32],
        offending: &[u8],
        reason: RxDiscard,
        detail: impl Into<String>,
    ) {
        discard(reason, self.id(), detail.into());
        if let Some(code) = code {
            let error = M3uaMessage::error(code, None, diagnostic(offending))
                .with_routing_contexts(contexts);
            self.send(&error).await;
        }
    }

    async fn submit(&self, input: Input, offending: &[u8]) {
        submit(&self.ctx, input, offending).await;
    }

    // ── The ASP side ─────────────────────────────────────────────────────────

    fn ack_after(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.slot.m3ua.ack_ms)
    }

    async fn ask_up(&mut self) {
        self.asking.up = false;
        self.asking.contexts.clear();
        self.asking.at = Some(self.ack_after());
        self.send(&M3uaMessage::asp_up(self.slot.m3ua.asp_id, None))
            .await;
    }

    /// Ask to become active in the server of a Routing Context this
    /// association is configured in.
    async fn ask_active(&mut self, context: u32) {
        let Some(membership) = self
            .slot
            .memberships()
            .iter()
            .find(|m| m.context == context)
        else {
            return;
        };
        if !self.asking.contexts.contains(&context) {
            self.asking.contexts.push(context);
        }
        self.asking.at = Some(self.ack_after());
        let message =
            M3uaMessage::asp_active(Some(aspm::mode_value(membership.mode)), Some(context));
        self.send(&message).await;
    }

    /// T(ack) ran out (RFC 4666 4.3.4.1, 4.3.4.3: "the ASP MAY restart T(ack)
    /// and resend").
    async fn ack_timeout(&mut self) {
        self.asking.at = None;
        if !self.asking.up {
            metrics::m3ua_event(Event::AckTimeout);
            eprintln!(
                "siphon-sigtran: m3ua `{}`: ASP Up not acknowledged, sent again",
                self.id()
            );
            self.ask_up().await;
            return;
        }
        for context in self.asking.contexts.clone() {
            metrics::m3ua_event(Event::AckTimeout);
            eprintln!(
                "siphon-sigtran: m3ua `{}`: ASP Active for routing context {context} not acknowledged, sent again",
                self.id()
            );
            self.ask_active(context).await;
        }
    }

    /// The Routing Contexts a message of the gateway is about: those it
    /// names, or every one this association is configured in.
    fn about(&self, message: &M3uaMessage) -> Vec<u32> {
        let named = message.routing_contexts();
        if named.is_empty() {
            self.slot.memberships().iter().map(|m| m.context).collect()
        } else {
            named
        }
    }

    async fn gateway_said(&mut self, message: &M3uaMessage, raw: &[u8]) {
        let named = (!message.routing_contexts().is_empty()).then(|| message.routing_contexts());
        match message.message_type {
            MessageType::AspUpAck => {
                // 4.3.4.1: "If the ASP receives an unexpected ASP Up Ack
                // message, the ASP should consider itself in the ASP-INACTIVE
                // state."
                let again = self.asking.up;
                self.asking.up = true;
                self.asking.at = None;
                if again {
                    self.submit(
                        Input::PeerInactive {
                            asp: self.asp,
                            contexts: None,
                        },
                        raw,
                    )
                    .await;
                } else {
                    self.submit(Input::PeerUp { asp: self.asp }, raw).await;
                }
                for context in self.about(message) {
                    self.ask_active(context).await;
                }
            }
            MessageType::AspActiveAck => {
                let contexts = self.about(message);
                self.asking.contexts.retain(|c| !contexts.contains(c));
                if self.asking.contexts.is_empty() {
                    self.asking.at = None;
                }
                self.submit(
                    Input::PeerActive {
                        asp: self.asp,
                        contexts: named,
                    },
                    raw,
                )
                .await;
            }
            MessageType::AspInactiveAck => {
                // 4.3.4.4: "If the ASP receives an ASP Inactive Ack without
                // having sent an ASP Inactive message, the ASP should now
                // consider itself to be in the ASP-INACTIVE state. If the ASP
                // was previously in the ASP-ACTIVE state, the ASP should then
                // initiate procedures to return itself to its previous
                // state." It asks again when T(ack) runs out, not at once: a
                // gateway that cannot serve says so every time.
                eprintln!(
                    "siphon-sigtran: m3ua `{}`: the gateway made this ASP inactive",
                    self.id()
                );
                for context in self.about(message) {
                    if !self.asking.contexts.contains(&context) {
                        self.asking.contexts.push(context);
                    }
                }
                self.asking.at = Some(self.ack_after());
                self.submit(
                    Input::PeerInactive {
                        asp: self.asp,
                        contexts: named,
                    },
                    raw,
                )
                .await;
            }
            MessageType::AspDownAck => {
                // 4.3.4.2: "If the ASP receives an ASP Down Ack without
                // having sent an ASP Down message, the ASP should now
                // consider itself to be in the ASP-DOWN state", and then
                // return to where it was: ASP Up goes out when T(ack) runs
                // out.
                eprintln!(
                    "siphon-sigtran: m3ua `{}`: the gateway took this ASP down",
                    self.id()
                );
                self.asking.up = false;
                self.asking.contexts.clear();
                self.asking.at = Some(self.ack_after());
                self.submit(Input::Lost { asp: self.asp }, raw).await;
            }
            MessageType::Notify => self.notified(message, raw).await,
            // A request only an ASP makes.
            _ => {
                self.refuse(
                    Some(error_code::UNEXPECTED_MESSAGE),
                    &message.routing_contexts(),
                    raw,
                    RxDiscard::Unexpected,
                    format!("{} from a signalling gateway", message.message_type),
                )
                .await;
            }
        }
    }

    /// A Notify from the gateway (RFC 4666 4.3.4.5).
    async fn notified(&mut self, message: &M3uaMessage, raw: &[u8]) {
        let Some(status) = message.status() else {
            self.refuse(
                Some(error_code::MISSING_PARAMETER),
                &[],
                raw,
                RxDiscard::Parameter,
                "NTFY without a Status",
            )
            .await;
            return;
        };
        let known = Status::from_code(status);
        eprintln!(
            "siphon-sigtran: m3ua `{}`: notified {} (status {}/{})",
            self.id(),
            known.map_or("of something this node does not know", Status::label),
            status.0,
            status.1
        );
        let contexts = self.about(message);
        match known {
            // 4.3.4.3: "The ASP receiving this Notify MUST consider itself
            // now in the ASP-INACTIVE state".
            Some(Status::AlternateAspActive) => {
                self.asking.contexts.retain(|c| !contexts.contains(c));
                let named = (!message.routing_contexts().is_empty()).then_some(contexts);
                self.submit(
                    Input::PeerInactive {
                        asp: self.asp,
                        contexts: named,
                    },
                    raw,
                )
                .await;
            }
            // "The ASPs remain in control of what (and when) traffic action
            // is taken." This one takes the traffic when the server has no
            // ASP for it, or too few.
            Some(Status::AsPending | Status::AsInactive | Status::InsufficientResources) => {
                for context in contexts {
                    let active =
                        self.ctx.registry.admits(&self.slot, Some(context)) == Admission::Active;
                    if self.asking.up && !active && !self.asking.contexts.contains(&context) {
                        self.ask_active(context).await;
                    }
                }
            }
            Some(Status::AsActive | Status::AspFailure) | None => {}
        }
    }

    // ── Both sides ───────────────────────────────────────────────────────────

    /// Decode what arrived. What cannot be read is answered with the Error
    /// of RFC 4666 3.8.1 that says why, and counted.
    async fn read(&self, data: &[u8]) -> Option<M3uaMessage> {
        let (code, detail) = match M3uaMessage::decode(data) {
            Ok(message) => {
                // 3.1.4: "The Message Length defines the length of the
                // message in octets, including the Common Header."
                let declared = CommonHeader::decode(data).map_or(0, |h| h.message_length as usize);
                if declared >= CommonHeader::SIZE && declared <= data.len() {
                    return Some(message);
                }
                (
                    error_code::PROTOCOL_ERROR,
                    format!("a message length of {declared} in {} octets", data.len()),
                )
            }
            Err(error) => {
                let code = match &error {
                    M3uaError::InvalidVersion(_) => error_code::INVALID_VERSION,
                    M3uaError::InvalidMessageClass(_) => error_code::UNSUPPORTED_MESSAGE_CLASS,
                    M3uaError::InvalidMessageType { class, .. } => {
                        if MessageClass::from_u8(*class).is_ok() {
                            error_code::UNSUPPORTED_MESSAGE_TYPE
                        } else {
                            error_code::UNSUPPORTED_MESSAGE_CLASS
                        }
                    }
                    M3uaError::InvalidParameter { .. } | M3uaError::ParameterTooShort { .. } => {
                        error_code::PARAMETER_FIELD_ERROR
                    }
                    M3uaError::MissingParameter(_) => error_code::MISSING_PARAMETER,
                    M3uaError::TooShort { .. } => error_code::PROTOCOL_ERROR,
                };
                (code, error.to_string())
            }
        };
        // 3.8.1: "Error messages MUST NOT be generated in response to other
        // Error messages." Class 0, type 0 is one, readable or not.
        let is_error = data.get(2..4) == Some(&[0, 0]);
        self.refuse(
            (!is_error).then_some(code),
            &[],
            data,
            RxDiscard::Undecodable,
            detail,
        )
        .await;
        None
    }

    async fn received(&mut self, data: &[u8], stream: u16) -> Next {
        let Some(message) = self.read(data).await else {
            return Next::Continue;
        };
        if message.message_type == MessageType::Data {
            self.data(&message, data, stream).await;
            return Next::Continue;
        }
        // Whatever follows changes state that belongs to the association the
        // slot has now.
        if !self.slot.is_sender(&self.assoc) {
            return Next::Superseded;
        }
        count(Dir::Rx, &message);
        // A list parameter that is not a whole number of entries has a wrong
        // length field (3.8.1, "Parameter Field Error").
        let lists = [
            message.routing_context_octets(),
            message.affected_point_code_octets(),
        ];
        if lists
            .iter()
            .flatten()
            .any(|octets| *octets == 0 || octets % 4 != 0)
            && message.message_type != MessageType::Error
        {
            self.refuse(
                Some(error_code::PARAMETER_FIELD_ERROR),
                &[],
                data,
                RxDiscard::Parameter,
                format!(
                    "{} with a list parameter of a wrong length",
                    message.message_type
                ),
            )
            .await;
            return Next::Continue;
        }
        match message.message_type {
            // 4.3.4.6: "Upon receiving a Heartbeat message, the M3UA peer
            // MUST respond with a Heartbeat Ack message", and the Heartbeat
            // Data "MUST be echoed back unchanged".
            MessageType::Heartbeat => {
                let data = message.heartbeat_data().map(<[u8]>::to_vec);
                self.send(&M3uaMessage::heartbeat_ack(data)).await;
            }
            MessageType::HeartbeatAck => {
                let sent = self.beat.to_be_bytes();
                if self.slot.m3ua.beat_ms > 0 && message.heartbeat_data() != Some(&sent[..]) {
                    metrics::m3ua_event(Event::BeatMismatch);
                    eprintln!(
                        "siphon-sigtran: m3ua `{}`: a heartbeat acknowledgement that does not return what was sent",
                        self.id()
                    );
                }
            }
            // Never answered (3.8.1).
            MessageType::Error => {
                let code = message.error_code().unwrap_or(0);
                eprintln!(
                    "siphon-sigtran: m3ua `{}`: the peer answered with Error {code:#04x} ({}), routing contexts {:?}",
                    self.id(),
                    error_name(code),
                    message.routing_contexts()
                );
            }
            MessageType::Duna
            | MessageType::Dava
            | MessageType::Daud
            | MessageType::Scon
            | MessageType::Dupu
            | MessageType::Drst => self.network_management(&message, data).await,
            // Routing Key Management is a class this node does not have.
            MessageType::RegReq
            | MessageType::RegRsp
            | MessageType::DeregReq
            | MessageType::DeregRsp => {
                self.refuse(
                    Some(error_code::UNSUPPORTED_MESSAGE_CLASS),
                    &[],
                    data,
                    RxDiscard::Unexpected,
                    format!(
                        "{}: routing key management is not supported",
                        message.message_type
                    ),
                )
                .await;
            }
            _ if self.gateway => self.asp_asked(&message, data).await,
            _ => self.gateway_said(&message, data).await,
        }
        Next::Continue
    }

    /// An ASP state maintenance or traffic maintenance message of an ASP.
    async fn asp_asked(&mut self, message: &M3uaMessage, raw: &[u8]) {
        let asp = self.asp;
        let contexts = message
            .routing_context_octets()
            .map(|_| message.routing_contexts());
        let input = match message.message_type {
            MessageType::AspUp => Input::Up {
                asp,
                identifier: message.asp_identifier(),
            },
            MessageType::AspDown => Input::Down { asp },
            MessageType::AspActive => Input::Active {
                asp,
                mode: message.traffic_mode_type(),
                contexts,
            },
            MessageType::AspInactive => Input::Inactive { asp, contexts },
            // An acknowledgement or a Notify: only a gateway sends those.
            _ => {
                self.refuse(
                    Some(error_code::UNEXPECTED_MESSAGE),
                    &message.routing_contexts(),
                    raw,
                    RxDiscard::Unexpected,
                    format!("{} from an ASP", message.message_type),
                )
                .await;
                return;
            }
        };
        self.submit(input, raw).await;
    }

    /// A DATA message: admitted, read and routed.
    async fn data(&mut self, message: &M3uaMessage, raw: &[u8], stream: u16) {
        let context = message.routing_context();
        let admission = self.ctx.registry.admits(&self.slot, context);
        if admission == Admission::NotActive {
            // 3.8.1: the gateway answers; "silent discard is used by an ASP
            // if it received a DATA message from an SGP while it was in the
            // ASP-INACTIVE state".
            self.refuse(
                self.gateway.then_some(error_code::UNEXPECTED_MESSAGE),
                &message.routing_contexts(),
                raw,
                RxDiscard::OutOfState,
                "DATA while the ASP is not active",
            )
            .await;
            return;
        }
        let payload = match message.protocol_data() {
            Ok(payload) => payload,
            Err(error) => {
                // 3.3.1 has Protocol Data mandatory.
                let code = match error {
                    M3uaError::MissingParameter(_) => error_code::MISSING_PARAMETER,
                    _ => error_code::PARAMETER_FIELD_ERROR,
                };
                self.refuse(
                    Some(code),
                    &[],
                    raw,
                    RxDiscard::NoPayload,
                    error.to_string(),
                )
                .await;
                return;
            }
        };
        if admission == Admission::Unconfigured {
            self.refuse(
                Some(error_code::INVALID_ROUTING_CONTEXT),
                &message.routing_contexts(),
                raw,
                RxDiscard::RoutingContext,
                format!("DATA for routing context {}", context.unwrap_or(0)),
            )
            .await;
            return;
        }
        // 1.4.3.2: "MTP3 management messages (such as TFPs or TFAs received
        // from the SS7 network) MUST NOT be encapsulated as Data message
        // Payload Data and sent either from SG to ASP or from ASP to SG."
        if payload.si == SI_MANAGEMENT {
            self.refuse(
                Some(error_code::PROTOCOL_ERROR),
                &message.routing_contexts(),
                raw,
                RxDiscard::Management,
                format!(
                    "signalling network management for dpc {} in a DATA message",
                    payload.dpc
                ),
            )
            .await;
            return;
        }
        // 1.4.7: "The DATA message MUST NOT be sent on stream 0." Accepted
        // all the same: a peer that was given a single stream has no other.
        if stream == 0 {
            metrics::m3ua_event(Event::DataOnStream0);
        }
        let msu = Msu {
            opc: payload.opc,
            dpc: payload.dpc,
            si: payload.si,
            ni: payload.ni,
            mp: payload.mp,
            sls: payload.sls,
            payload: payload.user_data,
        };
        dispatch(msu, &self.ctx, &self.slot.id).await;
    }

    /// The point codes of the routing table an Affected Point Code entry
    /// stands for (RFC 4666 3.4.1): one, or with a mask every one whose
    /// other bits are the same.
    fn range(&self, mask: u8, pc: u32) -> Vec<u32> {
        if mask == 0 {
            return vec![pc];
        }
        let shift = u32::from(mask).min(24);
        self.ctx
            .registry
            .destinations()
            .keys()
            .copied()
            .filter(|dpc| dpc >> shift == pc >> shift)
            .collect()
    }

    /// An SSNM message (RFC 4666 3.4).
    async fn network_management(&mut self, message: &M3uaMessage, raw: &[u8]) {
        let kind = message.message_type;
        let contexts = message.routing_contexts();
        // The first Routing Context that is not one of an active ASP decides.
        let admission = if contexts.is_empty() {
            self.ctx.registry.admits(&self.slot, None)
        } else {
            contexts
                .iter()
                .map(|c| self.ctx.registry.admits(&self.slot, Some(*c)))
                .find(|a| *a != Admission::Active)
                .unwrap_or(Admission::Active)
        };
        match admission {
            Admission::Active => {}
            Admission::NotActive => {
                self.refuse(
                    self.gateway.then_some(error_code::UNEXPECTED_MESSAGE),
                    &contexts,
                    raw,
                    RxDiscard::OutOfState,
                    format!("{kind} while the ASP is not active"),
                )
                .await;
                return;
            }
            Admission::Unconfigured => {
                let unconfigured: Vec<u32> = contexts
                    .iter()
                    .copied()
                    .filter(|c| !self.slot.memberships().iter().any(|m| m.context == *c))
                    .collect();
                self.refuse(
                    Some(error_code::INVALID_ROUTING_CONTEXT),
                    &unconfigured,
                    raw,
                    RxDiscard::RoutingContext,
                    format!("{kind} for routing contexts {unconfigured:?}"),
                )
                .await;
                return;
            }
        }
        let affected = message.affected_destinations();
        if affected.is_empty() {
            // Mandatory in every SSNM message (3.4.1 to 3.4.6).
            self.refuse(
                Some(error_code::MISSING_PARAMETER),
                &contexts,
                raw,
                RxDiscard::Parameter,
                format!("{kind} without an Affected Point Code"),
            )
            .await;
            return;
        }
        let variant = self.ctx.registry.variant();
        if affected
            .iter()
            .any(|(_, pc)| PointCode::from_value(*pc, variant).is_err())
        {
            self.refuse(
                Some(error_code::INVALID_PARAMETER_VALUE),
                &contexts,
                raw,
                RxDiscard::Parameter,
                format!("{kind} with a point code this network does not have"),
            )
            .await;
            return;
        }
        match kind {
            MessageType::Duna => {
                for (mask, pc) in affected {
                    for dpc in self.range(mask, pc) {
                        self.pause(dpc, true);
                    }
                }
            }
            // A restricted destination can be reached: for routing here it
            // is available.
            MessageType::Dava | MessageType::Drst => {
                for (mask, pc) in affected {
                    for dpc in self.range(mask, pc) {
                        self.pause(dpc, false);
                    }
                }
            }
            MessageType::Daud => self.audit(message.routing_context(), &affected).await,
            MessageType::Scon => self.congestion(message, &affected).await,
            // 3.4.5: "used by an SGP to inform concerned ASPs". An ASP has
            // none to send.
            MessageType::Dupu if self.gateway => {
                self.refuse(
                    Some(error_code::UNEXPECTED_MESSAGE),
                    &contexts,
                    raw,
                    RxDiscard::Unexpected,
                    "DUPU from an ASP",
                )
                .await;
            }
            MessageType::Dupu => {
                // "the Mask field is not used"; 3.8.1 has "a DUPU message
                // was received with a Mask value other than "0"" as the
                // example of an invalid parameter value.
                let (mask, pc) = affected[0];
                let Some((cause, user)) = message.user_cause().filter(|_| mask == 0) else {
                    let code = if mask != 0 {
                        error_code::INVALID_PARAMETER_VALUE
                    } else {
                        error_code::MISSING_PARAMETER
                    };
                    self.refuse(
                        Some(code),
                        &contexts,
                        raw,
                        RxDiscard::Parameter,
                        "DUPU with a mask, or without User/Cause",
                    )
                    .await;
                    return;
                };
                if let Ok(affected) = PointCode::from_value(pc, variant) {
                    self.ctx.router.apply_mtp3_event(
                        &self.ctx.tenant,
                        &Mtp3Event::Status {
                            affected,
                            status: Mtp3Status::UserPartUnavailable {
                                si: mtp3::ServiceIndicator(user as u8),
                                cause: cause as u8,
                            },
                        },
                    );
                }
                eprintln!(
                    "siphon-sigtran: m3ua `{}`: user part {user} of dpc {pc} is unavailable (cause {cause})",
                    self.id()
                );
            }
            _ => {}
        }
    }

    /// A destination became unavailable or available behind this peer: the
    /// routing tables follow, and signalling route management tells the
    /// adjacent points (transfer-prohibited, transfer-allowed).
    fn pause(&self, dpc: u32, paused: bool) {
        let Ok(affected) = PointCode::from_value(dpc, self.ctx.registry.variant()) else {
            return;
        };
        let event = if paused {
            Mtp3Event::Pause { affected }
        } else {
            Mtp3Event::Resume { affected }
        };
        self.ctx.router.apply_mtp3_event(&self.ctx.tenant, &event);
        self.ctx.registry.manage(RouteInput::Paused { dpc, paused });
    }

    /// Answer a DAUD (RFC 4666 4.5.3): "The status of each SS7 destination
    /// requested is indicated in a DUNA message (if unavailable), a DAVA
    /// message (if available), or a DRST (if restricted ...)". This node
    /// keeps no congestion status, so no SCON goes before them.
    async fn audit(&self, context: Option<u32>, affected: &[(u8, u32)]) {
        let (mut unavailable, mut restricted, mut available) = (Vec::new(), Vec::new(), Vec::new());
        for (mask, pc) in affected {
            let known = self.range(*mask, *pc);
            if known.is_empty() {
                // "An SG SHOULD respond with a DUNA message when DAUD was
                // received with an unknown Signalling Point Code": here a
                // range no destination is in, as it was asked.
                unavailable.push(u32::from(*mask) << 24 | *pc);
            }
            for dpc in known {
                match destination_status(&self.ctx, dpc, true) {
                    Told::Unavailable => unavailable.push(dpc),
                    Told::Restricted => restricted.push(dpc),
                    Told::Available => available.push(dpc),
                }
            }
        }
        for (dpcs, build) in [
            (
                unavailable,
                M3uaMessage::duna as fn(Option<u32>, Vec<u32>) -> M3uaMessage,
            ),
            (restricted, M3uaMessage::drst),
            (available, M3uaMessage::dava),
        ] {
            for chunk in dpcs.chunks(AFFECTED_PER_MESSAGE) {
                self.send(&build(context, chunk.to_vec())).await;
            }
        }
    }

    /// A SCON from the peer (RFC 4666 1.4.6): the congestion is noted, and
    /// one from an ASP that names the point whose traffic it is about "MAY
    /// trigger SS7 MTP3 Transfer Controlled management messages": it does.
    async fn congestion(&self, message: &M3uaMessage, affected: &[(u8, u32)]) {
        let variant = self.ctx.registry.variant();
        // Without the Congestion Indications a SCON still says congested.
        let level = message.congestion_level().unwrap_or(1);
        for (mask, pc) in affected {
            for dpc in self.range(*mask, *pc) {
                if let Ok(affected) = PointCode::from_value(dpc, variant) {
                    self.ctx.router.apply_mtp3_event(
                        &self.ctx.tenant,
                        &Mtp3Event::Status {
                            affected,
                            status: Mtp3Status::Congested { level },
                        },
                    );
                }
            }
        }
        // 3.4.4: "Any resulting Transfer Controlled (TFC) message from the SG
        // is sent to the Concerned Point Code using the single Affected DPC
        // contained in the SCON message".
        let (Some(concerned), [(0, pc)], true) =
            (message.concerned_destination(), affected, self.gateway)
        else {
            return;
        };
        let Ok(destination) = PointCode::from_value(*pc, variant) else {
            return;
        };
        let controlled = ManagementMessage::Tfc {
            destination,
            status: level & 0x03,
        };
        let payload = match controlled.encode(variant) {
            Ok(payload) => payload,
            Err(error) => {
                metrics::mtp3_discard(Mtp3Discard::NoPath, 1);
                eprintln!(
                    "siphon-sigtran: m3ua `{}`: transfer-controlled for dpc {pc} not encoded: {error}",
                    self.id()
                );
                return;
            }
        };
        let msu = Msu {
            opc: self
                .ctx
                .router
                .node_point_code(&self.ctx.tenant)
                .unwrap_or(0),
            dpc: concerned,
            si: SI_MANAGEMENT,
            ni: self.ctx.router.node_network_indicator(&self.ctx.tenant),
            mp: 0,
            sls: 0,
            payload,
        };
        match self
            .ctx
            .router
            .egress_for(&self.ctx.tenant, concerned, 0, None)
        {
            Some(via) => {
                if matches!(via, Destination::Linkset(_)) {
                    metrics::mtp3_management(Dir::Tx, "TFC");
                }
                forward::send_via(&via, &msu, &self.ctx.registry).await;
            }
            None => {
                metrics::mtp3_discard(Mtp3Discard::NoPath, 1);
                eprintln!(
                    "siphon-sigtran: m3ua `{}`: no route to dpc {concerned} for a transfer-controlled about dpc {pc}",
                    self.id()
                );
            }
        }
    }

    /// T(beat) ran out (RFC 4666 4.3.4.6). `false` when the peer is taken to
    /// be unavailable.
    async fn beat(&mut self) -> bool {
        if self.heard {
            self.silent = 0;
        } else {
            self.silent += 1;
        }
        self.heard = false;
        // "If no Heartbeat Ack message (or any other M3UA message) is
        // received from the M3UA peer within 2*T(beat), the remote M3UA peer
        // is considered unavailable. Transmission of Heartbeat messages is
        // stopped".
        if self.silent >= 2 {
            metrics::m3ua_event(Event::BeatTimeout);
            eprintln!(
                "siphon-sigtran: m3ua `{}`: nothing from the peer for {} ms, the association is aborted",
                self.id(),
                2 * self.slot.m3ua.beat_ms
            );
            let _ = self.assoc.abort().await;
            return false;
        }
        self.beat = self.beat.wrapping_add(1);
        self.send(&M3uaMessage::heartbeat(Some(
            self.beat.to_be_bytes().to_vec(),
        )))
        .await;
        true
    }

    async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let period = Duration::from_millis(self.slot.m3ua.beat_ms);
        let mut beat = (!period.is_zero()).then(|| {
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval
        });
        loop {
            let ack_at = self.asking.at;
            let ack = async {
                match ack_at {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending().await,
                }
            };
            let tick = async {
                match beat.as_mut() {
                    Some(interval) => {
                        interval.tick().await;
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.assoc.recv() => {
                    let Ok((data, info)) = r else { break };
                    if info.ppid != PPID_M3UA {
                        discard(
                            RxDiscard::Ppid,
                            self.id(),
                            format!("payload protocol identifier {}, not M3UA", info.ppid),
                        );
                        continue;
                    }
                    self.heard = true;
                    if self.received(&data, info.stream).await == Next::Superseded {
                        return;
                    }
                }
                _ = ack => self.ack_timeout().await,
                _ = tick => {
                    if !self.beat().await {
                        break;
                    }
                }
            }
        }
        // The association is gone (SCTP CDI): the ASP is down, unless another
        // association has the slot by now.
        if self.slot.is_sender(&self.assoc) {
            self.slot.clear_sender();
            self.submit(Input::Lost { asp: self.asp }, &[]).await;
        }
        self.ctx.registry.recompute(&self.ctx.router);
    }
}

fn peer(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    gateway: bool,
) -> Option<Peer> {
    Some(Peer {
        asp: slot.asp?,
        assoc,
        slot,
        ctx,
        gateway,
        heard: false,
        silent: 0,
        beat: 0,
        asking: Asking {
            up: false,
            contexts: Vec::new(),
            at: None,
        },
    })
}

/// The signalling gateway side: serve a peer ASP until its association ends.
pub async fn run_sg(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    shutdown: watch::Receiver<bool>,
) {
    let Some(peer) = peer(assoc, slot, ctx, true) else {
        return;
    };
    // A new association for the ASP: whatever state it had went with the one
    // before (4.3.1, SCTP RI).
    peer.submit(Input::Lost { asp: peer.asp }, &[]).await;
    peer.ctx.registry.recompute(&peer.ctx.router);
    peer.run(shutdown).await;
}

/// The ASP side: ask the gateway to bring this node up and make it active,
/// then carry traffic until the association ends.
pub async fn run_asp(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    shutdown: watch::Receiver<bool>,
) {
    let Some(mut peer) = peer(assoc, slot, ctx, false) else {
        return;
    };
    peer.ask_up().await;
    peer.run(shutdown).await;
}

/// A signalling network management message that would go to an Application
/// Server in a DATA message, which RFC 4666 1.4.3.2 forbids: "The SG MUST
/// terminate these messages and generate M3UA messages, as appropriate." A
/// transfer-controlled becomes a SCON, a user part unavailable a DUPU; any
/// other has no M3UA message and is counted.
pub(super) async fn management_for_server(name: &str, msu: &Msu, registry: &Registry) {
    let message = ManagementMessage::decode(&msu.payload, registry.variant());
    let server = registry.server_index(name);
    let context = server.and_then(|s| registry.server(s)).map(|(_, rc)| rc);
    let asps = server.map(|s| registry.active_asps(s)).unwrap_or_default();
    let mut sent = false;
    for slot in &asps {
        // The M3UA messages are for M3UA peers.
        if slot.adaptation != crate::config::Adaptation::M3ua {
            continue;
        }
        let gateway = slot.role == Role::Server;
        let translated = match &message {
            // 3.4.4: the Concerned Destination "is only used if the SCON
            // message is sent from an ASP to the SGP. It contains the point
            // code of the originator of the message that triggered the SCON".
            Ok(ManagementMessage::Tfc {
                destination,
                status,
            }) => Some(M3uaMessage::scon(
                context,
                vec![destination.value()],
                (!gateway).then_some(msu.dpc),
                (*status != 0).then_some(*status),
            )),
            Ok(ManagementMessage::Upu {
                destination,
                user_part,
                cause,
            }) if gateway => Some(M3uaMessage::dupu(
                context,
                destination.value(),
                u16::from(*cause),
                u16::from(*user_part),
            )),
            _ => None,
        };
        if let (Some(translated), Some(assoc)) = (translated, slot.sender()) {
            send_management(&assoc, &slot.id, &translated).await;
            sent = true;
        }
    }
    if !sent {
        metrics::m3ua_discard(Discard::Management, 1);
        let what = message.as_ref().map_or("unreadable", |m| m.name());
        eprintln!(
            "siphon-sigtran: m3ua: signalling network management ({what}) for dpc {} is not transferred to application server `{name}`",
            msu.dpc
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_of_3_8_1_has_a_name() {
        let codes = [
            0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0d, 0x0e, 0x0f, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x19, 0x1a,
        ];
        let names: std::collections::BTreeSet<&str> =
            codes.iter().map(|code| error_name(*code)).collect();
        assert_eq!(names.len(), codes.len(), "one name per code");
        assert!(!names.contains("other"));
        // "Not Used in M3UA".
        for unused in [0x02, 0x08, 0x0a, 0x0b, 0x0c, 0x10, 0x17, 0x18, 0x99] {
            assert_eq!(error_name(unused), "other");
        }
    }

    #[test]
    fn what_is_sent_is_built_by_the_codec_with_the_contexts_and_the_diagnostic() {
        let ack = encode(
            &Message::ActiveAck {
                mode: Some(2),
                contexts: vec![100, 200],
            },
            &[],
        );
        assert_eq!(ack.message_type, MessageType::AspActiveAck);
        assert_eq!(ack.routing_contexts(), [100, 200]);
        assert_eq!(ack.traffic_mode_type(), Some(2));

        let notify = encode(
            &Message::Notify {
                status: Status::AlternateAspActive,
                asp_identifier: Some(7),
                context: 100,
            },
            &[],
        );
        assert_eq!(notify.status(), Some((2, 2)));
        assert_eq!(notify.asp_identifier(), Some(7));
        assert_eq!(notify.routing_contexts(), [100]);

        // The Diagnostic Information is the first 40 octets of what offended.
        let offending = [0xAB; 64];
        let error = encode(
            &Message::Error {
                code: error_code::INVALID_ROUTING_CONTEXT,
                contexts: vec![9],
            },
            &offending,
        );
        assert_eq!(error.error_code(), Some(0x19));
        assert_eq!(error.routing_contexts(), [9]);
        assert_eq!(error.diagnostic_info(), Some(&offending[..40]));
        assert!(encode(&Message::UpAck, &[]).parameters.is_empty());
        assert!(encode(
            &Message::InactiveAck {
                contexts: Vec::new()
            },
            &[]
        )
        .parameters
        .is_empty());
        assert_eq!(
            encode(&Message::DownAck, &[]).message_type,
            MessageType::AspDownAck
        );
    }

    #[test]
    fn every_label_is_distinct() {
        let discards: std::collections::BTreeSet<&str> =
            Discard::ALL.iter().map(|d| d.label()).collect();
        assert_eq!(discards.len(), Discard::ALL.len());
        let events: std::collections::BTreeSet<&str> =
            Event::ALL.iter().map(|e| e.label()).collect();
        assert_eq!(events.len(), Event::ALL.len());
        assert_eq!(type_name(MessageType::Drst), "DRST");
        assert_eq!(
            availability(Told::Restricted, 5, vec![2000]).message_type,
            MessageType::Drst
        );
    }
}
