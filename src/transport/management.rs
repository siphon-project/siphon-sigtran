//! The task that runs signalling network management for a routing domain.
//!
//! [`crate::mtp3::management::Management`] decides; this module gives it its
//! inputs and carries out what it asks for. The inputs come from the link tasks
//! (a link became available or unavailable, a management message arrived), from
//! the transfer path (a message could not be transferred), from the registry (an
//! application server came or went) and from the clock: every timer of ITU-T
//! Q.704 that the machine starts is a deadline here, and one sleep waits for the
//! earliest.
//!
//! Nothing on the per-message path waits for this task. What it changes is read
//! there as it is: one atomic per link ([`LinkPort::is_routable`]), the route
//! state behind the router's lock, and the rerouting buffers.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use mtp3::mgmt::ManagementMessage;
use mtp3::Variant;
use tokio::sync::{mpsc, oneshot, watch};

use super::forward;
use super::framing::{self, Msu};
use super::registry::{DestinationChange, LinkCommand, LinkPort};
use super::TaskCtx;
use crate::metrics::{self, Mtp3Discard, Mtp3MgKind};
use crate::mtp3::management::{Action, Input, Management, Path, Subject, Timer};
use crate::mtp3::route::{Destination, RouteStatus};

/// The service indicator of signalling network management (Q.704 14.2.1).
const SI_MANAGEMENT: u8 = 0;

/// How long the task of a link is waited for to say that it buffers. It
/// answers within its next turn; the limit is for one that is gone.
const HOLD_WAIT: Duration = Duration::from_millis(250);

struct Runtime {
    machine: Management,
    ctx: TaskCtx,
    deadlines: BTreeMap<Timer, Instant>,
    own_pc: u32,
    ni: u8,
}

impl Runtime {
    fn port(&self, link: usize) -> Option<&LinkPort> {
        self.ctx.registry.link(link).and_then(|slot| slot.link())
    }

    fn link_name(&self, link: usize) -> &str {
        self.ctx.registry.link(link).map_or("?", |slot| &slot.id)
    }

    fn subject(&self, subject: Subject) -> String {
        match subject {
            Subject::Node => "this node".to_string(),
            Subject::Link(link) => format!("link `{}`", self.link_name(link)),
            Subject::Linkset(linkset) => format!(
                "linkset `{}`",
                self.ctx.registry.linkset_name(linkset).unwrap_or("?")
            ),
            Subject::Destination(dpc) => format!("dpc {dpc}"),
        }
    }

    async fn feed(&mut self, input: Input) {
        let actions = self.machine.handle(input);
        for action in actions {
            self.perform(action).await;
        }
    }

    async fn perform(&mut self, action: Action) {
        let registry = &self.ctx.registry;
        match action {
            Action::Send {
                dpc,
                slc,
                message,
                path,
            } => self.send(dpc, slc, &message, path).await,
            Action::Start(timer, after) => {
                self.deadlines.insert(timer, Instant::now() + after);
            }
            Action::Stop(timer) => {
                self.deadlines.remove(&timer);
            }
            // What routing does with a link follows from what the task that
            // serves it does with its traffic, so that task says when routing
            // leads to the link and when it passes it by. A hold is waited
            // for: a changeback declaration that follows (Q.704 6.3.1 ii) says
            // nothing of the diverted traffic comes after it on the
            // alternative link, which holds once routing leads to this one.
            Action::Hold(link) => {
                if let Some(port) = self.port(link) {
                    let (done, held) = oneshot::channel();
                    port.command(LinkCommand::Hold { done: Some(done) });
                    if tokio::time::timeout(HOLD_WAIT, held).await.is_err() {
                        eprintln!(
                            "siphon-sigtran: mtp3: link `{}` did not confirm that it buffers",
                            self.link_name(link)
                        );
                    }
                }
            }
            Action::Open(link) => {
                if let Some(port) = self.port(link) {
                    port.command(LinkCommand::Open);
                }
            }
            Action::Divert { link, fsnc } => {
                if let Some(port) = self.port(link) {
                    port.command(LinkCommand::Divert { fsnc });
                }
            }
            Action::Fail(link) => {
                if let Some(port) = self.port(link) {
                    port.command(LinkCommand::Fail);
                }
            }
            Action::Route {
                dpc,
                linkset,
                status,
            } => {
                let Some(name) = registry.linkset_name(linkset) else {
                    return;
                };
                let via = Destination::Linkset(name.to_string());
                self.ctx
                    .router
                    .note_route_status(&self.ctx.tenant, dpc, &via, status);
                let kind = match status {
                    RouteStatus::Allowed => Mtp3MgKind::Tfa,
                    RouteStatus::Prohibited | RouteStatus::Restricted => Mtp3MgKind::Tfp,
                };
                metrics::mtp3mg_event(dpc, kind);
                eprintln!("siphon-sigtran: mtp3: route to dpc {dpc} by {via} is {status:?}");
            }
            Action::HoldDestination(dpc) => registry.hold_destination(dpc),
            Action::ReleaseDestination(dpc) => forward::release_destination(dpc, &self.ctx).await,
            Action::Accessibility { dpc, accessible } => {
                let (change, kind, word) = if accessible {
                    (
                        DestinationChange::Accessible { dpc },
                        Mtp3MgKind::Resume,
                        "accessible",
                    )
                } else {
                    (
                        DestinationChange::Inaccessible { dpc },
                        Mtp3MgKind::Pause,
                        "inaccessible",
                    )
                };
                metrics::mtp3mg_event(dpc, kind);
                eprintln!("siphon-sigtran: mtp3: dpc {dpc} is {word}");
                registry.announce(change);
                self.ctx.router.refresh_route_metrics(&self.ctx.tenant);
            }
            // What the user parts and the application servers are told
            // (RFC 4666 3.4.6): restricted, or available again.
            Action::Restricted { dpc, restricted } => {
                eprintln!(
                    "siphon-sigtran: mtp3: dpc {dpc} is {}",
                    if restricted {
                        "reached by a restricted route only"
                    } else {
                        "not restricted any more"
                    }
                );
                registry.announce(if restricted {
                    DestinationChange::Restricted { dpc }
                } else {
                    DestinationChange::Accessible { dpc }
                });
            }
            Action::Restarting(on) => {
                registry.set_restarting(on);
                eprintln!(
                    "siphon-sigtran: mtp3: MTP restart {}",
                    if on {
                        "began: traffic from the linksets is discarded until it ends"
                    } else {
                        "ended"
                    }
                );
            }
            // Q.704 11.2.3.2: a transfer-controlled is for the user parts. It
            // is counted and passed on to whoever subscribes; routing does not
            // change.
            Action::Congestion { dpc, status } => {
                metrics::mtp3mg_event(dpc, Mtp3MgKind::Congestion);
                eprintln!(
                    "siphon-sigtran: mtp3: transfer-controlled for dpc {dpc}, status {status}"
                );
                registry.announce(DestinationChange::Congested { dpc, status });
            }
            Action::Note(procedure, subject) => {
                metrics::mtp3_procedure(procedure);
                eprintln!(
                    "siphon-sigtran: mtp3: {} ({})",
                    procedure.label(),
                    self.subject(subject)
                );
            }
            Action::Ignored { name, why } => {
                metrics::mtp3_discard(Mtp3Discard::Management, 1);
                eprintln!("siphon-sigtran: mtp3: {name} not acted on: {why}");
            }
        }
    }

    /// Send a management message of this node.
    async fn send(&self, dpc: u32, slc: u8, message: &ManagementMessage, path: Path) {
        let name = message.name();
        let msu = match message.encode(Variant::Itu) {
            Ok(payload) => Msu {
                opc: self.own_pc,
                dpc,
                si: SI_MANAGEMENT,
                ni: self.ni,
                mp: 0,
                sls: slc,
                payload,
            },
            Err(error) => {
                metrics::mtp3_discard(Mtp3Discard::NoPath, 1);
                eprintln!("siphon-sigtran: mtp3: {name} for dpc {dpc} not encoded: {error}");
                return;
            }
        };
        let raw = match framing::mtp3_msu(&msu) {
            Ok(raw) => raw,
            Err(error) => {
                metrics::mtp3_discard(Mtp3Discard::NoPath, 1);
                eprintln!("siphon-sigtran: mtp3: {name} for dpc {dpc} not framed: {error}");
                return;
            }
        };
        let registry = &self.ctx.registry;
        let (linkset, avoid) = match path {
            Path::Link(link) => {
                // On this link and no other (Q.704 2.3.4.2 a).
                if let Some(port) = self.port(link) {
                    metrics::mtp3_management(metrics::Dir::Tx, name);
                    port.command(LinkCommand::Direct(raw));
                }
                return;
            }
            Path::Behind(link) => {
                // In the link's queue, behind the traffic handed to it.
                if let Some(port) = self.port(link) {
                    if port.offer(raw) {
                        metrics::mtp3_management(metrics::Dir::Tx, name);
                    } else {
                        metrics::mtp3_discard(Mtp3Discard::NoPath, 1);
                        eprintln!(
                            "siphon-sigtran: mtp3: {name} not sent, the queue of `{}` is full",
                            self.link_name(link)
                        );
                    }
                }
                return;
            }
            Path::Adjacent { linkset, avoid } => (linkset, avoid),
        };
        // A link of the linkset that is in service, the first of them so that
        // messages about one destination stay in sequence (2.3.4.1, Note).
        let direct = registry.linkset_links(linkset).iter().find(|slot| {
            slot.is_carrying() && slot.link().is_some_and(|port| port.settings.index != avoid)
        });
        if let Some(port) = direct.and_then(|slot| slot.link()) {
            metrics::mtp3_management(metrics::Dir::Tx, name);
            port.command(LinkCommand::Direct(raw));
            return;
        }
        // "They may use any available signalling route that leads to that
        // signalling point" (13.2.1), but not the linkset that has no link.
        let own = registry
            .linkset_name(linkset)
            .map(|name| Destination::Linkset(name.to_string()));
        match self
            .ctx
            .router
            .egress_for(&self.ctx.tenant, dpc, slc, own.as_ref())
        {
            Some(via) => {
                metrics::mtp3_management(metrics::Dir::Tx, name);
                forward::send_via(&via, &msu, registry).await;
            }
            None => {
                metrics::mtp3_discard(Mtp3Discard::NoPath, 1);
                eprintln!("siphon-sigtran: mtp3: no link or route to dpc {dpc} for {name}");
            }
        }
    }

    /// The timers that ran out, earliest first.
    fn due(&mut self, now: Instant) -> Vec<Timer> {
        let mut due: Vec<(Instant, Timer)> = self
            .deadlines
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(timer, at)| (*at, *timer))
            .collect();
        due.sort();
        for (_, timer) in &due {
            self.deadlines.remove(timer);
        }
        due.into_iter().map(|(_, timer)| timer).collect()
    }
}

/// Run signalling network management of one domain until shutdown.
pub(super) async fn run(
    machine: Management,
    mut inputs: mpsc::UnboundedReceiver<Input>,
    mut unroutable: mpsc::Receiver<Input>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let own_pc = machine.topology().own_pc;
    let ni = ctx.router.node_network_indicator(&ctx.tenant);
    let mut runtime = Runtime {
        machine,
        ctx,
        deadlines: BTreeMap::new(),
        own_pc,
        ni,
    };
    loop {
        let wake = runtime.deadlines.values().min().copied();
        let sleep = async {
            match wake {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(input) = inputs.recv() => runtime.feed(input).await,
            Some(input) = unroutable.recv() => runtime.feed(input).await,
            _ = sleep => {
                for timer in runtime.due(Instant::now()) {
                    runtime.feed(Input::Timeout(timer)).await;
                }
            }
        }
    }
}
