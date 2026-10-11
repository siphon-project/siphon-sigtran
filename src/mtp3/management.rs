//! Signalling network management of a transfer point (ITU-T Q.704), without
//! I/O.
//!
//! [`Management`] holds what level 3 knows about one routing domain: which
//! links carry traffic, which routes the adjacent points have prohibited, which
//! destinations are accessible and what each adjacent point has been told about
//! them. It owns no socket and no clock. The caller reports an [`Input`] (a link
//! came up or went down, a management message arrived, a timer ran out, a
//! message could not be routed) and gets [`Action`]s back: messages to send,
//! timers to start and stop, links to hold, divert or open, routes to mark.
//!
//! What it implements, by clause:
//!
//! * **Changeover** (5): an extended changeover order with the sequence number
//!   of the last message accepted on the failed link (RFC 4165 4.2.3 has M2PA
//!   links use XCO / XCA of Q.2210 9.8.1), retrieval on the acknowledgement,
//!   T2 when none comes, the time-controlled changeover under T1 when the far
//!   end cannot be asked, and the answers of 5.6 and 5.7.
//! * **Changeback** (6): a changeback declaration on every link that carried
//!   the traffic of the link made available, T4 and T5, and the time-controlled
//!   diversion under T3 when a linkset comes back.
//! * **Forced and controlled rerouting** (7, 8): a transfer-prohibited moves
//!   the traffic of the route at once; a transfer-allowed or -restricted that
//!   changes the routes in use holds the destination for T6 first.
//! * **MTP restart** (9): this node's own restart (T18, T20), the restart of an
//!   adjacent point (T21), traffic restart allowed sent and awaited, T19.
//! * **Management inhibiting** (10): a request from the far end is granted or
//!   denied, the link is taken out of traffic and put back, and the inhibit
//!   tests are answered. This node never asks to inhibit a link itself.
//! * **Route management** (13): transfer-prohibited and transfer-allowed by
//!   the broadcast method and the response method (T8), received ones marked
//!   on the route, the signalling route set test sent (T10) and answered.
//!
//! One rule decides what an adjacent point is told about a destination, and it
//! is in one place ([`Management::settle`]): prohibited when the destination is
//! inaccessible from here (13.2.2 ii), or when this node routes to it through
//! that very point (13.2.2 i); allowed otherwise. After every input the rule is
//! compared with what the point was last told, and the difference is sent.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use mtp3::mgmt::ManagementMessage;
use mtp3::{PointCode, Variant};

use super::route::{routes_in_use, Destination, RouteResolver, RouteStatus, Usable};
use crate::config::{Adaptation, Association, Mtp3, Tenant};

/// A link, by its position in [`Topology::links`].
pub type LinkId = usize;
/// A linkset, by its position in [`Topology::linksets`].
pub type LinksetId = usize;

/// The timers of Q.704 16.8 that this layer runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timers {
    /// T1, delay to avoid mis-sequencing on changeover.
    pub t1: Duration,
    /// T2, waiting for the changeover acknowledgement.
    pub t2: Duration,
    /// T3, time-controlled diversion on changeback.
    pub t3: Duration,
    /// T4, waiting for the changeback acknowledgement (first attempt).
    pub t4: Duration,
    /// T5, waiting for the changeback acknowledgement (second attempt).
    pub t5: Duration,
    /// T6, delay to avoid mis-sequencing on controlled rerouting.
    pub t6: Duration,
    /// T8, transfer-prohibited inhibition.
    pub t8: Duration,
    /// T10, waiting to repeat the signalling route set test.
    pub t10: Duration,
    /// T12, waiting for the uninhibit acknowledgement.
    pub t12: Duration,
    /// T13, waiting for the force uninhibit.
    pub t13: Duration,
    /// T18, the first phase of this node's restart.
    pub t18: Duration,
    /// T19, supervision after a traffic restart allowed.
    pub t19: Duration,
    /// T20, this node's overall restart timer.
    pub t20: Duration,
    /// T21, the restart of an adjacent point.
    pub t21: Duration,
    /// T23, the remote inhibit test.
    pub t23: Duration,
}

impl From<&Mtp3> for Timers {
    fn from(c: &Mtp3) -> Self {
        let ms = Duration::from_millis;
        Self {
            t1: ms(c.t1_ms),
            t2: ms(c.t2_ms),
            t3: ms(c.t3_ms),
            t4: ms(c.t4_ms),
            t5: ms(c.t5_ms),
            t6: ms(c.t6_ms),
            t8: ms(c.t8_ms),
            t10: ms(c.t10_ms),
            t12: ms(c.t12_ms),
            t13: ms(c.t13_ms),
            t18: ms(c.t18_ms),
            t19: ms(c.t19_ms),
            t20: ms(c.t20_ms),
            t21: ms(c.t21_ms),
            t23: ms(c.t23_ms),
        }
    }
}

impl Default for Timers {
    fn default() -> Self {
        Self::from(&Mtp3::default())
    }
}

/// What a route goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// A linkset: an adjacent signalling point.
    Linkset(LinksetId),
    /// An application server, by its position in [`Topology::servers`].
    Server(usize),
}

/// One linkset of the domain.
#[derive(Debug, Clone)]
pub struct LinksetSpec {
    /// Its name in the configuration.
    pub name: String,
    /// The point at the other end, when the links say (`adjacent_pc`).
    pub adjacent: Option<u32>,
    /// Its links.
    pub links: Vec<LinkId>,
}

/// One link of the domain.
#[derive(Debug, Clone)]
pub struct LinkSpec {
    /// The association it rides, which names it.
    pub name: String,
    /// The linkset it is in.
    pub linkset: LinksetId,
    /// Its signalling link code.
    pub slc: u8,
}

/// One route to a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    /// What it goes through.
    pub via: Via,
    /// Its priority: the lower number is used first, equal ones share.
    pub priority: u8,
}

/// The routing domain as the configuration has it.
#[derive(Debug, Clone)]
pub struct Topology {
    /// This node's point code.
    pub own_pc: u32,
    /// The linksets.
    pub linksets: Vec<LinksetSpec>,
    /// Every link of every linkset.
    pub links: Vec<LinkSpec>,
    /// The application servers, by name.
    pub servers: Vec<String>,
    /// Destination point code to its routes, in priority order.
    pub routes: BTreeMap<u32, Vec<RouteSpec>>,
}

impl Topology {
    /// The domain of one tenant of the configuration.
    pub fn build(tenant: &Tenant, associations: &[Association]) -> Self {
        let adjacent_of = |assoc: &str| {
            associations
                .iter()
                .find(|a| a.id == assoc && a.adaptation == Adaptation::M2pa)
                .and_then(|a| a.adjacent_pc)
                .map(|pc| pc.0)
        };
        let mut links = Vec::new();
        let mut linksets = Vec::new();
        for (index, ls) in tenant.linksets.iter().enumerate() {
            let mut members = Vec::new();
            for (position, link) in ls.links.iter().enumerate() {
                members.push(links.len());
                links.push(LinkSpec {
                    name: link.assoc.clone(),
                    linkset: index,
                    slc: ls.slc_of(position),
                });
            }
            linksets.push(LinksetSpec {
                name: ls.name.clone(),
                adjacent: ls.links.iter().find_map(|l| adjacent_of(&l.assoc)),
                links: members,
            });
        }
        let servers: Vec<String> = tenant
            .application_servers
            .iter()
            .map(|a| a.name.clone())
            .collect();
        // The routes are the resolver's own, so both always agree on them.
        let resolver = RouteResolver::build(tenant, associations);
        let mut routes: BTreeMap<u32, Vec<RouteSpec>> = BTreeMap::new();
        for (dpc, dest, priority) in resolver.routes() {
            let via = match dest {
                Destination::Linkset(name) => linksets
                    .iter()
                    .position(|l| l.name == *name)
                    .map(Via::Linkset),
                Destination::ApplicationServer(name) => {
                    servers.iter().position(|s| s == name).map(Via::Server)
                }
            };
            let Some(via) = via else { continue };
            let entry = routes.entry(dpc).or_default();
            // Two links of one linkset name the same adjacent point twice.
            if !entry.iter().any(|r| r.via == via && r.priority == priority) {
                entry.push(RouteSpec { via, priority });
            }
        }
        let own_pc = tenant
            .resolved_point_code()
            .map(|pc| pc.value())
            .unwrap_or(tenant.point_code.0);
        routes.remove(&own_pc);
        Self {
            own_pc,
            linksets,
            links,
            servers,
            routes,
        }
    }
}

/// A timer of this layer. The number in each comment is the timer of Q.704
/// 16.8 that the variant runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Timer {
    /// T1 (time-controlled changeover) or T2 (the acknowledgement) of a link.
    Changeover(LinkId),
    /// T3, T4 or T5 of a link, by the phase its changeback is in.
    Changeback(LinkId),
    /// T6 of a destination.
    Rerouting(u32),
    /// T8 of a destination.
    Prohibited(u32),
    /// T10 of one route: a destination through one linkset.
    RouteSetTest(u32, LinksetId),
    /// T12 of a link.
    Uninhibit(LinkId),
    /// T13 of a link.
    ForceUninhibit(LinkId),
    /// T18.
    Restart,
    /// T19 of an adjacent point.
    RestartAllowed(LinksetId),
    /// T20.
    RestartOverall,
    /// T21 of an adjacent point.
    AdjacentRestart(LinksetId),
    /// T23 of a link.
    InhibitTest(LinkId),
    /// T1 as the limit of a short isolation (9.4.1).
    Isolation,
}

/// What happened, as the caller reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// A link is in service at level 2 and has passed its link test.
    LinkUp {
        /// The link.
        link: LinkId,
    },
    /// A link that was up is not any more.
    LinkDown {
        /// The link.
        link: LinkId,
        /// The sequence number of the last message accepted on it.
        bsnt: u32,
    },
    /// A management message for this node arrived.
    Received {
        /// The link it arrived on.
        link: LinkId,
        /// Its originating point code.
        opc: u32,
        /// The signalling link code of its label.
        slc: u8,
        /// The message.
        message: ManagementMessage,
    },
    /// A timer ran out.
    Timeout(Timer),
    /// A message arrived on `link` for `dpc` and could not be transferred.
    Unroutable {
        /// Its destination point code.
        dpc: u32,
        /// The link it arrived on.
        link: LinkId,
    },
    /// An application server came into service or left it.
    Server {
        /// Its position in [`Topology::servers`].
        index: usize,
        /// Whether it is in service.
        up: bool,
    },
    /// A destination was paused or resumed from outside this layer (a
    /// destination-unavailable or -available from an application server).
    Paused {
        /// The destination.
        dpc: u32,
        /// Whether it is paused.
        paused: bool,
    },
}

/// The way a management message is to leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// On this link and no other (Q.704 2.3.4.2 a), ahead of whatever the
    /// link does with traffic: a message about the link itself.
    Link(LinkId),
    /// On this link and no other, behind the traffic already handed to it: a
    /// changeback declaration, which says that nothing of the diverted traffic
    /// follows it on that link (6.3.1 ii).
    Behind(LinkId),
    /// By any link of the linkset, or any other route to its adjacent point,
    /// but not on `avoid` (2.3.4.2 b).
    Adjacent {
        /// The linkset of the adjacent point.
        linkset: LinksetId,
        /// The link the message must not take.
        avoid: Option<LinkId>,
    },
}

/// A procedure that ran, for the counters and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Procedure {
    /// Changeover completed on a changeover acknowledgement, with retrieval.
    ChangeoverAcknowledged,
    /// Changeover completed on an acknowledgement without a usable sequence
    /// number: no retrieval of what was sent (5.6.1, 5.7.3).
    ChangeoverEmergency,
    /// No acknowledgement within T2 (5.7.2).
    ChangeoverUnacknowledged,
    /// Changeover after T1, without asking the far end (5.6.2).
    ChangeoverTimeControlled,
    /// Changeback completed on its acknowledgements.
    ChangebackAcknowledged,
    /// Changeback completed when T5 ran out (6.5.3).
    ChangebackUnacknowledged,
    /// Traffic started after T3 (6.4).
    ChangebackTimeControlled,
    /// Traffic left a route its adjacent point prohibited (7).
    ForcedRerouting,
    /// Traffic was held for T6 and moved to a route made available (8).
    ControlledRerouting,
    /// This node's MTP restart began (9.2.1).
    RestartBegun,
    /// This node's MTP restart ended (9.2.4).
    RestartEnded,
    /// An adjacent point is taken to be restarting (9.3.1).
    AdjacentRestartBegun,
    /// Its traffic restart allowed arrived (9.3.2).
    AdjacentRestartEnded,
    /// T21 ran out without one.
    AdjacentRestartExpired,
    /// A link was inhibited at the far end's request (10.2).
    LinkInhibited,
    /// The request was denied (10.2 c).
    LinkInhibitDenied,
    /// The inhibition was lifted (10.3.1).
    LinkUninhibited,
    /// An uninhibit or force uninhibit got no answer twice (10.3.1 e, 10.3.2 e).
    UninhibitAbandoned,
}

impl Procedure {
    /// Every value, for the metrics rendering.
    pub const ALL: [Procedure; 18] = [
        Self::ChangeoverAcknowledged,
        Self::ChangeoverEmergency,
        Self::ChangeoverUnacknowledged,
        Self::ChangeoverTimeControlled,
        Self::ChangebackAcknowledged,
        Self::ChangebackUnacknowledged,
        Self::ChangebackTimeControlled,
        Self::ForcedRerouting,
        Self::ControlledRerouting,
        Self::RestartBegun,
        Self::RestartEnded,
        Self::AdjacentRestartBegun,
        Self::AdjacentRestartEnded,
        Self::AdjacentRestartExpired,
        Self::LinkInhibited,
        Self::LinkInhibitDenied,
        Self::LinkUninhibited,
        Self::UninhibitAbandoned,
    ];

    /// The `procedure` label of `sigtran_mtp3_procedures_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::ChangeoverAcknowledged => "changeover-acknowledged",
            Self::ChangeoverEmergency => "changeover-emergency",
            Self::ChangeoverUnacknowledged => "changeover-unacknowledged",
            Self::ChangeoverTimeControlled => "changeover-time-controlled",
            Self::ChangebackAcknowledged => "changeback-acknowledged",
            Self::ChangebackUnacknowledged => "changeback-unacknowledged",
            Self::ChangebackTimeControlled => "changeback-time-controlled",
            Self::ForcedRerouting => "forced-rerouting",
            Self::ControlledRerouting => "controlled-rerouting",
            Self::RestartBegun => "restart-begun",
            Self::RestartEnded => "restart-ended",
            Self::AdjacentRestartBegun => "adjacent-restart-begun",
            Self::AdjacentRestartEnded => "adjacent-restart-ended",
            Self::AdjacentRestartExpired => "adjacent-restart-expired",
            Self::LinkInhibited => "link-inhibited",
            Self::LinkInhibitDenied => "link-inhibit-denied",
            Self::LinkUninhibited => "link-uninhibited",
            Self::UninhibitAbandoned => "uninhibit-abandoned",
        }
    }
}

/// What a [`Procedure`] was about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// The node.
    Node,
    /// A link.
    Link(LinkId),
    /// A linkset, or its adjacent point.
    Linkset(LinksetId),
    /// A destination point code.
    Destination(u32),
}

/// What the caller has to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a management message from this node.
    Send {
        /// Its destination point code.
        dpc: u32,
        /// The signalling link code of its label.
        slc: u8,
        /// The message.
        message: ManagementMessage,
        /// How it leaves.
        path: Path,
    },
    /// Start, or restart, a timer.
    Start(Timer, Duration),
    /// Stop a timer.
    Stop(Timer),
    /// Buffer the traffic of this link instead of sending it (the changeover
    /// and changeback buffers of 5.5 and 6.3.1).
    Hold(LinkId),
    /// The changeover of this link is complete: retrieve what it holds (with
    /// the sequence number the far end last accepted, if it said), send that
    /// and then the buffered traffic on the alternative links, and route past
    /// the link from now on.
    Divert {
        /// The link.
        link: LinkId,
        /// The far end's last accepted sequence number.
        fsnc: Option<u32>,
    },
    /// Send the buffered traffic of this link on the link itself and carry
    /// traffic on it from now on.
    Open(LinkId),
    /// Take the link out of service at level 2: the far end ordered a
    /// changeover from it (Q.704 3.2.2).
    Fail(LinkId),
    /// Mark one route in the routing tables.
    Route {
        /// The destination.
        dpc: u32,
        /// The linkset the route goes through.
        linkset: LinksetId,
        /// What its adjacent point said.
        status: RouteStatus,
    },
    /// Buffer the traffic of this destination (the controlled rerouting
    /// buffer of 8.2.1 a).
    HoldDestination(u32),
    /// Send the buffered traffic of this destination, by the routing as it now
    /// is.
    ReleaseDestination(u32),
    /// A destination became accessible or inaccessible through this node. The
    /// one place that says so: anything that has to tell someone else (an
    /// application server, a user part) follows this.
    Accessibility {
        /// The destination.
        dpc: u32,
        /// Whether it can be reached.
        accessible: bool,
    },
    /// A destination that is accessible became so only by a route its
    /// adjacent point restricted (13.4), or stopped being so. A destination
    /// that is inaccessible is not restricted, and nothing says so.
    Restricted {
        /// The destination.
        dpc: u32,
        /// Whether every route in use is a restricted one.
        restricted: bool,
    },
    /// This node's MTP restart began or ended: while it runs, traffic from
    /// the linksets is discarded (9.6.6).
    Restarting(bool),
    /// A transfer-controlled arrived for a destination.
    Congestion {
        /// The congested destination.
        dpc: u32,
        /// The congestion status it carried.
        status: u8,
    },
    /// A procedure ran.
    Note(Procedure, Subject),
    /// A received management message was not acted on.
    Ignored {
        /// Its abbreviation in Table 1/Q.704.
        name: &'static str,
        /// Why.
        why: &'static str,
    },
}

/// Where a link is, as far as traffic goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Carries no traffic: down, inhibited, or never restored.
    Closed,
    /// Carries traffic.
    Open,
    /// Down; a changeover order is out and T2 runs.
    ChangeoverOrdered,
    /// Out of traffic; T1 runs.
    ChangeoverTimed,
    /// Up again; changeback declarations are out and T4 (or T5) runs.
    ChangebackDeclared {
        /// T5 is the one running.
        second: bool,
    },
    /// Up again; T3 runs.
    ChangebackTimed,
    /// Up, and waiting for the restart of this node or of the adjacent point
    /// to end before it carries traffic.
    AwaitRestart,
}

/// A changeover order the far end sent for a link that was up.
#[derive(Debug, Clone, Copy)]
struct Ordered {
    /// The sequence number it carried.
    fsnc: Option<u32>,
    /// Whether it is to be answered without one (it was a 7-bit order).
    emergency: bool,
}

#[derive(Debug, Clone)]
struct LinkState {
    up: bool,
    phase: Phase,
    /// Marked inhibited by the far end (10.2 d).
    remote_inhibited: bool,
    /// The last sequence number accepted before it went down.
    bsnt: u32,
    /// It came up while its changeover was still running.
    back: bool,
    ordered: Option<Ordered>,
    /// Changeback codes not yet acknowledged, with the link each went out on.
    declared: Vec<(u8, LinkId)>,
    /// Attempts of the uninhibit and force uninhibit in progress.
    uninhibit_attempts: u8,
    force_attempts: u8,
}

#[derive(Debug, Clone, Default)]
struct LinksetState {
    /// T21 runs for its adjacent point.
    restarting: bool,
    tra_sent: bool,
    tra_received: bool,
    /// T19 runs.
    guard: bool,
    /// The adjacent point has been told the present state of every
    /// destination since it could last be reached.
    synced: bool,
}

#[derive(Debug, Clone)]
struct RouteState {
    via: Via,
    priority: u8,
    /// What the adjacent point of the route said.
    status: RouteStatus,
}

#[derive(Debug, Clone)]
struct DestinationState {
    routes: Vec<RouteState>,
    paused: bool,
    accessible: bool,
    /// Accessible, and every route in use is a restricted one.
    restricted: bool,
    /// Linksets whose adjacent point was last told transfer-prohibited.
    told: BTreeSet<LinksetId>,
    /// T6 runs: the traffic is held.
    holding: bool,
    /// Route marks to apply when T6 runs out.
    deferred: Vec<Action>,
}

/// Signalling network management of one routing domain. See the module
/// documentation.
#[derive(Debug)]
pub struct Management {
    topology: Topology,
    timers: Timers,
    tfp_unknown: bool,
    links: Vec<LinkState>,
    linksets: Vec<LinksetState>,
    servers: Vec<bool>,
    destinations: BTreeMap<u32, DestinationState>,
    /// Destinations whose T8 runs.
    guarded: BTreeSet<u32>,
    restarting: bool,
    /// The next time the first link comes up, the restart procedure runs.
    restart_due: bool,
    isolated: bool,
    /// A link left out of the availability of its linkset, to ask what would
    /// be without it.
    without: Option<LinkId>,
    next_code: u8,
    out: Vec<Action>,
}

impl Management {
    /// The management of a domain in which nothing is up yet.
    pub fn new(topology: Topology, timers: Timers, tfp_for_unknown_destination: bool) -> Self {
        let links = topology
            .links
            .iter()
            .map(|_| LinkState {
                up: false,
                phase: Phase::Closed,
                remote_inhibited: false,
                bsnt: 0x00FF_FFFF,
                back: false,
                ordered: None,
                declared: Vec::new(),
                uninhibit_attempts: 0,
                force_attempts: 0,
            })
            .collect();
        let destinations = topology
            .routes
            .iter()
            .map(|(dpc, routes)| {
                (
                    *dpc,
                    DestinationState {
                        routes: routes
                            .iter()
                            .map(|r| RouteState {
                                via: r.via,
                                priority: r.priority,
                                status: RouteStatus::Allowed,
                            })
                            .collect(),
                        paused: false,
                        accessible: false,
                        restricted: false,
                        told: BTreeSet::new(),
                        holding: false,
                        deferred: Vec::new(),
                    },
                )
            })
            .collect();
        Self {
            linksets: vec![LinksetState::default(); topology.linksets.len()],
            servers: vec![false; topology.servers.len()],
            links,
            destinations,
            guarded: BTreeSet::new(),
            restarting: false,
            restart_due: true,
            isolated: true,
            without: None,
            next_code: 0,
            out: Vec::new(),
            topology,
            timers,
            tfp_unknown: tfp_for_unknown_destination,
        }
    }

    /// The domain this was built for.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Whether this node's MTP restart is running.
    pub fn is_restarting(&self) -> bool {
        self.restarting
    }

    /// Whether a destination can be reached, as last worked out.
    pub fn is_accessible(&self, dpc: u32) -> bool {
        self.destinations.get(&dpc).is_some_and(|d| d.accessible)
    }

    /// Whether a link carries traffic, or is about to (its changeback runs).
    pub fn carries(&self, link: LinkId) -> bool {
        self.links
            .get(link)
            .is_some_and(|_| self.link_available(link))
    }

    /// Whether the far end has a link marked inhibited.
    pub fn is_inhibited(&self, link: LinkId) -> bool {
        self.links.get(link).is_some_and(|l| l.remote_inhibited)
    }

    /// One event in, the actions it calls for out.
    pub fn handle(&mut self, input: Input) -> Vec<Action> {
        match input {
            Input::LinkUp { link } if link < self.links.len() => self.link_up(link),
            Input::LinkDown { link, bsnt } if link < self.links.len() => self.link_down(link, bsnt),
            Input::Received {
                link,
                opc,
                slc,
                message,
            } if link < self.links.len() => self.received(link, opc, slc, message),
            Input::Timeout(timer) => self.timeout(timer),
            // Nothing became available or unavailable: there is nothing to
            // settle, and under a flood of such messages that matters.
            Input::Unroutable { dpc, link } if link < self.links.len() => {
                self.unroutable(dpc, link);
                return std::mem::take(&mut self.out);
            }
            Input::Server { index, up } => {
                if let Some(slot) = self.servers.get_mut(index) {
                    *slot = up;
                }
            }
            Input::Paused { dpc, paused } => {
                if let Some(dest) = self.destinations.get_mut(&dpc) {
                    dest.paused = paused;
                }
            }
            // A link this domain does not have.
            Input::LinkUp { .. }
            | Input::LinkDown { .. }
            | Input::Received { .. }
            | Input::Unroutable { .. } => {}
        }
        self.settle();
        self.watch_isolation();
        std::mem::take(&mut self.out)
    }

    // ── Availability ─────────────────────────────────────────────────────────

    fn link_available(&self, link: LinkId) -> bool {
        self.without != Some(link)
            && matches!(
                self.links[link].phase,
                Phase::Open | Phase::ChangebackDeclared { .. } | Phase::ChangebackTimed
            )
    }

    fn linkset_available(&self, linkset: LinksetId) -> bool {
        self.topology.linksets[linkset]
            .links
            .iter()
            .any(|l| self.link_available(*l))
    }

    /// Whether any link of the linkset is up at level 2, whatever it carries.
    fn linkset_signalling(&self, linkset: LinksetId) -> bool {
        self.topology.linksets[linkset]
            .links
            .iter()
            .any(|l| self.links[*l].up)
    }

    fn usable(&self, dest: &DestinationState, route: &RouteState) -> Usable {
        if dest.paused {
            return Usable::No;
        }
        match route.via {
            Via::Server(index) => {
                if self.servers.get(index).copied().unwrap_or(false) {
                    Usable::Yes
                } else {
                    Usable::No
                }
            }
            Via::Linkset(linkset) => {
                if !self.linkset_available(linkset) {
                    return Usable::No;
                }
                match route.status {
                    RouteStatus::Allowed => Usable::Yes,
                    RouteStatus::Restricted => Usable::Restricted,
                    RouteStatus::Prohibited => Usable::No,
                }
            }
        }
    }

    /// The routes of a destination that carry traffic: the same rule the
    /// per-message resolver applies.
    fn in_use(&self, dpc: u32) -> Vec<usize> {
        match self.destinations.get(&dpc) {
            Some(dest) => routes_in_use(&dest.routes, |r| r.priority, |r| self.usable(dest, r)),
            None => Vec::new(),
        }
    }

    fn reachable(&self, dpc: u32) -> bool {
        !self.in_use(dpc).is_empty()
    }

    /// Whether a destination is reached only by routes their adjacent points
    /// restricted (13.4): an allowed route of the same priority would be used
    /// alone.
    fn only_restricted(&self, dpc: u32) -> bool {
        let Some(dest) = self.destinations.get(&dpc) else {
            return false;
        };
        let in_use = self.in_use(dpc);
        !in_use.is_empty()
            && in_use
                .iter()
                .all(|i| self.usable(dest, &dest.routes[*i]) == Usable::Restricted)
    }

    /// Whether a message can reach the adjacent point of a linkset at all: on
    /// one of its links, or by another route.
    fn can_tell(&self, linkset: LinksetId) -> bool {
        self.linkset_signalling(linkset)
            || self.topology.linksets[linkset]
                .adjacent
                .is_some_and(|pc| self.reachable(pc))
    }

    /// Whether this node should have the adjacent point of `linkset` believe
    /// `dpc` prohibited through it: inaccessible from here (13.2.2 ii), or
    /// routed through that very point (13.2.2 i).
    fn prohibited_toward(&self, dpc: u32, linkset: LinksetId) -> bool {
        let Some(dest) = self.destinations.get(&dpc) else {
            return true;
        };
        let in_use = self.in_use(dpc);
        in_use.is_empty()
            || in_use
                .iter()
                .any(|i| dest.routes[*i].via == Via::Linkset(linkset))
    }

    /// Bring what every adjacent point believes in line with what is: the
    /// broadcast of 13.2.2 ii) and 13.3.2 ii), the transfer-prohibited toward
    /// the point newly routed through and the transfer-allowed toward the one
    /// no longer (13.2.2 i, 13.3.2 i), and what a point that became accessible
    /// is owed (13.2.2 iv).
    fn settle(&mut self) {
        let dpcs: Vec<u32> = self.destinations.keys().copied().collect();
        for dpc in &dpcs {
            let accessible = self.reachable(*dpc);
            let restricted = accessible && self.only_restricted(*dpc);
            let Some(dest) = self.destinations.get_mut(dpc) else {
                continue;
            };
            if !accessible {
                dest.restricted = false;
            }
            if dest.accessible != accessible {
                dest.accessible = accessible;
                self.out.push(Action::Accessibility {
                    dpc: *dpc,
                    accessible,
                });
                // 13.2.2 ii): "and timer T8 is started concerning SP X".
                if !accessible && !self.restarting {
                    self.guard(*dpc);
                }
            }
            if let Some(dest) = self.destinations.get_mut(dpc) {
                if accessible && dest.restricted != restricted {
                    dest.restricted = restricted;
                    self.out.push(Action::Restricted {
                        dpc: *dpc,
                        restricted,
                    });
                }
            }
        }
        // 9.2.2: a restarting node sends nothing before its second phase.
        if self.restarting {
            return;
        }
        for linkset in 0..self.linksets.len() {
            let Some(adjacent) = self.topology.linksets[linkset].adjacent else {
                continue;
            };
            if !self.can_tell(linkset) {
                self.linksets[linkset].synced = false;
                continue;
            }
            if !self.linksets[linkset].synced {
                // It could not be reached, or it restarted: it takes every
                // route through this node to be allowed (9.6.2).
                self.linksets[linkset].synced = true;
                for dest in self.destinations.values_mut() {
                    dest.told.remove(&linkset);
                }
            }
            for dpc in &dpcs {
                // 13.3.2 ii): "except signalling point X if it is an adjacent
                // point"; nothing is said to a point about itself.
                if *dpc == adjacent {
                    continue;
                }
                let want = self.prohibited_toward(*dpc, linkset);
                let Some(dest) = self.destinations.get_mut(dpc) else {
                    continue;
                };
                if dest.told.contains(&linkset) == want {
                    continue;
                }
                let message = if want {
                    dest.told.insert(linkset);
                    about(*dpc, |destination| ManagementMessage::Tfp { destination })
                } else {
                    dest.told.remove(&linkset);
                    about(*dpc, |destination| ManagementMessage::Tfa { destination })
                };
                let Some(message) = message else { continue };
                self.out.push(Action::Send {
                    dpc: adjacent,
                    slc: 0,
                    message,
                    path: Path::Adjacent {
                        linkset,
                        avoid: None,
                    },
                });
            }
        }
    }

    fn guard(&mut self, dpc: u32) {
        self.guarded.insert(dpc);
        self.out
            .push(Action::Start(Timer::Prohibited(dpc), self.timers.t8));
    }

    /// 9.4.1: an isolation that lasts longer than T1 calls for the restart
    /// procedure when the first link returns.
    fn watch_isolation(&mut self) {
        let isolated = !self.links.iter().any(|l| l.up) && !self.servers.iter().any(|up| *up);
        if isolated == self.isolated {
            return;
        }
        self.isolated = isolated;
        if isolated {
            self.out
                .push(Action::Start(Timer::Isolation, self.timers.t1));
        } else {
            self.out.push(Action::Stop(Timer::Isolation));
        }
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Send a message to the adjacent point of a linkset. Nothing is sent to a
    /// linkset whose links do not say what the adjacent point is.
    fn send(&mut self, linkset: LinksetId, slc: u8, message: ManagementMessage, path: Path) {
        if let Some(dpc) = self.topology.linksets[linkset].adjacent {
            self.out.push(Action::Send {
                dpc,
                slc,
                message,
                path,
            });
        }
    }

    fn tell(&mut self, linkset: LinksetId, slc: u8, message: ManagementMessage) {
        self.send(
            linkset,
            slc,
            message,
            Path::Adjacent {
                linkset,
                avoid: None,
            },
        );
    }

    fn note(&mut self, procedure: Procedure, subject: Subject) {
        self.out.push(Action::Note(procedure, subject));
    }

    fn ignored(&mut self, name: &'static str, why: &'static str) {
        self.out.push(Action::Ignored { name, why });
    }

    // ── Links: restoration and changeback (clause 6) ─────────────────────────

    fn link_up(&mut self, link: LinkId) {
        // 9.2.1: "A signalling point starts the MTP restart procedure when its
        // first link is in service at level 2."
        if self.restart_due && !self.restarting && self.isolated {
            self.restarting = true;
            self.restart_due = false;
            // 9.6.1: "it considers at the beginning of the MTP restart
            // procedure all signalling routes to be allowed."
            for linkset in 0..self.linksets.len() {
                self.allow_routes_through(linkset);
                self.linksets[linkset].tra_received = false;
            }
            self.out.push(Action::Restarting(true));
            self.out
                .push(Action::Start(Timer::Restart, self.timers.t18));
            self.out
                .push(Action::Start(Timer::RestartOverall, self.timers.t20));
            self.note(Procedure::RestartBegun, Subject::Node);
        }
        // A link that returns while something else still served is not the
        // end of an isolation (9.4).
        if !self.isolated {
            self.restart_due = false;
        }
        self.links[link].up = true;
        match self.links[link].phase {
            // Its changeover has to complete first.
            Phase::ChangeoverOrdered | Phase::ChangeoverTimed => self.links[link].back = true,
            Phase::Closed if !self.links[link].remote_inhibited => self.restore(link),
            _ => {}
        }
        if self.restarting {
            self.restart_progress();
        }
    }

    /// A link that is up and not inhibited is to carry traffic again.
    fn restore(&mut self, link: LinkId) {
        let linkset = self.topology.links[link].linkset;
        if self.restarting || self.linksets[linkset].restarting {
            self.links[link].phase = Phase::AwaitRestart;
            return;
        }
        let carrying: Vec<LinkId> = self.topology.linksets[linkset]
            .links
            .iter()
            .copied()
            .filter(|l| *l != link && self.links[*l].phase == Phase::Open)
            .collect();
        let adjacent = self.topology.linksets[linkset].adjacent;
        if self.linkset_available(linkset) {
            // 6.2.1: the link shares a linkset that carries traffic. The
            // sequence control procedure, one declaration on each link that
            // carried its traffic (6.3.5).
            if carrying.is_empty() || adjacent.is_none() {
                self.time_controlled_changeback(link);
                return;
            }
            self.out.push(Action::Hold(link));
            let slc = self.topology.links[link].slc;
            let mut declared = Vec::new();
            for alternative in carrying {
                let code = self.next_code;
                self.next_code = self.next_code.wrapping_add(1);
                declared.push((code, alternative));
                self.send(
                    linkset,
                    slc,
                    ManagementMessage::Cbd { code },
                    Path::Behind(alternative),
                );
            }
            self.links[link].declared = declared;
            self.links[link].phase = Phase::ChangebackDeclared { second: false };
            self.out
                .push(Action::Start(Timer::Changeback(link), self.timers.t4));
            return;
        }
        // The first link of its linkset. 9.3.1: an adjacent point that was
        // inaccessible is taken to be restarting.
        if adjacent.is_some_and(|pc| !self.reachable(pc)) {
            self.linksets[linkset].restarting = true;
            self.linksets[linkset].tra_received = false;
            self.linksets[linkset].synced = false;
            // 9.6.2: "all routes using X are considered to be available unless
            // corresponding TFP or TFR messages have been received whilst T21
            // was running."
            self.allow_routes_through(linkset);
            self.links[link].phase = Phase::AwaitRestart;
            self.out.push(Action::Start(
                Timer::AdjacentRestart(linkset),
                self.timers.t21,
            ));
            self.note(Procedure::AdjacentRestartBegun, Subject::Linkset(linkset));
            // 9.3.2: "X sends any necessary TFP and TFR messages to Y; then X
            // sends a traffic restart allowed message to signalling point Y."
            self.settle();
            self.send(linkset, 0, ManagementMessage::Tra, Path::Link(link));
            self.linksets[linkset].tra_sent = true;
            return;
        }
        self.start_traffic(link);
    }

    /// A linkset became available: 6.2.5 and 6.4, the time-controlled
    /// diversion, when traffic it should carry is on another route now; at
    /// once when there is none (6.2.2, 6.2.3 i).
    fn start_traffic(&mut self, link: LinkId) {
        let linkset = self.topology.links[link].linkset;
        let diverted = self
            .destinations
            .values()
            .any(|d| d.accessible && d.routes.iter().any(|r| r.via == Via::Linkset(linkset)));
        if diverted {
            self.time_controlled_changeback(link);
        } else {
            self.links[link].phase = Phase::Open;
            // 9.3.2: "preventive TFP messages according to 13.2.2 i) must be
            // sent before MTP User traffic is restarted."
            self.settle();
            self.out.push(Action::Open(link));
        }
    }

    fn time_controlled_changeback(&mut self, link: LinkId) {
        self.links[link].phase = Phase::ChangebackTimed;
        self.out.push(Action::Hold(link));
        self.out
            .push(Action::Start(Timer::Changeback(link), self.timers.t3));
    }

    fn finish_changeback(&mut self, link: LinkId, how: Procedure) {
        self.out.push(Action::Stop(Timer::Changeback(link)));
        self.links[link].declared.clear();
        self.links[link].phase = Phase::Open;
        self.out.push(Action::Open(link));
        self.note(how, Subject::Link(link));
    }

    // ── Links: failure and changeover (clause 5) ─────────────────────────────

    fn link_down(&mut self, link: LinkId, bsnt: u32) {
        let linkset = self.topology.links[link].linkset;
        self.links[link].up = false;
        self.links[link].bsnt = bsnt;
        self.links[link].back = false;
        let ordered = self.links[link].ordered.take();
        if let Some(order) = ordered {
            self.acknowledge_order(link, order.emergency);
        }
        match self.links[link].phase {
            Phase::Open | Phase::ChangebackDeclared { .. } | Phase::ChangebackTimed => {
                self.out.push(Action::Stop(Timer::Changeback(link)));
                self.links[link].declared.clear();
                match ordered {
                    // 5.4.1: "In the case that the changeover was initiated by
                    // the reception of a changeover order, a changeover
                    // acknowledgement is sent instead."
                    Some(order) => {
                        self.out.push(Action::Hold(link));
                        self.complete_changeover(link, order.fsnc, None);
                    }
                    None => self.begin_changeover(link),
                }
            }
            Phase::ChangeoverOrdered | Phase::ChangeoverTimed => {
                if let Some(order) = ordered {
                    self.complete_changeover(link, order.fsnc, None);
                }
            }
            Phase::AwaitRestart => self.links[link].phase = Phase::Closed,
            Phase::Closed => {}
        }
        if !self.linkset_signalling(linkset) {
            let state = &mut self.linksets[linkset];
            if state.restarting {
                state.restarting = false;
                self.out.push(Action::Stop(Timer::AdjacentRestart(linkset)));
            }
            state.tra_sent = false;
            state.tra_received = false;
        }
    }

    fn begin_changeover(&mut self, link: LinkId) {
        let linkset = self.topology.links[link].linkset;
        self.out.push(Action::Hold(link));
        // 5.6.2 i): "No signalling path exists between the two ends of the
        // unavailable link, so that the exchange of changeover messages is
        // impossible."
        self.links[link].phase = Phase::ChangeoverOrdered;
        if self.can_tell(linkset) && self.topology.linksets[linkset].adjacent.is_some() {
            let slc = self.topology.links[link].slc;
            let fsn = self.links[link].bsnt;
            self.send(
                linkset,
                slc,
                ManagementMessage::Xco { fsn },
                Path::Adjacent {
                    linkset,
                    avoid: Some(link),
                },
            );
            self.out
                .push(Action::Start(Timer::Changeover(link), self.timers.t2));
        } else {
            self.links[link].phase = Phase::ChangeoverTimed;
            self.out
                .push(Action::Start(Timer::Changeover(link), self.timers.t1));
        }
    }

    /// 5.5: the buffer of the link is updated and its traffic diverted.
    fn complete_changeover(&mut self, link: LinkId, fsnc: Option<u32>, how: Option<Procedure>) {
        self.out.push(Action::Stop(Timer::Changeover(link)));
        self.links[link].phase = Phase::Closed;
        self.out.push(Action::Divert { link, fsnc });
        let how = how.unwrap_or(if fsnc.is_some() {
            Procedure::ChangeoverAcknowledged
        } else {
            Procedure::ChangeoverEmergency
        });
        self.note(how, Subject::Link(link));
        let state = &mut self.links[link];
        let restore = state.back && state.up && !state.remote_inhibited;
        state.back = false;
        if restore {
            self.restore(link);
        }
    }

    /// Answer a changeover order with this end's last accepted sequence
    /// number, or without one when the order was a 7-bit one: a 24-bit number
    /// does not fit its acknowledgement (RFC 4165 4.2.3), and 5.6.1 has "a
    /// changeover order ... acknowledged by an emergency changeover
    /// acknowledgement if there are local fault conditions".
    fn acknowledge_order(&mut self, link: LinkId, emergency: bool) {
        let linkset = self.topology.links[link].linkset;
        let slc = self.topology.links[link].slc;
        let message = if emergency {
            ManagementMessage::Eca
        } else {
            ManagementMessage::Xca {
                fsn: self.links[link].bsnt,
            }
        };
        self.send(
            linkset,
            slc,
            message,
            Path::Adjacent {
                linkset,
                avoid: Some(link),
            },
        );
    }

    fn changeover_order(&mut self, link: LinkId, fsnc: Option<u32>, emergency: bool) {
        match self.links[link].phase {
            // We asked too, or T1 runs: 5.4.3, the order updates the buffer
            // as an acknowledgement would. 5.6.2: "A changeover
            // acknowledgement however, must be returned in any case".
            Phase::ChangeoverOrdered | Phase::ChangeoverTimed if !self.links[link].up => {
                self.acknowledge_order(link, emergency);
                self.complete_changeover(link, fsnc, None);
            }
            // 3.2.2: "a signalling link which is available (not blocked) is
            // recognized by level 3 as failed when a changeover order is
            // received." The answer waits for level 2 to say where it stopped.
            _ if self.links[link].up => {
                self.links[link].ordered = Some(Ordered { fsnc, emergency });
                self.out.push(Action::Fail(link));
            }
            // 5.7.5: "If a changeover order is received relating to a
            // particular signalling link after the completion of changeover
            // from that signalling link, an emergency changeover
            // acknowledgement is sent in response, without any further action."
            _ => {
                let linkset = self.topology.links[link].linkset;
                let slc = self.topology.links[link].slc;
                self.send(
                    linkset,
                    slc,
                    ManagementMessage::Eca,
                    Path::Adjacent {
                        linkset,
                        avoid: Some(link),
                    },
                );
            }
        }
    }

    fn changeover_acknowledgement(&mut self, link: LinkId, fsnc: Option<u32>, name: &'static str) {
        if self.links[link].phase == Phase::ChangeoverOrdered {
            self.complete_changeover(link, fsnc, None);
        } else {
            // 5.7.4: "If a changeover acknowledgement is received without
            // having previously sent a changeover order, no action is taken."
            self.ignored(name, "no changeover order is out for the link");
        }
    }

    // ── Management inhibiting (clause 10) ────────────────────────────────────

    /// Whether taking a link out of traffic would make a destination that is
    /// accessible now inaccessible (10.2 c).
    fn would_isolate(&mut self, link: LinkId) -> bool {
        let before: Vec<u32> = self
            .destinations
            .keys()
            .copied()
            .filter(|dpc| self.reachable(*dpc))
            .collect();
        self.without = Some(link);
        let lost = before.iter().any(|dpc| !self.reachable(*dpc));
        self.without = None;
        lost
    }

    fn inhibit_message(&mut self, link: LinkId, message: &ManagementMessage) {
        let linkset = self.topology.links[link].linkset;
        let slc = self.topology.links[link].slc;
        // "via that link" while it is up (10.2 d), by any route otherwise.
        let path = if self.links[link].up {
            Path::Link(link)
        } else {
            Path::Adjacent {
                linkset,
                avoid: Some(link),
            }
        };
        match message {
            ManagementMessage::Lin => {
                if self.links[link].remote_inhibited {
                    // 10.4 a): answered "without taking any further action".
                    self.send(linkset, slc, ManagementMessage::Lia, path);
                    return;
                }
                if self.link_available(link) && self.would_isolate(link) {
                    self.send(linkset, slc, ManagementMessage::Lid, path);
                    self.note(Procedure::LinkInhibitDenied, Subject::Link(link));
                    return;
                }
                self.links[link].remote_inhibited = true;
                self.send(linkset, slc, ManagementMessage::Lia, path);
                self.note(Procedure::LinkInhibited, Subject::Link(link));
                match self.links[link].phase {
                    // 10.2 d): "diverts subsequent traffic for it, using the
                    // time controlled changeover procedure".
                    Phase::Open | Phase::ChangebackDeclared { .. } | Phase::ChangebackTimed => {
                        self.out.push(Action::Stop(Timer::Changeback(link)));
                        self.links[link].declared.clear();
                        self.links[link].phase = Phase::ChangeoverTimed;
                        self.out.push(Action::Hold(link));
                        self.out
                            .push(Action::Start(Timer::Changeover(link), self.timers.t1));
                    }
                    Phase::AwaitRestart => self.links[link].phase = Phase::Closed,
                    _ => {}
                }
                // "Y then starts inhibit test timer T23."
                self.out
                    .push(Action::Start(Timer::InhibitTest(link), self.timers.t23));
            }
            ManagementMessage::Lun => {
                // 10.3.1 c), and 10.4 b) when it was not inhibited.
                self.send(linkset, slc, ManagementMessage::Lua, path);
                self.out.push(Action::Stop(Timer::ForceUninhibit(link)));
                self.links[link].force_attempts = 0;
                if !self.links[link].remote_inhibited {
                    return;
                }
                self.links[link].remote_inhibited = false;
                self.out.push(Action::Stop(Timer::InhibitTest(link)));
                self.note(Procedure::LinkUninhibited, Subject::Link(link));
                let up = self.links[link].up;
                match self.links[link].phase {
                    // "it is put in the available state and changeback is
                    // initiated."
                    Phase::Closed if up => self.restore(link),
                    Phase::ChangeoverTimed | Phase::ChangeoverOrdered if up => {
                        self.links[link].back = true;
                    }
                    _ => {}
                }
            }
            // 10.4 c): "A force uninhibit signalling link message concerning
            // an uninhibited link is answered with an uninhibit signalling
            // link message without taking any further action." This node never
            // inhibits a link itself, so that is every force uninhibit.
            ManagementMessage::Lfu => self.send(linkset, slc, ManagementMessage::Lun, path),
            ManagementMessage::Lua => {
                if self.links[link].uninhibit_attempts > 0 {
                    self.links[link].uninhibit_attempts = 0;
                    self.out.push(Action::Stop(Timer::Uninhibit(link)));
                } else {
                    // 10.4 e).
                    self.ignored("LUA", "no uninhibit message is outstanding for the link");
                }
            }
            // 10.4 d): no inhibit message is ever outstanding here.
            ManagementMessage::Lia => {
                self.ignored("LIA", "no inhibit message is outstanding for the link")
            }
            ManagementMessage::Lid => {
                self.ignored("LID", "no inhibit message is outstanding for the link")
            }
            // 10.6.1: the far end has the link locally inhibited.
            ManagementMessage::Llt => {
                if !self.links[link].remote_inhibited && self.links[link].force_attempts == 0 {
                    // ii) "the force uninhibit procedure to be invoked".
                    self.links[link].force_attempts = 1;
                    self.send(linkset, slc, ManagementMessage::Lfu, path);
                    self.out
                        .push(Action::Start(Timer::ForceUninhibit(link), self.timers.t13));
                }
            }
            // 10.6.2: the far end has the link remotely inhibited, which this
            // node never asked for: ii) "the uninhibit procedure to be invoked".
            ManagementMessage::Lrt if self.links[link].uninhibit_attempts == 0 => {
                self.links[link].uninhibit_attempts = 1;
                self.send(linkset, slc, ManagementMessage::Lun, path);
                self.out
                    .push(Action::Start(Timer::Uninhibit(link), self.timers.t12));
            }
            _ => {}
        }
    }

    // ── Routes (clause 13) ───────────────────────────────────────────────────

    /// Every route through a linkset is allowed again, and no route set test
    /// runs for it.
    fn allow_routes_through(&mut self, linkset: LinksetId) {
        let mut cleared = Vec::new();
        for (dpc, dest) in &mut self.destinations {
            for route in &mut dest.routes {
                if route.via == Via::Linkset(linkset) && route.status != RouteStatus::Allowed {
                    route.status = RouteStatus::Allowed;
                    cleared.push(*dpc);
                }
            }
        }
        for dpc in cleared {
            self.out
                .push(Action::Stop(Timer::RouteSetTest(dpc, linkset)));
            self.out.push(Action::Route {
                dpc,
                linkset,
                status: RouteStatus::Allowed,
            });
        }
    }

    /// A transfer-prohibited, -restricted or -allowed from an adjacent point.
    fn route_message(
        &mut self,
        linkset: LinksetId,
        dpc: u32,
        status: RouteStatus,
        name: &'static str,
    ) {
        let position = self.destinations.get(&dpc).and_then(|dest| {
            dest.routes
                .iter()
                .position(|r| r.via == Via::Linkset(linkset))
        });
        let Some(position) = position else {
            // 13.2.4, 13.3.4, 13.4.4: "relating to a non-existent route ... no
            // actions are taken."
            self.ignored(
                name,
                "there is no route to that destination through the sender",
            );
            return;
        };
        let before = self.in_use(dpc);
        let was = self
            .destinations
            .get(&dpc)
            .map(|d| d.routes[position].status);
        if was == Some(status) {
            // A repeated message: "no actions are taken".
            return;
        }
        if let Some(dest) = self.destinations.get_mut(&dpc) {
            dest.routes[position].status = status;
        }
        let after = self.in_use(dpc);
        // 13.5.2: the route set test runs "every T10 period until a
        // transfer-allowed message ... is received".
        if status == RouteStatus::Allowed {
            self.out
                .push(Action::Stop(Timer::RouteSetTest(dpc, linkset)));
        } else {
            self.out.push(Action::Start(
                Timer::RouteSetTest(dpc, linkset),
                self.timers.t10,
            ));
        }
        let mark = Action::Route {
            dpc,
            linkset,
            status,
        };
        let moves = before != after;
        let Some(dest) = self.destinations.get_mut(&dpc) else {
            return;
        };
        if status == RouteStatus::Prohibited {
            // Clause 7: "transmission of signalling traffic towards the
            // concerned destination on the link set(s) pertaining to the
            // unavailable route is immediately stopped". The alternative is
            // known the moment the route is marked, so the forced rerouting
            // buffer is never filled: the next message takes the new route.
            let held = std::mem::take(&mut dest.deferred);
            self.out.extend(held);
            self.out.push(mark);
            if dest.holding {
                dest.holding = false;
                self.out.push(Action::Stop(Timer::Rerouting(dpc)));
                self.out.push(Action::ReleaseDestination(dpc));
            }
            if moves && !before.is_empty() {
                self.note(Procedure::ForcedRerouting, Subject::Destination(dpc));
            }
        } else if dest.holding {
            dest.deferred.push(mark);
        } else if moves && !before.is_empty() && !after.is_empty() {
            // Clause 8: the traffic is stopped and "stored in a controlled
            // rerouting buffer; a timer T6 is started".
            dest.holding = true;
            dest.deferred.push(mark);
            self.out.push(Action::HoldDestination(dpc));
            self.out
                .push(Action::Start(Timer::Rerouting(dpc), self.timers.t6));
            self.note(Procedure::ControlledRerouting, Subject::Destination(dpc));
        } else {
            self.out.push(mark);
        }
    }

    /// 13.5.4: a signalling route set test is answered only when what the
    /// sender believes differs from what is.
    fn route_set_test(&mut self, linkset: LinksetId, dpc: u32, believes: RouteStatus) {
        let prohibited = self.prohibited_toward(dpc, linkset);
        let actual = if prohibited {
            RouteStatus::Prohibited
        } else {
            RouteStatus::Allowed
        };
        if actual == believes {
            return;
        }
        let message = if prohibited {
            about(dpc, |destination| ManagementMessage::Tfp { destination })
        } else {
            about(dpc, |destination| ManagementMessage::Tfa { destination })
        };
        let Some(message) = message else { return };
        if let Some(dest) = self.destinations.get_mut(&dpc) {
            if prohibited {
                dest.told.insert(linkset);
            } else {
                dest.told.remove(&linkset);
            }
        }
        self.tell(linkset, 0, message);
    }

    /// 13.2.2 iii), the response method.
    fn unroutable(&mut self, dpc: u32, link: LinkId) {
        if self.restarting || dpc == self.topology.own_pc || self.guarded.contains(&dpc) {
            return;
        }
        let linkset = self.topology.links[link].linkset;
        if self.topology.linksets[linkset].adjacent.is_none() {
            return;
        }
        let Some(message) = about(dpc, |destination| ManagementMessage::Tfp { destination }) else {
            return;
        };
        match self.destinations.get_mut(&dpc) {
            Some(dest) => {
                dest.told.insert(linkset);
            }
            // Footnote 7: "It might be of advantage in national networks (at
            // the discretion of the network operator) not to send a TFP if no
            // routing data for X exists at Y."
            None if !self.tfp_unknown => return,
            None => {}
        }
        self.tell(linkset, 0, message);
        // "In addition, timer T8 is started concerning SP X."
        self.guard(dpc);
    }

    // ── MTP restart (clause 9) ───────────────────────────────────────────────

    /// 9.2.2: T18 "is stopped when ... enough TRA messages (and therefore
    /// routing data) have been received". Here: one from every adjacent point.
    fn restart_progress(&mut self) {
        let complete = (0..self.linksets.len()).all(|linkset| {
            self.topology.linksets[linkset].adjacent.is_none()
                || (self.linksets[linkset].tra_received && self.linkset_signalling(linkset))
        });
        if complete {
            self.end_restart();
        }
    }

    /// The second phase and the end of this node's restart (9.2.2, 9.2.4).
    fn end_restart(&mut self) {
        if !self.restarting {
            return;
        }
        self.restarting = false;
        self.out.push(Action::Stop(Timer::Restart));
        self.out.push(Action::Stop(Timer::RestartOverall));
        let mut opened = Vec::new();
        for link in 0..self.links.len() {
            if self.links[link].phase == Phase::AwaitRestart {
                self.links[link].phase = Phase::Open;
                opened.push(link);
            }
        }
        // "a broadcast of non-preventive transfer prohibited messages ...
        // taking into account signalling link sets which are not available and
        // any TFP, TFA and TFR messages received during phase 1", and the
        // preventive ones, which "must have been sent before normal User
        // traffic is carried".
        for state in &mut self.linksets {
            state.synced = false;
        }
        self.settle();
        self.out.extend(opened.into_iter().map(Action::Open));
        // 9.2.4: "sends traffic restart allowed messages to all adjacent
        // signalling points via corresponding available direct link sets ...
        // In addition, timer T19 is started".
        for linkset in 0..self.linksets.len() {
            if !self.linkset_signalling(linkset) {
                continue;
            }
            self.tell(linkset, 0, ManagementMessage::Tra);
            self.linksets[linkset].tra_sent = true;
            self.linksets[linkset].guard = true;
            self.out.push(Action::Start(
                Timer::RestartAllowed(linkset),
                self.timers.t19,
            ));
        }
        self.out.push(Action::Restarting(false));
        self.note(Procedure::RestartEnded, Subject::Node);
    }

    fn end_adjacent_restart(&mut self, linkset: LinksetId, how: Procedure) {
        self.linksets[linkset].restarting = false;
        self.out.push(Action::Stop(Timer::AdjacentRestart(linkset)));
        self.note(how, Subject::Linkset(linkset));
        let waiting: Vec<LinkId> = self.topology.linksets[linkset]
            .links
            .iter()
            .copied()
            .filter(|l| self.links[*l].phase == Phase::AwaitRestart)
            .collect();
        // 6.4.1: "The time-controlled diversion procedure is used at the end
        // of the MTP restart procedure when an adjacent signalling point
        // becomes available".
        for link in waiting {
            self.start_traffic(link);
        }
    }

    fn traffic_restart_allowed(&mut self, linkset: LinksetId) {
        if self.restarting {
            // 9.2.2: "the restarting MTP takes into account any traffic
            // restart allowed messages received from adjacent nodes."
            self.linksets[linkset].tra_received = true;
            self.restart_progress();
        } else if self.linksets[linkset].restarting {
            // 9.3.2: "When a traffic restart allowed message has been received
            // by X from signalling point Y, and a TRA message has been sent by
            // X to Y, X stops timer T21."
            self.linksets[linkset].tra_received = true;
            if self.linksets[linkset].tra_sent {
                self.end_adjacent_restart(linkset, Procedure::AdjacentRestartEnded);
            }
        } else if self.linksets[linkset].guard {
            // 9.5.2: "this TRA is discarded and no further action is
            // necessary."
            self.ignored("TRA", "T19 is running for the adjacent point");
        } else {
            // 9.5.1: "X sends to Y any necessary TFP and TFR messages if X has
            // the transfer function, and a TRA message to Y. In addition, X
            // starts a timer T19 associated with Y."
            self.linksets[linkset].synced = false;
            self.settle();
            self.tell(linkset, 0, ManagementMessage::Tra);
            self.linksets[linkset].guard = true;
            self.out.push(Action::Start(
                Timer::RestartAllowed(linkset),
                self.timers.t19,
            ));
        }
    }

    // ── Received messages ────────────────────────────────────────────────────

    /// The linkset whose adjacent point is `opc`: the one the message arrived
    /// on if that fits, else any.
    fn linkset_of(&self, opc: u32, link: LinkId) -> Option<LinksetId> {
        let arrived = self.topology.links[link].linkset;
        if self.topology.linksets[arrived].adjacent == Some(opc) {
            return Some(arrived);
        }
        self.topology
            .linksets
            .iter()
            .position(|l| l.adjacent == Some(opc))
    }

    fn received(&mut self, arrived: LinkId, opc: u32, slc: u8, message: ManagementMessage) {
        use ManagementMessage as M;
        let name = message.name();
        // These two come from anywhere in the network.
        match message {
            M::Tfc {
                destination,
                status,
            } => {
                if !self.restarting {
                    self.out.push(Action::Congestion {
                        dpc: destination.value(),
                        status,
                    });
                } else {
                    self.ignored(name, "this node is restarting");
                }
                return;
            }
            M::Upu { .. } => {
                self.ignored(name, "no user part of this node sent to that destination");
                return;
            }
            // 13.9.6: "When a signalling-route-set-congestion-test message
            // reaches its destination, it is discarded."
            M::Rct => {
                self.ignored(name, "discarded at its destination");
                return;
            }
            _ => {}
        }
        let Some(linkset) = self.linkset_of(opc, arrived) else {
            self.ignored(name, "its originating point is not an adjacent point");
            return;
        };
        // 9.6.6: of the messages for the node itself, a restarting MTP treats
        // those of the restart procedure; the "message groups CHM, ECM, FCM,
        // RSM, UFC, MIM and DLM" are discarded.
        if self.restarting
            && !matches!(
                message,
                M::Tfp { .. } | M::Tfr { .. } | M::Tfa { .. } | M::Tra
            )
        {
            self.ignored(name, "this node is restarting");
            return;
        }
        match message {
            M::Tfp { destination } => {
                self.route_message(linkset, destination.value(), RouteStatus::Prohibited, name)
            }
            M::Tfr { destination } => {
                self.route_message(linkset, destination.value(), RouteStatus::Restricted, name)
            }
            M::Tfa { destination } => {
                self.route_message(linkset, destination.value(), RouteStatus::Allowed, name)
            }
            M::Rst { destination } => {
                self.route_set_test(linkset, destination.value(), RouteStatus::Prohibited)
            }
            M::Rsr { destination } => {
                self.route_set_test(linkset, destination.value(), RouteStatus::Restricted)
            }
            M::Tra => self.traffic_restart_allowed(linkset),
            // 6.5.2, 6.3.2: a changeback declaration is always acknowledged,
            // by "any available signalling route between the two signalling
            // points". It names no link of ours that has to exist.
            M::Cbd { code } => self.tell(linkset, slc, M::Cba { code }),
            // The rest are about one link of the linkset.
            other => {
                let link = self.topology.linksets[linkset]
                    .links
                    .iter()
                    .copied()
                    .find(|l| self.topology.links[*l].slc == slc);
                let Some(link) = link else {
                    self.ignored(name, "the linkset has no link with that code");
                    return;
                };
                self.link_message(link, other, name);
            }
        }
    }

    fn link_message(&mut self, link: LinkId, message: ManagementMessage, name: &'static str) {
        use ManagementMessage as M;
        match message {
            M::Xco { fsn } => self.changeover_order(link, Some(fsn), false),
            // The 7-bit number of a changeover order cannot name a message of
            // an M2PA link (RFC 4165 4.2.3): 5.7.3, "no buffer updating or
            // retrieval is performed".
            M::Coo { .. } => self.changeover_order(link, None, true),
            // 5.6.1: "an emergency changeover order is acknowledged by a
            // changeover acknowledgement if the local conditions are normal".
            M::Eco => self.changeover_order(link, None, false),
            M::Xca { fsn } => self.changeover_acknowledgement(link, Some(fsn), name),
            M::Coa { .. } | M::Eca => self.changeover_acknowledgement(link, None, name),
            M::Cba { code } => {
                let state = &mut self.links[link];
                let before = state.declared.len();
                state.declared.retain(|(c, _)| *c != code);
                let matched = state.declared.len() != before
                    && matches!(state.phase, Phase::ChangebackDeclared { .. });
                let done = state.declared.is_empty();
                if !matched {
                    // 6.5.1.
                    self.ignored(name, "no changeback declaration with that code is out");
                } else if done {
                    self.finish_changeback(link, Procedure::ChangebackAcknowledged);
                }
            }
            M::Lin | M::Lun | M::Lia | M::Lua | M::Lid | M::Lfu | M::Llt | M::Lrt => {
                self.inhibit_message(link, &message)
            }
            // Clause 12.3 to 12.6, the allocation of data links and terminals,
            // has nothing to act on at a link that is an SCTP association.
            M::Dlc { .. } | M::Css | M::Cns | M::Cnp => {
                self.ignored(name, "signalling data links are not allocated on request")
            }
            _ => self.ignored(name, "not a message about a link"),
        }
    }

    // ── Timers ───────────────────────────────────────────────────────────────

    fn timeout(&mut self, timer: Timer) {
        match timer {
            Timer::Changeover(link) if link < self.links.len() => {
                match self.links[link].phase {
                    // 5.7.2: "new traffic is started on the alternative
                    // signalling link(s)."
                    Phase::ChangeoverOrdered => self.complete_changeover(
                        link,
                        None,
                        Some(Procedure::ChangeoverUnacknowledged),
                    ),
                    // 5.6.2: "after the expiry of a time T1, it starts
                    // signalling traffic not yet transmitted on the
                    // unavailable signalling link on the alternative link(s)".
                    Phase::ChangeoverTimed => self.complete_changeover(
                        link,
                        None,
                        Some(Procedure::ChangeoverTimeControlled),
                    ),
                    _ => {}
                }
            }
            Timer::Changeback(link) if link < self.links.len() => match self.links[link].phase {
                // 6.5.3: "the changeback-declaration is repeated and a new
                // timer T5 is started."
                Phase::ChangebackDeclared { second: false } => {
                    let linkset = self.topology.links[link].linkset;
                    let slc = self.topology.links[link].slc;
                    for (code, alternative) in self.links[link].declared.clone() {
                        self.send(
                            linkset,
                            slc,
                            ManagementMessage::Cbd { code },
                            Path::Behind(alternative),
                        );
                    }
                    self.links[link].phase = Phase::ChangebackDeclared { second: true };
                    self.out
                        .push(Action::Start(Timer::Changeback(link), self.timers.t5));
                }
                // "the maintenance functions are alerted and traffic on the
                // link made available is started."
                Phase::ChangebackDeclared { second: true } => {
                    self.finish_changeback(link, Procedure::ChangebackUnacknowledged)
                }
                Phase::ChangebackTimed => {
                    self.finish_changeback(link, Procedure::ChangebackTimeControlled)
                }
                _ => {}
            },
            Timer::Rerouting(dpc) => {
                if let Some(dest) = self.destinations.get_mut(&dpc) {
                    if dest.holding {
                        dest.holding = false;
                        let marks = std::mem::take(&mut dest.deferred);
                        self.out.extend(marks);
                        self.out.push(Action::ReleaseDestination(dpc));
                    }
                }
            }
            Timer::Prohibited(dpc) => {
                self.guarded.remove(&dpc);
            }
            Timer::RouteSetTest(dpc, linkset) if linkset < self.linksets.len() => {
                let status = self.destinations.get(&dpc).and_then(|dest| {
                    dest.routes
                        .iter()
                        .find(|r| r.via == Via::Linkset(linkset))
                        .map(|r| r.status)
                });
                let message = match status {
                    Some(RouteStatus::Prohibited) => {
                        about(dpc, |destination| ManagementMessage::Rst { destination })
                    }
                    Some(RouteStatus::Restricted) => {
                        about(dpc, |destination| ManagementMessage::Rsr { destination })
                    }
                    _ => None,
                };
                let Some(message) = message else { return };
                // 9.6.3: nothing is tested while this node restarts; a point
                // that cannot be reached is asked again next time.
                if !self.restarting && self.can_tell(linkset) {
                    self.tell(linkset, 0, message);
                }
                self.out.push(Action::Start(
                    Timer::RouteSetTest(dpc, linkset),
                    self.timers.t10,
                ));
            }
            Timer::Uninhibit(link) if link < self.links.len() => {
                self.repeat_uninhibit(link, false);
            }
            Timer::ForceUninhibit(link) if link < self.links.len() => {
                self.repeat_uninhibit(link, true);
            }
            Timer::InhibitTest(link) if link < self.links.len() => {
                // 10.6.2: "a remote inhibit test message is sent to signalling
                // point X at the other end of the link, and timer T23 is
                // restarted."
                if self.links[link].remote_inhibited {
                    let linkset = self.topology.links[link].linkset;
                    let slc = self.topology.links[link].slc;
                    let path = self.link_or_route(link);
                    self.send(linkset, slc, ManagementMessage::Lrt, path);
                    self.out
                        .push(Action::Start(Timer::InhibitTest(link), self.timers.t23));
                }
            }
            // 9.2.2: "When T18 is stopped or expires, the second phase
            // begins"; 9.2.4 for T20.
            Timer::Restart | Timer::RestartOverall => self.end_restart(),
            Timer::RestartAllowed(linkset) if linkset < self.linksets.len() => {
                self.linksets[linkset].guard = false;
            }
            Timer::AdjacentRestart(linkset) if linkset < self.linksets.len() => {
                if self.linksets[linkset].restarting {
                    self.end_adjacent_restart(linkset, Procedure::AdjacentRestartExpired);
                }
            }
            Timer::Isolation if self.isolated => self.restart_due = true,
            _ => {}
        }
    }

    fn link_or_route(&self, link: LinkId) -> Path {
        if self.links[link].up {
            Path::Link(link)
        } else {
            Path::Adjacent {
                linkset: self.topology.links[link].linkset,
                avoid: Some(link),
            }
        }
    }

    /// T12 or T13 ran out: once more, then give up (10.3.1 e, 10.3.2 e).
    fn repeat_uninhibit(&mut self, link: LinkId, force: bool) {
        let attempts = if force {
            self.links[link].force_attempts
        } else {
            self.links[link].uninhibit_attempts
        };
        let linkset = self.topology.links[link].linkset;
        let slc = self.topology.links[link].slc;
        let (timer, after, message) = if force {
            (
                Timer::ForceUninhibit(link),
                self.timers.t13,
                ManagementMessage::Lfu,
            )
        } else {
            (
                Timer::Uninhibit(link),
                self.timers.t12,
                ManagementMessage::Lun,
            )
        };
        let next = match attempts {
            0 => return,
            1 => {
                let path = self.link_or_route(link);
                self.send(linkset, slc, message, path);
                self.out.push(Action::Start(timer, after));
                2
            }
            _ => {
                self.note(Procedure::UninhibitAbandoned, Subject::Link(link));
                0
            }
        };
        if force {
            self.links[link].force_attempts = next;
        } else {
            self.links[link].uninhibit_attempts = next;
        }
    }
}

/// A message about a destination. `None` for a value that is not a 14-bit ITU
/// point code, which nothing this layer is configured with or receives is.
fn about(dpc: u32, make: fn(PointCode) -> ManagementMessage) -> Option<ManagementMessage> {
    PointCode::from_value(dpc, Variant::Itu).ok().map(make)
}

#[cfg(test)]
mod tests;
