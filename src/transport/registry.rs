//! The transport's shared runtime state: one slot per SCTP association, plus the
//! Application-Server / linkset egress maps compiled from the config.
//!
//! Association tasks update their slot (sender + adaptation-active flag) as the
//! handshake progresses; [`Registry::recompute`] then folds that into the
//! router's route state (an AS is up while ≥ 1 ASP is active, a linkset while
//! level 3 routes traffic to ≥ 1 of its links). [`Registry::select`] answers
//! the egress question: given a resolved [`Destination`], which association(s)
//! carry the MSU, honouring the AS traffic mode and the SLS.
//!
//! It is also where the per-message path meets signalling network management
//! ([`crate::mtp3::management`]): which links level 3 routes to (one atomic
//! per link), whether this node's MTP is restarting (one atomic), and the
//! controlled rerouting buffers (ITU-T Q.704 8.2.1), which cost the path one
//! atomic load while no destination is held.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use async_sctp::SctpAssociation;
use mtp3::Variant;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::framing::Msu;
use super::m2pa::link::{Discard, LinkTimers, Proving};
use super::m2pa::traffic::LinkTraffic;
use crate::config::{Adaptation, Config, M2paLink, ProvingMode, TenantId, TrafficMode};
use crate::metrics;
use crate::mtp3::management::{Input, Topology};
use crate::mtp3::route::{Destination, RouteResolver};
use crate::routing::Router;

/// A destination became accessible or inaccessible through this node, or a
/// transfer-controlled arrived for it. Signalling route management emits one
/// for every such change ([`Registry::destination_changes`]): whatever has to
/// tell someone else (an application server, a user part) subscribes here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationChange {
    /// The destination can be reached again.
    Accessible {
        /// Its point code.
        dpc: u32,
    },
    /// The destination cannot be reached.
    Inaccessible {
        /// Its point code.
        dpc: u32,
    },
    /// A transfer-controlled arrived for the destination (Q.704 13.6).
    Congested {
        /// Its point code.
        dpc: u32,
        /// The congestion status the message carried.
        status: u8,
    },
}

/// What level 3 tells the task that serves a link.
#[derive(Debug)]
pub(crate) enum LinkCommand {
    /// Route traffic to the link and buffer it. `done` is told once routing
    /// does: what is said to the far end afterwards (a changeback declaration)
    /// then holds.
    Hold {
        /// Told when the link buffers and routing leads to it.
        done: Option<oneshot::Sender<()>>,
    },
    /// The changeover is complete: divert what the link holds.
    Divert {
        /// The last message the far end accepted, when it said.
        fsnc: Option<u32>,
    },
    /// Send the buffer on the link and carry traffic.
    Open,
    /// Take the link out of service at level 2.
    Fail,
    /// Send this MSU on the link whatever it does with traffic: a management
    /// or link test message bound to this link (Q.704 2.3.4.2 a).
    Direct(Vec<u8>),
}

/// The receiving side of a link's queues, with the traffic state that goes
/// with them. One task holds it at a time.
pub(crate) struct LinkQueues {
    pub msus: mpsc::Receiver<Vec<u8>>,
    pub commands: mpsc::UnboundedReceiver<LinkCommand>,
    pub traffic: LinkTraffic,
}

/// What the signalling link test of a link needs (ITU-T Q.707 2.2).
#[derive(Debug, Clone)]
pub struct LinkTestSettings {
    /// T1, supervision of the acknowledgement.
    pub t1: Duration,
    /// T2, interval between tests.
    pub t2: Duration,
    /// The pattern sent, and expected back.
    pub pattern: Vec<u8>,
}

/// Everything the task of one M2PA link is configured with.
#[derive(Debug, Clone)]
pub struct LinkSettings {
    /// The level-2 timers.
    pub timers: LinkTimers,
    /// The proving period this end asks for.
    pub proving: Proving,
    /// MSUs held for transmission before the link discards.
    pub tx_queue: usize,
    /// Delay before alignment is tried again (Q.704 T17).
    pub restart: Duration,
    /// The test this node runs on the link; `None` when it is switched off or
    /// the link has no adjacent point code to address it to.
    pub test: Option<LinkTestSettings>,
    /// This node's point code.
    pub own_pc: u32,
    /// The point at the other end of the link.
    pub adjacent_pc: Option<u32>,
    /// The network indicator of this node.
    pub ni: u8,
    /// The signalling link code of the link in its linkset.
    pub slc: u8,
    /// The link's number in signalling network management; `None` for a link
    /// in no linkset, which level 3 never routes to.
    pub index: Option<usize>,
}

/// The transmit side of one M2PA link: MSUs are numbered and sent by the link's
/// own task, so every sender hands them over here.
pub struct LinkPort {
    /// The link's configuration.
    pub settings: LinkSettings,
    tx: mpsc::Sender<Vec<u8>>,
    commands: mpsc::UnboundedSender<LinkCommand>,
    /// Held by the task that currently serves the link.
    pub(super) rx: tokio::sync::Mutex<LinkQueues>,
    /// Bumped when a new association takes the link over, and when the task
    /// of an association hands the link back.
    pub(super) generation: watch::Sender<u64>,
    /// Level 2 is in service (aligned), whether or not the link is available.
    aligned: AtomicBool,
    /// Level 3 routes traffic to the link: it carries, or buffers for a
    /// changeover or changeback that is running.
    routable: AtomicBool,
}

impl LinkPort {
    fn new(settings: LinkSettings) -> Self {
        let (tx, rx) = mpsc::channel(settings.tx_queue.max(1));
        let (commands, command_rx) = mpsc::unbounded_channel();
        let traffic = LinkTraffic::new(settings.tx_queue);
        Self {
            settings,
            tx,
            commands,
            rx: tokio::sync::Mutex::new(LinkQueues {
                msus: rx,
                commands: command_rx,
                traffic,
            }),
            generation: watch::channel(0).0,
            aligned: AtomicBool::new(false),
            routable: AtomicBool::new(false),
        }
    }

    /// Tell the task that serves the link what level 3 wants of it.
    pub(crate) fn command(&self, command: LinkCommand) {
        // The receiver lives as long as the port: this cannot fail.
        let _ = self.commands.send(command);
    }

    /// Whether level 3 routes traffic to the link.
    pub fn is_routable(&self) -> bool {
        self.routable.load(Ordering::Relaxed)
    }

    pub(crate) fn set_routable(&self, on: bool) {
        self.routable.store(on, Ordering::Relaxed);
    }

    /// Hand an MSU (SIO and SIF) to the link for transmission. `false`, counted,
    /// when the link's transmit queue is full (transmit congestion, Q.704 3.8).
    pub fn offer(&self, msu: Vec<u8>) -> bool {
        match self.tx.try_send(msu) {
            Ok(()) => true,
            Err(_) => {
                metrics::m2pa_discard(Discard::TxCongestion, 1);
                false
            }
        }
    }

    /// Record whether level 2 is in service, for the link state gauge.
    /// Returns whether that changed.
    pub(super) fn set_aligned(&self, on: bool) -> bool {
        self.aligned.swap(on, Ordering::Relaxed) != on
    }

    fn is_aligned(&self) -> bool {
        self.aligned.load(Ordering::Relaxed)
    }
}

/// One SCTP association's live slot. The sender is set once the association is
/// established (client connect / server accept); the `active` flag tracks the
/// adaptation state (M3UA ASP-Active / M2PA in-service).
pub struct AssocSlot {
    /// The association id (config `associations[].id`).
    pub id: String,
    /// The adaptation layer carried.
    pub adaptation: Adaptation,
    /// The live association handle, once established.
    sender: RwLock<Option<Arc<SctpAssociation>>>,
    /// Whether the adaptation layer is carrying traffic (ASP-Active / in-service).
    active: AtomicBool,
    /// For an m2pa association: the link it is.
    link: Option<LinkPort>,
}

impl AssocSlot {
    fn new(id: String, adaptation: Adaptation, link: Option<LinkPort>) -> Self {
        Self {
            id,
            adaptation,
            sender: RwLock::new(None),
            active: AtomicBool::new(false),
            link,
        }
    }

    /// The M2PA link this association is, if it is one.
    pub fn link(&self) -> Option<&LinkPort> {
        self.link.as_ref()
    }

    /// Install the live association handle (on connect / accept).
    pub fn set_sender(&self, assoc: Arc<SctpAssociation>) {
        *self.sender.write().unwrap_or_else(|e| e.into_inner()) = Some(assoc);
    }

    /// Drop the live association handle (on disconnect).
    pub fn clear_sender(&self) {
        *self.sender.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The live association handle, if established.
    pub fn sender(&self) -> Option<Arc<SctpAssociation>> {
        self.sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Mark the adaptation active / inactive.
    pub fn set_active(&self, on: bool) {
        self.active.store(on, Ordering::Relaxed);
    }

    /// Whether the adaptation is active *and* a live sender is present.
    pub fn is_carrying(&self) -> bool {
        self.active.load(Ordering::Relaxed) && self.sender().is_some()
    }
}

/// A compiled Application Server: its traffic mode, routing context, and the
/// ordered association ids of its ASPs.
#[derive(Debug)]
struct AsEntry {
    name: String,
    traffic_mode: TrafficMode,
    routing_context: u32,
    asps: Vec<String>,
    /// Whether it was in service at the last recompute.
    up: AtomicBool,
}

/// A compiled linkset: its links in configuration order.
struct LinksetEntry {
    name: String,
    links: Vec<Arc<AssocSlot>>,
    /// How many ways the selection codes are split between linksets before
    /// one of this linkset's links is chosen (see [`Registry::select_link`]).
    width: usize,
}

/// The controlled rerouting buffers: destination point code to what is held.
type Held = BTreeMap<u32, VecDeque<Msu>>;

/// A chosen egress: the live association and the routing context to stamp on the
/// M3UA/SUA DATA (present only for an AS; `None` for an M2PA linkset).
#[derive(Clone)]
pub struct Selected {
    /// The egress association handle.
    pub assoc: Arc<SctpAssociation>,
    /// The slot of that association. An M2PA egress sends through its
    /// [`AssocSlot::link`], not on the association directly.
    pub slot: Arc<AssocSlot>,
    /// The AS routing context (M3UA / SUA), if this egress is an AS.
    pub routing_context: Option<u32>,
    /// The egress association's adaptation, so the forwarder frames the MSU for
    /// the right transport (M3UA DATA vs SUA CLDT vs M2PA User Data).
    pub adaptation: Adaptation,
}

/// The shared transport registry, compiled from one tenant's config.
pub struct Registry {
    tenant: TenantId,
    variant: Variant,
    assocs: HashMap<String, Arc<AssocSlot>>,
    application_servers: Vec<AsEntry>,
    linksets: Vec<LinksetEntry>,
    /// The links by their number in signalling network management.
    links: Vec<Arc<AssocSlot>>,
    /// Where signalling network management takes its inputs, once it runs.
    management: OnceLock<mpsc::UnboundedSender<Input>>,
    /// The same for messages that could not be transferred. Bounded: under a
    /// flood of them a hint that is dropped changes nothing, T8 lets one
    /// answer through per destination anyway.
    unroutable: OnceLock<mpsc::Sender<Input>>,
    /// This node's MTP restart is running (Q.704 9.6.6).
    restarting: AtomicBool,
    /// How many destinations are held for controlled rerouting.
    holding: AtomicUsize,
    held: Mutex<Held>,
    /// Messages held per destination before further ones are discarded.
    rerouting_buffer: usize,
    changes: broadcast::Sender<DestinationChange>,
    /// One recompute at a time: each reads the links and writes the route
    /// state, and the one that read last has to be the one that writes last.
    recomputing: Mutex<()>,
}

impl Registry {
    /// Compile the registry for a tenant of a [`Config`]. Errors if the tenant
    /// is unknown.
    pub fn build(config: &Config, tenant_id: &str) -> Option<Self> {
        let tenant = config.tenant(tenant_id)?;
        let own_pc = tenant
            .resolved_point_code()
            .map(|pc| pc.value())
            .unwrap_or(tenant.point_code.0);
        let topology = Topology::build(tenant, &config.associations);
        let assocs: HashMap<String, Arc<AssocSlot>> = config
            .associations
            .iter()
            .map(|a| {
                let link = (a.adaptation == Adaptation::M2pa).then(|| {
                    // The linkset the link is in gives it its link code and
                    // its test; a link in no linkset is code 0, untested.
                    let place = tenant.linksets.iter().find_map(|ls| {
                        ls.links
                            .iter()
                            .position(|l| l.assoc == a.id)
                            .map(|index| (ls, index))
                    });
                    let adjacent_pc = a.adjacent_pc.map(|pc| pc.0);
                    let test = place.and_then(|(ls, _)| {
                        let pattern = ls.link_test.pattern_octets()?;
                        (ls.link_test.enabled && adjacent_pc.is_some()).then(|| LinkTestSettings {
                            t1: Duration::from_millis(ls.link_test.t1_ms),
                            t2: Duration::from_millis(ls.link_test.t2_ms),
                            pattern,
                        })
                    });
                    let m2pa = a.m2pa.clone().unwrap_or_default();
                    LinkPort::new(LinkSettings {
                        timers: link_timers(&m2pa),
                        proving: match m2pa.proving {
                            ProvingMode::Normal => Proving::Normal,
                            ProvingMode::Emergency => Proving::Emergency,
                        },
                        tx_queue: m2pa.tx_queue,
                        restart: Duration::from_millis(m2pa.restart_ms),
                        test,
                        own_pc,
                        adjacent_pc,
                        ni: tenant.network_indicator.bits(),
                        slc: place.map_or(0, |(ls, index)| ls.slc_of(index)),
                        index: topology.links.iter().position(|l| l.name == a.id),
                    })
                });
                (
                    a.id.clone(),
                    Arc::new(AssocSlot::new(a.id.clone(), a.adaptation, link)),
                )
            })
            .collect();
        let application_servers = tenant
            .application_servers
            .iter()
            .map(|a| AsEntry {
                name: a.name.clone(),
                traffic_mode: a.traffic_mode,
                routing_context: a.routing_context,
                asps: a.asps.clone(),
                up: AtomicBool::new(false),
            })
            .collect();
        let resolver = RouteResolver::build(tenant, &config.associations);
        let linksets = tenant
            .linksets
            .iter()
            .map(|l| LinksetEntry {
                name: l.name.clone(),
                links: l
                    .links
                    .iter()
                    .filter_map(|k| assocs.get(&k.assoc).cloned())
                    .collect(),
                width: resolver.share_width(&Destination::Linkset(l.name.clone())),
            })
            .collect();
        let links = topology
            .links
            .iter()
            .filter_map(|l| assocs.get(&l.name).cloned())
            .collect();
        Some(Self {
            tenant: tenant_id.to_string(),
            variant: tenant.variant,
            assocs,
            application_servers,
            linksets,
            links,
            management: OnceLock::new(),
            unroutable: OnceLock::new(),
            restarting: AtomicBool::new(false),
            holding: AtomicUsize::new(0),
            held: Mutex::new(Held::new()),
            rerouting_buffer: tenant.mtp3.rerouting_buffer,
            changes: broadcast::channel(256).0,
            recomputing: Mutex::new(()),
        })
    }

    // ── Signalling network management ────────────────────────────────────────

    /// Where signalling network management of this domain takes its inputs.
    /// Set once, when its task starts.
    pub(crate) fn attach_management(
        &self,
        inputs: mpsc::UnboundedSender<Input>,
        unroutable: mpsc::Sender<Input>,
    ) {
        let _ = self.management.set(inputs);
        let _ = self.unroutable.set(unroutable);
    }

    /// Report an event to signalling network management. A no-op while none
    /// runs (a registry built without a transport).
    pub(crate) fn manage(&self, input: Input) {
        if let Some(tx) = self.management.get() {
            let _ = tx.send(input);
        }
    }

    /// A message for `dpc` that arrived on `inbound_assoc` could not be
    /// transferred: the response method of Q.704 13.2.2 iii) answers it when
    /// it came from a link.
    pub(crate) fn unroutable(&self, dpc: u32, inbound_assoc: &str) {
        let Some(link) = self
            .assocs
            .get(inbound_assoc)
            .and_then(|slot| slot.link())
            .and_then(|port| port.settings.index)
        else {
            return;
        };
        if let Some(tx) = self.unroutable.get() {
            let _ = tx.try_send(Input::Unroutable { dpc, link });
        }
    }

    /// The link with this number in signalling network management.
    pub(crate) fn link(&self, index: usize) -> Option<&Arc<AssocSlot>> {
        self.links.get(index)
    }

    /// The links of the linkset with this number, in configuration order.
    pub(crate) fn linkset_links(&self, index: usize) -> &[Arc<AssocSlot>] {
        self.linksets.get(index).map_or(&[], |l| l.links.as_slice())
    }

    /// The name of the linkset with this number.
    pub(crate) fn linkset_name(&self, index: usize) -> Option<&str> {
        self.linksets.get(index).map(|l| l.name.as_str())
    }

    /// Whether this node's MTP restart is running: traffic from the linksets
    /// is discarded until it ends (Q.704 9.6.6).
    pub fn is_restarting(&self) -> bool {
        self.restarting.load(Ordering::Relaxed)
    }

    pub(crate) fn set_restarting(&self, on: bool) {
        self.restarting.store(on, Ordering::Relaxed);
        metrics::set_mtp3_restarting(on);
    }

    /// Subscribe to the destinations that become accessible or inaccessible
    /// through this node. Every such change is sent here, once, by signalling
    /// route management.
    pub fn destination_changes(&self) -> broadcast::Receiver<DestinationChange> {
        self.changes.subscribe()
    }

    pub(crate) fn announce(&self, change: DestinationChange) {
        // Nobody listening is not an error.
        let _ = self.changes.send(change);
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start buffering the traffic of a destination (the controlled rerouting
    /// buffer of Q.704 8.2.1 a).
    pub(crate) fn hold_destination(&self, dpc: u32) {
        let mut held = self.held();
        if held.insert(dpc, VecDeque::new()).is_none() {
            self.holding.fetch_add(1, Ordering::Release);
        }
    }

    /// Buffer `msu` if its destination is held. `false` when it is not, and
    /// the message is to be sent now. The common case is one atomic load.
    pub(crate) fn hold_if_rerouting(&self, msu: &Msu) -> bool {
        if self.holding.load(Ordering::Acquire) == 0 {
            return false;
        }
        let mut held = self.held();
        let Some(buffer) = held.get_mut(&msu.dpc) else {
            return false;
        };
        if buffer.len() >= self.rerouting_buffer {
            drop(held);
            metrics::mtp3_discard(metrics::Mtp3Discard::BufferFull, 1);
            eprintln!(
                "siphon-sigtran: controlled rerouting buffer for dpc {} is full, message dropped",
                msu.dpc
            );
        } else {
            buffer.push_back(msu.clone());
        }
        true
    }

    /// Take what is buffered for a destination. `None` once the buffer was
    /// found empty, which also ends the buffering: under the same lock, so a
    /// message is either in a batch returned here or sent after the last one.
    pub(crate) fn release_destination(&self, dpc: u32) -> Option<VecDeque<Msu>> {
        let mut held = self.held();
        let buffer = held.get_mut(&dpc)?;
        if buffer.is_empty() {
            held.remove(&dpc);
            self.holding.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(std::mem::take(buffer))
    }

    /// The tenant id this registry serves.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The tenant's SS7 variant (for building point codes from raw MSU values).
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// The slot for an association id.
    pub fn slot(&self, id: &str) -> Option<&Arc<AssocSlot>> {
        self.assocs.get(id)
    }

    /// The routing context + traffic mode of the AS an m3ua ASP association
    /// belongs to (for the ASP-ACTIVE it should send). `None` if the association
    /// is not an ASP of any AS.
    pub fn as_membership(&self, assoc_id: &str) -> Option<(u32, TrafficMode)> {
        self.application_servers
            .iter()
            .find(|a| a.asps.iter().any(|x| x == assoc_id))
            .map(|a| (a.routing_context, a.traffic_mode))
    }

    /// The egress [`Destination`] an association *belongs to*: the AS it is an
    /// ASP of, or the linkset it is a link of. This is the destination an MSU
    /// arriving on that association came in over, which the transfer path's
    /// route-reflect guard compares against the resolved egress. `None` for an
    /// association that carries neither (e.g. a pure ingress SG association).
    pub fn inbound_destination(&self, assoc_id: &str) -> Option<Destination> {
        if let Some(a) = self
            .application_servers
            .iter()
            .find(|a| a.asps.iter().any(|x| x == assoc_id))
        {
            return Some(Destination::ApplicationServer(a.name.clone()));
        }
        self.linksets
            .iter()
            .find(|l| l.links.iter().any(|x| x.id == assoc_id))
            .map(|l| Destination::Linkset(l.name.clone()))
    }

    /// The link with signalling link code `slc` in the linkset that the link
    /// `assoc_id` belongs to (which may be `assoc_id` itself).
    pub fn link_by_slc(&self, assoc_id: &str, slc: u8) -> Option<&Arc<AssocSlot>> {
        let linkset = self
            .linksets
            .iter()
            .find(|l| l.links.iter().any(|x| x.id == assoc_id))?;
        linkset
            .links
            .iter()
            .find(|slot| slot.link().is_some_and(|l| l.settings.slc == slc))
    }

    /// Recompute AS + linkset availability from the current slot states, push it
    /// into the router's route state, and refresh the Prometheus state gauges.
    pub fn recompute(&self, router: &Router) {
        let _one_at_a_time = self.recomputing.lock().unwrap_or_else(|e| e.into_inner());
        // Per-association transport state, plus the M2PA link-liveness gauge.
        for slot in self.assocs.values() {
            let assoc_state = if slot.is_carrying() {
                2
            } else if slot.sender().is_some() {
                1
            } else {
                0
            };
            metrics::set_association_state(
                &slot.id,
                adaptation_label(slot.adaptation),
                assoc_state,
            );
            if let Some(link) = slot.link() {
                let ls = if slot.is_carrying() {
                    metrics::M2paLinkState::InService
                } else if link.is_aligned() && slot.sender().is_some() {
                    metrics::M2paLinkState::Aligned
                } else {
                    metrics::M2paLinkState::Failed
                };
                metrics::set_m2pa_link_state(&slot.id, ls);
                metrics::set_mtp3_link_traffic(&slot.id, link.is_routable());
            }
        }

        for (index, a) in self.application_servers.iter().enumerate() {
            let up = a
                .asps
                .iter()
                .filter_map(|id| self.assocs.get(id))
                .any(|s| s.is_carrying());
            // Signalling route management follows the application servers
            // too: a destination behind one is announced like any other.
            if a.up.swap(up, Ordering::Relaxed) != up {
                self.manage(Input::Server { index, up });
            }
            for asp in &a.asps {
                let active = self.assocs.get(asp).is_some_and(|s| s.is_carrying());
                metrics::set_asp_state(asp, &a.name, active);
            }
            if up {
                router.note_as_up(&self.tenant, &a.name);
            } else {
                router.note_as_down(&self.tenant, &a.name);
            }
        }
        for l in &self.linksets {
            let active_links = l.links.iter().filter(|s| s.is_carrying()).count();
            // A linkset is a route while level 3 routes traffic to one of its
            // links: one that carries, or one whose changeover or changeback
            // buffers what it is handed.
            let up = l
                .links
                .iter()
                .any(|s| s.link().is_some_and(|port| port.is_routable()));
            metrics::set_linkset(&l.name, up, active_links);
            if up {
                router.note_linkset_up(&self.tenant, &l.name);
            } else {
                router.note_linkset_down(&self.tenant, &l.name);
            }
        }

        // The route-availability gauge follows from the AS / linkset state above.
        router.refresh_route_metrics(&self.tenant);
    }

    /// Choose the egress association(s) for a resolved destination and SLS. An
    /// AS honours its traffic mode across its active ASPs; a linkset spreads by
    /// SLS across its in-service links. Empty if nothing is carrying.
    pub fn select(&self, dest: &Destination, sls: u8) -> Vec<Selected> {
        match dest {
            Destination::ApplicationServer(name) => {
                let Some(a) = self.application_servers.iter().find(|a| a.name == *name) else {
                    return Vec::new();
                };
                let slots: Vec<&Arc<AssocSlot>> =
                    a.asps.iter().filter_map(|id| self.assocs.get(id)).collect();
                let active: Vec<bool> = slots.iter().map(|s| s.is_carrying()).collect();
                choose(a.traffic_mode, &active, sls)
                    .into_iter()
                    .filter_map(|i| {
                        slots[i].sender().map(|assoc| Selected {
                            assoc,
                            slot: slots[i].clone(),
                            routing_context: Some(a.routing_context),
                            adaptation: slots[i].adaptation,
                        })
                    })
                    .collect()
            }
            Destination::Linkset(name) => self
                .select_link(name, sls)
                .and_then(|slot| {
                    slot.sender().map(|assoc| Selected {
                        assoc,
                        slot: slot.clone(),
                        routing_context: None,
                        adaptation: slot.adaptation,
                    })
                })
                .into_iter()
                .collect(),
        }
    }

    /// The link of a linkset that carries selection code `sls` (ITU-T Q.704
    /// 2.3.2 a). Each code has a normal link, fixed by the configuration; while
    /// level 3 does not route to that one, the code goes to one of the links it
    /// does route to, and the codes of the other links stay where they are.
    ///
    /// A linkset that shares destinations with others of equal priority
    /// chooses its link by the bits of the code that the choice of the linkset
    /// left over, as Figure 5/Q.704 has it: with two linksets of two links,
    /// the lowest bit picks the linkset and the next one the link. The label
    /// itself is not changed.
    pub fn select_link(&self, linkset: &str, sls: u8) -> Option<&Arc<AssocSlot>> {
        self.select_link_avoiding(linkset, sls, None)
    }

    /// [`select_link`](Self::select_link) without the link `avoid`: where the
    /// traffic of that link goes when it is diverted (Q.704 4.3.2).
    pub(crate) fn select_link_avoiding(
        &self,
        linkset: &str,
        sls: u8,
        avoid: Option<&str>,
    ) -> Option<&Arc<AssocSlot>> {
        let l = self.linksets.iter().find(|l| l.name == linkset)?;
        if l.links.is_empty() {
            return None;
        }
        let key = usize::from(sls) / l.width.max(1);
        let routable = |slot: &&Arc<AssocSlot>| {
            avoid != Some(slot.id.as_str()) && slot.link().is_some_and(|port| port.is_routable())
        };
        let normal = &l.links[key % l.links.len()];
        if routable(&normal) {
            return Some(normal);
        }
        let count = l.links.iter().filter(routable).count();
        if count == 0 {
            return None;
        }
        l.links.iter().filter(routable).nth(key % count)
    }
}

/// The level-2 timers of a link from its `m2pa:` block.
fn link_timers(m2pa: &M2paLink) -> LinkTimers {
    LinkTimers {
        t1: Duration::from_millis(m2pa.t1_ms),
        t2: Duration::from_millis(m2pa.t2_ms),
        t3: Duration::from_millis(m2pa.t3_ms),
        t4_normal: Duration::from_millis(m2pa.t4n_ms),
        t4_emergency: Duration::from_millis(m2pa.t4e_ms),
        t6: Duration::from_millis(m2pa.t6_ms),
        t7: Duration::from_millis(m2pa.t7_ms),
        proving_interval: Duration::from_millis(m2pa.proving_interval_ms),
    }
}

/// The metric label for an adaptation layer.
fn adaptation_label(a: Adaptation) -> &'static str {
    match a {
        Adaptation::M3ua => "m3ua",
        Adaptation::M2pa => "m2pa",
        Adaptation::Sua => "sua",
    }
}

/// Pure egress-index selection. Given which candidates are active (in config
/// order) and the SLS, return the indices to send on:
/// * `Override`  → the first active candidate (the primary), the rest stand by.
/// * `Loadshare` → one active candidate keyed by SLS.
/// * `Broadcast` → every active candidate.
fn choose(mode: TrafficMode, active: &[bool], sls: u8) -> Vec<usize> {
    let up: Vec<usize> = active
        .iter()
        .enumerate()
        .filter(|(_, &a)| a)
        .map(|(i, _)| i)
        .collect();
    if up.is_empty() {
        return Vec::new();
    }
    match mode {
        TrafficMode::Override => vec![up[0]],
        TrafficMode::Loadshare => vec![up[(sls as usize) % up.len()]],
        TrafficMode::Broadcast => up,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_picks_first_active() {
        // Primary (idx 0) down → the next active (idx 1) becomes the primary.
        assert_eq!(choose(TrafficMode::Override, &[true, true], 0), vec![0]);
        assert_eq!(choose(TrafficMode::Override, &[false, true], 9), vec![1]);
        assert!(choose(TrafficMode::Override, &[false, false], 0).is_empty());
    }

    #[test]
    fn loadshare_keys_on_sls() {
        // Two active links: even SLS → 0, odd SLS → 1.
        assert_eq!(choose(TrafficMode::Loadshare, &[true, true], 0), vec![0]);
        assert_eq!(choose(TrafficMode::Loadshare, &[true, true], 1), vec![1]);
        assert_eq!(choose(TrafficMode::Loadshare, &[true, true], 2), vec![0]);
        // One active: everything lands on it.
        assert_eq!(choose(TrafficMode::Loadshare, &[false, true], 5), vec![1]);
    }

    #[test]
    fn broadcast_hits_all_active() {
        assert_eq!(
            choose(TrafficMode::Broadcast, &[true, false, true], 0),
            vec![0, 2]
        );
    }

    const COMBINED: &str = r#"
node: { point_code: 1000, variant: ITU }
mtp3: { rerouting_buffer: 2 }
associations:
  - { id: a-0, adaptation: m2pa, role: server, addrs: [192.0.2.1], port: 3565, adjacent_pc: 3000 }
  - { id: a-1, adaptation: m2pa, role: server, addrs: [192.0.2.1], port: 3566, adjacent_pc: 3000 }
  - { id: b-0, adaptation: m2pa, role: server, addrs: [192.0.2.2], port: 3565, adjacent_pc: 4000 }
  - { id: b-1, adaptation: m2pa, role: server, addrs: [192.0.2.2], port: 3566, adjacent_pc: 4000 }
  - { id: c-0, adaptation: m2pa, role: server, addrs: [192.0.2.3], port: 3565, adjacent_pc: 5000 }
  - { id: c-1, adaptation: m2pa, role: server, addrs: [192.0.2.3], port: 3566, adjacent_pc: 5000 }
  - { id: gw-0, adaptation: m3ua, role: server, addrs: [192.0.2.4], port: 2905 }
application_servers:
  - { name: gateway, traffic_mode: override, routing_context: 1, asps: [gw-0] }
linksets:
  - { name: a, links: [{assoc: a-0}, {assoc: a-1}] }
  - { name: b, links: [{assoc: b-0}, {assoc: b-1}] }
  - { name: c, links: [{assoc: c-0}, {assoc: c-1}] }
mtp3_routes:
  - { dpc: 2000, linkset: a, priority: 1 }
  - { dpc: 2200, linkset: b, priority: 1 }
  - { dpc: 2200, linkset: c, priority: 1 }
"#;

    fn registry() -> Registry {
        let cfg = Config::parse(COMBINED).expect("config parses");
        let registry = Registry::build(&cfg, "default").expect("the default tenant");
        for slot in &registry.links {
            slot.link().unwrap().set_routable(true);
        }
        registry
    }

    fn chosen(registry: &Registry, linkset: &str, sls: u8) -> String {
        registry
            .select_link(linkset, sls)
            .map(|slot| slot.id.clone())
            .unwrap_or_default()
    }

    #[test]
    fn the_links_of_a_linkset_share_by_selection_code() {
        // Q.704 2.3.2 a), Figure 4: "SLS = XXX0" on one link, "XXX1" on the
        // other.
        let r = registry();
        for sls in 0..16u8 {
            let expected = if sls % 2 == 0 { "a-0" } else { "a-1" };
            assert_eq!(chosen(&r, "a", sls), expected, "selection code {sls}");
        }
    }

    #[test]
    fn a_combined_linkset_chooses_its_links_by_the_bits_left_over() {
        // Figure 5/Q.704: the lowest bit picks the linkset (the resolver does
        // that), so the links are picked by the next one. Otherwise each
        // linkset would only ever see one value of the bit it uses, and one
        // of its links would carry nothing.
        let r = registry();
        for sls in 0..16u8 {
            let expected = if (sls >> 1) % 2 == 0 { "b-0" } else { "b-1" };
            assert_eq!(chosen(&r, "b", sls), expected, "selection code {sls}");
        }
        // Even codes are linkset b's, odd ones linkset c's: both links of
        // each get half of them.
        let on = |linkset: &str, parity: u8, link: &str| {
            (0..16u8)
                .filter(|sls| sls % 2 == parity && chosen(&r, linkset, *sls) == link)
                .count()
        };
        assert_eq!((on("b", 0, "b-0"), on("b", 0, "b-1")), (4, 4));
        assert_eq!((on("c", 1, "c-0"), on("c", 1, "c-1")), (4, 4));
    }

    #[test]
    fn a_link_level_3_does_not_route_to_is_passed_by() {
        let r = registry();
        r.slot("a-0").unwrap().link().unwrap().set_routable(false);
        // Its codes move to the other link; that link's own stay.
        for sls in 0..16u8 {
            assert_eq!(chosen(&r, "a", sls), "a-1");
        }
        r.slot("a-1").unwrap().link().unwrap().set_routable(false);
        assert!(r.select_link("a", 0).is_none());
        assert!(r.select(&Destination::Linkset("a".into()), 0).is_empty());
        assert!(r.select_link("no-such-linkset", 0).is_none());
    }

    #[test]
    fn links_are_numbered_as_signalling_network_management_numbers_them() {
        let r = registry();
        let topology = Topology::build(
            Config::parse(COMBINED).unwrap().default_tenant().unwrap(),
            &Config::parse(COMBINED).unwrap().associations,
        );
        for (index, link) in topology.links.iter().enumerate() {
            let slot = r.link(index).expect("a slot per link");
            assert_eq!(slot.id, link.name);
            assert_eq!(slot.link().unwrap().settings.index, Some(index));
            assert_eq!(slot.link().unwrap().settings.slc, link.slc);
        }
        assert_eq!(r.linkset_name(1), Some("b"));
        assert_eq!(r.linkset_links(2).len(), 2);
        assert!(r.linkset_links(9).is_empty());
    }

    fn msu(dpc: u32, tag: u8) -> Msu {
        Msu {
            opc: 3000,
            dpc,
            si: 8,
            ni: 2,
            mp: 0,
            sls: 0,
            payload: vec![tag],
        }
    }

    #[test]
    fn a_held_destination_buffers_in_order_and_ends_when_found_empty() {
        let r = registry();
        // Not held: sent now.
        assert!(!r.hold_if_rerouting(&msu(2000, 1)));
        r.hold_destination(2000);
        assert!(r.hold_if_rerouting(&msu(2000, 1)));
        assert!(r.hold_if_rerouting(&msu(2000, 2)));
        // Another destination is not concerned.
        assert!(!r.hold_if_rerouting(&msu(2200, 9)));
        // The buffer is bounded (`rerouting_buffer: 2`): the third is dropped
        // and counted, and still not sent out of turn.
        let full = metrics::mtp3_discards(metrics::Mtp3Discard::BufferFull);
        assert!(r.hold_if_rerouting(&msu(2000, 3)));
        assert!(metrics::mtp3_discards(metrics::Mtp3Discard::BufferFull) > full);

        let batch = r.release_destination(2000).expect("what was held");
        let tags: Vec<u8> = batch.iter().map(|m| m.payload[0]).collect();
        assert_eq!(tags, [1, 2]);
        // Still held while the batch goes out: a message that arrives now
        // waits for the next round.
        assert!(r.hold_if_rerouting(&msu(2000, 4)));
        assert_eq!(r.release_destination(2000).map(|b| b.len()), Some(1));
        assert!(r.release_destination(2000).is_none(), "found empty: over");
        assert!(!r.hold_if_rerouting(&msu(2000, 5)));
        assert!(r.release_destination(2000).is_none());
    }

    #[test]
    fn only_a_message_from_a_link_is_reported_as_not_transferred() {
        let r = registry();
        let (inputs, mut input_rx) = mpsc::unbounded_channel();
        let (hints, mut hint_rx) = mpsc::channel(4);
        r.attach_management(inputs, hints);
        r.unroutable(2999, "b-1");
        assert_eq!(
            hint_rx.try_recv().ok(),
            Some(Input::Unroutable { dpc: 2999, link: 3 })
        );
        // From an application server, or from nowhere: not level 3's.
        r.unroutable(2999, "gw-0");
        r.unroutable(2999, "no-such-association");
        assert!(hint_rx.try_recv().is_err());
        r.manage(Input::LinkUp { link: 0 });
        assert_eq!(input_rx.try_recv().ok(), Some(Input::LinkUp { link: 0 }));
    }

    #[test]
    fn changes_reach_every_subscriber_and_the_restart_flag_is_read_back() {
        let r = registry();
        let mut first = r.destination_changes();
        let mut second = r.destination_changes();
        r.announce(DestinationChange::Inaccessible { dpc: 2000 });
        for rx in [&mut first, &mut second] {
            assert_eq!(
                rx.try_recv().ok(),
                Some(DestinationChange::Inaccessible { dpc: 2000 })
            );
        }
        assert!(!r.is_restarting());
        r.set_restarting(true);
        assert!(r.is_restarting());
        r.set_restarting(false);
    }
}
