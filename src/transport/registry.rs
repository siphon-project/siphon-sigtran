//! The transport's shared runtime state: one slot per SCTP association, plus the
//! Application-Server / linkset egress maps compiled from the config.
//!
//! Association tasks update their slot (sender + adaptation-active flag) as the
//! handshake progresses; [`Registry::recompute`] then folds that into the
//! router's route state (an AS is up while ≥ 1 ASP is active, a linkset while
//! ≥ 1 link is in service). [`Registry::select`] answers the egress question:
//! given a resolved [`Destination`], which association(s) carry the MSU, honouring
//! the AS traffic mode and the SLS.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_sctp::SctpAssociation;
use mtp3::Variant;
use tokio::sync::{mpsc, watch};

use super::m2pa::link::{Discard, LinkTimers, Proving};
use crate::config::{Adaptation, Config, M2paLink, ProvingMode, TenantId, TrafficMode};
use crate::metrics;
use crate::mtp3::route::Destination;
use crate::routing::Router;

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
}

/// The transmit side of one M2PA link: MSUs are numbered and sent by the link's
/// own task, so every sender hands them over here.
pub struct LinkPort {
    /// The link's configuration.
    pub settings: LinkSettings,
    tx: mpsc::Sender<Vec<u8>>,
    /// Held by the task that currently runs the link.
    pub(super) rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Bumped when a new association takes the link over.
    pub(super) generation: watch::Sender<u64>,
    /// Level 2 is in service (aligned), whether or not the link is available.
    aligned: AtomicBool,
}

impl LinkPort {
    fn new(settings: LinkSettings) -> Self {
        let (tx, rx) = mpsc::channel(settings.tx_queue.max(1));
        Self {
            settings,
            tx,
            rx: tokio::sync::Mutex::new(rx),
            generation: watch::channel(0).0,
            aligned: AtomicBool::new(false),
        }
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
    pub(super) fn set_aligned(&self, on: bool) {
        self.aligned.store(on, Ordering::Relaxed);
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
#[derive(Debug, Clone)]
struct AsEntry {
    name: String,
    traffic_mode: TrafficMode,
    routing_context: u32,
    asps: Vec<String>,
}

/// A compiled linkset: its ordered link association ids.
#[derive(Debug, Clone)]
struct LinksetEntry {
    name: String,
    links: Vec<String>,
}

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
        let assocs = config
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
            })
            .collect();
        let linksets = tenant
            .linksets
            .iter()
            .map(|l| LinksetEntry {
                name: l.name.clone(),
                links: l.links.iter().map(|k| k.assoc.clone()).collect(),
            })
            .collect();
        Some(Self {
            tenant: tenant_id.to_string(),
            variant: tenant.variant,
            assocs,
            application_servers,
            linksets,
        })
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
            .find(|l| l.links.iter().any(|x| x == assoc_id))
            .map(|l| Destination::Linkset(l.name.clone()))
    }

    /// The link with signalling link code `slc` in the linkset that the link
    /// `assoc_id` belongs to (which may be `assoc_id` itself).
    pub fn link_by_slc(&self, assoc_id: &str, slc: u8) -> Option<&Arc<AssocSlot>> {
        let linkset = self
            .linksets
            .iter()
            .find(|l| l.links.iter().any(|x| x == assoc_id))?;
        linkset
            .links
            .iter()
            .filter_map(|id| self.assocs.get(id))
            .find(|slot| slot.link().is_some_and(|l| l.settings.slc == slc))
    }

    /// Recompute AS + linkset availability from the current slot states, push it
    /// into the router's route state, and refresh the Prometheus state gauges.
    pub fn recompute(&self, router: &Router) {
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
            }
        }

        for a in &self.application_servers {
            let up = a
                .asps
                .iter()
                .filter_map(|id| self.assocs.get(id))
                .any(|s| s.is_carrying());
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
            let active_links = l
                .links
                .iter()
                .filter_map(|id| self.assocs.get(id))
                .filter(|s| s.is_carrying())
                .count();
            let up = active_links > 0;
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
            Destination::Linkset(name) => {
                let Some(l) = self.linksets.iter().find(|l| l.name == *name) else {
                    return Vec::new();
                };
                let slots: Vec<&Arc<AssocSlot>> = l
                    .links
                    .iter()
                    .filter_map(|id| self.assocs.get(id))
                    .collect();
                let active: Vec<bool> = slots.iter().map(|s| s.is_carrying()).collect();
                // A linkset has no traffic mode: SLS load-spreads across the
                // in-service links (Q.704 signalling-link selection).
                choose(TrafficMode::Loadshare, &active, sls)
                    .into_iter()
                    .filter_map(|i| {
                        slots[i].sender().map(|assoc| Selected {
                            assoc,
                            slot: slots[i].clone(),
                            routing_context: None,
                            adaptation: slots[i].adaptation,
                        })
                    })
                    .collect()
            }
        }
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
}
