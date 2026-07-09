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

use async_sctp::SctpAssociation;
use mtp3::Variant;

use crate::config::{Adaptation, Config, TenantId, TrafficMode};
use crate::mtp3::route::Destination;
use crate::routing::Router;

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
}

impl AssocSlot {
    fn new(id: String, adaptation: Adaptation) -> Self {
        Self {
            id,
            adaptation,
            sender: RwLock::new(None),
            active: AtomicBool::new(false),
        }
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
        let assocs = config
            .associations
            .iter()
            .map(|a| {
                (
                    a.id.clone(),
                    Arc::new(AssocSlot::new(a.id.clone(), a.adaptation)),
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

    /// Recompute AS + linkset availability from the current slot states, push it
    /// into the router's route state, and refresh the Prometheus state gauges.
    pub fn recompute(&self, router: &Router) {
        use crate::metrics;

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
            if slot.adaptation == Adaptation::M2pa {
                let ls = if slot.is_carrying() {
                    metrics::M2paLinkState::InService
                } else if slot.sender().is_some() {
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
                            routing_context: None,
                            adaptation: slots[i].adaptation,
                        })
                    })
                    .collect()
            }
        }
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
