//! The MTP3 route resolver: DPC + tenant → best available linkset.
//!
//! # Route sources (in resolution order)
//!
//! 1. **Implicit adjacent routes.** An m2pa association's `adjacent_pc` is a
//!    full route to that point code via the linkset that carries the link, no
//!    `mtp3_routes` entry needed. Adjacent routes are treated as priority 0
//!    (the strongest primary): the peer is one hop away.
//! 2. **Explicit `mtp3_routes`.** `{ dpc, linkset, priority }`, **1 = primary**,
//!    higher numbers are alternates.
//!
//! # Availability
//!
//! A route is eligible only while (a) its linkset is *available* (M3UA ASPAC /
//! M2PA in-service) **and** (b) the DPC is not prohibited (MTP3-MG TFP / M3UA
//! DUNA). Availability is an in-memory [`RouteState`] mutated by
//! [`RouteState::apply_event`] (Pause → prohibited, Resume → allowed, Status →
//! congestion) and [`RouteState::set_linkset_up`]. [`RouteResolver::resolve`]
//! walks the candidate routes lowest-priority-first and returns the first
//! eligible linkset.

use std::collections::{BTreeMap, BTreeSet};

use mtp3::{Mtp3Event, Mtp3Status, PointCode, Variant};

// `RouteState` is scoped to a single tenant of a fixed variant, so a DPC's raw
// integer value is a sufficient key for the prohibited / congestion tables.
// `mtp3::Variant` intentionally isn't `Ord`, and mixing variants in one state
// never happens.

use crate::config::{Adaptation, Association, Tenant};

/// A linkset name: the routing destination the resolver returns.
pub type LinksetId = String;

/// Priority assigned to an implicit adjacent route (strongest primary).
const ADJACENT_PRIORITY: u8 = 0;

/// One candidate route to a DPC.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    linkset: LinksetId,
    priority: u8,
}

/// Mutable, in-memory availability state fed by network-management events and
/// linkset up/down. Cheap to clone; the resolver borrows it read-only.
#[derive(Debug, Clone, Default)]
pub struct RouteState {
    /// Linksets currently in service.
    linksets_up: BTreeSet<LinksetId>,
    /// DPC values currently prohibited (TFP / PAUSE).
    prohibited: BTreeSet<u32>,
    /// Congestion level per DPC value (0 = none).
    congestion: BTreeMap<u32, u8>,
}

impl RouteState {
    /// A fresh state with the given linksets brought up.
    pub fn with_linksets_up<I, S>(linksets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<LinksetId>,
    {
        let mut s = Self::default();
        for ls in linksets {
            s.linksets_up.insert(ls.into());
        }
        s
    }

    /// Bring a linkset up (M3UA AS active / M2PA in-service).
    pub fn set_linkset_up(&mut self, linkset: impl Into<LinksetId>) {
        self.linksets_up.insert(linkset.into());
    }

    /// Bring a linkset down (all links out of service).
    pub fn set_linkset_down(&mut self, linkset: &str) {
        self.linksets_up.remove(linkset);
    }

    /// Whether a linkset is currently in service.
    pub fn is_linkset_up(&self, linkset: &str) -> bool {
        self.linksets_up.contains(linkset)
    }

    /// Whether a DPC is currently prohibited.
    pub fn is_prohibited(&self, dpc: PointCode) -> bool {
        self.prohibited.contains(&dpc.value())
    }

    /// The congestion level for a DPC (0 = uncongested).
    pub fn congestion(&self, dpc: PointCode) -> u8 {
        self.congestion.get(&dpc.value()).copied().unwrap_or(0)
    }

    /// Fold an MTP3-user network-management event into the state:
    /// `Pause` → prohibit, `Resume` → allow, `Status(Congested)` → set level.
    /// `Transfer` (a delivered MSU) carries no availability change and is
    /// ignored here.
    pub fn apply_event(&mut self, event: &Mtp3Event) {
        match event {
            Mtp3Event::Pause { affected } => {
                self.prohibited.insert(affected.value());
            }
            Mtp3Event::Resume { affected } => {
                self.prohibited.remove(&affected.value());
                self.congestion.remove(&affected.value());
            }
            Mtp3Event::Status { affected, status } => match status {
                Mtp3Status::Congested { level } => {
                    self.congestion.insert(affected.value(), *level);
                }
                Mtp3Status::UserPartUnavailable { .. } => {
                    // A user-part being unavailable doesn't prohibit the PC for
                    // routing at the MTP3 layer; SCCP handles SSN status.
                }
            },
            Mtp3Event::Transfer(_) => {}
        }
    }
}

/// The compiled route table for one tenant: DPC → priority-ordered candidates.
#[derive(Debug, Clone)]
pub struct RouteResolver {
    variant: Variant,
    /// DPC value → candidates (unsorted; resolve sorts by priority).
    routes: BTreeMap<u32, Vec<Candidate>>,
}

impl RouteResolver {
    /// Build the resolver for a tenant, folding in the implicit adjacent routes
    /// from the m2pa associations referenced by the tenant's linksets.
    pub fn build(tenant: &Tenant, associations: &[Association]) -> Self {
        let variant = tenant.variant;
        let mut routes: BTreeMap<u32, Vec<Candidate>> = BTreeMap::new();

        // Map association id → the m2pa adjacent_pc it reaches (if any).
        let adj: BTreeMap<&str, u32> = associations
            .iter()
            .filter(|a| a.adaptation == Adaptation::M2pa)
            .filter_map(|a| a.adjacent_pc.map(|pc| (a.id.as_str(), pc.0)))
            .collect();

        // Implicit adjacent routes: for each linkset, any of its links whose
        // association has an adjacent_pc creates a priority-0 route to that PC
        // via the linkset.
        for ls in &tenant.linksets {
            for link in &ls.links {
                if let Some(&pc) = adj.get(link.assoc.as_str()) {
                    routes.entry(pc).or_default().push(Candidate {
                        linkset: ls.name.clone(),
                        priority: ADJACENT_PRIORITY,
                    });
                }
            }
        }

        // Explicit routes.
        for r in &tenant.mtp3_routes {
            routes.entry(r.dpc.0).or_default().push(Candidate {
                linkset: r.linkset.clone(),
                priority: r.priority,
            });
        }

        Self { variant, routes }
    }

    /// The variant these routes are keyed under.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Resolve a DPC to the best currently-available linkset, or `None` if the
    /// DPC is prohibited or every candidate route is down / has no route at all.
    pub fn resolve(&self, dpc: PointCode, state: &RouteState) -> Option<LinksetId> {
        if state.is_prohibited(dpc) {
            return None;
        }
        let mut candidates: Vec<&Candidate> = self.routes.get(&dpc.value())?.iter().collect();
        // Lowest priority number first (0 adjacent, then 1 primary, then 2…).
        candidates.sort_by_key(|c| c.priority);
        candidates
            .into_iter()
            .find(|c| state.is_linkset_up(&c.linkset))
            .map(|c| c.linkset.clone())
    }

    /// Whether we have *any* route (available or not) to a DPC.
    pub fn has_route(&self, dpc: PointCode) -> bool {
        self.routes.contains_key(&dpc.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn sample() -> (RouteResolver, RouteState, Variant) {
        let cfg = Config::parse(crate::config::tests::SAMPLE).unwrap();
        let tenant = cfg.default_tenant().unwrap();
        let resolver = RouteResolver::build(tenant, &cfg.associations);
        // Bring every linkset up to start.
        let mut state = RouteState::default();
        for ls in &tenant.linksets {
            state.set_linkset_up(&ls.name);
        }
        (resolver, state, tenant.variant)
    }

    fn pc(v: u32, variant: Variant) -> PointCode {
        PointCode::from_value(v, variant).unwrap()
    }

    #[test]
    fn implicit_adjacent_route() {
        let (r, state, var) = sample();
        // 3000 / 3001 are adjacent via the m2pa transit linkset, no mtp3_route
        // entry exists for them, yet they resolve.
        assert_eq!(r.resolve(pc(3000, var), &state).as_deref(), Some("transit"));
        assert_eq!(r.resolve(pc(3001, var), &state).as_deref(), Some("transit"));
    }

    #[test]
    fn primary_then_alternate_failover_and_restore() {
        let (r, mut state, var) = sample();
        // 2000 has priority-1 via hlr and priority-2 via transit.
        assert_eq!(r.resolve(pc(2000, var), &state).as_deref(), Some("hlr"));

        // Bring the primary linkset down → fail over to the alternate.
        state.set_linkset_down("hlr");
        assert_eq!(r.resolve(pc(2000, var), &state).as_deref(), Some("transit"));

        // Restore the primary → back to hlr.
        state.set_linkset_up("hlr");
        assert_eq!(r.resolve(pc(2000, var), &state).as_deref(), Some("hlr"));
    }

    #[test]
    fn pause_prohibits_then_resume_restores() {
        let (r, mut state, var) = sample();
        let dpc = pc(2000, var);
        assert!(r.resolve(dpc, &state).is_some());

        // MTP-PAUSE for 2000 → no route even though the linksets are up.
        state.apply_event(&Mtp3Event::Pause { affected: dpc });
        assert!(state.is_prohibited(dpc));
        assert!(r.resolve(dpc, &state).is_none());

        // MTP-RESUME → routes again.
        state.apply_event(&Mtp3Event::Resume { affected: dpc });
        assert_eq!(r.resolve(dpc, &state).as_deref(), Some("hlr"));
    }

    #[test]
    fn status_sets_congestion_level() {
        let (r, mut state, var) = sample();
        let dpc = pc(2000, var);
        state.apply_event(&Mtp3Event::Status {
            affected: dpc,
            status: Mtp3Status::Congested { level: 2 },
        });
        assert_eq!(state.congestion(dpc), 2);
        // Congestion doesn't remove the route (still deliverable).
        assert!(r.resolve(dpc, &state).is_some());
    }

    #[test]
    fn no_route_for_unknown_dpc() {
        let (r, state, var) = sample();
        assert!(r.resolve(pc(9999, var), &state).is_none());
        assert!(!r.has_route(pc(9999, var)));
    }

    #[test]
    fn primary_down_and_alternate_down_yields_none() {
        let (r, mut state, var) = sample();
        state.set_linkset_down("hlr");
        state.set_linkset_down("transit");
        assert!(r.resolve(pc(2000, var), &state).is_none());
    }
}
