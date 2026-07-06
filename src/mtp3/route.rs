//! The MTP3 route resolver: DPC + tenant → best available egress destination.
//!
//! An egress [`Destination`] is either an **M3UA Application Server** (RFC 4666)
//! or an **M2PA linkset** (RFC 4165). Both are named route targets a DPC can
//! resolve to.
//!
//! # Route sources (in resolution order)
//!
//! 1. **Implicit adjacent routes.** An m2pa association's `adjacent_pc` is a
//!    full route to that point code via the linkset that carries the link, no
//!    `mtp3_routes` entry needed. Adjacent routes are treated as priority 0
//!    (the strongest primary): the peer is one hop away.
//! 2. **Explicit `mtp3_routes`.** `{ dpc, as|linkset, priority }`, **1 = primary**,
//!    higher numbers are alternates.
//!
//! # Availability
//!
//! A route is eligible only while (a) its destination is *available* (an AS with
//! at least one ASP in the ASPAC state, or an M2PA linkset with an in-service
//! link) **and** (b) the DPC is not prohibited (MTP3-MG TFP / M3UA DUNA).
//! Availability is an in-memory [`RouteState`] mutated by
//! [`RouteState::apply_event`] (Pause → prohibited, Resume → allowed, Status →
//! congestion) and the AS / linkset up/down setters. [`RouteResolver::resolve`]
//! walks the candidate routes lowest-priority-first and returns the first
//! eligible destination.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mtp3::{Mtp3Event, Mtp3Status, PointCode, Variant};

// `RouteState` is scoped to a single tenant of a fixed variant, so a DPC's raw
// integer value is a sufficient key for the prohibited / congestion tables.
// `mtp3::Variant` intentionally isn't `Ord`, and mixing variants in one state
// never happens.

use crate::config::{Adaptation, Association, Tenant};

/// A linkset name (kept for readability where a linkset is meant specifically).
pub type LinksetId = String;

/// A resolved egress destination for a DPC: an M3UA Application Server or an
/// M2PA linkset. Both are addressed by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Destination {
    /// An M3UA Application Server (RFC 4666), by name.
    ApplicationServer(String),
    /// An M2PA linkset (RFC 4165), by name.
    Linkset(String),
}

impl Destination {
    /// The destination's name.
    pub fn name(&self) -> &str {
        match self {
            Self::ApplicationServer(n) | Self::Linkset(n) => n,
        }
    }

    /// Whether this destination is an M3UA Application Server.
    pub fn is_application_server(&self) -> bool {
        matches!(self, Self::ApplicationServer(_))
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationServer(n) => write!(f, "as:{n}"),
            Self::Linkset(n) => write!(f, "linkset:{n}"),
        }
    }
}

/// Priority assigned to an implicit adjacent route (strongest primary).
const ADJACENT_PRIORITY: u8 = 0;

/// One candidate route to a DPC.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    dest: Destination,
    priority: u8,
}

/// Mutable, in-memory availability state fed by network-management events and
/// AS / linkset up/down. Cheap to clone; the resolver borrows it read-only.
#[derive(Debug, Clone, Default)]
pub struct RouteState {
    /// Application Servers currently in service (≥ 1 ASP active).
    as_up: BTreeSet<String>,
    /// Linksets currently in service (≥ 1 link aligned).
    linksets_up: BTreeSet<LinksetId>,
    /// DPC values currently prohibited (TFP / PAUSE).
    prohibited: BTreeSet<u32>,
    /// Congestion level per DPC value (0 = none).
    congestion: BTreeMap<u32, u8>,
}

impl RouteState {
    /// A fresh state with the given linksets brought up (AS all down).
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

    /// Bring an Application Server up (≥ 1 ASP reached ASP-Active).
    pub fn set_as_up(&mut self, name: impl Into<String>) {
        self.as_up.insert(name.into());
    }

    /// Bring an Application Server down (no ASP active).
    pub fn set_as_down(&mut self, name: &str) {
        self.as_up.remove(name);
    }

    /// Whether an Application Server is currently in service.
    pub fn is_as_up(&self, name: &str) -> bool {
        self.as_up.contains(name)
    }

    /// Bring a linkset up (M2PA in-service).
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

    /// Clear every AS + linkset to down (the transport calls this at startup,
    /// then drives each destination up as its ASPs / links come into service).
    pub fn set_all_down(&mut self) {
        self.as_up.clear();
        self.linksets_up.clear();
    }

    /// Whether a resolved [`Destination`] is currently in service.
    pub fn is_available(&self, dest: &Destination) -> bool {
        match dest {
            Destination::ApplicationServer(n) => self.is_as_up(n),
            Destination::Linkset(n) => self.is_linkset_up(n),
        }
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
                        dest: Destination::Linkset(ls.name.clone()),
                        priority: ADJACENT_PRIORITY,
                    });
                }
            }
        }

        // Explicit routes: each targets an AS (`as:`) or a linkset (`linkset:`).
        // The config validator guarantees exactly one of the two is set.
        for r in &tenant.mtp3_routes {
            let dest = match (&r.as_, &r.linkset) {
                (Some(a), _) => Destination::ApplicationServer(a.clone()),
                (None, Some(l)) => Destination::Linkset(l.clone()),
                (None, None) => continue,
            };
            routes.entry(r.dpc.0).or_default().push(Candidate {
                dest,
                priority: r.priority,
            });
        }

        Self { variant, routes }
    }

    /// The variant these routes are keyed under.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// The DPC values this table has a route for (explicit or adjacent). Used to
    /// refresh the per-DPC route-availability metric on a state change.
    pub fn dpcs(&self) -> impl Iterator<Item = u32> + '_ {
        self.routes.keys().copied()
    }

    /// Resolve a DPC to the best currently-available destination, or `None` if
    /// the DPC is prohibited or every candidate route is down / has no route.
    pub fn resolve(&self, dpc: PointCode, state: &RouteState) -> Option<Destination> {
        if state.is_prohibited(dpc) {
            return None;
        }
        let mut candidates: Vec<&Candidate> = self.routes.get(&dpc.value())?.iter().collect();
        // Lowest priority number first (0 adjacent, then 1 primary, then 2…).
        candidates.sort_by_key(|c| c.priority);
        candidates
            .into_iter()
            .find(|c| state.is_available(&c.dest))
            .map(|c| c.dest.clone())
    }

    /// Whether we have *any* route (available or not) to a DPC.
    pub fn has_route(&self, dpc: PointCode) -> bool {
        self.routes.contains_key(&dpc.value())
    }

    /// Add (or extend) a route to a DPC live: a script programming the table via
    /// `ss7.routes.add(...)`. `priority` follows the config rule (1 = primary,
    /// higher numbers are alternates). Idempotent for an identical
    /// destination + priority, so re-running a start hook does not duplicate.
    pub fn add(&mut self, dpc: u32, dest: Destination, priority: u8) {
        let candidates = self.routes.entry(dpc).or_default();
        let candidate = Candidate { dest, priority };
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
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
        // Bring every AS + linkset up to start.
        let mut state = RouteState::default();
        for a in &tenant.application_servers {
            state.set_as_up(&a.name);
        }
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
        assert_eq!(
            r.resolve(pc(3000, var), &state),
            Some(Destination::Linkset("transit".into()))
        );
        assert_eq!(
            r.resolve(pc(3001, var), &state),
            Some(Destination::Linkset("transit".into()))
        );
    }

    #[test]
    fn primary_as_then_alternate_linkset_failover_and_restore() {
        let (r, mut state, var) = sample();
        // 2000 has priority-1 via AS hlr and priority-2 via linkset transit.
        assert_eq!(
            r.resolve(pc(2000, var), &state),
            Some(Destination::ApplicationServer("hlr".into()))
        );

        // Bring the primary AS down → fail over to the alternate linkset.
        state.set_as_down("hlr");
        assert_eq!(
            r.resolve(pc(2000, var), &state),
            Some(Destination::Linkset("transit".into()))
        );

        // Restore the primary → back to the AS.
        state.set_as_up("hlr");
        assert_eq!(
            r.resolve(pc(2000, var), &state),
            Some(Destination::ApplicationServer("hlr".into()))
        );
    }

    #[test]
    fn pause_prohibits_then_resume_restores() {
        let (r, mut state, var) = sample();
        let dpc = pc(2000, var);
        assert!(r.resolve(dpc, &state).is_some());

        // MTP-PAUSE for 2000 → no route even though the destinations are up.
        state.apply_event(&Mtp3Event::Pause { affected: dpc });
        assert!(state.is_prohibited(dpc));
        assert!(r.resolve(dpc, &state).is_none());

        // MTP-RESUME → routes again (to the primary AS).
        state.apply_event(&Mtp3Event::Resume { affected: dpc });
        assert_eq!(
            r.resolve(dpc, &state),
            Some(Destination::ApplicationServer("hlr".into()))
        );
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
        state.set_as_down("hlr");
        state.set_linkset_down("transit");
        assert!(r.resolve(pc(2000, var), &state).is_none());
    }

    #[test]
    fn set_all_down_clears_availability() {
        let (r, mut state, var) = sample();
        assert!(r.resolve(pc(2000, var), &state).is_some());
        state.set_all_down();
        assert!(r.resolve(pc(2000, var), &state).is_none());
        assert!(!state.is_as_up("hlr"));
        assert!(!state.is_linkset_up("transit"));
    }
}
