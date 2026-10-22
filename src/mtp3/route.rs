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
//! congestion), the AS / linkset up/down setters, and
//! [`RouteState::set_route_status`] (a transfer-prohibited, -restricted or
//! -allowed received from the adjacent point of one linkset, ITU-T Q.704
//! clause 13, which marks that one route and no other).
//!
//! # Load sharing
//!
//! [`RouteResolver::resolve_for`] takes the signalling link selection of the
//! message. Routes of the same priority are a combined linkset (Q.704 2.3.2 b,
//! 4.2.1) and share the traffic by it: each selection code has one of them as
//! its normal route, and moves to another only while that one is unavailable,
//! so the codes on the routes that stayed up do not move. A route marked
//! restricted is used only when no route of the same priority is unrestricted
//! (Q.704 4.7). [`RouteResolver::resolve`] is the same with selection code 0.

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

/// What an adjacent signalling transfer point has said about one route
/// through it (ITU-T Q.704 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteStatus {
    /// Transfer-allowed, or nothing said: "at the beginning of the MTP restart
    /// procedure all signalling routes [are considered] to be allowed" (9.6.1).
    #[default]
    Allowed,
    /// Transfer-restricted (national option, 13.4).
    Restricted,
    /// Transfer-prohibited (13.2).
    Prohibited,
}

/// Whether a candidate route can carry traffic, for [`choose_route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Usable {
    /// Not available, or prohibited.
    No,
    /// Available, and restricted by the adjacent point.
    Restricted,
    /// Available.
    Yes,
}

/// The routes that carry traffic among candidates sorted by priority: the
/// first priority that has a usable route, and of its routes the unrestricted
/// ones if there are any, the restricted ones otherwise. Returns the range of
/// that priority and the class in use.
fn tier_in_use<T>(
    sorted: &[T],
    priority: impl Fn(&T) -> u8,
    usable: impl Fn(&T) -> Usable,
) -> Option<(std::ops::Range<usize>, Usable)> {
    let mut start = 0;
    while start < sorted.len() {
        let level = priority(&sorted[start]);
        let mut end = start;
        let mut class = Usable::No;
        while end < sorted.len() && priority(&sorted[end]) == level {
            match usable(&sorted[end]) {
                Usable::Yes => class = Usable::Yes,
                Usable::Restricted if class == Usable::No => class = Usable::Restricted,
                _ => {}
            }
            end += 1;
        }
        if class != Usable::No {
            return Some((start..end, class));
        }
        start = end;
    }
    None
}

/// The index of the route that carries selection code `sls`, among candidates
/// sorted by priority. One function for the per-message resolver and for
/// signalling route management, so both always name the same route.
pub(crate) fn choose_route<T>(
    sorted: &[T],
    priority: impl Fn(&T) -> u8,
    usable: impl Fn(&T) -> Usable,
    sls: u8,
) -> Option<usize> {
    let (tier, class) = tier_in_use(sorted, priority, &usable)?;
    // The normal route of this selection code, while it is in use.
    let normal = tier.start + usize::from(sls) % tier.len();
    if usable(&sorted[normal]) == class {
        return Some(normal);
    }
    let count = tier
        .clone()
        .filter(|i| usable(&sorted[*i]) == class)
        .count();
    tier.filter(|i| usable(&sorted[*i]) == class)
        .nth(usize::from(sls) % count.max(1))
}

/// Every route that carries some selection code (see [`choose_route`]).
pub(crate) fn routes_in_use<T>(
    sorted: &[T],
    priority: impl Fn(&T) -> u8,
    usable: impl Fn(&T) -> Usable,
) -> Vec<usize> {
    match tier_in_use(sorted, priority, &usable) {
        Some((tier, class)) => tier.filter(|i| usable(&sorted[*i]) == class).collect(),
        None => Vec::new(),
    }
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
    /// Routes an adjacent point has prohibited or restricted, per DPC value.
    /// Empty unless a transfer-prohibited or -restricted is outstanding.
    route_status: BTreeMap<u32, Vec<(Destination, RouteStatus)>>,
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

    /// Record what the adjacent point of `via` said about its route to `dpc`
    /// (transfer-prohibited, -restricted, -allowed; ITU-T Q.704 13.2 to 13.4).
    pub fn set_route_status(&mut self, dpc: u32, via: &Destination, status: RouteStatus) {
        let marks = self.route_status.entry(dpc).or_default();
        marks.retain(|(dest, _)| dest != via);
        if status != RouteStatus::Allowed {
            marks.push((via.clone(), status));
        }
        if marks.is_empty() {
            self.route_status.remove(&dpc);
        }
    }

    /// The status of the route to `dpc` through `via`.
    pub fn route_status(&self, dpc: u32, via: &Destination) -> RouteStatus {
        self.route_status
            .get(&dpc)
            .and_then(|marks| marks.iter().find(|(dest, _)| dest == via))
            .map_or(RouteStatus::Allowed, |(_, status)| *status)
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
    /// DPC value → candidates, sorted by priority (stable: config order
    /// within one priority).
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
                    // Every link of a linkset names the same adjacent point:
                    // one route, not one per link.
                    let candidate = Candidate {
                        dest: Destination::Linkset(ls.name.clone()),
                        priority: ADJACENT_PRIORITY,
                    };
                    let candidates = routes.entry(pc).or_default();
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
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

        // Lowest priority number first (0 adjacent, then 1 primary, then 2…),
        // once, so resolving a message neither sorts nor allocates.
        for candidates in routes.values_mut() {
            candidates.sort_by_key(|c| c.priority);
        }
        Self { variant, routes }
    }

    /// Every route of the table: `(dpc, destination, priority)`, the routes of
    /// one DPC in priority order.
    pub fn routes(&self) -> impl Iterator<Item = (u32, &Destination, u8)> + '_ {
        self.routes
            .iter()
            .flat_map(|(dpc, candidates)| candidates.iter().map(|c| (*dpc, &c.dest, c.priority)))
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
    /// The route of selection code 0: see [`resolve_for`](Self::resolve_for).
    pub fn resolve(&self, dpc: PointCode, state: &RouteState) -> Option<Destination> {
        self.resolve_for(dpc, 0, state)
    }

    /// Resolve a DPC for a message with signalling link selection `sls`: the
    /// available routes of the best priority share the selection codes (see
    /// the module documentation).
    pub fn resolve_for(&self, dpc: PointCode, sls: u8, state: &RouteState) -> Option<Destination> {
        self.resolve_avoiding(dpc, sls, state, None)
    }

    /// [`resolve_for`](Self::resolve_for) without the routes through `avoid`,
    /// for a message that must not go that way (Q.704 2.3.4.2 b).
    pub(crate) fn resolve_avoiding(
        &self,
        dpc: PointCode,
        sls: u8,
        state: &RouteState,
        avoid: Option<&Destination>,
    ) -> Option<Destination> {
        if state.is_prohibited(dpc) {
            return None;
        }
        let candidates = self.routes.get(&dpc.value())?;
        let marks = state.route_status.get(&dpc.value());
        let usable = |c: &Candidate| {
            if !state.is_available(&c.dest) || avoid == Some(&c.dest) {
                return Usable::No;
            }
            let status = marks
                .and_then(|marks| marks.iter().find(|(dest, _)| *dest == c.dest))
                .map_or(RouteStatus::Allowed, |(_, status)| *status);
            match status {
                RouteStatus::Allowed => Usable::Yes,
                RouteStatus::Restricted => Usable::Restricted,
                RouteStatus::Prohibited => Usable::No,
            }
        };
        choose_route(candidates, |c| c.priority, usable, sls).map(|i| candidates[i].dest.clone())
    }

    /// The most routes of one priority that any destination reached through
    /// `via` has: how many ways the selection codes are split before a link of
    /// `via` is chosen (1 when `via` is in no combined linkset).
    pub fn share_width(&self, via: &Destination) -> usize {
        let mut width = 1;
        for candidates in self.routes.values() {
            let Some(own) = candidates.iter().find(|c| c.dest == *via) else {
                continue;
            };
            let tier = candidates
                .iter()
                .filter(|c| c.priority == own.priority)
                .count();
            width = width.max(tier);
        }
        width
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
            candidates.sort_by_key(|c| c.priority);
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

    /// Two linksets of one priority toward 2200, a third as the alternative.
    fn combined() -> (RouteResolver, RouteState, Variant) {
        let cfg = Config::parse(
            r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: b-0, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3565, adjacent_pc: 4000 }
  - { id: c-0, adaptation: m2pa, role: client, addrs: [192.0.2.2], port: 3565, adjacent_pc: 5000 }
  - { id: d-0, adaptation: m2pa, role: client, addrs: [192.0.2.3], port: 3565, adjacent_pc: 6000 }
linksets:
  - { name: b, links: [{assoc: b-0}] }
  - { name: c, links: [{assoc: c-0}] }
  - { name: d, links: [{assoc: d-0}] }
mtp3_routes:
  - { dpc: 2200, linkset: d, priority: 2 }
  - { dpc: 2200, linkset: b, priority: 1 }
  - { dpc: 2200, linkset: c, priority: 1 }
"#,
        )
        .unwrap();
        let tenant = cfg.default_tenant().unwrap();
        let resolver = RouteResolver::build(tenant, &cfg.associations);
        let state = RouteState::with_linksets_up(["b", "c", "d"]);
        (resolver, state, tenant.variant)
    }

    fn linkset(name: &str) -> Destination {
        Destination::Linkset(name.into())
    }

    #[test]
    fn routes_of_one_priority_share_by_selection_code() {
        // Q.704 2.3.2 b): "traffic relating to a given destination is shared
        // (on the basis of the signalling link selection field) between
        // different signalling links not belonging to the same link set".
        let (r, state, var) = combined();
        let dpc = pc(2200, var);
        let via: Vec<Destination> = (0..16)
            .map(|sls| r.resolve_for(dpc, sls, &state).unwrap())
            .collect();
        for (sls, dest) in via.iter().enumerate() {
            let expected = if sls % 2 == 0 { "b" } else { "c" };
            assert_eq!(*dest, linkset(expected), "selection code {sls}");
        }
        // The alternative of lower priority carries nothing while they are up.
        assert!(!via.contains(&linkset("d")));
        // `resolve` is selection code 0.
        assert_eq!(r.resolve(dpc, &state), Some(linkset("b")));
    }

    #[test]
    fn a_failed_route_moves_only_its_own_selection_codes() {
        let (r, mut state, var) = combined();
        let dpc = pc(2200, var);
        state.set_linkset_down("c");
        for sls in 0..16 {
            assert_eq!(r.resolve_for(dpc, sls, &state), Some(linkset("b")));
        }
        // Both of the priority down: the alternative takes everything.
        state.set_linkset_down("b");
        for sls in 0..16 {
            assert_eq!(r.resolve_for(dpc, sls, &state), Some(linkset("d")));
        }
        state.set_linkset_down("d");
        assert_eq!(r.resolve_for(dpc, 3, &state), None);
    }

    #[test]
    fn a_prohibited_route_is_one_route_not_the_destination() {
        // Q.704 13.2.3: a transfer-prohibited from the adjacent point of one
        // linkset makes that route unavailable (3.4.1), not the others.
        let (r, mut state, var) = combined();
        let dpc = pc(2200, var);
        state.set_route_status(2200, &linkset("b"), RouteStatus::Prohibited);
        assert_eq!(
            state.route_status(2200, &linkset("b")),
            RouteStatus::Prohibited
        );
        assert_eq!(
            state.route_status(2200, &linkset("c")),
            RouteStatus::Allowed
        );
        for sls in 0..16 {
            assert_eq!(r.resolve_for(dpc, sls, &state), Some(linkset("c")));
        }
        // Another destination through the same linkset is not touched.
        assert_eq!(r.resolve(pc(4000, var), &state), Some(linkset("b")));
        // Transfer-allowed puts it back.
        state.set_route_status(2200, &linkset("b"), RouteStatus::Allowed);
        assert_eq!(r.resolve_for(dpc, 0, &state), Some(linkset("b")));
    }

    #[test]
    fn a_restricted_route_yields_to_an_equal_one_and_to_no_other() {
        // Q.704 4.7: traffic is transferred "if an equal priority alternative
        // is available and not restricted".
        let (r, mut state, var) = combined();
        let dpc = pc(2200, var);
        state.set_route_status(2200, &linkset("b"), RouteStatus::Restricted);
        for sls in 0..16 {
            assert_eq!(r.resolve_for(dpc, sls, &state), Some(linkset("c")));
        }
        // With its equal gone, the restricted route is used before the
        // alternative of lower priority.
        state.set_linkset_down("c");
        assert_eq!(r.resolve_for(dpc, 1, &state), Some(linkset("b")));
    }

    #[test]
    fn a_route_can_be_avoided_and_the_width_of_a_combined_linkset_is_known() {
        let (r, state, var) = combined();
        let dpc = pc(2200, var);
        assert_eq!(
            r.resolve_avoiding(dpc, 0, &state, Some(&linkset("b"))),
            Some(linkset("c"))
        );
        assert_eq!(r.share_width(&linkset("b")), 2);
        assert_eq!(r.share_width(&linkset("c")), 2);
        assert_eq!(r.share_width(&linkset("d")), 1);
    }

    #[test]
    fn a_route_added_at_run_time_keeps_the_priority_order() {
        let (mut r, mut state, var) = combined();
        state.set_as_up("gateway");
        r.add(2200, Destination::ApplicationServer("gateway".into()), 0);
        assert_eq!(
            r.resolve(pc(2200, var), &state),
            Some(Destination::ApplicationServer("gateway".into()))
        );
    }
}
