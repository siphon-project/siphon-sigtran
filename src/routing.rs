//! The shared routing decision types and the top-level [`Router`] that ties
//! MTP3 transfer + SCCP GTT + content routing into one inbound-message answer.
//!
//! # The decision flow
//!
//! For an inbound message addressed by DPC + SCCP:
//!
//! 1. **MTP3 transfer.** If the DPC is *not* one of our own point codes, the
//!    message transits: hand it to the [route resolver](crate::mtp3::route) and
//!    forward on the chosen linkset (or [`RouteDecision::Drop`] if no route).
//! 2. **SCCP GTT.** If the DPC *is* ours, translate the called-party global
//!    title (after the E.214→E.164 pre-step) via [GTT](crate::sccp::gtt). A
//!    concrete `(dpc, ssn)` or group result routes onward; `Local` (or a called
//!    SSN we own) terminates here.
//! 3. **Content routing.** When a decoded MAP/CAP view is available, the
//!    [content engine](crate::content) can override with a rule action (route,
//!    rewrite, screen, or defer-to-Python), evaluated first, before GTT, since
//!    it routes on the richer application layer.
//!
//! The router is **synchronous and allocation-light**, the line-rate guarantee.
//! Anything dynamic (a Python hook) surfaces as [`RouteDecision::Python`] for the
//! async layer above to resolve.

use crate::content::{Action, MapView};
use crate::mtp3::route::Destination;
use crate::sccp::gtt::{GttResult, GttSelector};
use crate::tenant::{Tenancy, TenantRuntime};

/// A resolved routing decision for one inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Forward via the given egress destination (MTP3 transfer to a non-local
    /// DPC): an M3UA Application Server or an M2PA linkset.
    Route {
        /// The egress destination.
        via: Destination,
    },
    /// Forward to a concrete destination after SCCP/content translation.
    RouteTo {
        /// Destination point code (decimal, in the deciding tenant's variant).
        dpc: u32,
        /// Subsystem number.
        ssn: u8,
        /// The egress destination the DPC resolves to (if a route exists).
        via: Option<Destination>,
    },
    /// Terminate locally (we own the subsystem).
    Local,
    /// Hand off to another routing domain. Carries whether PC + GT conversion
    /// applies (the two domains' variants differ).
    CrossTenant {
        /// The destination tenant.
        tenant: String,
        /// Destination point code within that tenant.
        dpc: u32,
        /// Subsystem number.
        ssn: u8,
        /// Whether variant conversion applies.
        conversion: bool,
    },
    /// Defer to a named Python hook (phase-3): the async layer calls it.
    Python {
        /// The hook name.
        hook: String,
    },
    /// Drop the message, with a reason.
    Drop {
        /// Why it was dropped (no-route, screened, no-translation, …).
        reason: String,
    },
}

/// An inbound message to route, decoded to the fields the router needs.
///
/// The transport layer (phase-2) fills this in from a real MSU; the integration
/// tests fill it from genuinely-assembled SS7 bytes.
#[derive(Debug, Clone, Default)]
pub struct Inbound {
    /// Destination point code value from the routing label / M3UA protocol data.
    pub dpc: u32,
    /// Called-party GT selector (for GTT), if the message routes on GT.
    pub cdpa: Option<GttSelector>,
    /// The called-party SSN, if present (route-on-SSN or GTT result SSN).
    pub called_ssn: Option<u8>,
    /// A decoded MAP/CAP view for content routing, if the layer was decoded.
    pub view: Option<MapView>,
}

/// The top-level router. Holds the compiled [`Tenancy`] and resolves inbound
/// messages against a chosen tenant.
#[derive(Debug)]
pub struct Router {
    tenancy: Tenancy,
}

impl Router {
    /// Build a router from a validated [`Config`](crate::config::Config).
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            tenancy: Tenancy::build(config),
        }
    }

    /// Build directly from a compiled [`Tenancy`].
    pub fn from_tenancy(tenancy: Tenancy) -> Self {
        Self { tenancy }
    }

    /// The compiled tenancy (read-only).
    pub fn tenancy(&self) -> &Tenancy {
        &self.tenancy
    }

    /// Mutable tenancy access, the transport layer feeds route-state events in.
    pub fn tenancy_mut(&mut self) -> &mut Tenancy {
        &mut self.tenancy
    }

    // ── Live availability seam (the async transport drives these) ────────────
    //
    // The route state is interior-mutable (RwLock), so a *shared* `Arc<Router>`
    // can both route (read) and fold in ASP / link / SSNM changes (write). All
    // of these no-op on an unknown tenant.

    /// Mark an Application Server up (≥ 1 of its ASPs reached ASP-Active).
    pub fn note_as_up(&self, tenant: &str, name: &str) {
        if let Some(rt) = self.tenancy.get(tenant) {
            rt.state_write().set_as_up(name);
        }
    }

    /// Mark an Application Server down (no ASP active).
    pub fn note_as_down(&self, tenant: &str, name: &str) {
        if let Some(rt) = self.tenancy.get(tenant) {
            rt.state_write().set_as_down(name);
        }
    }

    /// Mark an M2PA linkset up (≥ 1 link in service).
    pub fn note_linkset_up(&self, tenant: &str, name: &str) {
        if let Some(rt) = self.tenancy.get(tenant) {
            rt.state_write().set_linkset_up(name);
        }
    }

    /// Mark an M2PA linkset down (all links out of service).
    pub fn note_linkset_down(&self, tenant: &str, name: &str) {
        if let Some(rt) = self.tenancy.get(tenant) {
            rt.state_write().set_linkset_down(name);
        }
    }

    /// Fold an MTP3-user network-management event (from M3UA SSNM / native MTP3)
    /// into a tenant's route state: PAUSE→prohibit, RESUME→allow, STATUS→level.
    pub fn apply_mtp3_event(&self, tenant: &str, event: &mtp3::Mtp3Event) {
        if let Some(rt) = self.tenancy.get(tenant) {
            rt.state_write().apply_event(event);
            match event {
                mtp3::Mtp3Event::Pause { affected } => {
                    crate::metrics::mtp3mg_event(
                        affected.value(),
                        crate::metrics::Mtp3MgKind::Pause,
                    );
                }
                mtp3::Mtp3Event::Resume { affected } => {
                    crate::metrics::mtp3mg_event(
                        affected.value(),
                        crate::metrics::Mtp3MgKind::Resume,
                    );
                }
                mtp3::Mtp3Event::Status { affected, .. } => {
                    crate::metrics::mtp3mg_event(
                        affected.value(),
                        crate::metrics::Mtp3MgKind::Congestion,
                    );
                }
                mtp3::Mtp3Event::Transfer(_) => {}
            }
            self.refresh_route_metrics(tenant);
        }
    }

    /// Refresh the `sigtran_route_available{dpc}` gauge for every DPC in a
    /// tenant's route table. Cheap and rare (called on a state change, never per
    /// MSU), so it walks the whole table.
    pub fn refresh_route_metrics(&self, tenant: &str) {
        if let Some(rt) = self.tenancy.get(tenant) {
            let state = rt.state_read();
            for dpc_value in rt.routes.dpcs() {
                let up = mtp3::PointCode::from_value(dpc_value, rt.variant)
                    .ok()
                    .and_then(|dpc| rt.routes.resolve(dpc, &state))
                    .is_some();
                crate::metrics::set_route_available(dpc_value, up);
            }
        }
    }

    /// Reset a tenant's route state to all-down. The transport calls this at
    /// startup before any ASP / link has come into service.
    pub fn reset_availability_down(&self, tenant: &str) {
        if let Some(rt) = self.tenancy.get(tenant) {
            rt.state_write().set_all_down();
        }
    }

    /// A tenant's own point code value (the node's PC in that routing domain).
    /// Used by the transfer path's own-OPC loop guard.
    pub fn node_point_code(&self, tenant: &str) -> Option<u32> {
        self.tenancy.get(tenant).map(|rt| rt.point_code)
    }

    /// Whether a DPC currently resolves to any available egress (used by the
    /// transport to answer an M3UA DAUD audit).
    pub fn is_reachable(&self, tenant: &str, dpc_value: u32) -> bool {
        self.tenancy
            .get(tenant)
            .map(|rt| resolve_destination(rt, dpc_value).is_some())
            .unwrap_or(false)
    }

    /// Route an inbound message within the implicit-default tenant.
    pub fn route(&self, msg: &Inbound) -> RouteDecision {
        self.route_in(crate::config::DEFAULT_TENANT, msg)
    }

    /// Route an inbound message within a named tenant.
    pub fn route_in(&self, tenant: &str, msg: &Inbound) -> RouteDecision {
        let Some(rt) = self.tenancy.get(tenant) else {
            return RouteDecision::Drop {
                reason: format!("unknown tenant `{tenant}`"),
            };
        };

        // 1. MTP3 transfer: DPC is not one of our point codes → transit. This is
        //    point-code routing and applies to *any* Service Indicator (ISUP,
        //    SNM, …), not just SCCP; only a message addressed to us climbs the
        //    SCCP stack below.
        if msg.dpc != rt.point_code {
            return match resolve_destination(rt, msg.dpc) {
                Some(via) => RouteDecision::Route { via },
                None => RouteDecision::Drop {
                    reason: format!("no MTP3 route to {}", msg.dpc),
                },
            };
        }

        // The DPC is ours → SCCP. If addressed by a local SSN we own and there's
        // no GT to translate, terminate.
        if let Some(ssn) = msg.called_ssn {
            if rt.gtt.owns_ssn(ssn) && msg.cdpa.is_none() {
                return RouteDecision::Local;
            }
        }

        // 2. Content routing overrides GTT when a decoded view is present, it
        //    routes on the richer application layer.
        if let (Some(engine), Some(view)) = (rt.content.as_ref(), msg.view.as_ref()) {
            if let Some(hit) = engine.evaluate(view) {
                crate::metrics::content_rule_hit(&hit.rule, action_label(&hit.action));
                if let Some(decision) = self.decision_from_action(rt, hit.action, msg) {
                    return decision;
                }
            }
        }

        // 3. SCCP GTT on the called-party GT (E.214 → E.164 pre-step first).
        if let Some(sel) = &msg.cdpa {
            let sel = self.pre_convert(rt, sel);
            match rt.gtt.translate(&sel) {
                Some(result) => return self.decision_from_gtt(rt, result),
                None => {
                    crate::metrics::gtt_error(crate::metrics::GttError::NoTranslation);
                    return RouteDecision::Drop {
                        reason: "no GTT translation".into(),
                    };
                }
            }
        }

        // Addressed to us by SSN we own but with no GT → local.
        if let Some(ssn) = msg.called_ssn {
            if rt.gtt.owns_ssn(ssn) {
                return RouteDecision::Local;
            }
        }

        RouteDecision::Drop {
            reason: "no route-on-GT and no owned SSN".into(),
        }
    }

    /// Apply the inbound E.214 → E.164 conversion pre-step to a called-party
    /// selector (np 0x03 marks E.214). A no-op if the digits aren't a known MGT.
    fn pre_convert(&self, rt: &TenantRuntime, sel: &GttSelector) -> GttSelector {
        // np == 3 is E.214 (mobile global title); convert before lookup.
        if sel.np == Some(3) {
            if let Some(e164) = rt.converter.e214_to_e164(&sel.digits) {
                let mut out = sel.clone();
                out.digits = e164;
                out.np = Some(1); // E.164
                return out;
            }
        }
        sel.clone()
    }

    fn decision_from_gtt(&self, rt: &TenantRuntime, result: GttResult) -> RouteDecision {
        use crate::metrics::{self, GttError, GttResultKind};
        match result {
            GttResult::Local => {
                metrics::gtt_translation(GttResultKind::Local);
                RouteDecision::Local
            }
            GttResult::Dpc { dpc, ssn } => {
                metrics::gtt_translation(GttResultKind::Dpc);
                let via = resolve_destination(rt, dpc);
                if via.is_none() {
                    metrics::gtt_error(GttError::NoRoute);
                }
                RouteDecision::RouteTo { dpc, ssn, via }
            }
            GttResult::Tenant { tenant, dpc, ssn } => {
                metrics::gtt_translation(GttResultKind::Tenant);
                let conversion = self
                    .tenancy
                    .cross_tenant(&rt.id, &tenant)
                    .map(|x| x.conversion)
                    .unwrap_or(false);
                RouteDecision::CrossTenant {
                    tenant,
                    dpc,
                    ssn,
                    conversion,
                }
            }
        }
    }

    fn decision_from_action(
        &self,
        rt: &TenantRuntime,
        action: Action,
        _msg: &Inbound,
    ) -> Option<RouteDecision> {
        match action {
            Action::Screen => Some(RouteDecision::Drop {
                reason: "screened by content rule".into(),
            }),
            Action::Python { hook } => Some(RouteDecision::Python { hook }),
            Action::Route { target, .. } => {
                // A content route target resolves through the same GTT machinery
                // as a `to:` clause: dpc, group (cost primary / share cursor),
                // local, or cross-tenant.
                let result = rt.gtt.resolve_target(&target)?;
                Some(self.decision_from_gtt(rt, result))
            }
        }
    }
}

/// The `action` metric label for a matched content action.
fn action_label(action: &Action) -> &'static str {
    match action {
        Action::Route {
            rewrite_cdpa_gt: Some(_),
            ..
        } => "rewrite",
        Action::Route { .. } => "route",
        Action::Screen => "screen",
        Action::Python { .. } => "python",
    }
}

/// Resolve a DPC to an egress [`Destination`] within a tenant, honouring live
/// availability (reads the interior-mutable route state).
fn resolve_destination(rt: &TenantRuntime, dpc_value: u32) -> Option<Destination> {
    let dpc = mtp3::PointCode::from_value(dpc_value, rt.variant).ok()?;
    let state = rt.state_read();
    rt.routes.resolve(dpc, &state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn router() -> Router {
        let cfg = Config::parse(crate::config::tests::SAMPLE).unwrap();
        Router::new(&cfg)
    }

    #[test]
    fn transit_dpc_routes_on_application_server() {
        let r = router();
        // 2000 is not our PC (1000) → MTP3 transfer to AS hlr (route priority 1).
        let d = r.route(&Inbound {
            dpc: 2000,
            ..Default::default()
        });
        assert_eq!(
            d,
            RouteDecision::Route {
                via: Destination::ApplicationServer("hlr".into())
            }
        );
    }

    #[test]
    fn transit_no_route_drops() {
        let r = router();
        let d = r.route(&Inbound {
            dpc: 9999,
            ..Default::default()
        });
        assert!(matches!(d, RouteDecision::Drop { .. }));
    }

    #[test]
    fn local_ssn_terminates() {
        let r = router();
        // Addressed to our PC (1000), SSN 6 (HLR, owned), no GT → local.
        let d = r.route(&Inbound {
            dpc: 1000,
            called_ssn: Some(6),
            ..Default::default()
        });
        assert_eq!(d, RouteDecision::Local);
    }

    #[test]
    fn gtt_translates_to_dpc() {
        let r = router();
        // Our PC, route-on-GT, digits match the "1555" rule → dpc 2000 ssn 6.
        let d = r.route(&Inbound {
            dpc: 1000,
            cdpa: Some(GttSelector::from_digits("15559999")),
            ..Default::default()
        });
        match d {
            RouteDecision::RouteTo { dpc, ssn, via } => {
                assert_eq!(dpc, 2000);
                assert_eq!(ssn, 6);
                assert_eq!(via, Some(Destination::ApplicationServer("hlr".into())));
            }
            other => panic!("expected RouteTo, got {other:?}"),
        }
    }

    #[test]
    fn e214_pre_conversion_before_gtt() {
        let r = router();
        // E.214 MGT: 00101 + MSIN, np=3. Converts to 15551+MSIN, then the
        // "155501" rule (gti/tt/np/nai) would need those fields; with only
        // digits the "1555" fallback rule matches → dpc 2000.
        let d = r.route(&Inbound {
            dpc: 1000,
            cdpa: Some(GttSelector {
                digits: "0010123456".into(),
                np: Some(3),
                ..Default::default()
            }),
            ..Default::default()
        });
        match d {
            RouteDecision::RouteTo { dpc, .. } => assert_eq!(dpc, 2000),
            other => panic!("expected RouteTo, got {other:?}"),
        }
    }

    #[test]
    fn content_rule_overrides_with_python() {
        let r = router();
        // Our PC, sri-sm with a non-home cdpa GT and no imsi → sri-sm-np python.
        let d = r.route(&Inbound {
            dpc: 1000,
            cdpa: Some(GttSelector::from_digits("15559999")),
            view: Some(MapView {
                operation: Some(crate::content::Operation::SriSm),
                cdpa_gt: Some("19990001".into()),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            d,
            RouteDecision::Python {
                hook: "on_np_dip".into()
            }
        );
    }

    #[test]
    fn content_rule_routes_to_dpc() {
        let r = router();
        // updateLocation for buyer-a IMSI → buyer-a-home route dpc 2005 ssn 6.
        let d = r.route(&Inbound {
            dpc: 1000,
            view: Some(MapView {
                operation: Some(crate::content::Operation::UpdateLocation),
                imsi: Some("001010000000042".into()),
                ..Default::default()
            }),
            ..Default::default()
        });
        match d {
            RouteDecision::RouteTo { dpc, ssn, .. } => {
                assert_eq!(dpc, 2005);
                assert_eq!(ssn, 6);
            }
            other => panic!("expected RouteTo, got {other:?}"),
        }
    }
}
