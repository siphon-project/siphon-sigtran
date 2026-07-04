//! Routing domains (instances).
//!
//! With no domains configured, one implicit `default` domain holds the
//! top-level tables. Each domain has its own MTP3 routes, GTT, and content
//! rules. A decision can resolve into another domain, applying point-code and
//! global-title conversion when the two domains' variants differ (ITU vs ANSI).
//!
//! A [`TenantRuntime`] bundles the compiled routing brains for one domain: the
//! MTP3 [`RouteResolver`], the SCCP [`GttResolver`] and [`GtConverter`], and the
//! [`ContentEngine`].

use std::collections::BTreeMap;

use mtp3::Variant;

use crate::config::{Config, TenantId};
use crate::content::ContentEngine;
use crate::mtp3::route::{RouteResolver, RouteState};
use crate::sccp::gtt::{GtConverter, GttResolver};

/// The compiled runtime for a single tenant.
#[derive(Debug)]
pub struct TenantRuntime {
    /// The tenant id.
    pub id: TenantId,
    /// The tenant's SS7 variant.
    pub variant: Variant,
    /// The tenant's own point code value (decimal).
    pub point_code: u32,
    /// MTP3 route resolver.
    pub routes: RouteResolver,
    /// Live MTP3 availability state.
    pub route_state: RouteState,
    /// SCCP GTT resolver.
    pub gtt: GttResolver,
    /// E.214 ↔ E.164 converter.
    pub converter: GtConverter,
    /// Content-routing engine (absent if the tenant has no `content_routing`).
    pub content: Option<ContentEngine>,
}

impl TenantRuntime {
    /// Whether this tenant would need conversion to hand off to `other`
    /// (their SS7 variants differ → PC + GT conversion required).
    pub fn needs_conversion_to(&self, other: &TenantRuntime) -> bool {
        self.variant != other.variant
    }
}

/// A marker describing a cross-tenant hand-off decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossTenant {
    /// The source tenant.
    pub from: TenantId,
    /// The destination tenant.
    pub to: TenantId,
    /// Whether PC + GT conversion applies (variants differ).
    pub conversion: bool,
}

/// The whole node's compiled tenancy: every tenant's runtime keyed by id, with
/// the implicit `default` always present for a flat config.
#[derive(Debug)]
pub struct Tenancy {
    tenants: BTreeMap<TenantId, TenantRuntime>,
}

impl Tenancy {
    /// Compile every tenant in a [`Config`] into its runtime.
    pub fn build(config: &Config) -> Self {
        let mut tenants = BTreeMap::new();
        for (id, tenant) in &config.tenants {
            let routes = RouteResolver::build(tenant, &config.associations);
            // Start every linkset up; the transport layer (phase-2) will drive
            // this down/up from real association state.
            let mut route_state = RouteState::default();
            for ls in &tenant.linksets {
                route_state.set_linkset_up(&ls.name);
            }
            let gtt = GttResolver::compile(&tenant.sccp);
            let converter = GtConverter::from(&tenant.sccp.gt_conversion);
            let content = tenant.content_routing.as_ref().map(ContentEngine::compile);
            let point_code = tenant
                .resolved_point_code()
                .map(|pc| pc.value())
                .unwrap_or(tenant.point_code.0);
            tenants.insert(
                id.clone(),
                TenantRuntime {
                    id: id.clone(),
                    variant: tenant.variant,
                    point_code,
                    routes,
                    route_state,
                    gtt,
                    converter,
                    content,
                },
            );
        }
        Self { tenants }
    }

    /// The runtime for a tenant id.
    pub fn get(&self, id: &str) -> Option<&TenantRuntime> {
        self.tenants.get(id)
    }

    /// Mutable access (the transport layer feeds route-state events in here).
    pub fn get_mut(&mut self, id: &str) -> Option<&mut TenantRuntime> {
        self.tenants.get_mut(id)
    }

    /// The implicit-default tenant.
    pub fn default_tenant(&self) -> Option<&TenantRuntime> {
        self.tenants.get(crate::config::DEFAULT_TENANT)
    }

    /// The tenant ids present.
    pub fn ids(&self) -> impl Iterator<Item = &TenantId> {
        self.tenants.keys()
    }

    /// The number of tenants.
    pub fn len(&self) -> usize {
        self.tenants.len()
    }

    /// Whether there are no tenants (never true for a valid config).
    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }

    /// Describe a cross-tenant hand-off from `from` to `to`, flagging whether
    /// PC + GT conversion applies (variants differ). `None` if either tenant is
    /// unknown.
    pub fn cross_tenant(&self, from: &str, to: &str) -> Option<CrossTenant> {
        let a = self.tenants.get(from)?;
        let b = self.tenants.get(to)?;
        Some(CrossTenant {
            from: from.to_string(),
            to: to.to_string(),
            conversion: a.needs_conversion_to(b),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multi_tenant_cfg() -> Config {
        let yaml = r#"
associations:
  - { id: a1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
tenants:
  default:
    point_code: 1000
    variant: ITU
    linksets:
      - { name: ls, adaptation: m3ua, traffic_mode: override, links: [{assoc: a1, slc: 0}] }
    mtp3_routes:
      - { dpc: 2000, linkset: ls, priority: 1 }
  partner-ansi:
    point_code: 5000
    variant: ANSI
    linksets:
      - { name: ls, adaptation: m3ua, traffic_mode: override, links: [{assoc: a1, slc: 0}] }
    mtp3_routes:
      - { dpc: 6000, linkset: ls, priority: 1 }
"#;
        Config::parse(yaml).unwrap()
    }

    #[test]
    fn implicit_default_present() {
        let cfg = Config::parse(crate::config::tests::SAMPLE).unwrap();
        let ten = Tenancy::build(&cfg);
        assert_eq!(ten.len(), 1);
        assert!(ten.default_tenant().is_some());
        assert_eq!(ten.default_tenant().unwrap().point_code, 1000);
    }

    #[test]
    fn cross_tenant_marks_conversion_when_variants_differ() {
        let cfg = multi_tenant_cfg();
        let ten = Tenancy::build(&cfg);
        // default (ITU) → partner-ansi (ANSI) → conversion required.
        let x = ten.cross_tenant("default", "partner-ansi").unwrap();
        assert!(x.conversion);
        // default → default → same variant → no conversion.
        let y = ten.cross_tenant("default", "default").unwrap();
        assert!(!y.conversion);
    }

    #[test]
    fn per_tenant_tables_are_isolated() {
        let cfg = multi_tenant_cfg();
        let ten = Tenancy::build(&cfg);
        let d = ten.get("default").unwrap();
        let p = ten.get("partner-ansi").unwrap();
        // Each tenant only routes its own DPCs.
        let dpc_2000 = mtp3::PointCode::from_value(2000, Variant::Itu).unwrap();
        let dpc_6000 = mtp3::PointCode::from_value(6000, Variant::Ansi).unwrap();
        assert!(d.routes.has_route(dpc_2000));
        assert!(!d
            .routes
            .has_route(mtp3::PointCode::from_value(6000, Variant::Itu).unwrap()));
        assert!(p.routes.has_route(dpc_6000));
    }
}
