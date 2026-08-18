//! Routing-brain micro-benchmarks.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table. Four
//! representative operations, all built from the public API with synthetic data
//! (test PLMN 001/01, +1-555-01xx GTs, decimal point codes):
//!
//!   * **config load**: parse + validate a full single-tenant `sigtran.yaml`.
//!   * **route resolve**: MTP3 DPC to linkset with a failover alternate.
//!   * **gtt lookup**: SCCP global-title translation to a group primary.
//!   * **content match**: a first-match content rule over a decoded MAP view.
//!
//! No I/O is in any path. These isolate exactly the routing work.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use siphon_sigtran::config::Config;
use siphon_sigtran::content::{MapView, Operation};
use siphon_sigtran::routing::{Inbound, Router};
use siphon_sigtran::sccp::gtt::GttSelector;

const SAMPLE: &str = r#"
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
  - { id: xit-1, adaptation: m2pa, role: client, addrs: [10.0.1.1], port: 3565, adjacent_pc: 3000 }
application_servers:
  - { name: hlr, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a] }
linksets:
  - { name: transit, links: [{assoc: xit-1}] }
mtp3_routes:
  - { dpc: 2000, as: hlr,          priority: 1 }
  - { dpc: 2000, linkset: transit, priority: 2 }
sccp:
  local_ssns: [6, 8]
  gtt_groups:
    - { name: ag-hlr, mode: cost, members: [{dpc: 2000, ssn: 6, cost: 1}, {dpc: 2001, ssn: 6, cost: 2}] }
  gtt:
    - { match: {gt_prefix: "155501", gti: 4, tt: 0, np: 1, nai: 4}, to: {group: ag-hlr} }
    - { match: {gt_prefix: "1555"}, to: {dpc: 2000, ssn: 6} }
content_routing:
  protocol: gsm-map
  imsi_tables:
    - { name: customer-a, prefixes: ["001010"] }
  rules:
    - name: customer-a-home
      match:  { operation: [update-location, send-auth-info], imsi_in: customer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: sri-sm-np
      match:  { operation: sri-sm }
      action: { python: on_np_dip }
"#;

fn bench_routing(c: &mut Criterion) {
    let mut g = c.benchmark_group("routing");
    g.throughput(Throughput::Elements(1));

    g.bench_function("config_load", |b| b.iter(|| Config::parse(SAMPLE).unwrap()));

    let cfg = Config::parse(SAMPLE).unwrap();
    let router = Router::new(&cfg);

    // MTP3 transit resolve (DPC 2000 → hlr, with a transit alternate present).
    let transit = Inbound {
        dpc: 2000,
        ..Default::default()
    };
    g.bench_function("route_resolve", |b| b.iter(|| router.route(&transit)));

    // SCCP GTT lookup (our PC, route-on-GT to the "1555" rule).
    let gtt = Inbound {
        dpc: 1000,
        cdpa: Some(GttSelector::from_digits("15559999")),
        ..Default::default()
    };
    g.bench_function("gtt_lookup", |b| b.iter(|| router.route(&gtt)));

    // Content-rule match (updateLocation for a customer-a IMSI → route action).
    let content = Inbound {
        dpc: 1000,
        view: Some(MapView {
            operation: Some(Operation::UpdateLocation),
            imsi: Some("001010000000042".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    g.bench_function("content_match", |b| b.iter(|| router.route(&content)));

    g.finish();
}

criterion_group!(benches, bench_routing);
criterion_main!(benches);
