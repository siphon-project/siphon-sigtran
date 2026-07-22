//! Memory-leak check.
//!
//! A counting global allocator tracks live bytes (allocated minus freed). RSS is
//! too noisy (the OS and allocator retain freed pages), but live bytes are
//! exact, so a real leak shows up as monotonic growth. Two phases:
//!
//!   1. **config** parse + validate a full single-tenant `sigtran.yaml` over and
//!      over (the serde_yaml + validation + table-compile path).
//!   2. **route** build a `Router` once, then churn resolutions: an MTP3 transit
//!      transfer, an SCCP GTT lookup, and a content-rule match, each cloning the
//!      small `Inbound`/decision structs.
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. Driven by `scripts/mem_leak_test.sh`.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use siphon_sigtran::config::Config;
use siphon_sigtran::content::{MapView, Operation};
use siphon_sigtran::routing::{Inbound, Router};
use siphon_sigtran::sccp::gtt::GttSelector;

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

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
  gtt:
    - { match: {gt_prefix: "1555"}, to: {dpc: 2000, ssn: 6} }
content_routing:
  protocol: gsm-map
  imsi_tables:
    - { name: customer-a, prefixes: ["001010"] }
  rules:
    - name: customer-a-home
      match:  { operation: [update-location], imsi_in: customer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: sri-sm-np
      match:  { operation: sri-sm }
      action: { python: on_np_dip }
"#;

// ── Phase 1: config parse/validate churn ────────────────────────────────────
fn config_cycle(iters: usize) {
    for _ in 0..iters {
        let cfg = Config::parse(SAMPLE).unwrap();
        std::hint::black_box(cfg.tenants.len());
    }
}

// ── Phase 2: route-resolve churn ────────────────────────────────────────────
fn route_cycle(router: &Router, iters: usize) {
    let transit = Inbound {
        dpc: 2000,
        ..Default::default()
    };
    let gtt = Inbound {
        dpc: 1000,
        cdpa: Some(GttSelector::from_digits("15559999")),
        ..Default::default()
    };
    let content = Inbound {
        dpc: 1000,
        view: Some(MapView {
            operation: Some(Operation::UpdateLocation),
            imsi: Some("001010000000042".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    for _ in 0..iters {
        std::hint::black_box(router.route(&transit));
        std::hint::black_box(router.route(&gtt));
        std::hint::black_box(router.route(&content));
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (delta {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 50_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: config parse + validate.
    println!("[config] {CYCLES} x {ITERS} parse + validate cycles");
    config_cycle(ITERS); // warm up
    let cfg_base = live();
    for c in 1..=CYCLES {
        config_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), cfg_base);
    }
    let cfg_growth = live() - cfg_base;

    // Phase 2: route resolution.
    println!("\n[route] {CYCLES} x {ITERS} x 3 resolutions (transit + gtt + content)");
    let cfg = Config::parse(SAMPLE).unwrap();
    let router = Router::new(&cfg);
    route_cycle(&router, ITERS); // warm up
    let route_base = live();
    for c in 1..=CYCLES {
        route_cycle(&router, ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), route_base);
    }
    let route_growth = live() - route_base;

    // Verdict.
    println!();
    let mut ok = true;
    if cfg_growth > BUDGET {
        eprintln!("FAIL: config live bytes grew {cfg_growth} (> {BUDGET})");
        ok = false;
    }
    if route_growth > BUDGET {
        eprintln!("FAIL: route live bytes grew {route_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!("PASS: config delta {cfg_growth} <= {BUDGET}; route delta {route_growth} <= {BUDGET}");
}
