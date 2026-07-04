# siphon-sigtran

[![crates.io](https://img.shields.io/crates/v/siphon-sigtran.svg)](https://crates.io/crates/siphon-sigtran)
[![docs.rs](https://docs.rs/siphon-sigtran/badge.svg)](https://docs.rs/siphon-sigtran)
[![CI](https://github.com/siphon-project/siphon-sigtran/actions/workflows/ci.yml/badge.svg)](https://github.com/siphon-project/siphon-sigtran/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A **SIGTRAN/SS7 runtime**. It turns a declarative `sigtran.yaml` into a running
signalling node: SCTP transport (M3UA / M2PA), MTP3 routing, SCCP Global Title
Translation with E.214/E.164 conversion, **content routing** on the decoded
MAP/CAP layer, and MAP/CAP dialogue termination.

It is built on the published SS7 codec crates (`mtp3`, `m3ua`, `m2pa`, `sccp`,
`tcap`, `gsm_map`, `gsm_cap`, `async-sctp`) and adds the parts a node needs on
top of them. The per-message routing decision always runs in Rust, synchronously
and without I/O, so the node holds line rate.

> **Status: phase 1.** This release is the pure-Rust routing brain: the config
> loader and the resolvers. The SCTP transport, the dialogue-termination SAP, an
> on-the-wire loopback test harness, and the Python bindings are later phases and
> ship as clearly-marked trait stubs. See the [changelog](CHANGELOG.md).

## Quickstart

```rust
use siphon_sigtran::{Config, Router};
use siphon_sigtran::routing::{Inbound, RouteDecision};

let config = Config::parse(YAML)?;
let router = Router::new(&config);

// A message addressed to a point code the node doesn't own transits: the route
// resolver picks the egress linkset.
let decision = router.route(&Inbound { dpc: 2000, ..Default::default() });
assert!(matches!(decision, RouteDecision::Route { .. }));
# Ok::<(), siphon_sigtran::Error>(())
```

## The config, `sigtran.yaml`

A single file describes the node. Every value below is synthetic (test PLMN 001/01,
`+1-555-01xx` global titles, decimal point codes).

```yaml
node:
  point_code: 1000            # our PC (ITU 14-bit, decimal)
  variant: itu
  network_indicator: international

# SCTP transport plane. m2pa links carry their adjacent PC inline.
associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
  - { id: msc,   adaptation: m3ua, role: server, addrs: [10.1.0.12], port: 2905 }
  - { id: xit-1, adaptation: m2pa, role: client, addrs: [10.0.1.1], port: 3565, adjacent_pc: 3000 }

# Linksets (m3ua = an application server with a traffic mode; m2pa = a linkset).
linksets:
  - { name: hlr,     adaptation: m3ua, traffic_mode: loadshare, links: [{assoc: hlr-a, slc: 0}] }
  - { name: msc,     adaptation: m3ua, traffic_mode: override,  links: [{assoc: msc, slc: 0}] }
  - { name: transit, adaptation: m2pa, traffic_mode: loadshare, links: [{assoc: xit-1, slc: 0}] }

# MTP3 routes: dpc -> linkset, priority (1 = primary, higher = alternate). The
# adjacent PC of an m2pa link (3000) is an implicit route; no entry needed.
mtp3_routes:
  - { dpc: 2000, linkset: hlr,     priority: 1 }
  - { dpc: 2000, linkset: transit, priority: 2 }   # alternate to the HLR
  - { dpc: 2002, linkset: msc,     priority: 1 }

# SCCP: local subsystems, GTT groups, GTT rules, and E.214/E.164 conversion.
sccp:
  local_ssns: [6, 8]          # inbound for these terminates locally
  gtt_groups:
    - { name: ag-hlr,    mode: cost,  members: [{dpc: 2000, ssn: 6, cost: 1}, {dpc: 2001, ssn: 6, cost: 2}] }
    - { name: ag-router, mode: share, members: [{dpc: 2003, ssn: 8, weight: 1}, {dpc: 2004, ssn: 8, weight: 1}] }
  gtt:
    - { match: {gt_prefix: "155501", gti: 4, tt: 0, np: 1, nai: 4}, to: {group: ag-hlr} }
    - { match: {gt_prefix: "1555"},                                 to: {dpc: 2000, ssn: 6} }
  gt_conversion:
    plmn_map:
      - { mcc: "001", mnc: "01", e164_prefix: "15551" }
    rules:
      - { name: e214-in, match: {np: e214}, action: {to_e164_via: plmn_map} }

# Content routing: routes/screens on the decoded MAP layer.
content_routing:
  protocol: gsm-map
  address_tables:
    - { name: home-subs, addrs: ["15550142", "15550143"] }
  imsi_tables:
    - { name: buyer-a, prefixes: ["001010", "001011"] }
  rules:
    - name: buyer-a-home
      match:  { operation: [update-location, send-auth-info, cancel-location], imsi_in: buyer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: sri-sm-np
      match:  { operation: sri-sm }
      action: { python: on_np_dip }
```

### Config reference

| Block | Fields |
|---|---|
| `node` | `point_code` (decimal), `variant` (`itu`/`ansi`/`china`), `network_indicator` |
| `associations` | `id`, `adaptation` (`m3ua`/`m2pa`), `role` (`server`/`client`), `addrs`, `port`, `adjacent_pc` (m2pa) |
| `linksets` | `name`, `adaptation`, `traffic_mode` (`loadshare`/`override`/`broadcast`), `links` (`assoc` + `slc`) |
| `mtp3_routes` | `dpc`, `linkset`, `priority` (1 = primary) |
| `sccp.local_ssns` | the subsystems the node owns |
| `sccp.gtt_groups` | `name`, `mode` (`cost`/`share`), `members` (`dpc` + `ssn` + `cost`/`weight`) |
| `sccp.gtt` | ordered rules: `match` (`gt_prefix`, `gti`, `tt`, `np`, `nai`) to a `dpc`+`ssn`, a `group`, or `local` |
| `sccp.gt_conversion` | `plmn_map` (MCC+MNC to E.164 prefix) + `rules` (E.214 <-> E.164) |
| `content_routing` | `protocol`, `address_tables`, `imsi_tables`, ordered `rules` |

A content rule `match` combines `operation` (a name or a list), `imsi_in`,
`imsi_prefix`, `cdpa_gt_in`, `cgpa_gt_in` (all AND). Its `action` is one of
`route` (to a `dpc`+`ssn` or a `group`), `rewrite_cdpa_gt`, `screen`, or
`python` (defer to a named hook, resolved by the runtime).

## What it covers (phase 1)

| Area | Covered |
|---|---|
| Config | full `sigtran.yaml` parse + semantic validation (dangling refs, duplicate names, point-code range, unknown operations) |
| MTP3 routing | implicit adjacent routes, explicit routes by priority, availability from Pause/Resume/Status + linkset up/down, failover |
| SCCP GTT | ordered prefix + gti/tt/np/nai matching, cost + weighted-share groups, local termination |
| GT conversion | E.214 to/from E.164 via the PLMN map |
| Content routing | first-match over operation / GT / IMSI-table membership; route, rewrite, screen, hook-deferral |
| Transport (M3UA/M2PA/SCTP) | trait stubs only (phase-2) |
| Dialogue termination | trait stubs only (phase-2) |
| Python bindings | phase-3 |

Standards referenced: M3UA (RFC 4666), M2PA (RFC 4165), SCTP (RFC 4960),
MTP3 (ITU-T Q.704), SCCP GTT (ITU-T Q.714), TCAP (Q.773), MAP (3GPP TS 29.002),
CAMEL (TS 29.078).

## Performance

The routing brain is allocation-light. Rough single-core numbers (criterion,
`benches/routing.rs`, synthetic single-domain node):

| Operation | Time |
|---|---|
| config load (parse + validate) | ~28 µs |
| MTP3 route resolve (with failover alternate) | ~28 ns |
| SCCP GTT lookup | ~40 ns |
| content-rule match | ~50 ns |

A full config reload is microseconds; a per-message routing decision is tens of
nanoseconds. Run `cargo bench` for numbers on your hardware.

## Where it fits

```
   content routing     (routes on the decoded MAP/CAP layer)
        │
   map / cap · tcap    (operations + transactions)
        │
   sccp                (GTT + E.214/E.164)
        │
   mtp3                (route resolver, DPC to linkset)
        │
   m3ua / m2pa · sctp  (transport, phase-2)
```

More: [`docs/OVERVIEW.md`](docs/OVERVIEW.md).

## Development

```bash
cargo test                                  # unit + integration + doctest
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo bench --no-run                        # keep the benches compiling
cargo run --release --example leak_check    # counting-allocator leak gate -> PASS
cargo deny check
```

The integration tests in `tests/routing.rs` assemble real SS7 (a MAP/CAP argument
into TCAP into an SCCP UDT into M3UA/M2PA framing) and route the resulting bytes
through the full `Router`. The on-the-wire SCTP-loopback harness is the phase-2
milestone (marked in that file).

## License

MIT, see [LICENSE](LICENSE).
