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

> **Status: phase 4.** The routing brain (phase 1) sits under a working SIGTRAN
> transport over real kernel SCTP (phase 2): M3UA (ASPSM/ASPTM) and M2PA (link
> alignment), SSNM folded into route state, and inbound DATA routed and forwarded
> to the resolved egress. Phase 3 added the MAP/CAP dialogue-termination SAP, a
> synchronous TCAP transaction engine that terminates the messages addressed to a
> subsystem we own (SRI-SM, updateLocation with an ISD leg, multi-segment
> MT-ForwardSM, CAMEL initialDP to connect), plus the full Prometheus metric
> family set. This release adds the **siphon addon face**: a `register(py,
> parent)` seam, built and tested against siphon-sip the way the sibling addons
> `siphon-smpp` and `siphon-http` are, that makes siphon-sigtran a scriptable
> siphon node. See [the siphon addon](#the-siphon-addon) and the
> [changelog](CHANGELOG.md).

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

## The siphon addon

The `python` feature turns siphon-sigtran into a scriptable siphon node. It is a
siphon addon, not a package. There is no wheel and no PyPI. It builds and is
tested against siphon-sip, the way the sibling addons `siphon-smpp` and
`siphon-http` are. A composing siphon binary calls the one seam at startup:

```rust
// once, with the siphon package module as `parent`
siphon_sigtran::python::register(py, parent)?;
```

That mounts the `ss7` / `gsm_map` / `gsm_cap` namespaces (plus `configure` /
`metrics` and the shared types) onto `siphon`, so scripts import them with
`from siphon import ...`. The default crate build pulls neither pyo3 nor siphon,
so `cargo add siphon-sigtran` for the pure-Rust routing brain stays lean.
Configure the node from a `sigtran.yaml`, then program it:

```python
import siphon
from siphon import ss7, gsm_map

siphon.configure("sigtran.yaml")   # a path, inline YAML, or a dict

# 1. Program the Rust routing tables live (routing stays in Rust at line rate).
ss7.routes.add(dpc=2000, linkset="transit", priority=3)
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")

# 2. Defer a config rule (action `{python: on_np_dip}`) to a hook.
@ss7.content.on("on_np_dip")
async def np_dip(msg):
    return ss7.route(dpc=2006, ssn=6) if ported(msg.msisdn) else ss7.route_default()

# 3. Terminate a MAP/CAP dialogue.
@gsm_map.on_mo_forward_sm
async def on_mo(dlg, arg):
    await forward_to_smpp(sender=arg.sm_rp_oa, dest=arg.sm_rp_da, tpdu=arg.sm_rp_ui)
    dlg.reply(gsm_map.mo_forward_sm_res())
    dlg.end()
```

Routing decisions (`ss7.route` / `ss7.drop` / `ss7.route_default` / `ss7.allow`)
and the general override `@ss7.on_route(when=...)` round out the three override
styles. The runnable tutorial lives under [`examples/`](examples): `stp.py`
(a thin STP), `smsc.py` (MAP termination + multi-segment MT), and `scp.py`
(a CAMEL SCP). An `async def` handler runs on siphon's runtime; an originating
helper (`gsm_map.send_routing_info_for_sm`, `dlg.result()`) returns an awaitable
bridged onto tokio, and the SCTP transport that fulfils it is driven by the
composing siphon binary.

## What it covers (phase 4)

| Area | Covered |
|---|---|
| Config | full `sigtran.yaml` parse + semantic validation (dangling refs, duplicate names, point-code range, unknown operations); `tcap` timers + ceiling |
| MTP3 routing | implicit adjacent routes, explicit routes by priority, availability from Pause/Resume/Status + linkset up/down, failover |
| SCCP GTT | ordered prefix + gti/tt/np/nai matching, cost + weighted-share groups, local termination |
| GT conversion | E.214 to/from E.164 via the PLMN map |
| Content routing | first-match over operation / GT / IMSI-table membership; route, rewrite, screen, hook-deferral |
| Transport (M3UA/M2PA/SCTP) | real kernel SCTP; M3UA ASPSM/ASPTM handshake + traffic modes, M2PA link alignment, SSNM to route state, load-share + failover, SI-agnostic transfer, own-opc + route-reflect loop guards |
| Dialogue termination | TCAP transaction engine: Begin/Continue/End + AARQ/AARE, per-(SSN, operation) handlers, single response, held-open multi-leg, originating dialogues, invoke / dialogue timers + ceiling, aborts |
| Metrics | full Prometheus family set (association / ASP / linkset state, route availability, MSU rate, GTT + content + MTP3-management counters, active dialogues, dialogue / invoke timeouts, aborts, loop guards) with a text renderer |
| siphon addon | `register(py, parent)` seam (built + tested against siphon-sip, no wheel/PyPI); live table programming (`ss7.routes` / `ss7.gtt` / `ss7.content`), deferred + general routing hooks, MAP/CAP termination decorators driving a `Dialogue` handle |

The transport is proven end-to-end in `tests/wire.rs`: genuinely-assembled SS7
MSUs (SRI-SM, updateLocation, MO/MT-ForwardSM, initialDP) driven over real SCTP
loopback through a running node, asserting load-share across an AS's ASPs,
failover to an M2PA linkset when an ASP drops, SI-agnostic transfer of a non-SCCP
MSU, both loop guards, and an SRI-SM terminated in the dialogue engine with the
result read back off the wire, with a tshark gate over the forwarded frames. The
dialogue engine is driven against assembled TCAP end to end in `tests/dialogue.rs`.

Standards referenced: M3UA (RFC 4666), M2PA (RFC 4165), SCTP (RFC 4960),
MTP3 (ITU-T Q.704), SCCP GTT (ITU-T Q.714), TCAP (ITU-T Q.771-775),
MAP (3GPP TS 29.002), CAMEL (TS 29.078).

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
   m3ua / m2pa · sctp  (transport over real kernel SCTP)
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
through the full `Router`. `tests/wire.rs` then drives the same kind of bytes over
real SCTP loopback through a running node. The wire tests need kernel SCTP
(`sudo modprobe sctp`); they print a SKIP and pass if it is unavailable, and the
tshark dissection gate skips if `tshark` is not installed.

## License

MIT, see [LICENSE](LICENSE).
