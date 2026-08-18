# siphon-sigtran

[![CI](https://github.com/siphon-project/siphon-sigtran/actions/workflows/ci.yml/badge.svg)](https://github.com/siphon-project/siphon-sigtran/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-000000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![SIGTRAN](https://img.shields.io/badge/SIGTRAN-M3UA%20%7C%20M2PA-blue)](https://www.rfc-editor.org/rfc/rfc4666)

**Documentation: [sigtran.siphon-sip.org](https://sigtran.siphon-sip.org)** — concepts,
quickstart, configuration, the STP/HLR/SMSC/SCP cookbook, and the script API.

A **SIGTRAN/SS7 runtime**. It turns a declarative `sigtran.yaml` into a running
signalling node: SCTP transport (M3UA / M2PA), MTP3 routing, SCCP Global Title
Translation with E.214/E.164 conversion, **content routing** on the decoded
MAP/CAP layer, and MAP/CAP dialogue termination.

It is built on the published SS7 codec crates (`mtp3`, `m3ua`, `m2pa`, `sccp`,
`tcap`, `gsm_map`, `gsm_cap`, `async-sctp`) and adds the parts a node needs on
top of them. The per-message routing decision always runs in Rust, synchronously
and without I/O, so the node holds line rate.

> The routing brain sits under a working SIGTRAN transport over real kernel SCTP:
> M3UA (ASPSM/ASPTM) and M2PA (link alignment), SSNM folded into route state,
> inbound DATA routed and forwarded to the resolved egress. Messages addressed to
> a subsystem the node owns terminate in a synchronous TCAP transaction engine
> (SRI-SM, updateLocation with an ISD leg, multi-segment MT-ForwardSM, CAMEL
> initialDP to connect), and the full Prometheus metric family set is exposed. The
> **siphon addon face**, a `configure_from(cfg)` + `register(py, parent)` startup
> seam built and tested against siphon-sip the way the sibling addons
> `siphon-smpp` and `siphon-http` are, makes siphon-sigtran a scriptable siphon
> node. See [the siphon addon](#the-siphon-addon) and the [changelog](CHANGELOG.md).

## Quickstart

siphon-sigtran is a **library that runs inside a siphon binary**, not a standalone
server. The binary reads a `sigtran.yaml` (below), configures the node, and runs
your handler script. Policy is a few decorators; every socket, timer and codec
byte stays in Rust:

```python
from siphon import gsm_map

# Terminate mobile-originated SMS. `arg.sm_rp_*` are the raw address + TPDU bytes.
@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    await forward(sender=arg.sm_rp_oa, dest=arg.sm_rp_da, tpdu=arg.sm_rp_ui)
    dlg.reply(gsm_map.mo_forward_sm_res())   # returnResultLast, in a closing End
    dlg.end()
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
  - { id: hlr-b, adaptation: m3ua, role: server, addrs: [10.1.0.11], port: 2905 }
  - { id: msc,   adaptation: m3ua, role: server, addrs: [10.1.0.12], port: 2905 }
  - { id: xit-1, adaptation: m2pa, role: client, addrs: [10.0.1.1], port: 3565, adjacent_pc: 3000 }

# M3UA Application Servers: one AS per destination, served by its ASPs (the m3ua
# associations), with a traffic mode (RFC 4666).
application_servers:
  - { name: hlr, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a, hlr-b] }
  - { name: msc, traffic_mode: override,  routing_context: 101, asps: [msc] }

# M2PA linksets (RFC 4165): links grouped toward an adjacent PC. SLS spreads
# traffic across the links, so there is no traffic mode here.
linksets:
  - { name: transit, links: [{assoc: xit-1}] }

# MTP3 routes: dpc -> an AS or a linkset, priority (1 = primary, higher = alternate).
# The adjacent PC of an m2pa link (3000) is an implicit route; no entry needed.
mtp3_routes:
  - { dpc: 2000, as: hlr,          priority: 1 }
  - { dpc: 2000, linkset: transit, priority: 2 }   # alternate to the HLR via M2PA transit
  - { dpc: 2002, as: msc,          priority: 1 }

# SCCP: local subsystems, GTT groups, GTT rules, and E.214/E.164 conversion.
sccp:
  local_ssns: [6, 8]          # inbound for these terminates locally
  gtt_groups:
    - { name: ag-hlr,    mode: cost,  members: [{dpc: 2000, ssn: 6, cost: 1}, {dpc: 2001, ssn: 6, cost: 2}] }
    - { name: ag-home-router, mode: share, members: [{dpc: 2003, ssn: 8, weight: 1}, {dpc: 2004, ssn: 8, weight: 1}] }
  gtt:
    - { match: {gt_prefix: "155501", gti: 4, tt: 0, np: 1, nai: 4}, to: {group: ag-hlr} }
    - { match: {gt_prefix: "1555"},                                 to: {dpc: 2000, ssn: 6} }
  gt_conversion:
    plmn_map:
      - { mcc: "001", mnc: "01", e164_prefix: "15551" }

# Content routing: routes/screens on the decoded MAP layer.
content_routing:
  protocol: gsm-map
  address_tables:
    - { name: home-subs, addrs: ["15550142", "15550143"] }
  imsi_tables:
    - { name: customer-a, prefixes: ["001010", "001011"] }
  rules:
    - name: customer-a-home
      match:  { operation: [update-location, send-auth-info, cancel-location], imsi_in: customer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: sri-sm-route
      match:  { operation: sri-sm }
      action: { route: {dpc: 2000, ssn: 6} }
```

### Config reference

| Block | Fields |
|---|---|
| `node` | `point_code` (decimal), `variant` (`itu`/`ansi`/`china`), `network_indicator` |
| `associations` | `id`, `adaptation` (`m3ua`/`m2pa`), `role` (`server`/`client`), `addrs`, `port`, `adjacent_pc` (m2pa) |
| `application_servers` | `name`, `traffic_mode` (`loadshare`/`override`/`broadcast`), `routing_context`, `asps` (m3ua association ids) |
| `linksets` | `name`, `links` (`assoc`); M2PA only, adjacent PC comes from the association |
| `mtp3_routes` | `dpc`, `as` or `linkset`, `priority` (1 = primary) |
| `sccp.local_ssns` | the subsystems the node owns |
| `sccp.gtt_groups` | `name`, `mode` (`cost`/`share`), `members` (`dpc` + `ssn` + `cost`/`weight`) |
| `sccp.gtt` | ordered rules: `match` (`gt_prefix`, `gti`, `tt`, `np`, `nai`) to a `dpc`+`ssn`, a `group`, or `local` |
| `sccp.gt_conversion` | `plmn_map` (MCC+MNC to E.164 prefix), driving the inbound E.214 to E.164 pre-step before GTT |
| `content_routing` | `protocol`, `address_tables`, `imsi_tables`, ordered `rules` |

A content rule `match` combines `operation` (a name or a list), `imsi_in`,
`imsi_prefix`, `cdpa_gt_in`, `cgpa_gt_in` (all AND). Its `action` is one of
`route` (to a `dpc`+`ssn` or a `group`), `rewrite_cdpa_gt`, `screen`, or
`python` (defer to a named hook, resolved by the runtime).

## The siphon addon

siphon-sigtran is a siphon addon, not a package. There is no wheel and no PyPI. It
builds and is tested against siphon-sip, the way the sibling addons `siphon-smpp`
and `siphon-http` are, behind the `python` feature. A composing siphon binary
wires it in at startup with two seams: it reads its `extensions.sigtran` config
and calls `configure_from(cfg)` to build the node, and it mounts the namespaces:

```rust
// at startup: build the node from the addon config, then mount the namespaces
siphon_sigtran::python::configure_from(&cfg);
siphon_sigtran::python::register(py, parent)?;
```

`register` mounts the `ss7` / `gsm_map` / `gsm_cap` / `inap` namespaces (plus
`metrics` and the shared types) onto `siphon`, so scripts import them with
`from siphon import ...`. The script never configures the node; it just programs
it:

```python
from siphon import ss7, gsm_map

# 1. Program the Rust routing tables live (routing stays in Rust at line rate).
ss7.routes.add(dpc=2000, linkset="transit", priority=3)
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")

# 2. A content rule on the decoded MAP layer (route / rewrite / screen, in Rust).
ss7.content.add_rule(
    name="steer-home-sri-sm",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"route": {"group": "ag-router"}},
)

# 3. Terminate a MAP/CAP dialogue (one or more operations, pipe-separated).
@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    await forward_to_smpp(sender=arg.sm_rp_oa, dest=arg.sm_rp_da, tpdu=arg.sm_rp_ui)
    dlg.reply(gsm_map.mo_forward_sm_res())
    dlg.end()
```

The termination decorators, result builders and invoke builders cover a full HLR
(updateLocation held open for an insertSubscriberData leg, then the result;
sendAuthenticationInfo), a terminating SMSC front end (MO-ForwardSM), and a CAMEL
SCP (initialDP to connect or releaseCall, with RequestReportBCSMEvent and
applyCharging). On a held-open dialogue's follow-up leg the handler is re-entered
with a decoded `PeerTurn`, so it can observe the peer's reply (the
insertSubscriberData `returnResultLast`, say) before it closes.

The runnable tutorials live under [`examples/`](examples): `stp.py` (a thin STP),
`hlr.py` (an HLR), `smsc.py` (MO-SMS termination), and `scp.py` (a CAMEL SCP).
Routing is Rust: the static `sigtran.yaml`, plus live table programming from a
script (`ss7.routes` / `ss7.gtt` / `ss7.content`), so every per-message decision
stays in Rust at line rate.

## What it covers

| Area | Covered |
|---|---|
| Config | full `sigtran.yaml` parse + semantic validation (dangling refs, duplicate names, point-code range, unknown operations); `tcap` timers + ceiling |
| MTP3 routing | implicit adjacent routes, explicit routes by priority, availability from Pause/Resume/Status + linkset up/down, failover |
| SCCP GTT | ordered prefix + gti/tt/np/nai matching, cost + weighted-share groups, local termination |
| GT conversion | E.214 to/from E.164 via the PLMN map |
| Content routing | first-match over operation / GT / IMSI-table membership; route, rewrite the called-party GT, or screen, on the live wire |
| Transport (M3UA/M2PA/SCTP) | real kernel SCTP; M3UA ASPSM/ASPTM handshake + traffic modes, M2PA link alignment, SSNM to route state, load-share + failover, SI-agnostic transfer, own-opc + route-reflect loop guards |
| Dialogue termination | TCAP transaction engine: Begin/Continue/End + AARQ/AARE, per-(SSN, operation) handlers, single response, held-open multi-leg, invoke / dialogue timers + ceiling, aborts |
| Metrics | full Prometheus family set (association / ASP / linkset state, route availability, MSU rate, GTT + content + MTP3-management counters, active dialogues, dialogue / invoke timeouts, aborts, loop guards) with a text renderer |
| siphon addon | `configure_from` + `register(py, parent)` startup seams (built + tested against siphon-sip, no wheel/PyPI); live table programming (`ss7.routes` / `ss7.gtt` / `ss7.content`); MAP/CAP/INAP termination decorators (`@ns.on_operation`) for the full HLR / terminating-SMSC / SCP set, MAP result + invoke builders (`update_location_res`, `send_authentication_info_res`, `insert_subscriber_data`, ...) and CAP `connect` / `release_call` / `request_report_bcsm_event` / `apply_charging`, driving a `Dialogue` handle with a decoded `PeerTurn` on held-open follow-up legs |

> **Scope (1.0).** The 1.0 API is exactly what works, tested over real SCTP: SS7
> transit + routing, GTT, static + live-programmed content routing, and MAP/CAP/INAP
> dialogue **termination**. Two capabilities are deliberately **not** in the 1.0
> surface and are the post-1.0 roadmap: **per-message Python routing overrides**
> (dispatching a routing decision into a script hook on the wire) and **dialogue
> origination** (an SMSC's MT delivery, an SMS-GMSC), both of which need the async
> Python override / originating bridge. Routing is programmed from Python at load
> time (the decision stays in Rust); termination is scripted per dialogue.

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
