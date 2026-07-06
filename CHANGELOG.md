# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [0.4.0]

Phase 4: the siphon addon face. siphon-sigtran becomes a scriptable siphon node,
built and tested against siphon-sip the way the sibling addons `siphon-smpp` and
`siphon-http` are. It is an addon, not a package: there is no wheel and no PyPI,
a composing siphon binary links the crate and mounts its namespaces. The default
crate build pulls neither pyo3 nor siphon, so consumers of the pure-Rust routing
brain stay lean.

### Added
- **The `python` module** (feature `python`), the addon face. The single seam is
  `python::register(py, parent)`: a composing siphon binary calls it once at
  startup with the `siphon` package module as `parent`, mounting the `ss7` /
  `gsm_map` / `gsm_cap` namespace singletons, the `configure` / `metrics`
  functions, the `SigtranError` exception, and the shared types onto it. Scripts
  reach them with `from siphon import ss7, gsm_map, gsm_cap`. Links siphon-sip
  (git, `branch = main`), pyo3 0.29 (`auto-initialize`), and pyo3-async-runtimes
  0.29 (`tokio-runtime`), the same pins as the sibling addons.
  - **`ss7`**, the routing surface. Program the Rust tables live
    (`ss7.routes.add` / `.cache`, `ss7.gtt.add`, `ss7.content.add_rule` /
    `.address_table(...).add`), defer a config rule to a hook
    (`@ss7.content.on(name)`) or take a selector-gated general override
    (`@ss7.on_route(when=...)`), and build decisions (`ss7.route` / `ss7.drop` /
    `ss7.route_default` / `ss7.allow`). A read-only `MapView` is handed to hooks.
  - **`gsm_map` / `gsm_cap`**, MAP/CAP termination decorators
    (`@gsm_map.on_mo_forward_sm`, `@gsm_cap.on_initial_dp`, ...) that register a
    Python handler (sync or `async def`, driven to completion) per operation. The
    handler drives a `Dialogue` handle (`invoke` / `reply` / `send` / `end`); the
    engine replays the staged components onto the real Rust dialogue to build
    wire-real TCAP. Application-context helpers (`gsm_map.AC`), the originating
    helpers (`gsm_map.begin`, `mt_forward_sm`, `gsm_cap.connect`), and
    `ss7.gt(...)` addressing.
  - **Originating awaitables**: `gsm_map.send_routing_info_for_sm` and
    `dlg.result()` return an awaitable bridged onto tokio via pyo3-async-runtimes
    (the shape the sibling addons' send helpers use). Awaiting one needs a live
    SCTP transport driven by the composing siphon binary; without one it resolves
    to a clear error.
  - **`configure`** builds the node from a `sigtran.yaml` (a path, inline YAML,
    or a dict, validated through the same typed deserialiser); `metrics()`
    renders the Prometheus text.
- **Live routing-table programming** on the Rust side: `RouteResolver::add`,
  `GttResolver::add_rule`, `ContentEngine::add_rule` / `address_table_add` /
  `imsi_table_add` / `empty`, so a script mutates the tables the resolver reads
  without a restart.
- **Addon test harness** (`tests/python.rs`, feature `python`): compiled against
  siphon-sip, it mounts the namespaces through `register`, then drives a script
  end to end: the import surface, the decision constructors, live table
  programming and its error paths, a content hook firing, a genuine MO-ForwardSM
  Begin terminated through the engine, CAP `connect` staging, and the
  tokio-bridged originating awaitable. A second test names a siphon host type to
  prove the linkage.
- **Example scripts** (`examples/`): `stp.py` (a thin STP, the three override
  styles), `smsc.py` (MAP termination + multi-segment MT origination), and
  `scp.py` (a CAMEL SCP).
- **CI**: the `rust` job lints and tests both faces: the pyo3-free routing brain
  and `--features python` (which links siphon-sip and runs the addon tests). No
  wheel, maturin, or PyPI jobs.

## [0.3.0]

Phase 3: the MAP/CAP dialogue-termination SAP and the full Prometheus metric
family set. When the router decides a message terminates here, a synchronous TCAP
transaction engine now drives the dialogue and answers it; every layer feeds a
process-wide metric set a scrape endpoint renders.

### Added
- **Dialogue termination** (`dialogue`): a synchronous TCAP (Q.771-775)
  transaction engine on the published `tcap` / `sccp` / `gsm_map` / `gsm_cap`
  codecs. `DialogueEngine::deliver` decodes a locally-terminated SCCP UDT, reads
  the AARQ application context, decodes the `Invoke` operation (MAP TS 29.002 /
  CAP TS 29.078), and dispatches to a `TerminationHandler` registered per
  (SSN, operation).
  - **`Dialogue` handle**: `reply` (a ReturnResultLast in a closing End with an
    AARE), `invoke` + `send` (a Continue that holds the dialogue open), `end`,
    `abort`, keyed by transaction id (OTID/DTID) with per-dialogue invoke-id
    bookkeeping.
  - **Multi-leg flows**: a held-open dialogue (updateLocation answered with an
    insertSubscriberData leg, then the result on the peer's ack), the SMSC
    multi-segment MT-ForwardSM (one dialogue, `moreMessagesToSend` NULL on all
    but the last, each segment acked, End on the last), and the CAMEL SCP
    (initialDP answered with a connect in the closing End).
  - **Originating side**: `DialogueEngine::begin` opens a dialogue the node
    initiates (an SMSC's SRI-SM then MT-ForwardSM); the handler stages the
    opening invoke in `on_start`, and each peer Continue/End re-enters
    `on_continue`.
  - **Timers + ceiling**: the config `tcap` block (`invoke_timer_ms`,
    `dialogue_timer_ms`, `max_dialogues`). `DialogueEngine::sweep` ages out a
    dialogue whose outstanding invoke or idle time expired (returning a TCAP
    Abort); a Begin over the ceiling, or for an operation with no registered
    handler, is refused with an Abort rather than dropped.
  - Wired into the transport with `TransportHandle::serve_dialogues`: it pumps
    each locally-terminated MSU into the engine and sends the reply back to the
    peer that asked, over the association the request arrived on, plus a periodic
    sweep.
- **Metrics** (`metrics`): the full family set, maintained in Rust and rendered
  in Prometheus text-exposition format, with no per-transit-MSU allocation and no
  tenant label. Transport / link state gauges (`sigtran_association_state`,
  `sigtran_asp_state`, `sigtran_linkset_available` / `_active_links`,
  `sigtran_m2pa_link_state`), routing (`sigtran_route_available`,
  `sigtran_mtp3mg_events_total`), traffic (`sigtran_msu_total{dir,si}`,
  `sigtran_gtt_translations_total` / `_errors_total`,
  `sigtran_content_rule_hits_total`), and dialogue / TCAP
  (`sigtran_active_dialogues`, `sigtran_dialogue_timeouts_total`,
  `sigtran_invoke_timeouts_total`, `sigtran_abort_total`) alongside the existing
  `sigtran_loops_detected_total`.
- **Dialogue test harness** (`tests/dialogue.rs`): genuinely-assembled TCAP
  (Begin + AARQ + Invoke over SCCP UDT) driven through the engine end to end for
  SRI-SM, updateLocation with the ISD leg, the multi-segment MT-ForwardSM flow,
  initialDP to connect, and the originating SRI-SM, plus dialogue-ceiling and
  invoke / dialogue timer coverage. `tests/wire.rs` gains an over-the-wire
  termination scenario: an SRI-SM Begin driven over real SCTP into a running
  node, terminated in the engine, and the ReturnResultLast decoded off the wire.

### Changed
- `LocalDelivery` now carries the ingress association id so a reply routes back
  to the peer that asked.

### Still deferred
- **Python bindings** (pyo3): a later phase, exposing the routing brain and the
  `@gsm_map.on_*` / `@gsm_cap.on_*` termination decorators.
- **`sua`** stays reserved: parsed and accepted, but starting a node with a `sua`
  association returns a clear "not implemented".

## [0.2.0]

Phase 2: a working SIGTRAN transport over real kernel SCTP under the phase-1
routing brain. A [`Config`] now starts a running node that binds/connects every
association, brings its adaptation layers up, and routes + forwards real traffic.

### Added
- **Transport plane** (`transport`): `TransportHandle::start` turns a validated
  `Config` into a live node on `async-sctp`.
  - **M3UA** (RFC 4666): the ASPSM/ASPTM handshake in both directions (ASP-UP/
    -ACK, ASP-ACTIVE/-ACK honouring the AS traffic mode, ASP-INACTIVE/-DOWN,
    BEAT/-ACK), DATA carriage, and SSNM (DUNA/DAVA to PAUSE/RESUME, DAUD answered
    from live route state, SCON/DUPU noted) folded into the router.
  - **M2PA** (RFC 4165): link alignment (Alignment/Proving/Ready) driving linkset
    availability, then MTP3 MSUs in User Data.
  - **Egress selection** (`transport::registry`): an AS spreads over its active
    ASPs by traffic mode (load-share keyed on SLS, override, broadcast); an M2PA
    linkset load-spreads across its in-service links. Live ASP/link state drives
    route availability and failover to the next-priority route.
- **SI-agnostic transfer**: the transfer path routes by point code for any
  Service Indicator; a non-SCCP MSU (ISUP `SI=5`, network management, …) transits
  natively with its payload untouched. Only an SCCP MSU addressed to us is decoded
  further.
- **Loop guards**: the transfer path drops-and-counts a looping MSU, own-opc
  (the MSU's OPC is our own point code) and route-reflect (the resolved egress is
  the association the MSU arrived on), each warn-logged with OPC/DPC context.
- **`metrics`**: process-wide `sigtran_loops_detected_total{kind}` counters plus a
  Prometheus text renderer.
- **On-the-wire test harness** (`tests/wire.rs`): genuinely-assembled SS7 MSUs
  (SRI-SM, updateLocation, MO/MT-ForwardSM, initialDP) driven over real SCTP
  loopback through a running node, asserting transit forwarding, load-share
  across an AS's ASPs, failover to an M2PA linkset on ASP drop, SI-agnostic
  transfer, and both loop guards, with a tshark dissection gate over the
  forwarded frames (skips gracefully without SCTP or tshark).

### Still deferred
- **Dialogue** (`dialogue`): the MAP/CAP dialogue-termination SAP is a trait
  skeleton (phase-4); local-termination decisions are handed to it over the
  transport's local-delivery channel, ready to wire.
- **Python bindings** (pyo3): phase-3.
- **`sua`** stays reserved: parsed and accepted, but starting a node with a `sua`
  association returns a clear "not implemented".

## [0.1.0]

First release. Phase 1: the pure-Rust routing brain (config loader + resolvers +
the top-level router), built on the published SS7 codec crates (mtp3, m3ua,
sccp, tcap, gsm_map, gsm_cap, async-sctp, m2pa). Synchronous, no I/O.

### Added
- **`Config`**: the typed `sigtran.yaml` model, its serde `Deserialize`, and
  semantic validation. `Config::load(path)` / `Config::parse(text)`. Covers
  `node`, `associations`, `linksets`, `mtp3_routes`, `sccp` (local SSNs, GTT
  groups, GTT rules, E.214/E.164 `gt_conversion`), and `content_routing`. A
  routing-domain model normalises a flat file and an explicit multi-domain file
  into one internal map; the flat top level is the implicit `default` domain.
- **`point_code`**: decimal-first helpers over `mtp3::PointCode`, resolving a
  bare decimal against a node/domain variant.
- **MTP3 route resolver** (`mtp3::route`): DPC to linkset, honouring implicit
  adjacent routes (an m2pa link's `adjacent_pc`), explicit route priority
  (1 = primary), and availability. `RouteState` folds `mtp3::Mtp3Event`
  (Pause/Resume/Status) and linkset up/down; `RouteResolver::resolve` picks the
  best available route and fails over.
- **SCCP GTT resolver** (`sccp::gtt`): ordered prefix + gti/tt/np/nai matching to
  a dpc/ssn, a group (cost primary or weighted-share round-robin), local, or a
  cross-domain result. `GtConverter` does E.214 to/from E.164 via the `plmn_map`.
- **Content-routing engine** (`content`): first-match rules over a decoded
  MAP/CAP view (operation, cgpa/cdpa GT, IMSI, address/imsi-table membership) to
  a route, rewrite, screen, or Python-hook-deferral action.
- **`Router`** (`routing`): ties MTP3 transfer, SCCP GTT, and content routing
  into one inbound decision (`RouteDecision`). Content rules override GTT when a
  decoded view is present; a non-local DPC transits via the route resolver.
- **Quality bar**: unit tests across every module, integration tests that route
  genuinely-assembled SS7 (real MAP/CAP arg to TCAP to SCCP UDT to M3UA/M2PA
  framing, then peeled back into a routing decision) for SRI-SM, updateLocation,
  sendAuthInfo, cancelLocation, MO/MT-ForwardSM, and initialDP; criterion benches
  (`benches/routing.rs`); a counting-allocator leak check
  (`examples/leak_check.rs` + `scripts/mem_leak_test.sh`); CI running fmt,
  clippy (`-D warnings`), tests, `cargo bench --no-run`, and the leak gate.

### Deferred (later phases)
- **Transport** (`transport`): the SCTP-backed M3UA/M2PA serving loop is a
  trait skeleton (phase-2). No SCTP yet.
- **Dialogue** (`dialogue`): the MAP/CAP dialogue-termination SAP is a trait
  skeleton (phase-2).
- **On-the-wire test harness**: an SCTP-loopback harness (peer node sending MSUs
  over real SCTP, M3UA PPID 3 / M2PA PPID 5, with a tshark-validated pcap gate)
  is the next milestone, marked `phase2_wire_loopback_placeholder` in
  `tests/routing.rs`.
- **Python bindings** (pyo3): phase-3.

[0.3.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v0.3.0
[0.2.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v0.2.0
[0.1.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v0.1.0
