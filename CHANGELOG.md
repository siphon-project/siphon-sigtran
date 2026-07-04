# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

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

[0.1.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v0.1.0
