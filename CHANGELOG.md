# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.0.0] — 2026-07-21

Initial release. A SIGTRAN/SS7 runtime that turns a declarative `sigtran.yaml`
into a running signalling node, plus a siphon addon for scripting it in Python.

### Transport

- **SCTP over M3UA (RFC 4666), M2PA (RFC 4165), and SUA (RFC 3868)**, on real
  kernel SCTP. M3UA runs the ASPSM/ASPTM handshake (ASP-UP, ASP-ACTIVE honouring
  the AS traffic mode of load-share / override / broadcast, ASP-INACTIVE/DOWN,
  BEAT); M2PA aligns links; SUA carries connectionless SCCP-user traffic
  (CLDT/CLDR) bridged one-for-one to SCCP so any-to-any interworking
  (SUA ↔ M3UA ↔ M2PA) falls out of the egress framing. SSNM (DUNA/DAVA → route
  state, DAUD answered from live state) folds into the router.

### Routing

- **MTP3 routing**: implicit adjacent routes, explicit routes by priority,
  availability from Pause/Resume/Status and linkset up/down, with failover.
- **SCCP GTT**: ordered prefix + gti/tt/np/nai matching, cost and weighted-share
  groups, local termination, and the E.214 → E.164 pre-step from a PLMN map.
- **Content routing** on the decoded MAP/CAP layer (operation, calling/called GT,
  IMSI/MSISDN), first-match, evaluated on the live wire: **route**, **rewrite the
  called-party GT**, or **screen**. The decode runs only for a tenant that has
  content rules, so a pure-transit node adds no per-message cost.
- **Loop guards** (own-OPC, route-reflect, SCCP hop-counter) and **SCCP
  return-on-error** (UDTS/XUDTS/LUDTS) on undeliverable connectionless messages.
- Optional **ISUP-aware screening** on the SI=5 transit path (block/allow rules
  on message type + called/calling prefix), counted under
  `sigtran_isup_screened_total`.

### Dialogue termination

- A synchronous **TCAP transaction engine** (Begin/Continue/End + AARQ/AARE):
  single request/response, held-open multi-leg (updateLocation with an
  insertSubscriberData leg), invoke and dialogue timers, a dialogue ceiling, and
  aborts. The TCAP + SCCP bytes are wire-real, built with the published codecs.

### The siphon addon (feature = "python")

- Two startup seams a composing siphon binary calls: `configure_from(cfg)` builds
  the node from its `extensions.sigtran` config, and `register(py, parent)` mounts
  the `ss7` / `gsm_map` / `gsm_cap` / `inap` namespaces.
- **Live table programming** from Python (`ss7.routes` / `ss7.gtt` / `ss7.content`),
  so routing is shaped from a script at load time while every per-message decision
  stays in Rust.
- **MAP/CAP/INAP termination** via one decorator per namespace,
  `@ns.on_operation("<name>")` (pipe-separated for several, bare for a catch-all),
  covering a full HLR, a terminating SMSC front end, and a CAMEL/INAP SCP; with the
  MAP result and invoke builders and the CAP/INAP invoke builders, driving a
  `Dialogue` handle that observes a decoded `PeerTurn` on held-open follow-up legs.
- An in-process test seam (`siphon.configure` → a `Node` that assembles genuine
  inbound MSUs and drives them through the dialogue engine off the wire).

### Observability

- The full Prometheus metric family (association / ASP / linkset state, route
  availability, MSU rate, GTT / content / MTP3-management counters, active
  dialogues, dialogue / invoke timeouts, aborts, loop guards, ISUP screening) with
  a text renderer.

### Not in this release (planned)

- **Per-message Python routing overrides** — dispatching a routing decision into a
  script hook on the live wire. Route from Python by programming the tables live
  instead; static content-rule actions (route / rewrite / screen) run in Rust.
- **Dialogue origination** — opening a dialogue the node initiates (an SMSC's MT
  delivery, an SMS-GMSC) and correlating the peer's response over SCTP. Termination
  of inbound dialogues is fully supported.

[1.0.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v1.0.0
