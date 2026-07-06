# Configuration

One file, `sigtran.yaml`, describes the node: its point code, the SCTP
transport plane, the MTP3 route table, the SCCP/GTT tables, and the
content-routing rules. The addon loads it with
[`siphon.configure(...)`](script-api.md#configure) (a path, an inline YAML
string, or a dict); a pure-Rust embedding loads the same file with
`Config::load`. Parsing **validates** the whole file: dangling references,
duplicate names, point codes out of range for the variant, and unknown
operation names are rejected at load, not at 3 am.

A complete annotated example (every value synthetic: test PLMN 001/01,
`+1-555-01xx` global titles, decimal point codes):

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

# M3UA Application Servers: one AS per destination, served by its ASPs (the
# m3ua associations), with a traffic mode (RFC 4666).
application_servers:
  - { name: hlr, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a, hlr-b] }
  - { name: msc, traffic_mode: override,  routing_context: 101, asps: [msc] }

# M2PA linksets (RFC 4165): links grouped toward an adjacent PC. SLS spreads
# traffic across the links, so there is no traffic mode here.
linksets:
  - { name: transit, links: [{assoc: xit-1, slc: 0}] }

# MTP3 routes: dpc -> an AS or a linkset, priority (1 = primary, higher =
# alternate). The adjacent PC of an m2pa link (3000) is an implicit route.
mtp3_routes:
  - { dpc: 2000, as: hlr,          priority: 1 }
  - { dpc: 2000, linkset: transit, priority: 2 }   # alternate via M2PA transit
  - { dpc: 2002, as: msc,          priority: 1 }

# SCCP: local subsystems, GTT groups, GTT rules, and E.214/E.164 conversion.
sccp:
  local_ssns: [6, 8]          # inbound for these terminates locally
  gtt_groups:
    - { name: ag-hlr,         mode: cost,  members: [{dpc: 2000, ssn: 6, cost: 1}, {dpc: 2001, ssn: 6, cost: 2}] }
    - { name: ag-home-router, mode: share, members: [{dpc: 2003, ssn: 8, weight: 1}, {dpc: 2004, ssn: 8, weight: 1}] }
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
    - { name: customer-a, prefixes: ["001010", "001011"] }
  rules:
    - name: customer-a-home
      match:  { operation: [update-location, send-auth-info, cancel-location], imsi_in: customer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: sri-sm-np
      match:  { operation: sri-sm }
      action: { python: on_np_dip }
```

## `node` { #node }

Our identity.

| Field | Default | Meaning |
|---|---|---|
| `point_code` | *(required)* | Our point code, **decimal**, resolved under `variant`. |
| `variant` | *(required)* | SS7 variant: `itu`, `ansi`, or `china`. Fixes the point-code width, so an out-of-range PC is a load error. |
| `network_indicator` | `international` | Q.704 NI for messages we originate: `international`, `international_spare`, `national`, `national_spare`. |

Point codes are decimal integers throughout the file, the way an operator
reads them off a plan.

## `associations` { #associations }

The SCTP transport plane: one entry per association.

| Field | Default | Meaning |
|---|---|---|
| `id` | *(required)* | Association id, referenced by AS `asps` and linkset `links`. Unique. |
| `adaptation` | *(required)* | `m3ua` (RFC 4666) or `m2pa` (RFC 4165). |
| `role` | *(required)* | `server` (we listen) or `client` (we connect). |
| `addrs` | *(required)* | One or more IP addresses. More than one enables SCTP multihoming. |
| `port` | *(required)* | SCTP port. Convention: 2905 for M3UA, 3565 for M2PA. |
| `adjacent_pc` | *(m2pa only)* | The adjacent point code reached directly over this link. An adjacent PC is an **implicit route**; it needs no `mtp3_routes` entry. |

The value `sua` is accepted by the parser as a reserved adaptation so a plan
can name it, but no SUA transport exists in this release; starting a node with
a `sua` association returns a clear "not implemented".

## `application_servers` { #application-servers }

M3UA Application Servers (RFC 4666). An AS is a logical destination served by
one or more ASPs; each ASP is an `m3ua` association, and the per-ASP
ASPSM/ASPTM state machine brings it up.

| Field | Meaning |
|---|---|
| `name` | AS name, referenced by `mtp3_routes` (`as:`). Shares one namespace with linkset names, so a route reference never resolves two ways. |
| `traffic_mode` | `loadshare` (SLS-keyed spread over the active ASPs), `override` (one active, others standby), or `broadcast` (every active ASP). An AS property, not per-ASP. |
| `routing_context` | The Routing Context identifying this AS in ASPAC/DATA. |
| `asps` | The member ASPs: association ids. Each must be an `m3ua` association. |

## `linksets` { #linksets }

M2PA linksets (RFC 4165). M2PA replaces MTP2, so the classic linkset/link
model applies directly: a linkset groups links toward an adjacent point code,
and SLS spreads traffic across the in-service links. There is no traffic mode
here.

| Field | Meaning |
|---|---|
| `name` | Linkset name, referenced by `mtp3_routes` (`linkset:`). |
| `links` | The member links: `{assoc, slc}`. Each `assoc` must be an `m2pa` association; its adjacent PC comes from the association's `adjacent_pc`. |

## `mtp3_routes` { #mtp3-routes }

The static route table: DPC to a destination, by priority.

| Field | Meaning |
|---|---|
| `dpc` | Destination point code (decimal, validated against the node variant). |
| `as` **or** `linkset` | The destination. Exactly one of the two; naming both, or neither, is a load error. |
| `priority` | **1 = primary**; higher numbers are alternates. The resolver picks the lowest-priority *available* route and fails over as availability changes. |

Adjacent PCs on M2PA links are implicit routes and need no entry. Availability
comes from live state: M3UA ASP active/inactive, M2PA link in/out of service,
and MTP3 management (Pause / Resume / Status) folded in from the wire. See
[Routing model & coverage](routing.md#availability).

## `sccp` { #sccp }

### `local_ssns`

The subsystem numbers this node owns. Inbound SCCP addressed to one of them
(directly, or via a GTT result of `local`) terminates in the dialogue engine
instead of being forwarded. Termination decorators register handlers on these
SSNs ([Script API](script-api.md#gsm-map)).

### `gtt_groups`

Named result sets for GTT, for cost-based failover or weighted sharing:

| Field | Meaning |
|---|---|
| `name` | Group name, referenced by `gtt` and content-rule `route` targets. |
| `mode` | `cost` (lowest cost primary, others fail-over alternates) or `share` (weighted round-robin). |
| `members` | `{dpc, ssn}` plus `cost` (for `cost` groups) or `weight` (for `share` groups). |

### `gtt` { #gtt }

The ordered translation rules. First match wins.

- **`match`**: any of `gt_prefix` (leading GT digits), `gti`, `tt`, `np`,
  `nai`. All present fields must hold.
- **`to`**: exactly one of `{dpc, ssn}` (a concrete destination), `{group}` (a
  named group), or `{local: true}` (terminate here).

### `gt_conversion` { #gt-conversion }

E.214 (mobile global title) to E.164 conversion and back. Roaming MAP
addresses an HLR with an E.214 called party: the home network's E.164 prefix
(mapped from the IMSI's MCC+MNC) plus the MSIN. The converter runs **before**
GTT inbound, and can build the E.214 form outbound.

- **`plmn_map`**: the network numbering map, `{mcc, mnc, e164_prefix}` entries.
- **`rules`**: ordered, each `{name, match, action}`:
    - `match.np`: `e214` or `e164`;
    - `match.addressing`: optional hint, e.g. `imsi` for the outbound
      E.164-to-E.214 case;
    - `action`: `to_e164_via` or `to_e214_via`, naming the map (`plmn_map`).

## `tcap` { #tcap }

The dialogue-termination engine's timers and ceiling. Node-wide; the defaults
sit in the Q.774 default operation-timer neighbourhood, and a low-volume node
never touches them.

```yaml
tcap:
  invoke_timer_ms: 15000       # outstanding invoke ages out (default)
  dialogue_timer_ms: 30000     # idle dialogue ages out (default)
  max_dialogues: 100000        # Begin over the ceiling is refused with an Abort
```

| Field | Default | Meaning |
|---|---|---|
| `invoke_timer_ms` | `15000` | How long an outstanding invoke waits for its result before it is aged out (counted in `sigtran_invoke_timeouts_total`). |
| `dialogue_timer_ms` | `30000` | How long a dialogue may sit idle before it is aged out (counted in `sigtran_dialogue_timeouts_total`). |
| `max_dialogues` | `100000` | Ceiling on concurrently open dialogues. A `Begin` over it is rejected with a P-Abort. |

## `content_routing` { #content-routing }

Routing on the decoded MAP/CAP layer. Ordered rules, first match wins; rules a
script adds live are prepended, so a fresh override wins over config.

| Field | Meaning |
|---|---|
| `protocol` | Which application layer to decode: `gsm-map` (TS 29.002) or `gsm-cap` (TS 29.078). |
| `address_tables` | Named sets of GT digit strings: `{name, addrs}`. |
| `imsi_tables` | Named sets of IMSI prefixes (leading MCC+MNC[+MSIN] digits): `{name, prefixes}`. |
| `rules` | The ordered rules: `{name, match, action}`. |

A rule `match` combines (all present fields must hold, absent fields are
wildcards):

| Match field | Meaning |
|---|---|
| `operation` | A kebab-case operation name or a list of them. Unknown names are a load error; see [the operation table](routing.md#operations). |
| `imsi_in` | The decoded IMSI is in this named `imsi_table`. |
| `imsi_prefix` | The decoded IMSI starts with this prefix. |
| `cdpa_gt_in` | The called-party GT digits are in this named `address_table`. |
| `cgpa_gt_in` | The calling-party GT digits are in this named `address_table`. |

The `action` is one of:

| Action | Meaning |
|---|---|
| `route` | To `{dpc, ssn}` or `{group: ...}`. |
| `rewrite_cdpa_gt` | Rewrite the called-party GT digits before forwarding (may be combined with `route`; alone, the rewrite applies and the message falls through to GTT). |
| `screen` | `true` drops the message (counted per rule). |
| `python` | Defer to a named script hook registered with [`@ss7.content.on(name)`](script-api.md#hooks). |

## How the pieces connect

```
sigtran.yaml
  |- node                 -> our PC / variant / NI
  |- associations         -> SCTP transport plane
  |- application_servers  -> M3UA AS over the m3ua associations
  |- linksets             -> M2PA linksets over the m2pa associations
  |- mtp3_routes          -> DPC -> AS/linkset, by priority
  |- sccp                 -> owned SSNs, GTT (+ groups), E.214 conversion
  |- tcap                 -> dialogue timers + ceiling
  |- content_routing      -> rules on the decoded MAP/CAP view
```

A full config load (parse + validation) costs about 28 microseconds, so
re-configuring is free. Next: the [Script API](script-api.md) your handlers
use, or the [Cookbook](cookbook/index.md) to see config and script work
together.
