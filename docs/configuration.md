# Configuration

One file, `sigtran.yaml`, describes the node: its point code, the SCTP
transport plane, the MTP3 route table, the SCCP/GTT tables, and the
content-routing rules. The composing siphon binary loads it at startup (you
point `extensions.sigtran` at it; see
[Using it in a SIPhon build](integration.md)). Parsing **validates** the whole
file: dangling references, duplicate names, point codes out of range for the
variant, and unknown operation names are rejected at load, not at 3 am.

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
  - { name: transit, links: [{assoc: xit-1}] }

# Signalling network management (ITU-T Q.704): its timers, in milliseconds.
# Every key is optional; these two are the ones a lab changes first.
mtp3:
  t18_ms: 20000               # how long a restart waits for adjacent points
  t21_ms: 64000               # how long a restarting adjacent point is waited for

# MTP3 routes: dpc -> an AS or a linkset, priority (1 = primary, higher =
# alternate, equal = shared by SLS). The adjacent PC of an m2pa link (3000)
# is an implicit route.
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
| `m2pa` | *(m2pa only)* every default below | Level 2 of the link: see [the `m2pa` block](#m2pa-link). |
| `m3ua` | *(m3ua only)* every default below | The heartbeat and the acknowledgement timer of the peer: see [the `m3ua` block](#m3ua-peer). |

An `m3ua` association carries traffic only as an ASP of an
[application server](#application-servers). One that is in no server can come
up and cannot become active: its ASP Active is answered with Error, "No
Configured AS for ASP" (RFC 4666 3.8.1).

### The `m3ua` block { #m3ua-peer }

What RFC 4666 leaves to provisioning for one M3UA peer, on an `m3ua`
association. The timers are in milliseconds.

| Field | Default | Meaning |
|---|---|---|
| `beat_ms` | `0` | T(beat) of RFC 4666 4.3.4.6: the interval at which this node sends Heartbeat. `0` sends none, which is the default because SCTP has a heartbeat of its own; set it to notice a peer whose process hangs while its SCTP stack still answers. When nothing at all arrives from the peer for twice the interval ("If no Heartbeat Ack message (or any other M3UA message) is received from the M3UA peer within 2*T(beat), the remote M3UA peer is considered unavailable") the association is aborted: for a `server` association the ASP is then down and may connect again, a `client` association is not dialled again by this release. A Heartbeat from the peer is always acknowledged with its data unchanged, whatever is set here. |
| `ack_ms` | `2000` | T(ack) of RFC 4666 4.3.4.1 and 4.3.4.3 ("provisionable, with a default of 2 seconds"): on a `client` association, an ASP Up or ASP Active that is not acknowledged is sent again every `ack_ms`. Not `0`. |
| `asp_id` | *(none)* | The ASP Identifier this node puts in its ASP Up on a `client` association (RFC 4666 3.5.1: "a unique value that is locally significant among the ASPs that support an AS"). Left out when not set. A gateway quotes it in the Notify that tells the other ASPs of a takeover or a failure. |

### The `m2pa` block { #m2pa-link }

Level 2 of one M2PA link (RFC 4165), on an `m2pa` association. The timers are
those of ITU-T Q.703 12.3; the defaults are inside the ranges it gives for a
64 kbit/s link, which RFC 4165 clause 4 has M2PA use. All of them are in
milliseconds and none may be `0`.

| Field | Default | Meaning |
|---|---|---|
| `proving` | `normal` | The proving period this end asks for at alignment: `normal` (Link Status Proving Normal, `t4n_ms`) or `emergency` (Proving Emergency, `t4e_ms`). When the peer asks for the emergency period it is used whatever is set here (Q.703 7.2). |
| `t1_ms` | `45000` | T1, alignment ready (Q.703: 40 to 50 s): how long to wait, after proving, for the peer to finish its own. |
| `t2_ms` | `30000` | T2, not aligned (5 to 150 s): how long to wait for the peer to start alignment. |
| `t3_ms` | `1500` | T3, aligned (1 to 2 s): how long to wait for the peer to start proving. |
| `t4n_ms` | `8200` | T4, the normal proving period (7.5 to 9.5 s). |
| `t4e_ms` | `500` | T4, the emergency proving period (400 to 600 ms). |
| `t6_ms` | `4500` | T6, remote congestion (3 to 6 s): how long the peer may stay busy with messages unacknowledged (RFC 4165 4.1.5). |
| `t7_ms` | `2000` | T7, excessive delay of acknowledgement (0.5 to 2 s): a User Data message unacknowledged for this long fails the link (RFC 4165 4.2.1). |
| `proving_interval_ms` | `100` | The interval between Link Status Proving messages while T4 runs (RFC 4165 4.1.3, `Proving_Interval`). |
| `restart_ms` | `1000` | The delay before alignment is started again after it failed or the link failed (ITU-T Q.704 12.2.2, timer T17, 800 to 1500 ms). |
| `tx_queue` | `4096` | MSUs the link holds for transmission (waiting for the link's task, or because the peer is busy or in processor outage) before further ones are discarded and counted (Q.704 3.8). |

A link starts alignment as soon as its association is up, and starts it again
after every failure for as long as the association lasts.

The value `sua` selects SUA (RFC 3868) for connectionless SCCP-user traffic:
like `m3ua` it terminates SCTP and feeds the SCCP messages this node routes and
terminates onto the same path. (SUA connection-oriented service is out of scope.)

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
| `recovery_ms` | T(r) of RFC 4666 4.3.2 and 4.3.4.4, in milliseconds, default `2000` (the RFC has it "configurable by the network operator" and names no value). When the last active ASP of the server leaves, the server is pending for this long: it stays a route, what arrives for it is queued, and the ASP that becomes active in time gets the queue. When the timer runs out the queue is discarded and the server is inactive or down. `0` switches the pending state off. Only a server this node is the signalling gateway of (one with a `server` association) is ever pending. |
| `pending_queue` | Messages queued for the server while it is pending, default `4096`. Further ones are discarded and counted. Not `0`. |
| `required_asps` | "n" of RFC 4666 4.3.2, default `1`: the number of ASPs that have to be active before the server is, and so before it is a route. Once active the server stays active until its last ASP leaves; while it has fewer than `required_asps` its inactive ASPs are told ("Insufficient ASP Resources Active in AS"). `1` for an `override` server, at most the number of `asps` otherwise. |

The traffic mode and the routing context are enforced. An ASP Active that
names a Traffic Mode Type other than the server's is answered with Error,
"Unsupported Traffic Mode Type"; one that names a routing context the
association is not configured in, with "Invalid Routing Context" (RFC 4666
4.3.4.3, 3.8.1). The same goes for DATA: it is routed only from an ASP that is
active in the server whose context it names, or in any server when it names
none. In an `override` server the ASP that asks last takes all the traffic, and
the one that had it is told ("Alternate ASP Active").

## `linksets` { #linksets }

M2PA linksets (RFC 4165). M2PA replaces MTP2, so the classic linkset/link
model applies directly: a linkset groups links toward an adjacent point code,
and SLS spreads traffic across its links. There is no traffic mode here.

Each selection code has a normal link, by the position of the links in
`links` (ITU-T Q.704 2.3.2 a: with two links, the even codes on the first and
the odd ones on the second). While a link carries no traffic its codes go to
the links that do, and come back by changeback when it returns
([Routing model](routing.md#management)). The links of a linkset are expected
to name the same `adjacent_pc`: changeover orders, transfer-prohibited and
traffic restart allowed for the linkset go to the first one named, and a
linkset whose links name none gets no management messages at all.

| Field | Meaning |
|---|---|
| `name` | Linkset name, referenced by `mtp3_routes` (`linkset:`). |
| `links` | The member links, each `{assoc, slc}`, at most 16. Each `assoc` must be an `m2pa` association; its adjacent PC comes from the association's `adjacent_pc`. `slc` is the signalling link code, 0 to 15, unique in the linkset; it defaults to the position of the link in the list. Both ends of a link must use the same code (RFC 4165 4.1.2). |
| `link_test` | The signalling link test of ITU-T Q.707 2.2 on every link of the linkset: see below. |

### `link_test` { #link-test }

After alignment a link is tested before it carries traffic, and again at an
interval while it is in service (Q.707 2.2: "The signalling link becomes
available only if the test is successful"). A test that is not acknowledged
within `t1_ms`, or is acknowledged with another pattern, from another point
code or for another link code, is repeated once; the second failure takes the
link out of service and alignment starts again. Q.707 leaves the action on a
failed periodic test for further study; here it is the same as at activation.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Whether this node tests its links. A test message from the peer is answered either way. |
| `t1_ms` | `8000` | T1, supervision of the acknowledgement (Q.707 5.5: 4 to 12 s, and not less than `t6_ms`). |
| `t2_ms` | `60000` | T2, the interval between tests (30 to 90 s). |
| `pattern` | `a5a5a5a5a5a5a5a5` | The test pattern: 1 to 15 octets in hexadecimal. |

The test is addressed to the link's `adjacent_pc`. A link without one, or with
`enabled: false`, is not tested: it is available as soon as it is aligned, and
the node says so in a warning when the link starts.

## `mtp3_routes` { #mtp3-routes }

The static route table: DPC to a destination, by priority.

| Field | Meaning |
|---|---|
| `dpc` | Destination point code (decimal, validated against the node variant). |
| `as` **or** `linkset` | The destination. Exactly one of the two; naming both, or neither, is a load error. |
| `priority` | **1 = primary**; higher numbers are alternates. The resolver picks the lowest-priority *available* route and fails over as availability changes. Routes of the **same** priority to one DPC are a combined linkset (ITU-T Q.704 2.3.2 b, 4.2.1): they share its traffic by SLS, in the order they are listed. |

Adjacent PCs on M2PA links are implicit routes and need no entry. Availability
comes from live state: M3UA ASP active/inactive, M2PA link in/out of traffic,
a transfer-prohibited or transfer-allowed from the adjacent point of a linkset
(which marks that one route), and Pause / Resume from an application server.
See [Routing model & coverage](routing.md#availability).

With two routes of one priority, the lowest bit of the SLS picks the route and
the links of each linkset are picked by the next bits, as Figure 5/Q.704 has
it, so every link of both linksets carries traffic. The SLS in the label is
not rewritten. A route added at run time with `ss7.routes.add(...)` shares like
any other, but the width a linkset divides the codes by is fixed from this
file at start.

## `mtp3` { #mtp3 }

Signalling network management of a transfer point (ITU-T Q.704), per routing
domain: what the node does when a link, a route or an adjacent point changes
state. Every key is optional and every timer is in milliseconds; the defaults
are the values of Q.704 16.8, or a value inside the range it gives. What each
procedure does is in [Routing model](routing.md#management).

```yaml
mtp3:
  t2_ms: 1400
  t21_ms: 64000
  tfp_for_unknown_destination: true
```

| Field | Default | Meaning |
|---|---|---|
| `t1_ms` | `800` | T1 (500 to 1200 ms), "delay to avoid message mis-sequencing on changeover": how long the traffic of a link is withheld when the far end cannot be asked what it received (Q.704 5.6.2), and when a link is inhibited (10.2). Also the isolation that is short enough not to call for a restart (9.4.1). |
| `t2_ms` | `1400` | T2 (700 to 2000 ms), "waiting for changeover acknowledgement" (5.7.2). |
| `t3_ms` | `800` | T3 (500 to 1200 ms), "time controlled diversion-delay to avoid mis-sequencing on changeback": how long the traffic of a linkset that became available is withheld (6.4). |
| `t4_ms` | `800` | T4 (500 to 1200 ms), "waiting for changeback acknowledgement (first attempt)" (6.5.3). |
| `t5_ms` | `800` | T5 (500 to 1200 ms), the same for the second attempt, after which traffic starts on the link anyway. |
| `t6_ms` | `800` | T6 (500 to 1200 ms), "delay to avoid message mis-sequencing on controlled rerouting": how long the traffic of a destination is held when a transfer-allowed or -restricted moves it to another route (8.2.1). |
| `t8_ms` | `1000` | T8 (800 to 1200 ms), "transfer prohibited inhibition timer": after a transfer-prohibited for a destination, no further one is sent by the response method for this long (13.2.2). |
| `t10_ms` | `45000` | T10 (30 to 60 s), "waiting to repeat signalling route set test message" (13.5.2). |
| `t12_ms` | `1150` | T12 (800 to 1500 ms), "waiting for uninhibit acknowledgement" (10.3.1 e). |
| `t13_ms` | `1150` | T13 (800 to 1500 ms), "waiting for force uninhibit" (10.3.2 e). |
| `t18_ms` | `20000` | T18, the first phase of this node's MTP restart: how long it waits for the traffic restart allowed of every adjacent point before it goes on without them (9.2.2). Q.704 leaves the value to the implementation and the network; it has to be shorter than `t20_ms`. |
| `t19_ms` | `68000` | T19 (67 to 69 s): after a traffic restart allowed was sent to an adjacent point, another one from it is ignored for this long (9.5). |
| `t20_ms` | `60000` | T20 (59 to 61 s), the "overall MTP restart timer at the signalling point whose MTP restarts" (9.2.4). |
| `t21_ms` | `64000` | T21 (63 to 65 s), the "overall MTP restart timer at a signalling point adjacent to one whose MTP restarts": how long an adjacent point that became reachable again is waited for before traffic is sent to it without its traffic restart allowed (9.3.2). |
| `t23_ms` | `240000` | T23 (3 to 6 minutes), the "remote inhibit test timer" (10.6.2). |
| `tfp_for_unknown_destination` | `true` | Whether a message for a point code this node has no route for at all is answered with transfer-prohibited, as it is for a destination that is configured and inaccessible (13.2.2 iii). Footnote 7 of that clause leaves it to the network operator: `false` avoids route set tests for destinations that do not exist. |
| `rerouting_buffer` | `4096` | Messages held for one destination while T6 runs, before further ones are discarded and counted. The changeover and changeback buffers of a link are bounded by that link's `tx_queue`. |

No timer may be `0`. T7, T11, T14 to T17 and T22 of Q.704 16.8 have no key:
they belong to procedures this node does not run (the allocation of data
links, the transfer-restricted timer, inhibiting a link on its own initiative,
the route set congestion test), except T17, which is `restart_ms` of
[the `m2pa` block](#m2pa-link).

**A node that starts, and a peer that does not answer.** A node whose first
link comes into service runs the MTP restart procedure: until every adjacent
point has sent traffic restart allowed, or `t18_ms` is over, it discards what
arrives on its linksets (Q.704 9.6.6). An adjacent point that was unreachable
and returns is waited for in the same way under `t21_ms`. Against a conformant
peer both end within milliseconds of the link test. Against one that never
sends traffic restart allowed they last the whole timer: two nodes that start
together each wait `t18_ms` for the other, and a peer that does not implement
the procedure costs `t21_ms` every time its linkset comes back. Lower the two
timers for such a peer rather than expect traffic at once.

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

E.214 (mobile global title) to E.164 conversion. Roaming MAP addresses an HLR
with an E.214 called party: the home network's E.164 prefix (mapped from the
IMSI's MCC+MNC) plus the MSIN. The converter runs the E.214→E.164 pre-step
**before** GTT on an inbound called party whose numbering plan marks it E.214.

- **`plmn_map`**: the network numbering map, `{mcc, mnc, e164_prefix}` entries.
  An E.214 called party matched to a `plmn_map` prefix is rewritten to its E.164
  form, then translated by GTT.

## `tcap` { #tcap }

The dialogue-termination engine's timers and ceiling. Node-wide; the defaults
sit in the Q.774 default operation-timer neighbourhood, and a low-volume node
never touches them.

```yaml
tcap:
  invoke_timer_ms: 15000       # default invocation timer (default)
  dialogue_timer_ms: 30000     # default idle timeout of a dialogue (default)
  max_dialogues: 100000        # Begin over the ceiling is refused with a P-Abort
```

| Field | Default | Meaning |
|---|---|---|
| `invoke_timer_ms` | `15000` | The invocation timer of an invoke that does not name its own. Its expiry is reported to the handler and means what the operation's class says ([operation classes](script-api.md#operation-classes)); only a class 1 expiry is counted in `sigtran_invoke_timeouts_total`, and only a handler (or the default for class 1) aborts the dialogue on it. |
| `dialogue_timer_ms` | `30000` | How long a dialogue may go without a message in either direction before it is aborted (a U-Abort to the peer, the handler told, counted in `sigtran_dialogue_timeouts_total`). `0` disables it. A dialogue sets its own with `dlg.set_idle_timeout(...)`: a call-control dialogue that waits for the end of a call needs more than a request / response default. |
| `max_dialogues` | `100000` | Ceiling on concurrently open dialogues. A `Begin` over it is refused with a P-Abort, cause resource limitation. |

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
| `rewrite_cdpa_gt` | Rewrite the called-party GT digits on the egress SCCP before relay (combined with `route`). |
| `screen` | `true` drops the message (counted per rule). |

The rules are evaluated on a TCAP `Begin` or `Continue` that decodes in full. One
that does not (a damaged transaction or dialogue portion, a component that cannot
be read, octets after the end of the message) is **dropped** in a domain that has
content rules, and counted in
`sigtran_content_unscreened_total{reason="undecodable",action="dropped"}`: a
message that cannot be inspected has not passed a rule, so damaging a message is
not a way past `screen`. The drop takes the same path as any other, so a sender
that asked for return on error gets its UDTS. Everything the rules do not look at
(an `End`, an `Abort`, a payload that is not TCAP) is routed as before.

A rule that tests the IMSI (`imsi_in`, `imsi_prefix`) reads it from the argument
of the operation, decoded strictly. If the argument of an operation that carries
an IMSI does not decode, the IMSI is unknown, not absent: the first such rule
whose other tests hold cannot be evaluated, and the message is **dropped** there
(counted as `sigtran_content_rule_hits_total{rule=…,action="unevaluable"}`)
instead of falling through to a later rule or to GTT. The argument types are the
MAP version 3 ones. The version 1 and 2 arguments of `cancel-location`, `purge-ms`
and `send-auth-info` are different types and do not decode as them, so an IMSI
rule on those operations drops version 1 and 2 dialogues; leave those operations
out of IMSI rules in a domain that still carries them.

One segment of a segmented XUDT / LUDT does not hold a whole TCAP message, and the
node does not reassemble in transit: segments are **not** evaluated against the
rules and are routed on, counted in
`sigtran_content_unscreened_total{reason="segmented",action="passed"}`. Watch that
counter if a `screen` rule matters to you.

## `isup_screening` { #isup-screening }

Optional ISUP-aware screening on the SI=5 transit path. When the block is absent
the transit path is byte-for-byte unchanged; when present, each transiting ISUP
message is decoded and evaluated against the ordered rules (first match wins). A
`block` drops the message and counts it under `sigtran_isup_screened_total`.

```yaml
sccp: { local_ssns: [] }
isup_screening:
  default: allow                    # action when no rule matches (default: allow)
  rules:
    - { name: block-premium, match: { message_type: iam, called_prefix: "1999" }, action: block }
```

| Field | Meaning |
|---|---|
| `default` | Action for a message no rule matches: `allow` (default) or `block`. |
| `rules` | Ordered `{name, match, action}`; first match wins. |
| `match.message_type` | ISUP message by its lower-case Q.763 acronym (`iam`, `rel`, `acm`, …). |
| `match.called_prefix` / `calling_prefix` | Leading-digit prefix of the called / calling party number. |
| `action` | `block` (drop) or `allow` (explicitly pass). |

All present `match` fields must hold (AND); absent fields are wildcards. A
message that will not decode as ISUP takes the `default` action.

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
