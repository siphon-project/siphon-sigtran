# Routing model & coverage

This page is the reference for how the node resolves an inbound message, the
MAP/CAP operations it recognises, and the runtime features that keep a
signalling node honest: availability-driven failover, Service-Indicator-
agnostic transit, and the loop guards.

## The decision flow

Every inbound message runs the same synchronous Rust path, top to bottom, first
answer wins:

1. **MTP3 transfer.** If the destination point code is **not** one of the
   node's own, the message transits. The route resolver picks the egress and
   the MSU leaves. No SCCP decode, no Python. This is the cheapest outcome and
   the common one for an STP.
2. **Content routing.** For a message addressed to us carrying SCCP + TCAP, the
   decoded MAP/CAP view is evaluated against the ordered content rules
   **first**, because they decide on the richest layer. A rule routes,
   rewrites the called-party GT, screens, or defers to a hook. A `Begin` or
   `Continue` that cannot be decoded in full is dropped here instead of being
   routed unseen ([details](configuration.md#content-routing)).
3. **SCCP GTT.** Otherwise the called-party global title is translated (after
   an E.214 to E.164 pre-step) to a concrete `(dpc, ssn)`, a group member, or
   local termination.
4. **Termination.** A result of `local` (or a called SSN the node owns) hands
   the message to the [dialogue engine](#termination).

The resulting decision is one of: forward via an egress destination, route to a
concrete `(dpc, ssn)`, terminate locally, defer to a named Python hook, or drop
with a reason.

## The cost ladder

Route at the cheapest layer that can answer. Rising cost:

| Decision on | Layer | Cost (single core) |
|---|---|---|
| destination point code | MTP3 route table | ~28 ns |
| GT prefix (+ gti/tt/np/nai) | SCCP GTT | ~40 ns |
| home network (MCC+MNC) | E.214 conversion + GT prefix | SCCP; still a table transform |
| full IMSI / operation / GT-table membership | content routing | ~50 ns (needs the MAP/CAP decode) |
| a live dip the tables can't answer | a Python hook | yours |

PLMN-level steering belongs at SCCP: the roaming subscriber's MCC+MNC is the
leading digits of the E.214 called party, so it is a GTT prefix rule, not a
content rule. Keep content rules for decisions that genuinely need the decoded
IMSI or operation. See [the cost ladder in Concepts](concepts.md#the-cost-ladder).

## Availability and failover { #availability }

A route is usable only while its destination is available. The resolver picks
the lowest-priority available route for a DPC and fails over as state changes.
Availability is driven from the live transport:

- **M3UA**: an AS is up when at least one of its ASPs reaches ASP-Active
  (ASPSM/ASPTM). Load-share spreads over the active ASPs by SLS; override keeps
  one active with the rest on standby; broadcast sends to all active.
- **M2PA**: a linkset is a route while level 3 routes traffic to at least one
  of its links: a link that is in service, has passed its link test, is not
  inhibited, and whose adjacent point has said traffic may restart. SLS
  spreads traffic across those links.
- **Route management**: a transfer-prohibited from the adjacent point of a
  linkset takes that one route to the destination out; a transfer-allowed puts
  it back; a transfer-restricted makes it the last choice among routes of its
  priority.
- **Application servers**: a destination-unavailable from an ASP prohibits a
  DPC, a destination-available allows it.

When the primary route for a DPC goes unavailable the resolver uses the next
priority automatically; an alternate linkset behind an AS route
([Configuration](configuration.md#mtp3-routes)) is the common failover shape.
Routes of the same priority share the traffic by SLS; when one of them goes,
only its selection codes move.

## Signalling network management { #management }

A node with linksets is a signalling transfer point, and its neighbours expect
ITU-T Q.704 of it. One task per routing domain runs the procedures below. All
their timers are keys of the [`mtp3` block](configuration.md#mtp3). Messages
are the ITU 14-bit formats of Q.704 clause 15; a management message for this
node (service indicator 0) arriving on a link goes to this task, one for
another point code is transferred like any other message.

**A link fails (changeover, clause 5).** Traffic for the link is buffered. An
extended changeover order goes to the far end on another link (or route) with
the sequence number of the last message accepted on the failed link: M2PA
numbers are 24 bits, so RFC 4165 4.2.3 has XCO and XCA of Q.2210 take the place
of COO and COA. On the acknowledgement, the messages the far end does not have
are sent again on the alternative links, then what was never sent, then the
buffer, in that order: none lost and none twice. An order from the far end is
acknowledged the same way, also for a link that still looked fine here. Without
an acknowledgement in T2, with an emergency acknowledgement, or when nothing
leads to the far end (T1), only what was never sent goes out again: what was
sent and never acknowledged might be a duplicate, so it is not, and is counted
in `sigtran_m2pa_discarded_total{reason="tx-lost-on-failure"}`. A 7-bit COO is
answered with ECA, since its number cannot name an M2PA message.

**A link returns (changeback, clause 6).** In a linkset that carries traffic,
the link's traffic is buffered, a changeback declaration goes out on every link
that carried it meanwhile, and the buffer goes out on the link once each is
acknowledged (or after T4 and T5). A linkset that returns as a whole takes its
traffic back after T3, or at once when nothing has to move. A declaration from
the far end is always acknowledged.

**An adjacent point prohibits or allows a route (clauses 7, 8, 13).** A
transfer-prohibited marks the route and the next message takes the
alternative (forced rerouting; the alternative is known the moment the route
is marked, so nothing waits). The route is then tested with a signalling route
set test every T10 until a transfer-allowed arrives. A transfer-allowed or
transfer-restricted that moves traffic between routes holds the destination's
messages for T6 first (controlled rerouting), so the ones still on the old
route arrive before the first on the new one.

**What this node tells its neighbours (clause 13).** One rule: an adjacent
point is told transfer-prohibited for a destination when the destination is
inaccessible from here (the broadcast method, 13.2.2 ii), or when this node
routes to it through that very point (13.2.2 i); transfer-allowed otherwise.
Whatever changes (a link, a linkset, an application server, a received
transfer-prohibited), the difference to what each point was last told is sent.
A message for a destination that cannot be reached is also answered with
transfer-prohibited toward the point it came from, once per T8 (the response
method, 13.2.2 iii), in addition to whatever SCCP returns. A route set test
from a neighbour is answered when what it believes differs from what is
(13.5.4). Transfer-restricted is acted on and never sent.

**Restart (clause 9).** When the first link comes into service after the node
was isolated (at start, or for longer than T1), it restarts: it collects
transfer-prohibited messages and traffic restart allowed from its adjacent
points for at most T18, discards traffic from the linksets meanwhile, then
sends its own transfer-prohibited messages and a traffic restart allowed to
each. When one adjacent point returns, it is sent what it must not route here
and a traffic restart allowed, and no traffic goes to it until its own arrives
or T21 is over. An unexpected traffic restart allowed is answered once per T19.

**Inhibiting (clause 10).** A request to inhibit a link is granted (the link
leaves traffic after T1, and is tested every T23) unless a destination would
become inaccessible, in which case it is denied. Uninhibit, force uninhibit
and the inhibit tests are answered as 10.3, 10.4 and 10.6 have it. This node
never asks to inhibit a link itself: there is no management interface to ask
it to.

**Congestion.** A transfer-controlled is counted and published; routing does
not change, and none is sent.

**Not done.** Transfer-restricted and transfer-controlled are never
originated; the route set congestion test, the allocation of signalling data
links (clause 12.3 on), uninhibiting on the initiative of routing (10.3.2) and
user part unavailable are not run: such a message for this node is counted in
`sigtran_mtp3_discarded_total{reason="management-not-acted-on"}`. The formats
are ITU only. Toward application servers nothing of this is translated yet: a
destination that becomes inaccessible is announced to adjacent signalling
points, not to ASPs. The registry publishes every such change for whatever
does that (`Registry::destination_changes`).

**Order.** A message is held, sent again or diverted by the task of the link
it was handed to, and that task is also what tells routing to lead to the link
or to pass it by: it does so after it knows what to do with the traffic, and
after it has passed on what it held. So the messages of one link keep their
order through a changeover and a changeback, and a changeback declaration
travels in the queue of the alternative link, behind the traffic already
handed to it. What is left is the instant between a message choosing its link
and being handed to it: one that chose a link just as routing stopped leading
there is passed on by that link's task and can be overtaken by the next one,
and one that chose the alternative link just as a changeback began can follow
the declaration. Both need a link to change state inside that instant.

## Service-Indicator-agnostic transit

MTP3 transfer routes by point code for **any** Service Indicator. SCCP (SI 3)
is decapsulated up to GTT / TCAP / termination when the node is the
destination; a non-SCCP MSU (call control and other SIs) that is not addressed
to the node transits by DPC alone, with no codec for its upper layer needed.
An STP relays those for free.

## Loop guards

An STP that loops is a signalling storm, so transit carries runtime guards. Each
drops the offending MSU and counts it in
`sigtran_loops_detected_total{kind=...}`:

- **own-opc**: the originating point code of a transit MSU equals the node's
  own point code, so a message the node originated has come back. Dropped.
- **route-reflect**: the only available route would send the MSU back out the
  linkset it arrived on. Dropped rather than reflected.
- **hop-counter**: an SCCP XUDT/LUDT carries a Q.713 hop counter, decremented at
  each GTT relay; at zero the message is a translation loop, dropped and returned
  as an XUDTS/LUDTS "hop counter violation" when it asked to be returned on error.

The first two catch route-config loops that no upper-layer mechanism sees
(call-control SIs have no application-level hop counter); the hop counter is the
SCCP-layer complement on the GTT relay path. Because they run on the transit
path, they cost nothing on the normal case and show up on a graph when a route
table is wrong.

## MAP/CAP operations { #operations }

The operation names a content rule can match (`operation:`), and the
subset with a termination decorator. Names are kebab-case; an unknown name is a
config load error.

| Operation | Match name | Terminate with |
|---|---|---|
| SendRoutingInfoForSM | `sri-sm` | `@gsm_map.on_operation("sri-sm")` |
| MO-ForwardSM | `mo-forward-sm` | `@gsm_map.on_operation("mo-forward-sm")` |
| MT-ForwardSM | `mt-forward-sm` | `@gsm_map.on_operation("mt-forward-sm")` |
| updateLocation | `update-location` | `@gsm_map.on_operation("update-location")` |
| cancelLocation | `cancel-location` | `@gsm_map.on_operation("cancel-location")` |
| sendAuthenticationInfo | `send-auth-info` | `@gsm_map.on_operation("send-auth-info")` |
| insertSubscriberData | `insert-subscriber-data` | *(staged as an invoke leg)* |
| provideSubscriberInfo | `provide-subscriber-info` | `@gsm_map.on_operation("provide-subscriber-info")` |
| initialDP (CAMEL/INAP) | `initial-dp` | `@gsm_cap.on_operation("initial-dp")` / `@inap.on_operation("initial-dp")` |
| connect (CAMEL) | `connect` | *(staged as an invoke via `gsm_cap.connect`)* |

The **match** names above are the content-rule vocabulary (`operation:`). The
**termination** vocabulary is a per-namespace superset (it adds `ready-for-sm`,
`purge-ms`, `report-sm-delivery-status`, `event-report-bcsm`, and the INAP
operations); the full list each `on_operation` accepts is in the
[Script API](script-api.md#gsm-map). One handler can take several operations
pipe-separated (`@gsm_map.on_operation("mo-forward-sm|mt-forward-sm")`), the same
`on_<message>("<name>")` shape as `@smpp.on_pdu` and the SIP proxy's
`@proxy.on_request`.

Operations staged only as an invoke (`insert-subscriber-data`, `connect`) are not
terminated; you send them inside an open dialogue. Anything you don't terminate is
still first-class for **routing**: match and route or screen it at the content
layer. The full MAP/CAP argument surface lives in the published `gsm_map` /
`gsm_cap` codecs.

## Termination shapes { #termination }

When routing says *local*, the TCAP dialogue engine dispatches the operation to
your handler. Three shapes cover MAP and CAMEL practice:

- **single request/response**: a `Begin(AARQ, Invoke)` arrives, the handler
  replies, the reply is an `End(AARE, ReturnResultLast)` echoing the peer's
  transaction id. SRI-SM and initialDP are this shape.
- **held-open, multi-leg**: the handler answers a `Begin` with a `Continue`
  that keeps the dialogue open (an updateLocation answered with an
  insertSubscriberData invoke), and the peer's follow-up re-enters the handler
  to finish with an `End`. See [Building an HLR](cookbook/hlr.md).

Invoke and dialogue timers, and the dialogue ceiling, come from the
[`tcap:` block](configuration.md#tcap) and are enforced by the engine.

## Metrics { #metrics }

The node maintains a Prometheus family set in Rust and renders it with
`ss7.metrics()` (or `node.metrics()`); it is never a per-message Python
call. The families:

| Family | Kind | Labels |
|---|---|---|
| `sigtran_association_state` | gauge | `assoc`, `adaptation` |
| `sigtran_asp_state` | gauge | `asp`, `as` |
| `sigtran_linkset_available` | gauge | `linkset` |
| `sigtran_linkset_active_links` | gauge | `linkset` |
| `sigtran_m2pa_link_state` | gauge | `link` |
| `sigtran_route_available` | gauge | `dpc`, `linkset` |
| `sigtran_mtp3mg_events_total` | counter | `dpc`, `type` |
| `sigtran_msu_total` | counter | `linkset`, `dir`, `si` |
| `sigtran_gtt_translations_total` | counter | `selector`, `result` |
| `sigtran_gtt_errors_total` | counter | `reason` |
| `sigtran_content_rule_hits_total` | counter | `rule`, `action` |
| `sigtran_content_unscreened_total` | counter | `reason`, `action` |
| `sigtran_active_dialogues` | gauge | |
| `sigtran_dialogue_timeouts_total` | counter | |
| `sigtran_invoke_timeouts_total` | counter | `operation` |
| `sigtran_abort_total` | counter | `source` |
| `sigtran_tcap_abort_total` | counter | `dir`, `kind`, `cause` |
| `sigtran_tcap_reject_total` | counter | `dir`, `problem` |
| `sigtran_tcap_discarded_total` | counter | `reason` |
| `sigtran_tcap_send_errors_total` | counter | |
| `sigtran_rx_discarded_total` | counter | `reason` |
| `sigtran_m2pa_discarded_total` | counter | `reason` |
| `sigtran_m2pa_link_failures_total` | counter | `reason` |
| `sigtran_link_tests_total` | counter | `result` |
| `sigtran_mtp3_link_traffic` | gauge | `link` |
| `sigtran_mtp3_restarting` | gauge | |
| `sigtran_mtp3_management_total` | counter | `dir`, `type` |
| `sigtran_mtp3_procedures_total` | counter | `procedure` |
| `sigtran_mtp3_retrieved_total` | counter | `fate` |
| `sigtran_mtp3_discarded_total` | counter | `reason` |
| `sigtran_loops_detected_total` | counter | `kind` |
| `sigtran_isup_screened_total` | counter | `reason` |

`sigtran_rx_discarded_total` counts what an association received and dropped
before routing: `ppid` (not the adaptation layer's payload protocol identifier),
`undecodable`, `out-of-state` (traffic from an ASP that is not active),
`no-payload` (a data message without its user part), `not-unitdata` (addressed
to a local subsystem and not a UDT) and `link-test` (a signalling link test
message for another point code, for a link code the linkset does not have, or
an acknowledgement of a test that is not running). Each is also a line on
stderr naming the association. Alert on any of them moving.

An M2PA link has three families of its own. `sigtran_m2pa_link_state` is `0`
while the link is out of service or aligning, `1` once level 2 is in service
(aligned, the link test still to pass, or the peer in processor outage) and `2`
when the link is available for traffic. `sigtran_m2pa_link_failures_total`
counts every time a link leaves service or fails to align, by `reason`: `t1`,
`t2`, `t3` (alignment timers), `t6` (the peer stayed busy), `t7` (a message was
not acknowledged), `peer-status` (the peer sent Alignment, Proving or Out of
Service), `abnormal-bsn`, `link-test`, `association` (SCTP lost) and `stopped`.
`sigtran_m2pa_discarded_total` counts messages a link did not carry:
`rx-out-of-sequence`, `rx-not-in-service`, `rx-abnormal-bsn`,
`tx-not-in-service`, `tx-congestion` (the transmit queue was full),
`tx-lost-on-failure` (sent or queued, not acknowledged, and the link failed),
`tx-flushed-by-peer` (discarded by a peer recovering from processor outage) and
`encode`. `sigtran_link_tests_total` counts signalling link test messages
`sent`, `passed` and `failed`.

The level-3 families ([Signalling network management](#management)):

- `sigtran_mtp3_link_traffic{link}` is `1` while level 3 routes traffic to the
  link, `0` while the link is down, changed over, inhibited, or waiting for a
  restart to end. `sigtran_m2pa_link_state` says what level 2 thinks of the
  same link. `sigtran_mtp3_restarting` is `1` while this node's restart runs.
- `sigtran_mtp3_management_total{dir,type}` counts management messages by
  their abbreviation in Table 1/Q.704 (`TFP`, `TFA`, `XCO`, `TRA`, ...).
  `sigtran_mtp3mg_events_total{dpc,type}` counts per destination: `tfp` and
  `tfa` for a route marked by an adjacent point, `pause` and `resume` for the
  destination becoming inaccessible and accessible, `congestion` for a
  transfer-controlled.
- `sigtran_mtp3_procedures_total{procedure}` counts what ran and how it ended:
  `changeover-acknowledged`, `changeover-emergency` (acknowledged without a
  usable sequence number), `changeover-unacknowledged` (T2),
  `changeover-time-controlled` (T1), `changeback-acknowledged`,
  `changeback-unacknowledged` (T5), `changeback-time-controlled` (T3),
  `forced-rerouting`, `controlled-rerouting`, `restart-begun`, `restart-ended`,
  `adjacent-restart-begun`, `adjacent-restart-ended`,
  `adjacent-restart-expired` (T21, the peer never said traffic restart
  allowed), `link-inhibited`, `link-inhibit-denied`, `link-uninhibited` and
  `uninhibit-abandoned`.
- `sigtran_mtp3_retrieved_total{fate}` counts what a failed link still held at
  changeover: `resent` on an alternative link, `confirmed` (the far end had
  it), `link-test` (a link test message, which goes nowhere else). What was
  sent, never acknowledged and not sent again is in
  `sigtran_m2pa_discarded_total{reason="tx-lost-on-failure"}`: that counter
  moving is traffic that may be lost, and `changeover-unacknowledged` or
  `changeover-time-controlled` moving with it says why.
- `sigtran_mtp3_discarded_total{reason}` counts what level 3 did not carry:
  `no-route` (a message for a point code nothing leads to, answered with
  transfer-prohibited), `no-egress` (a route was chosen and nothing on it
  carries), `restarting` (received from a linkset during this node's restart),
  `no-alternative` (held at changeover, and nothing else leads to its
  destination), `buffer-full` (a changeover, changeback or rerouting buffer
  overflowed), `management-not-acted-on` and `management-no-path` (a management
  message of this node had no link or route to leave on).

Good first panels: linkset / ASP state and route availability (is the node
wired up?), MSU rate by SI, GTT translations vs errors, active dialogues, and
`sigtran_loops_detected_total` (a route-table mistake shows up here instead of
as an outage).
