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
- **M2PA**: a linkset is up while at least one of its links is in service;
  SLS spreads traffic across the in-service links.
- **MTP3 management**: Pause prohibits a DPC, Resume allows it, and Status
  folds in a congestion level. These arrive as M3UA SSNM or native MTP3 events
  and update route state before the next message routes.

When the primary route for a DPC goes unavailable the resolver uses the next
priority automatically; an alternate linkset behind an AS route
([Configuration](configuration.md#mtp3-routes)) is the common failover shape.

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
  The translation that leads to a subsystem of this node counts as one (Q.714
  2.3.1): an XUDT addressed by global title that arrives with one hop left is
  dropped the same way and not terminated. One addressed by subsystem number is
  not translated, and its hop counter is not looked at.

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
| `sigtran_loops_detected_total` | counter | `kind` |
| `sigtran_isup_screened_total` | counter | `reason` |

`sigtran_rx_discarded_total` counts what an association received and dropped
before routing: `ppid` (not the adaptation layer's payload protocol identifier),
`undecodable`, `out-of-state` (traffic from an ASP that is not active, or on a
link that is not in service), `no-payload` (a data message without its user
part) and `not-unitdata` (addressed to a local subsystem and not a message the
dialogue engine reads: a segment of a segmented XUDT, an LUDT, a service
message). Each is also a line on stderr naming the association. Alert on any of
them moving.

The dialogue engine reads a UDT and an XUDT that holds a whole message (no
segmentation parameter, or one that says first segment, none remaining), and
answers in the form the dialogue was opened in: XUDT for XUDT, with a hop
counter of 15. It does not reassemble: the segments of a segmented XUDT are
counted under `not-unitdata` and the message is not answered.

Good first panels: linkset / ASP state and route availability (is the node
wired up?), MSU rate by SI, GTT translations vs errors, active dialogues, and
`sigtran_loops_detected_total` (a route-table mistake shows up here instead of
as an outage).
