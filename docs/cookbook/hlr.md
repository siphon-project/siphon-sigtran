# Building an HLR

Mobility signalling, updateLocation, sendAuthenticationInfo, cancelLocation and
SRI-SM, is the busiest MAP traffic in a core. This recipe builds the node that
sits in front of it: it steers each subscriber's mobility operations to the
right home HLR by IMSI, and terminates updateLocation locally to apply policy
before the subscriber is admitted.

```
   VLR / MSC ──updateLocation──▶  ┌──────────────────┐
             ──sendAuthInfo────▶  │   this node      │  ──by IMSI──▶  home HLR A
             ──SRI-SM──────────▶  │  (siphon-sigtran) │  ──by IMSI──▶  home HLR B
                                  └──────────────────┘
```

Two halves, both on real API: **route** mobility operations to a home HLR by
IMSI (content routing), and **terminate** updateLocation to authorize.

## Route mobility operations by IMSI

An HLR is addressed for a range of IMSIs. The routing half is config: an
`imsi_table` names the ranges, and a content rule sends the mobility operations
for those IMSIs to their home HLR. The IMSI lives inside the MAP argument, so
this is a content-layer decision.

```yaml
node:
  point_code: 1000
  variant: itu

associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }

application_servers:
  - { name: hlr-a, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a] }

mtp3_routes:
  - { dpc: 2005, as: hlr-a, priority: 1 }

sccp:
  local_ssns: [6]        # we own the HLR subsystem for the operations we terminate

content_routing:
  protocol: gsm-map
  imsi_tables:
    - { name: customer-a, prefixes: ["001010", "001011"] }
  rules:
    - name: customer-a-home
      match:  { operation: [update-location, send-auth-info, cancel-location], imsi_in: customer-a }
      action: { route: {dpc: 2005, ssn: 6} }
```

Everything for a `customer-a` IMSI routes to DPC 2005 in Rust, at line rate,
with no script involvement. To steer by a rule the static table can't answer (a
freshly ported range, a per-subscriber override), defer to a hook exactly as
the [STP recipe](stp.md#2-deferred-rule-hooks) does, and cache the answer back
with `ss7.routes.cache(...)`.

!!! tip "PLMN steering is cheaper at SCCP"
    Steering by *network* rather than by IMSI range (all of MCC+MNC 001/01 goes
    to one HLR) is a GTT prefix on the E.214 called party, not a content rule.
    The subscriber's MCC+MNC is the leading digits of the mobile global title.
    See [the cost ladder](../concepts.md#the-cost-ladder).

## Terminate updateLocation to authorize

Own the operation to make an admission decision. Register a handler for
updateLocation; the engine hands you the [`Dialogue`](../script-api.md#dialogue)
and the decoded [`IncomingOp`](../script-api.md#incomingop). The calling VLR's
global title (`arg.calling_gt`) and the raw MAP argument (`arg.argument`) are
there to base the policy on.

```python
from siphon import gsm_map

TRUSTED_VLRS = {"15550180", "15550181"}

@gsm_map.on_update_location
async def on_update_location(dlg, arg):
    if arg.calling_gt not in TRUSTED_VLRS:
        # Refuse an update from an untrusted VLR (a MAP error on the invoke).
        dlg.error(arg.invoke_id, error_code=8)     # unknownSubscriber / policy refuse
        dlg.end()
        return
    await note_location(arg.calling_gt, arg.argument)
    dlg.end()                                      # accept and close the dialogue
```

`arg.argument` is the raw BER updateLocation argument; decode it with the
published `gsm_map` codec when you need the IMSI or the fields inside. The
handler answers on the wire either way, an accept or a MAP error, because a
terminated dialogue must always be answered.

## The held-open success flow

A full HLR answers a successful updateLocation with an **insertSubscriberData**
leg held open toward the VLR, then the updateLocation result once the VLR acks
the ISD. That is the engine's held-open, multi-leg
[termination shape](../routing.md#termination): a `Begin` answered with a
`Continue` that keeps the dialogue open, the peer's follow-up re-entering the
handler to finish with an `End`. The dialogue engine drives that shape (it is
exercised end to end in the crate's dialogue tests); it is the same
stage-then-flush model the [SMSC recipe](smsc.md) uses for multi-segment MT.

## Next

- **Terminate SMS instead**: [Building an SMSC](smsc.md).
- **Route without terminating**: [Building an STP](stp.md).
- **The termination model**:
  [Routing model & coverage](../routing.md#termination).
- **Ship it**: [Deployment](../deployment.md),
  [Kubernetes & scaling](../kubernetes.md).
