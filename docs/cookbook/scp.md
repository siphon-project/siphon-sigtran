# Building a CAMEL SCP

A Service Control Point is where call-control intelligence lives. The gsmSSF in
the switch triggers a CAMEL dialogue at a detection point; the SCP terminates
it and tells the switch what to do. The smallest useful SCP answers an
**initialDP** with a **Connect**, rerouting the call to a new destination. This
recipe is
[`examples/scp.py`](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/scp.py).

```
   gsmSSF ──initialDP──▶  ┌─────────────────┐
   (switch)               │   this SCP      │
          ◀──Connect────  │  (siphon-sigtran) │
                          └─────────────────┘
```

## Terminate initialDP, answer with Connect

Register a handler for the CAMEL initialDP. The engine hands you the
[`Dialogue`](../script-api.md#dialogue) and the decoded
[`IncomingOp`](../script-api.md#incomingop); `idp.called_party_number` is the
dialled number. Decide a new destination, stage a `Connect` invoke, and `end`
the dialogue so the Connect rides the closing message.

```python
from siphon import gsm_cap

@gsm_cap.on_operation("initial-dp")
async def on_idp(dlg, idp):
    target = reroute(idp.called_party_number)      # your routing logic
    dlg.invoke(gsm_cap.connect(destination_routing_address=[target]))
    dlg.end()                                      # connect in the closing dialogue


def reroute(called_party_number):
    """Map the dialled number to a new destination (an E.164 digit string).

    A fixed reroute here; replace with a portability dip, a time-of-day plan,
    or a per-subscriber service."""
    _ = called_party_number
    return "15550199"
```

That is the whole node. `gsm_cap.connect` takes a list of destination
called-party numbers (each an E.164 digit string, encoded for you, or raw bytes)
and stages a CAP Connect invoke;
[`dlg.end()`](../script-api.md#dialogue) flushes it as the closing End.

## The config

An SCP owns the CAP subsystem so initialDP terminates locally:

```yaml
node:
  point_code: 1000
  variant: itu

associations:
  - { id: ssf-1, adaptation: m3ua, role: server, addrs: [10.1.0.20], port: 2905 }

application_servers:
  - { name: ssf, traffic_mode: loadshare, routing_context: 200, asps: [ssf-1] }

mtp3_routes:
  - { dpc: 2100, as: ssf, priority: 1 }

sccp:
  local_ssns: [146]      # the CAP subsystem; initialDP to it terminates here
```

## Beyond a fixed Connect

The Connect target is just bytes you decide, so the SCP is as smart as your
`reroute`: dip a portability database and cache the answer, or pick a destination
from a time-of-day plan or a subscriber profile.

A real SCP also does more than connect. Stage several CAP invokes in the one
dialogue, then flush them together:

```python
@gsm_cap.on_operation("initial-dp")
async def on_idp(dlg, idp):
    if barred(idp.calling_party_number):
        dlg.invoke(gsm_cap.release_call(cause=b"\x90\x95"))   # Q.850 call rejected
        dlg.end()
        return
    # Arm the answer / disconnect detection points, meter the call, then connect.
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 0), (9, 1)]))
    dlg.invoke(gsm_cap.apply_charging(charging_characteristics=budget(idp)))
    dlg.invoke(gsm_cap.connect(destination_routing_address=[reroute(idp.called_party_number)]))
    dlg.end()
```

- **`gsm_cap.release_call(cause=…)`** answers a barred call with a release instead
  of a Connect.
- **`gsm_cap.request_report_bcsm_event(events=[…])`** arms detection points; each is
  an `(event_type_bcsm, monitor_mode)` integer pair (TS 29.078), e.g. `(7, 0)` =
  oAnswer interrupted, `(9, 1)` = oDisconnect notifyAndContinue.
- **`gsm_cap.apply_charging(charging_characteristics=…)`** hands the gsmSSF an
  online-charging control (a call-duration limit, say).

When you arm detection points, the gsmSSF reports them back with EventReportBCSM
in the same dialogue. Terminate those with `@gsm_cap.on_operation("event-report-bcsm")` and
drive the next leg (extend the timer, play an announcement, release).

For a routing-heavy node that mixes call control with transit SS7, pair this with
the [STP recipe](stp.md); to terminate SMS instead, see
[Building an SMSC](smsc.md).

## Next

- **The full CAP surface**: [Script API](../script-api.md#gsm-cap).
- **How termination fits the routing model**:
  [Routing model & coverage](../routing.md#termination).
- **Ship it**: [Deployment](../deployment.md),
  [Kubernetes & scaling](../kubernetes.md).
