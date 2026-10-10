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
[`IncomingOp`](../script-api.md#incomingop); `idp.called_party_bcd_number` is what
was dialled on a mobile-originated call, `idp.called_party_number` the called
party of a forwarded or terminating one. Decide a new destination, stage a `Connect` invoke, and `end`
the dialogue so the Connect rides the closing message.

```python
from siphon import gsm_cap

@gsm_cap.on_operation("initial-dp")
async def on_idp(dlg, idp):
    # What was dialled: the BCD number of a mobile-originated call, the called
    # party number of a forwarded or terminating one.
    target = reroute(idp.called_party_bcd_number or idp.called_party_number)
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
    # Arm the answer and the disconnect of both legs, meter the call, then connect.
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 1, 2), (9, 0, 1), (9, 0, 2)]))
    dlg.invoke(gsm_cap.apply_charging(max_call_period_duration=budget(idp),   # 100 ms units
                                      release_if_duration_exceeded=True, party_to_charge=1))
    dlg.invoke(gsm_cap.connect(destination_routing_address=[reroute(idp.called_party_number)]))
    dlg.end()
```

- **`gsm_cap.release_call(cause=…)`** answers a barred call with a release instead
  of a Connect.
- **`gsm_cap.request_report_bcsm_event(events=[…])`** arms detection points; each is
  an `(event_type_bcsm, monitor_mode, leg)` integer triple (TS 29.078), e.g.
  `(7, 1, 2)` = oAnswer notifyAndContinue on leg 2, `(9, 0, 1)` = oDisconnect
  interrupted on leg 1. A disconnect is armed on each leg it should be reported
  for; the leg can be left out for events that have none.
- **`gsm_cap.apply_charging(max_call_period_duration=…)`** grants the gsmSSF a call
  period to meter, in units of 100 ms. The characteristics are encoded for the
  CAMEL phase of the dialogue (phase 3 and phase 4 differ on the wire), from its
  application context; see [the script API](../script-api.md#gsm-cap).

When you arm detection points and want the reports, keep the dialogue open
(`dlg.send()` instead of `dlg.end()`): the gsmSSF reports each event with
EventReportBCSM in the same dialogue, and the handler is re-entered with a
[`PeerTurn`](../script-api.md#peerturn).

```python
@gsm_cap.on_operation("initial-dp")
async def on_idp(dlg, event):
    if not event.is_peer_turn:
        dlg.set_idle_timeout(4 * 3600)          # as long as a call may last
        dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 1), (9, 1)]))
        dlg.invoke(gsm_cap.connect(destination_routing_address=[reroute(event.called_party_number)]))
        dlg.send()                               # Continue: the dialogue stays open
        return
    if event.closed or event.is_end:
        close_charging_session(dlg.otid)         # however it ended: told once
    elif event.is_invoke:
        note_event(dlg.otid, event.argument)     # an EventReportBCSM; nothing to answer
```

Three things make this work for a dialogue that waits minutes for its next event:

- `request_report_bcsm_event` and `connect` are **class 2** operations: no reply is
  their success, so the expiry of their invocation timer ends nothing. (The handler
  is told, with `event.is_timeout`; ignore it.)
- A handler that stages nothing on a follow-up leg leaves the dialogue open. An
  EventReportBCSM needs no answer.
- The idle timeout is per dialogue. The node default (`tcap.dialogue_timer_ms`) is
  sized for request / response dialogues, so set what the call can last.

`event.closed` tells the handler the dialogue is gone when the gsmSSF aborted it,
a damaged message arrived for it, or it sat idle: release what you tied to it
there, as well as on `event.is_end`.

For a routing-heavy node that mixes call control with transit SS7, pair this with
the [STP recipe](stp.md); to terminate SMS instead, see
[Building an SMSC](smsc.md).

## Next

- **The full CAP surface**: [Script API](../script-api.md#gsm-cap).
- **How termination fits the routing model**:
  [Routing model & coverage](../routing.md#termination).
- **Ship it**: [Deployment](../deployment.md),
  [Kubernetes & scaling](../kubernetes.md).
