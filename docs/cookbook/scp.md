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

@gsm_cap.on_initial_dp
async def on_idp(dlg, idp):
    target = reroute(idp.called_party_number)      # your routing logic
    dlg.invoke(gsm_cap.connect(destination_routing_address=[target]))
    dlg.end()                                      # connect in the closing dialogue


def reroute(called_party_number):
    """Map the dialled number to a new destination (called-party-number bytes).

    A fixed reroute here; replace with a portability dip, a time-of-day plan,
    or a per-subscriber service."""
    _ = called_party_number
    return b"\x00\x15\x55\x01\x99"
```

That is the whole node. `gsm_cap.connect` takes a list of destination
called-party-number byte strings and stages a CAP Connect invoke;
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
`reroute`:

- **Number portability**: dip a live database, then cache the answer so repeat
  calls to the same number decide without the dip.
- **Time-of-day / per-subscriber plans**: choose the destination from a
  schedule or a subscriber profile.
- **Release instead of connect**: for a barred call, answer with a release
  rather than a Connect (a different CAP component in the same dialogue).

For a routing-heavy node that mixes call control with transit SS7, pair this
with the [STP recipe](stp.md); to terminate SMS instead, see
[Building an SMSC](smsc.md).

## Next

- **The full CAP surface**: [Script API](../script-api.md#gsm-cap).
- **How termination fits the routing model**:
  [Routing model & coverage](../routing.md#termination).
- **Ship it**: [Deployment](../deployment.md),
  [Kubernetes & scaling](../kubernetes.md).
