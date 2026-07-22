# Building an HLR

An HLR is a subscriber database that **answers**. A VLR or MSC queries it as a
subscriber roams in (updateLocation, sendAuthenticationInfo), an SMSC asks it
where to deliver (SRI-SM), a VLR tells it a subscriber has gone (purgeMS). Every
one of those is a MAP operation addressed to the HLR subsystem, and the HLR
terminates it and replies. This recipe builds that node: it owns SSN 6 and
answers the mobility and SMS-routing operations sent to it.

```
   VLR / MSC ──updateLocation──────▶  ┌──────────────────┐
             ──sendAuthInfo────────▶  │   this HLR       │
             ──purgeMS─────────────▶  │  (siphon-sigtran) │  ──answer──▶
   SMSC      ──SRI-SM──────────────▶  └──────────────────┘
```

## Own the HLR subsystem

The config declares the subsystem so mobility operations addressed to it
terminate here. The associations and route reach the VLRs/MSCs the HLR answers
(and pushes subscriber data to), so a reply and the insertSubscriberData leg have
a path back.

```yaml
node:
  point_code: 1000
  variant: itu

associations:
  - { id: vlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }

application_servers:
  - { name: vlr-a, traffic_mode: loadshare, routing_context: 100, asps: [vlr-a] }

mtp3_routes:
  - { dpc: 2005, as: vlr-a, priority: 1 }   # reach the querying VLR/MSC to answer

sccp:
  local_ssns: [6]        # we own SSN 6; mobility operations to it terminate here
```

Nothing routes onward. A message addressed to SSN 6 is handed to the dialogue
engine, which decodes the MAP operation and dispatches it to your handler.

## Answer updateLocation

Own the operation to make an admission decision. Register a handler for
updateLocation; the engine hands you the [`Dialogue`](../script-api.md#dialogue)
and the decoded [`IncomingOp`](../script-api.md#incomingop). The calling VLR's
global title (`arg.calling_gt`) and the raw MAP argument (`arg.argument`) are
there to base the policy on.

```python
from siphon import gsm_map

TRUSTED_VLRS = {"15550180", "15550181"}

@gsm_map.on_operation("update-location")
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

A full updateLocation does not just accept. The HLR pushes the subscriber's
profile to the VLR with an **insertSubscriberData** leg held open, then sends the
updateLocation result once the VLR acks it. That is the engine's held-open,
multi-leg [termination shape](../routing.md#termination): a `Begin` answered with
a `Continue` that keeps the dialogue open, the VLR's follow-up re-entering the
handler to finish with an `End`.

One handler drives both legs. On the opening leg it gets the decoded
[`IncomingOp`](../script-api.md#incomingop); on the follow-up leg it gets a
[`PeerTurn`](../script-api.md#peerturn), the decoded view of what the VLR sent
back. Branch on `is_peer_turn`.

```python
from siphon import gsm_map

HLR_NUMBER = "15550190"                       # our E.164 address (+1 555 0190)

@gsm_map.on_operation("update-location")
async def on_update_location(dlg, event):
    if event.is_peer_turn:
        # Follow-up leg: the VLR answered our insertSubscriberData.
        if event.is_result:
            dlg.reply(gsm_map.update_location_res(hlr_number=HLR_NUMBER))
            dlg.end()                            # close with the updateLocation result
        elif event.is_error:
            dlg.abort()                          # the VLR refused the data
        return
    # Opening leg: push the subscriber profile, hold the dialogue open.
    imsi, msisdn = await load_profile(event.argument)
    dlg.invoke(gsm_map.insert_subscriber_data(imsi=imsi, msisdn=msisdn))
    dlg.send()                                   # Continue: ISD invoke, dialogue stays open
```

Three moving parts, all on real API:

- **`gsm_map.insert_subscriber_data(imsi=…, msisdn=…)`** stages the ISD invoke the
  HLR sends inside the open dialogue. `dlg.send()` flushes it as a `Continue` that
  carries the AARE and keeps the transaction open.
- **The [`PeerTurn`](../script-api.md#peerturn)** the follow-up leg receives says
  what the VLR sent: `is_result` / `is_invoke` / `is_error`, the `operation_code`
  it answers, and the raw `result` bytes. The handler waits for the ISD
  `returnResultLast` before it closes.
- **`gsm_map.update_location_res(hlr_number=…)`** builds the updateLocation result;
  `dlg.reply(...)` then `dlg.end()` sends it in the closing `End`, which echoes the
  VLR's original transaction id.

The engine drives that shape end to end (it is exercised in the crate's dialogue
tests and the addon test). It is the same stage-then-flush model the
[SMSC recipe](smsc.md) uses for multi-segment MT.

## Single-shot answers

updateLocation is the multi-leg case. Most of what an HLR answers is single-shot:
one invoke in, one result out in a closing `End`. Each is named on
`@gsm_map.on_operation("<name>")` (see the
[selector list](../script-api.md#on_operation)) and has its own `*_res` builder.

**sendAuthenticationInfo.** The VLR asks for vectors, the HLR answers with them.
Build the vectors with `gsm_map.send_authentication_info_res`, quintuplets for
UMTS/EPS AKA (each `(rand, xres, ck, ik, autn)`) or triplets for GSM (each
`(rand, sres, kc)`).

```python
@gsm_map.on_operation("send-auth-info")
async def on_send_auth_info(dlg, arg):
    vectors = await mint_quintuplets(arg.argument, n=5)   # your Milenage / TUAK
    dlg.reply(gsm_map.send_authentication_info_res(quintuplets=vectors))
    dlg.end()
```

`mint_quintuplets` runs your Milenage or TUAK against the subscriber's K / OP; the
MAP side is one `reply` then `end`.

**SRI-SM.** An SMSC asks where to deliver a message. The HLR answers with the
recipient's IMSI and the serving MSC/SGSN so the SMSC can raise the MT dialogue.

```python
@gsm_map.on_operation("sri-sm")
async def on_sri_sm(dlg, arg):
    imsi, msc = await locate(arg.argument)        # look the subscriber up
    dlg.reply(gsm_map.send_routing_info_for_sm_res(imsi=imsi, network_node_number=msc))
    dlg.end()
```

**purgeMS** answers the same single-shot way with `gsm_map.purge_ms_res(...)`, and
**readyForSM** with `gsm_map.ready_for_sm_res()`.

## Fronting a pool of HLRs

Steering a subscriber's operations to their *home* HLR by IMSI range is a
different node. That is signalling relay, not an HLR: the front node terminates
nothing, it routes each mobility operation to the HLR that owns the IMSI. Build
that as an [STP](stp.md) with a content rule on the IMSI (or, cheaper, a GTT
prefix on the E.214 called party when a whole network maps to one HLR). See
[the cost ladder](../concepts.md#the-cost-ladder).

## Next

- **Terminate SMS instead**: [Building an SMSC](smsc.md).
- **Route without terminating**: [Building an STP](stp.md).
- **The termination model**:
  [Routing model & coverage](../routing.md#termination).
- **Ship it**: [Deployment](../deployment.md),
  [Kubernetes & scaling](../kubernetes.md).
