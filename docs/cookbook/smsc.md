# Building an SMSC

A store-and-forward SMSC does two jobs over SS7: it **terminates**
mobile-originated SMS (MO-ForwardSM) and it **originates** mobile-terminated
delivery (SRI-SM to the HLR, then MT-ForwardSM to the serving MSC). This recipe
is
[`examples/smsc.py`](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/smsc.py),
walked section by section.

```
   MSC ──MO-ForwardSM──▶  ┌──────────────────┐
                          │   this SMSC      │  ──SRI-SM──▶  HLR
   MSC ◀─MT-ForwardSM───  │  (siphon-sigtran) │  ◀routing──
                          └──────────────────┘  ──MT-ForwardSM──▶ serving MSC
```

siphon-sigtran owns the MAP and TCAP layers: the dialogue, the transaction ids,
moreMessagesToSend, and the wire encoding. It deliberately does **not** touch
the SMS content. The `sm_rp_ui` field of a ForwardSM is an opaque octet string,
the SMS transfer-layer PDU. To read or build that (SMS-SUBMIT / SMS-DELIVER per
3GPP TS 23.040, GSM 7-bit packing per TS 23.038, the User-Data-Header for
concatenation, TON/NPI addresses), a script uses the sibling
[`tpdu`](https://crates.io/crates/tpdu) crate, which also ships as a Python
wheel ([`pip install tpdu`](https://pypi.org/project/tpdu/)).

!!! note "The layer split"
    MAP transaction, dialogue, moreMessagesToSend, addressing at SCCP: **this
    crate**. SMS-SUBMIT / SMS-DELIVER, GSM-7 packing, UDH concatenation: the
    **`tpdu`** crate. Keeping them apart is deliberate; siphon-sigtran handles
    the signalling, `tpdu` handles the message bytes.

## We own SSN 8

The config declares the SMSC's subsystem so inbound MO SMS terminates locally:

```yaml
node:
  point_code: 1000
  variant: itu

associations:
  - { id: msc-1, adaptation: m3ua, role: server, addrs: [10.1.0.12], port: 2905 }

application_servers:
  - { name: msc, traffic_mode: override, routing_context: 101, asps: [msc-1] }

mtp3_routes:
  - { dpc: 2002, as: msc, priority: 1 }

sccp:
  local_ssns: [8]        # we own SSN 8; MO-ForwardSM to it terminates here
  gtt:
    - { match: {gt_prefix: "1555"}, to: {dpc: 2000, ssn: 6} }   # SRI-SM toward the HLR
```

## Terminate mobile-originated SMS

Register a handler for MO-ForwardSM. The engine hands you the
[`Dialogue`](../script-api.md#dialogue) and the decoded
[`IncomingOp`](../script-api.md#incomingop); `arg.sm_rp_oa`, `arg.sm_rp_da` and
`arg.sm_rp_ui` are the raw originating address, destination address, and TPDU
bytes.

```python
import tpdu
from siphon import ss7, gsm_map

OUR_GT = b"\x15\x55\x01\x00"

@gsm_map.on_mo_forward_sm
async def on_mo(dlg, arg):
    # arg.sm_rp_ui is the opaque SMS TPDU: decode it with tpdu to read the message.
    rp = tpdu.parse_rp_data(arg.sm_rp_ui)              # RP-DATA carrying SMS-SUBMIT
    submit = rp.sms_submit
    await forward_to_store(dest=submit.tp_destination_address,
                           text=submit.tp_user_data)
    dlg.reply(gsm_map.mo_forward_sm_res())             # returnResultLast, in a closing End
    dlg.end()
```

The moment you have the decoded TPDU, the message is yours: spool it, route it,
hand it to another transport. The MAP side is two lines, `reply` then `end`.

## Originate multi-segment MT delivery

Delivering a mobile-terminated message is two dialogues. First an **SRI-SM** to
the HLR to learn the subscriber's IMSI and serving MSC; then **one** MT dialogue
to that MSC, held open across the segments of a concatenated message, with
`moreMessagesToSend` set on all but the last.

The SMS-DELIVER TPDUs, including the User-Data-Header that ties the segments
together, are built with `tpdu`. moreMessagesToSend and the dialogue lifetime
are siphon-sigtran's job.

The SMS-DELIVER segments are built by a small helper that calls `tpdu`. It packs
the body (GSM-7 or UCS-2), splits it, and writes the concatenation
User-Data-Header, all TS 23.040 / TS 23.038 work that belongs to `tpdu`:

```python
def sms_deliver_segments(sender, text):
    """Return one or more SMS-DELIVER TPDU byte strings for `text`.

    tpdu owns the content: pack_gsm7 for the body, the SMS-DELIVER builder for
    each TPDU, and a concatenation UserDataHeader when the message spans
    multiple segments. siphon-sigtran never inspects these bytes.
    """
    ...   # your tpdu builder calls
```

The delivery itself is one MAP dialogue held open across those segments:

```python
async def deliver_mt(msisdn, text):
    # 1. Ask the HLR where the subscriber is (routed by GTT to the HLR).
    res = await gsm_map.send_routing_info_for_sm(msisdn=msisdn, sc_addr=OUR_GT)
    imsi, msc = res.imsi, res.network_node_number

    # 2. Build the SMS-DELIVER segments with tpdu.
    segments = sms_deliver_segments(sender=OUR_GT, text=text)

    # 3. ONE MT dialogue to the serving MSC, held open across segments.
    dlg = gsm_map.begin(to=ss7.gt(msc), ssn=8, ac=gsm_map.AC.short_msg_mt_relay)
    last = len(segments) - 1
    for i, seg in enumerate(segments):
        dlg.invoke(gsm_map.mt_forward_sm(
            imsi=imsi,
            sc_addr=OUR_GT,
            tpdu=seg,                                # the SMS-DELIVER bytes from tpdu
            more_messages_to_send=(i != last),
        ))
        dlg.send() if i != last else dlg.end()       # Continue while more, End on the last
        await dlg.result()                           # await this segment's returnResultLast
```

Two things are worth calling out:

- **One dialogue, many segments.** `gsm_map.begin` opens the MT dialogue once;
  the loop stages an MT-ForwardSM invoke per segment and flushes with `send`
  (keep it open) or `end` (close on the last). `moreMessagesToSend` is a flag on
  the invoke builder, so the serving MSC knows more is coming and keeps the
  radio connection up.
- **`tpdu` owns the concatenation.** Splitting the message into segments and
  writing the UDH concatenation IE is `tpdu`'s work (TS 23.040). siphon-sigtran
  never inspects the bytes; it carries them and sequences the dialogue.

!!! note "Awaitables need the live node"
    `await gsm_map.send_routing_info_for_sm(...)` and `await dlg.result()`
    drive the SCTP transport the composing siphon binary owns. In-process
    termination (the MO handler above) needs no transport and can be exercised
    with [`node.deliver`](../script-api.md#node); origination needs the running
    node. See [Script API](../script-api.md#dialogue).

## From here to production

- **Spool and retry.** Back the store between MO and MT with a durable queue;
  retry MT delivery on failure or on an `alert` that the subscriber is
  reachable again.
- **DLR handling.** A delivery report comes back as its own MAP operation; parse
  the status with `tpdu` and correlate it to the original submission.
- **Screening.** If this SMSC also fronts transit SMS, screen SRI-SM origins at
  the content layer (GSMA FS.11); see [Building an STP](stp.md).
- **Deploy it.** [Deployment](../deployment.md) and
  [Kubernetes & scaling](../kubernetes.md).
