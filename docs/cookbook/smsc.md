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

OUR_GT = "15550100"                       # our E.164 address (+1 555 0100)

@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    # arg.sm_rp_ui is the opaque RP-DATA carrying an SMS-SUBMIT. tpdu decodes it.
    rp = tpdu.parse_rp_data(arg.sm_rp_ui)
    submit = rp.sms_submit
    dest = submit.tp_destination_address.to_e164()     # the recipient MSISDN
    text = submit.text()                               # decoded for GSM-7 / UCS-2 DCS
    await spool(sender=rp.rp_originator_address, dest=dest, text=text)
    dlg.reply(gsm_map.mo_forward_sm_res())             # returnResultLast, in a closing End
    dlg.end()
```

The moment you have the decoded TPDU, the message is yours: spool it, route it,
hand it to another transport. The MAP side is two lines, `reply` then `end`. A
TPDU that arrives without the RP wrapper (an SMPP `submit_sm`, or a bare
`sm-RP-UI`) parses just as well with `tpdu.parse_sms_submit(...)` /
`tpdu.destination_from_tpdu(...)`.

## Mobile-terminated delivery

Terminating mobile-originated SMS (above) runs on the wire today. Delivering a
mobile-**terminated** message is the other half of a store-and-forward SMSC, and
it **originates** dialogues: an SRI-SM to the HLR to learn the subscriber's IMSI
and serving MSC, then one MT-ForwardSM dialogue to that MSC held open across the
segments of a concatenated message. The node opens a dialogue it initiates and
awaits the peer's response over SCTP with `gsm_map.begin(...)` for a single
request/response, or `node.originate(...)` with an `on_reply(dlg, peer)` callback
for a multi-leg delivery (segment 1 with `moreMessagesToSend`, the ack, segment
2, the closing End). A terminate-only SMSC front end (decode, screen, spool, ack
the MO leg) works equally well.

The SMS-DELIVER TPDUs, including the User-Data-Header that ties the segments
together, are built with `tpdu` (TS 23.040 / TS 23.038 / TS 24.011);
`moreMessagesToSend` and the dialogue lifetime are siphon-sigtran's job.
siphon-sigtran never inspects the SMS bytes; it carries them and sequences the
dialogue.

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
