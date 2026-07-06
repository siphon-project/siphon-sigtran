"""smsc.py, a store-and-forward SMSC: MAP termination + multi-segment MT.

siphon-sigtran owns the MAP dialogue: the transaction ids, moreMessagesToSend, and
the wire TCAP. It never touches the SMS content. The `sm_rp_ui` of a ForwardSM is
an opaque transfer-layer PDU, and the `tpdu` crate owns that
(`pip install tpdu`, or the sibling Rust crate): SMS-SUBMIT / SMS-DELIVER per
TS 23.040, RP-DATA per TS 24.011, GSM 7-bit packing per TS 23.038, and the
User-Data-Header for concatenation.

We own SSN 8. The engine terminates mobile-originated SMS and hands us the
dialogue plus the decoded argument; we parse the TPDU with `tpdu`, ack, and spool
it. For delivery we originate: SRI-SM to the HLR, then one MT dialogue to the
serving MSC held open across segments, moreMessagesToSend on all but the last,
each SMS-DELIVER built with `tpdu` and wrapped in RP-DATA Network->MS.

Load it into a siphon binary that has mounted the siphon-sigtran namespaces and
wires the SCTP transport (origination and `dlg.result()` need the live node).
"""

import tpdu

from siphon import ss7, gsm_map

OUR_GT = b"\x91\x15\x55\x01\x00"       # the SMSC's own E.164 address, TBCD
GSM7 = 0x00                            # TP-DCS: default GSM 7-bit alphabet
CONCAT_SEPTETS = 153                   # per-segment body with an 8-bit concat UDH


# ── Terminate mobile-originated SMS ──────────────────────────────────────────
# arg.sm_rp_ui is the opaque RP-DATA carrying an SMS-SUBMIT. tpdu decodes it; the
# MAP side is two lines, reply then end.
@gsm_map.on_mo_forward_sm
async def on_mo(dlg, arg):
    rp = tpdu.parse_rp_data(arg.sm_rp_ui)          # RP-DATA(SMS-SUBMIT) from the MS
    submit = rp.sms_submit
    dest = submit.tp_destination_address.to_e164()  # the recipient MSISDN
    text = submit.text()                            # decoded for GSM-7 / UCS-2 DCS

    await spool(sender=rp.rp_originator_address, dest=dest, text=text)

    dlg.reply(gsm_map.mo_forward_sm_res())          # returnResultLast, in a closing End
    dlg.end()


def dest_of_bare_tpdu(tpdu_bytes):
    """Pull the recipient out of a bare SMS-SUBMIT TPDU (no RP-DATA wrapper).

    A submit_sm arriving over SMPP, or an SS7 MO with the TPDU only, parses just
    as well: tpdu reads the TP-DA straight off the SUBMIT.
    """
    submit = tpdu.parse_sms_submit(tpdu_bytes)
    _ = submit  # inspect submit.tp_dcs / .tp_user_data / .text() as needed
    return tpdu.destination_from_tpdu(tpdu_bytes)   # the TP-DA digits


# ── Originate multi-segment mobile-terminated delivery ───────────────────────
# SRI-SM to the HLR for the IMSI + serving MSC, then ONE MT dialogue held open
# across the SMS-DELIVER segments; moreMessagesToSend on all but the last.
async def deliver_mt(recipient_msisdn, sender_msisdn, text):
    res = await gsm_map.send_routing_info_for_sm(msisdn=recipient_msisdn, sc_addr=OUR_GT)
    imsi, msc = res.imsi, res.network_node_number

    segments = sms_deliver_segments(sender_msisdn, text)   # tpdu builds each RP-DATA

    dlg = gsm_map.begin(to=ss7.gt(msc), ssn=8, ac=gsm_map.AC.short_msg_mt_relay)
    last = len(segments) - 1
    for i, seg in enumerate(segments):
        dlg.invoke(gsm_map.mt_forward_sm(
            imsi=imsi,
            sc_addr=OUR_GT,
            tpdu=seg,                              # RP-DATA(SMS-DELIVER) bytes from tpdu
            more_messages_to_send=(i != last),
        ))
        dlg.send() if i != last else dlg.end()      # Continue while more, End on the last
        await dlg.result()                          # await this segment's returnResultLast


# ── tpdu owns the SMS content ────────────────────────────────────────────────
def sms_deliver_segments(sender_msisdn, text):
    """Return one or more RP-DATA(SMS-DELIVER) byte strings for `text`.

    tpdu packs the body (pack_gsm7), builds each SMS-DELIVER, adds a concatenation
    User-Data-Header when the message spans multiple segments, and wraps each in an
    RP-DATA Network->MS. siphon-sigtran never inspects these bytes; it carries them
    and sequences the dialogue.
    """
    oa = tpdu.Address(sender_msisdn, ton=1, npi=1)
    chunks = _chunks(text, CONCAT_SEPTETS)

    # Single segment: no UDH. The builder packs the body and sets the septet TP-UDL.
    if len(chunks) == 1:
        deliver = (tpdu.SmsDeliver.builder(oa)
                   .gsm7_text(text)                 # sets user data + septet TP-UDL
                   .dcs(GSM7)
                   .build())
        return [tpdu.RpDataNetworkToMs(deliver).encode()]

    # Concatenated: each segment carries the 8-bit concatenation IE
    # (05 00 03 <ref> <total> <seq>), which reserves the first seven septets of the
    # body (six UDH octets plus one fill bit). tpdu owns the GSM-7 packing.
    ref = 0x42                                       # concat reference, one per message
    total = len(chunks)
    out = []
    for seq, chunk in enumerate(chunks, start=1):
        packed, septets = tpdu.pack_gsm7(chunk)
        udh = tpdu.UserDataHeader([0x00, 0x03, ref, total, seq])
        udh_bytes = udh.encode()
        deliver = tpdu.SmsDeliver(
            oa,
            udh_bytes + packed,
            tp_udhi=True,
            tp_dcs=GSM7,
            user_data_length=_septets(len(udh_bytes)) + septets,
        )
        out.append(tpdu.RpDataNetworkToMs(deliver).encode())
    return out


def _chunks(text, size):
    return [text[i:i + size] for i in range(0, max(len(text), 1), size)]


def _septets(octets):
    """GSM-7 septets a run of `octets` header bytes occupies (rounded up)."""
    return (octets * 8 + 6) // 7


async def spool(sender, dest, text):
    """Hand the message to your durable store / SMPP submit path."""
    # Wire this to your queue; left as a stand-in for the tutorial.
    _ = (sender, dest, text)
