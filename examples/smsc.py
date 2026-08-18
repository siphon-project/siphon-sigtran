"""smsc.py, a terminating SMSC front end: MAP termination of mobile-originated SMS.

siphon-sigtran owns the MAP dialogue: the transaction ids and the wire TCAP. It
never touches the SMS content. The `sm_rp_ui` of a ForwardSM is an opaque
transfer-layer PDU, and the `tpdu` crate owns that (`pip install tpdu`, or the
sibling Rust crate): SMS-SUBMIT / SMS-DELIVER per TS 23.040, RP-DATA per
TS 24.011, GSM 7-bit packing per TS 23.038, and the User-Data-Header for
concatenation.

We own SSN 8. The engine terminates mobile-originated SMS and hands us the
dialogue plus the decoded argument; we parse the TPDU with `tpdu`, ack, and spool
it. (Mobile-terminated delivery originates a dialogue over the SCTP transport,
which is a roadmap feature; see the changelog.)

Load it into a siphon binary that has mounted the siphon-sigtran namespaces.
Every value is synthetic (test PLMN 001/01, +1-555-01xx addresses).
"""

import tpdu

from siphon import gsm_map


# ── Terminate mobile-originated SMS ──────────────────────────────────────────
# arg.sm_rp_ui is the opaque RP-DATA carrying an SMS-SUBMIT. tpdu decodes it; the
# MAP side is two lines, reply then end.
@gsm_map.on_operation("mo-forward-sm")
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


async def spool(sender, dest, text):
    """Hand the message to your durable store / SMPP submit path."""
    # Wire this to your queue; left as a stand-in for the tutorial.
    _ = (sender, dest, text)
