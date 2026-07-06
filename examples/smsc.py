"""smsc.py, a store-and-forward SMSC: MAP termination + multi-segment MT.

We own SSN 8. The engine terminates mobile-originated SMS and hands us the
dialogue plus the decoded argument; we ack and forward to SMPP. For delivery we
originate: SRI-SM to the HLR, then one MT dialogue to the serving MSC held open
across segments, `moreMessagesToSend` on all but the last.

Load it into a siphon binary that has mounted the siphon-sigtran namespaces and
wires the SCTP transport (origination and `dlg.result()` need the live node).
"""

from siphon import ss7
from siphon import gsm_map

OUR_GT = b"\x15\x55\x01\x00"


# ── Terminate mobile-originated SMS ──────────────────────────────────────────
@gsm_map.on_mo_forward_sm
async def on_mo(dlg, arg):
    # arg.sm_rp_oa / arg.sm_rp_da / arg.sm_rp_ui are the raw address + TPDU bytes.
    await forward_to_smpp(sender=arg.sm_rp_oa, dest=arg.sm_rp_da, tpdu=arg.sm_rp_ui)
    dlg.reply(gsm_map.mo_forward_sm_res())  # returnResultLast, in a closing End
    dlg.end()


# ── Originate mobile-terminated delivery of a (possibly concatenated) message ─
# SRI-SM to the HLR, then ONE MT dialogue to the serving MSC held open across
# segments; moreMessagesToSend on all but the last, each segment acked.
async def deliver_mt(msisdn, segments):
    res = await gsm_map.send_routing_info_for_sm(msisdn=msisdn, sc_addr=OUR_GT)
    imsi, msc = res.imsi, res.network_node_number

    dlg = gsm_map.begin(to=ss7.gt(msc), ssn=8, ac=gsm_map.AC.short_msg_mt_relay)
    last = len(segments) - 1
    for i, seg in enumerate(segments):
        dlg.invoke(
            gsm_map.mt_forward_sm(
                imsi=imsi,
                sc_addr=OUR_GT,
                tpdu=seg,
                more_messages_to_send=(i != last),
            )
        )
        if i != last:
            dlg.send()  # Continue while more segments follow
        else:
            dlg.end()  # End on the last segment
        await dlg.result()  # await this segment's returnResultLast


async def forward_to_smpp(sender, dest, tpdu):
    """Hand the message to your SMPP client (e.g. the siphon-smpp addon)."""
    # Wire this to your submit path; left as a stand-in for the tutorial.
    _ = (sender, dest, tpdu)
