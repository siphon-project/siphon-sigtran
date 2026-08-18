"""hlr.py, a small HLR: answer the mobility and SMS-routing operations.

A VLR/MSC queries the HLR as a subscriber roams in (updateLocation,
sendAuthenticationInfo), an SMSC asks it where to deliver (SRI-SM), a VLR tells
it a subscriber has gone (purgeMS). The HLR owns its subsystem (SSN 6, set in
`sigtran.yaml`) so those operations terminate here; each is answered on the wire.
Load it into a siphon binary that has mounted the siphon-sigtran namespaces.

Every value is synthetic (test PLMN 001/01, +1-555-01xx addresses).
"""

from siphon import gsm_map

HLR_NUMBER = b"\x91\x51\x55\x10\x09"  # our E.164 address (+15550190), TBCD


# updateLocation is multi-leg: the HLR pushes the subscriber profile to the VLR
# with an insertSubscriberData leg held open, then sends the updateLocation
# result once the VLR acks it. One handler drives both legs, branching on the
# re-entry with a PeerTurn.
@gsm_map.on_operation("update-location")
async def on_update_location(dlg, event):
    if event.is_peer_turn:
        # Follow-up leg: the VLR answered our insertSubscriberData.
        if event.is_result:
            dlg.reply(gsm_map.update_location_res(hlr_number=HLR_NUMBER))
            dlg.end()  # close with the updateLocation result
        elif event.is_error:
            dlg.abort()  # the VLR refused the data
        return
    # Opening leg: push the subscriber profile, hold the dialogue open.
    imsi, msisdn = await load_profile(event.argument)
    dlg.invoke(gsm_map.insert_subscriber_data(imsi=imsi, msisdn=msisdn))
    dlg.send()  # Continue: ISD invoke, dialogue stays open


# sendAuthenticationInfo, SRI-SM and purgeMS are single-shot: one invoke in, one
# result out in a closing End.
@gsm_map.on_operation("send-auth-info")
async def on_send_auth_info(dlg, arg):
    vectors = await mint_quintuplets(arg.argument, n=5)  # your Milenage / TUAK
    dlg.reply(gsm_map.send_authentication_info_res(quintuplets=vectors))
    dlg.end()


@gsm_map.on_operation("sri-sm")
async def on_sri_sm(dlg, arg):
    imsi, msc = await locate(arg.argument)  # look the subscriber up
    dlg.reply(gsm_map.send_routing_info_for_sm_res(imsi=imsi, network_node_number=msc))
    dlg.end()


@gsm_map.on_operation("purge-ms")
async def on_purge_ms(dlg, arg):
    _ = arg
    dlg.reply(gsm_map.purge_ms_res())
    dlg.end()


# ── Your subscriber database. Replace these stand-ins with real lookups. ──────
async def load_profile(argument):
    """Return (imsi, msisdn) for the updateLocation subscriber (synthetic)."""
    _ = argument
    imsi = b"\x00\x11\x10\x00\x00\x00\x00\x14"  # 001010000000041, TBCD
    msisdn = b"\x91\x15\x55\x01\x70"  # +15550170
    return imsi, msisdn


async def mint_quintuplets(argument, n):
    """Run your Milenage/TUAK against the subscriber's K/OP. Placeholder vectors."""
    _ = argument
    return [(b"\x00" * 16, b"\x11" * 8, b"\x22" * 16, b"\x33" * 16, b"\x44" * 16)] * n


async def locate(argument):
    """Return (imsi, serving MSC/SGSN number) for an SRI-SM (synthetic)."""
    _ = argument
    imsi = b"\x00\x11\x10\x00\x00\x00\x00\x14"  # 001010000000041, TBCD
    msc = b"\x91\x15\x55\x01\x80"  # +15550180
    return imsi, msc
