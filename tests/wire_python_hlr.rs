//! The HLR role driven from a siphon addon script (TS 29.002 clauses 8 and
//! 10): the arguments of updateLocation, updateGprsLocation,
//! sendAuthenticationInfo, purgeMS and sendRoutingInfo, written by hand from
//! the ASN.1, read through the addon; insertSubscriberData, cancelLocation,
//! provideRoamingNumber and the results it sends read back by tshark.
//!
//! All values are synthetic (test PLMN 001/01, `+1-555-01xx`, decimal PCs).

#![cfg(feature = "python")]
#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads

mod python_wire;
use python_wire::{dissect, fields, run, tshark_available, Frame};

/// The HLR role, driven from a script: every argument the node terminates is
/// BER written by hand from the TS 29.002 ASN.1 (MAP-MS-DataTypes,
/// MAP-CH-DataTypes), never produced by this crate's encoder, and its decoded
/// view is asserted in the script; everything the node sends is captured and
/// read back by tshark below.
const HLR_SCRIPT: &str = r#"
import siphon
from siphon import gsm_map

CONFIG = """
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: peer, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
application_servers:
  - { name: peer, traffic_mode: override, routing_context: 100, asps: [peer] }
mtp3_routes:
  - { dpc: 2000, as: peer, priority: 1 }
sccp:
  local_ssns: [6]
"""
node = siphon.configure(CONFIG)

HLR = "15550100"; VLR = "15550201"; MSC = "15550209"; SGSN = "15550301"; GMSC = "15550401"
SCF = "15550600"; IMSI = "001010000000001"; MSISDN = "15550100"

def tlv(tag, content):
    assert len(content) < 128
    return bytes([tag, len(content)]) + content

# IMSI 001010000000001 as a TBCD-STRING, an odd count filled with 1111.
IMSI_TBCD = bytes([0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xf1])
def isdn(digits):       # ISDN-AddressString: international, E.164, then TBCD
    pairs = [digits[i:i + 2] for i in range(0, len(digits), 2)]
    return bytes([0x91]) + bytes(int(p[1] if len(p) > 1 else "f", 16) << 4 | int(p[0]) for p in pairs)

# updateLocationArg: imsi IMSI, msc-Number [1], vlr-Number.
UL_ARG = tlv(0x30, tlv(0x04, IMSI_TBCD) + tlv(0x81, isdn(MSC)) + tlv(0x04, isdn(VLR)))
# updateGprsLocationArg: imsi, sgsn-Number, sgsn-Address (IPv4 192.0.2.1).
ULG_ARG = tlv(0x30, tlv(0x04, IMSI_TBCD) + tlv(0x04, isdn(SGSN))
              + tlv(0x04, bytes([0x04, 192, 0, 2, 1])))
# sendAuthenticationInfoArg: imsi [0], numberOfRequestedVectors 3,
# requestingNodeType [3] vlr; and with re-synchronisationInfo instead.
SAI_ARG = tlv(0x30, tlv(0x80, IMSI_TBCD) + tlv(0x02, b"\x03") + tlv(0x83, b"\x00"))
RAND = bytes(range(16)); AUTS = bytes(range(0x20, 0x2e))
SAI_RESYNC = tlv(0x30, tlv(0x80, IMSI_TBCD) + tlv(0x02, b"\x01")
                 + tlv(0x30, tlv(0x04, RAND) + tlv(0x04, AUTS)))
SAI_V2 = tlv(0x04, IMSI_TBCD)
# PurgeMS-Arg ::= [3] SEQUENCE: imsi, vlr-Number [0].
PURGE_ARG = tlv(0xa3, tlv(0x04, IMSI_TBCD) + tlv(0x80, isdn(VLR)))
# sendRoutingInfoArg: msisdn [0], interrogationType [3] basicCall,
# gmsc-OrGsmSCF-Address [6], callReferenceNumber [7], camelInfo [11]
# {supportedCamelPhases phases 1-3, suppress-T-CSI}.
SRI_ARG = tlv(0x30, tlv(0x80, isdn(MSISDN)) + tlv(0x83, b"\x00") + tlv(0x86, isdn(GMSC))
              + tlv(0x87, b"\x12\x34")
              + tlv(0xab, tlv(0x03, b"\x05\xe0") + tlv(0x05, b"")))
SRI_PLAIN = tlv(0x30, tlv(0x80, isdn(MSISDN)) + tlv(0x83, b"\x00") + tlv(0x86, isdn(GMSC)))

seen = {}

def begin(op, arg, frames, opc=2000):
    b = node.assemble_begin(op=op, called_gt=HLR, called_ssn=6, calling_gt=VLR, arg=arg)
    frames.append((opc, 1000, b))
    out = node.deliver(b, opc=opc, dpc=1000)
    for o in out:
        frames.append((1000, opc, o))
    return out

# ── updateLocation: ISD with the CS profile and an O-CSI, then the UL result ──
ul = []
@gsm_map.on_operation("update-location")
def on_ul(dlg, event):
    if event.is_peer_turn:
        if event.is_result:
            dlg.reply(gsm_map.update_location_res(hlr_number=HLR))
            dlg.end()
        elif event.is_error:
            dlg.refuse(34)                              # systemFailure, to the updateLocation
            dlg.end()
        return
    seen["ul"] = event.update_location
    assert event.send_routing_info is None          # another operation's view is None
    dlg.invoke(gsm_map.insert_subscriber_data(
        imsi=IMSI, msisdn=MSISDN, category=0x0a, subscriber_status="service-granted",
        teleservices=[0x11, 0x21, 0x22], odb=["international-og-calls-barred"],
        o_csi=[{"trigger": "collected-info", "service_key": 100, "gsmscf": SCF}],
        camel_phase=2, network_access_mode="packet-and-circuit"))
    dlg.send()

out = begin("update-location", UL_ARG, ul)
isd = node.decode(out[0])
assert isd.kind == "continue" and isd.invoke[0] == 7
ack = node.assemble_continue(dtid=isd.otid, staged=gsm_map.insert_subscriber_data_res())
ul.append((2000, 1000, ack))
for o in node.deliver(ack, opc=2000, dpc=1000):
    ul.append((1000, 2000, o))
# A VLR that refuses the subscriber data: a Continue carrying a returnError
# (Q.773: [3] { invokeID, errorCode local }) for the ISD, written by hand.
# The updateLocation is then answered with a returnError on its own invoke
# id, from that later turn (`dlg.refuse`).
out = node.deliver(node.assemble_begin(op="update-location", called_gt=HLR, called_ssn=6,
                                        calling_gt=VLR, arg=UL_ARG), opc=2000, dpc=1000)
isd = node.decode(out[0])
error = tlv(0xa3, tlv(0x02, b"\x01") + tlv(0x02, b"\x24"))   # invoke 1, unexpectedDataValue (36)
refusal = tlv(0x65, tlv(0x48, b"\x11\x22\x33\x44") + tlv(0x49, bytes(isd.otid)) + tlv(0x6c, error))
answered = node.decode(node.deliver(node.assemble_tcap(refusal), opc=2000, dpc=1000)[0])
assert answered.kind == "end", answered.kind
assert answered.error == (1, 34), answered.error              # the updateLocation's invoke, systemFailure
u = seen["ul"]
assert (u.imsi, u.msc_number, u.vlr_number) == (IMSI, MSC, VLR), (u.imsi, u.msc_number, u.vlr_number)
assert u.lmsi is None and u.skip_subscriber_data_update is False

# ── updateGprsLocation: ISD with two PDP contexts, then the result ─────────────
ulg = []
@gsm_map.on_operation("update-gprs-location")
def on_ulg(dlg, event):
    if event.is_peer_turn:
        if event.is_result:
            dlg.reply(gsm_map.update_gprs_location_res(hlr_number=HLR))
            dlg.end()
        return
    seen["ulg"] = event.update_gprs_location
    dlg.invoke(gsm_map.insert_subscriber_data(imsi=IMSI, msisdn=MSISDN, gprs=[
        {"context_id": 1, "apn": "internet", "qos_subscribed": b"\x23\x93\x1f",
         "ext_qos_subscribed": b"\x02\x93\x96\x40\x40\x74\xfe\x74\xfe",
         "ext_pdp_type": b"\xf1\x8d", "vplmn_address_allowed": True, "ambr": (50000, 100000)},
        {"context_id": 2, "apn": "ims", "qos_subscribed": b"\x23\x93\x1f"},
    ], network_access_mode="packet-and-circuit"))
    dlg.send()

out = begin("update-gprs-location", ULG_ARG, ulg)
isd = node.decode(out[0])
ack = node.assemble_continue(dtid=isd.otid, staged=gsm_map.insert_subscriber_data_res())
ulg.append((2000, 1000, ack))
for o in node.deliver(ack, opc=2000, dpc=1000):
    ulg.append((1000, 2000, o))
g = seen["ulg"]
assert (g.imsi, g.sgsn_number, bytes(g.sgsn_address)) == (IMSI, SGSN, bytes([4, 192, 0, 2, 1]))

# ── sendAuthenticationInfo: the three argument shapes ─────────────────────────
@gsm_map.on_operation("send-auth-info")
def on_sai(dlg, event):
    try:
        seen.setdefault("sai", []).append(event.send_authentication_info)
    except siphon.MistypedParameter as problem:
        seen.setdefault("sai", []).append(str(problem))
        raise
    dlg.reply(gsm_map.send_authentication_info_res(
        triplets=[(RAND, b"\x46\xf8\x41\x6a", bytes.fromhex("eae4be823af9a08b"))]))
    dlg.end()

sai = []
begin("send-auth-info", SAI_ARG, sai)
begin("send-auth-info", SAI_RESYNC, [])
begin("send-auth-info", SAI_V2, [])
plain, resync, v2 = seen["sai"]
assert (plain.imsi, plain.number_of_requested_vectors, plain.requesting_node_type) == (IMSI, 3, 0)
assert plain.re_synchronisation is None and plain.immediate_response_preferred is False
assert resync.number_of_requested_vectors == 1 and resync.requesting_node_type is None
assert tuple(bytes(x) for x in resync.re_synchronisation) == (RAND, AUTS)
assert "version 2" in v2, v2

# ── purgeMS ───────────────────────────────────────────────────────────────────
@gsm_map.on_operation("purge-ms")
def on_purge(dlg, event):
    seen["purge"] = event.purge_ms
    dlg.reply(gsm_map.purge_ms_res(freeze_tmsi=True))
    dlg.end()

begin("purge-ms", PURGE_ARG, [])
p = seen["purge"]
assert (p.imsi, p.vlr_number, p.sgsn_number) == (IMSI, VLR, None)

# ── sendRoutingInfo: a T-CSI first, then the roaming number ───────────────────
sri = []
@gsm_map.on_operation("send-routing-info")
def on_sri(dlg, event):
    info = event.send_routing_info
    seen.setdefault("sri", []).append(info)
    if not info.suppress_t_csi:
        dlg.reply(gsm_map.send_routing_info_res(imsi=IMSI, camel_phase=2, t_csi=[
            {"trigger": "term-attempt-authorized", "service_key": 200, "gsmscf": SCF}]))
    else:
        dlg.reply(gsm_map.send_routing_info_res(imsi=IMSI, roaming_number="15550501",
                                                vmsc_address=MSC))
    dlg.end()

begin("send-routing-info", SRI_PLAIN, sri, opc=2000)
begin("send-routing-info", SRI_ARG, sri, opc=2000)
first, second = seen["sri"]
assert (first.msisdn, first.interrogation_type, first.gmsc_address) == (MSISDN, "basic-call", GMSC)
assert first.suppress_t_csi is False and first.supported_camel_phases == [], (first.suppress_t_csi, first.supported_camel_phases, first.interrogation_type)
assert second.suppress_t_csi is True and second.supported_camel_phases == [1, 2, 3], (second.suppress_t_csi, second.supported_camel_phases)
assert bytes(second.call_reference_number) == b"\x12\x34"

# ── The dialogues the HLR opens: cancelLocation and provideRoamingNumber ──────
cl = [(1000, 2000, node.originate(
    invoke=gsm_map.cancel_location(imsi=IMSI), on_reply=lambda dlg, peer: None,
    called_gt=VLR, called_ssn=7, calling_gt=HLR, calling_ssn=6, dpc=2000,
    ac=gsm_map.AC.location_cancellation)[0])]
prn = [(1000, 2000, node.originate(
    invoke=gsm_map.provide_roaming_number(imsi=IMSI, msc_number=MSC, msisdn=MSISDN,
                                          gmsc_address=GMSC, call_reference_number=b"\x12\x34"),
    on_reply=lambda dlg, peer: None,
    called_gt=VLR, called_ssn=7, calling_gt=HLR, calling_ssn=6, dpc=2000,
    ac=gsm_map.AC.roaming_number_enquiry)[0])]

# Builders refuse what the specification does not allow.
for bad in (lambda: gsm_map.send_routing_info_res(roaming_number="1", t_csi=[]),
            lambda: gsm_map.send_routing_info_res(),
            lambda: gsm_map.insert_subscriber_data(odb=["no-such-barring"]),
            lambda: gsm_map.insert_subscriber_data(camel_phase=5, o_csi=[
                {"trigger": "collected-info", "service_key": 1, "gsmscf": SCF}]),
            lambda: gsm_map.insert_subscriber_data(o_csi=[]),
            lambda: gsm_map.cancel_location(imsi=IMSI, cancellation_type="later"),
            lambda: gsm_map.insert_subscriber_data(gprs=[{"context_id": 1, "apn": "ims",
                "qos_subscribed": b"\x23\x93\x1f", "ext_pdp_type": b"\x8d"}])):
    try:
        bad()
    except siphon.SigtranError:
        continue
    raise AssertionError("a builder accepted what it must refuse")

FRAMES = {"hlr_update_location": ul, "hlr_update_gprs_location": ulg, "hlr_auth": sai,
          "hlr_routing_info": sri, "hlr_cancel_location": cl, "hlr_roaming_number": prn}
"#;

#[test]
fn python_driven_hlr_capture() {
    let flows = run(HLR_SCRIPT);
    let flow = |name: &str| -> &Vec<Frame> {
        &flows
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name}"))
            .1
    };
    assert_eq!(
        flow("hlr_update_location").len(),
        4,
        "Begin, Continue(ISD), Continue(ack), End"
    );
    assert_eq!(flow("hlr_update_gprs_location").len(), 4);

    if !tshark_available() {
        eprintln!("SKIP wire_python HLR dissection: tshark not installed");
        return;
    }
    for (name, frames) in &flows {
        dissect(name, frames, "gsm_map");
    }
    // What tshark reads back from the frames this node sent, frame by frame.
    let read = |name: &str, field: &str| fields(name, flow(name), field);

    // The insertSubscriberData of the location update (frame 2).
    let ul = "hlr_update_location";
    assert_eq!(read(ul, "gsm_map.ms.serviceKey")[1], "100");
    assert_eq!(read(ul, "gsm_map.ms.o_BcsmTriggerDetectionPoint")[1], "2");
    assert_eq!(read(ul, "gsm_map.ms.camelCapabilityHandling")[1], "2");
    assert!(!read(ul, "gsm_map.ms.gsmSCF_Address")[1].is_empty());
    assert_eq!(read(ul, "gsm_map.ms.category")[1], "0a");
    assert_eq!(read(ul, "gsm_map.ms.subscriberStatus")[1], "0");
    assert_eq!(read(ul, "gsm_map.ms.networkAccessMode")[1], "0");
    assert_eq!(read(ul, "gsm_map.ms.Ext_TeleserviceCode")[1], "17,33,34");
    assert_eq!(
        read(ul, "gsm.map.ms.ODB.GeneralData.internationalOGCallsBarred")[1],
        "True"
    );
    assert_eq!(
        read(ul, "gsm.map.ms.ODB.GeneralData.allOG.CallsBarred")[1],
        "False"
    );
    // The updateLocation result closes the dialogue (frame 4).
    assert!(!read(ul, "gsm_map.ms.hlr_Number")[3].is_empty());

    let ulg = "hlr_update_gprs_location";
    assert_eq!(read(ulg, "gsm_map.ms.pdp_ContextId")[1], "1,2");
    assert_eq!(read(ulg, "gsm_map.apn_str")[1], "internet,ims");
    assert!(!read(ulg, "gsm_map.ms.ext_pdp_Type")[1].is_empty());
    assert!(!read(ulg, "gsm_map.ms.vplmnAddressAllowed_element")[1].is_empty());
    assert!(!read(ulg, "gsm_map.ms.hlr_Number")[3].is_empty());

    // The first routing answer carries the T-CSI, the second the roaming number.
    let sri = "hlr_routing_info";
    assert!(!read(sri, "gsm_map.ch.camelRoutingInfo_element")[1].is_empty());
    assert_eq!(read(sri, "gsm_map.ms.t_BcsmTriggerDetectionPoint")[1], "12");
    assert_eq!(read(sri, "gsm_map.ms.serviceKey")[1], "200");
    assert!(!read(sri, "gsm_map.ch.roamingNumber")[3].is_empty());
    assert!(read(sri, "gsm_map.ch.roamingNumber")[1].is_empty());

    assert_eq!(
        read("hlr_cancel_location", "gsm_map.ms.cancellationType")[0],
        "0"
    );
    assert!(!read("hlr_roaming_number", "gsm_map.ch.msc_Number")[0].is_empty());
}
