# A prepaid call from trigger to release, decided by a script that reads what the
# gsmSSF sends through the typed views. Run by tests/python.rs.
#
# Everything the gsmSSF sends is assembled here by hand, tag, length, content,
# from the ASN.1 of TS 29.078 (and Q.773 for TCAP). The node's answers are kept
# with the requests in FRAMES as (opc, dpc, sccp) so that the harness can hand
# the whole exchange to Wireshark. Test PLMN 001/01, +1-555-01xx numbers.

import siphon
from siphon import gsm_cap

CONFIG = """
node: { point_code: 1000, variant: ITU }
associations:
  - { id: msc, adaptation: m3ua, role: server, addrs: [192.0.2.10], port: 2905 }
application_servers:
  - { name: msc, traffic_mode: override, routing_context: 100, asps: [msc] }
mtp3_routes:
  - { dpc: 4000, as: msc, priority: 1 }
sccp:
  local_ssns: [146]
"""
node = siphon.configure(CONFIG)

SCP, MSC = 1000, 4000          # point codes
CAP = 146                      # the CAP subsystem


# ── The script under test: a prepaid SCP ───────────────────────────────────────
# Credit and grants are in the unit of the charging operations, 100 ms.
credit = {"001010000000001": 900}
GRANT = 600
calls = {}        # our transaction id -> the state of one call
seen = {}         # what the script read, for the assertions below


@gsm_cap.on_operation("initial-dp")
def prepaid(dlg, event):
    if not event.is_peer_turn:
        return on_trigger(dlg, event)
    call = calls.get(bytes(dlg.otid))
    if call is None or event.closed or event.is_timeout:
        # The dialogue is gone, or a class 2 operation was not refused.
        if event.closed:
            calls.pop(bytes(dlg.otid), None)
        return
    for component in event.components:
        report = component.event_report_bcsm
        if report is not None:
            on_event(dlg, call, report)
        charging = component.apply_charging_report
        if charging is not None:
            on_charging_report(dlg, call, charging)


def on_trigger(dlg, idp):
    seen["phase"] = dlg.camel_phase
    seen["context"] = dlg.application_context
    seen["trigger"] = (idp.service_key, idp.event_type_bcsm, idp.imsi,
                       bytes(idp.calling_party_number), idp.calling_partys_category)
    location = idp.location_information
    seen["where"] = (location.vlr_number, bytes(location.cell_global_id),
                     bytes(location.location_area_id), location.age_of_location)
    seen["record"] = (bytes(idp.call_reference_number), idp.msc_address,
                      bytes(idp.time_and_timezone))
    seen["state"] = (idp.subscriber_state, idp.ext_basic_service_code,
                     idp.call_forwarding_ss_pending)

    left = credit.get(idp.imsi, 0)
    if idp.event_type_bcsm != 2 or left <= 0:
        dlg.invoke(gsm_cap.release_call(cause=b"\x80\x9f"))   # normal, unspecified
        dlg.end()
        return
    calls[bytes(dlg.otid)] = {"imsi": idp.imsi, "billed": 0, "answered": False}
    dlg.set_idle_timeout(3600)
    # The answer as a notification on the called leg, the disconnect of either
    # leg as a request; then the first period, and the call may go on.
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 1, 2), (9, 0, 1), (9, 0, 2)]))
    dlg.invoke(gsm_cap.apply_charging(max_call_period_duration=min(GRANT, left),
                                      party_to_charge=1))
    dlg.invoke(gsm_cap.continue_())
    dlg.send()


def on_event(dlg, call, report):
    seen.setdefault("events", []).append(
        (report.event_type, report.leg, report.message_type, report.specific_info))
    if report.event_type == 7:
        call["answered"] = True


def on_charging_report(dlg, call, report):
    seen.setdefault("reports", []).append(
        (report.party_to_charge, report.time_if_no_tariff_switch, report.leg_active))
    # The time is counted from the answer: bill what is new since the last report.
    used = report.time_if_no_tariff_switch
    credit[call["imsi"]] -= used - call["billed"]
    call["billed"] = used
    left = credit[call["imsi"]]
    if not report.leg_active:
        dlg.end()
    elif left > 0:
        dlg.invoke(gsm_cap.apply_charging(max_call_period_duration=min(GRANT, left),
                                          tone=True, party_to_charge=1))
        dlg.send()
    else:
        dlg.invoke(gsm_cap.release_call(cause=b"\x80\x90"))   # normal call clearing
        dlg.end()


# ── BER by hand ───────────────────────────────────────────────────────────────
def tlv(tag, content):
    tag = bytes([tag]) if isinstance(tag, int) else bytes.fromhex(tag)
    content = bytes(content)
    length = bytes([len(content)]) if len(content) < 128 else bytes([0x81, len(content)])
    return tag + length + content


def invoke(invoke_id, operation, argument=b""):
    """Invoke ::= [1] { invokeID INTEGER, operationCode INTEGER, parameter }."""
    return tlv(0xA1, tlv(0x02, [invoke_id]) + tlv(0x02, [operation]) + argument)


# capssf-scfGenericAC of CAMEL phase 3, 0.4.0.0.1.21.3.4, and of phase 4.
PHASE3 = bytes.fromhex("04000001150304")
PHASE4 = bytes.fromhex("04000001170304")


def begin(otid, context, *components):
    """Begin ::= [APPLICATION 2] { otid, dialoguePortion { EXTERNAL { dialogue-as-id,
    [0] { AARQ { application-context-name [1] } } } }, components }."""
    aarq = tlv(0x60, tlv(0xA1, tlv(0x06, context)))
    external = tlv(0x28, tlv(0x06, bytes.fromhex("00118605010101")) + tlv(0xA0, aarq))
    return tlv(0x62, tlv(0x48, otid) + tlv(0x6B, external) + tlv(0x6C, b"".join(components)))


def cont(otid, dtid, *components):
    """Continue ::= [APPLICATION 5] { otid, dtid, components }."""
    return tlv(0x65, tlv(0x48, otid) + tlv(0x49, dtid) + tlv(0x6C, b"".join(components)))


FRAMES = []


def from_ssf(tcap):
    """Deliver TCAP octets from the gsmSSF and return the node's answers."""
    sccp = bytes(node.assemble_tcap(tcap, called_ssn=CAP))
    FRAMES.append((MSC, SCP, sccp))
    out = [bytes(frame) for frame in node.deliver(sccp, opc=MSC, dpc=SCP)]
    FRAMES.extend((SCP, MSC, frame) for frame in out)
    return out


# ── What the gsmSSF sends ─────────────────────────────────────────────────────
IMSI = bytes.fromhex("00010100000000f1")              # 001010000000001, TBCD
MSC_ADDRESS = bytes.fromhex("9151551008")             # international, 15550180
CELL = bytes.fromhex("00f11000010001")                # 001/01, LAC 1, CI 1
INITIAL_DP = tlv(0x30, b"".join([
    bytes.fromhex("800164"),                          # serviceKey [0] 100
    bytes.fromhex("8306041351551010"),                # callingPartyNumber [3] 15550101
    bytes.fromhex("85010a"),                          # callingPartysCategory [5]
    bytes.fromhex("bb0580038090a3"),                  # bearerCapability [27] { bearerCap [0] }
    bytes.fromhex("9c0102"),                          # eventTypeBCSM [28] collectedInfo
    tlv("9f32", IMSI),                                # iMSI [50]
    bytes.fromhex("bf33028000"),                      # subscriberState [51] { assumedIdle [0] }
    tlv("bf34", bytes.fromhex("020100")               # locationInformation [52]: age 0,
        + tlv(0x81, MSC_ADDRESS)                      #   vlr-number [1],
        + tlv(0xA3, tlv(0x80, CELL))),                #   [3] { cell global id [0] }
    bytes.fromhex("bf3503830111"),                    # ext-basicServiceCode [53] { ext-Teleservice [3] }
    bytes.fromhex("9f360401020304"),                  # callReferenceNumber [54]
    tlv("9f37", MSC_ADDRESS),                         # mscAddress [55]
    bytes.fromhex("9f38028178"),                      # calledPartyBCDNumber [56] 87
    bytes.fromhex("9f39080262011180510300"),          # timeAndTimezone [57] 2026-10-11 08:15:30
]))

# EventReportBCSM { eventTypeBCSM [0] oAnswer, eventSpecificInformationBCSM [2] {
# oAnswerSpecificInfo [5] {} }, legID [3] { receivingSideID [1] 02 }, miscCallInfo
# [4] { messageType [0] notification } }
ANSWER = bytes.fromhex("3011" "800107" "a202a500" "a303810102" "a403800101")


def charging_report(used, leg_active=None):
    """ApplyChargingReportArg: an OCTET STRING holding CAMEL-CallResult {
    timeDurationChargingResult [0] { partyToCharge [0] { receivingSideID [1] 01 },
    timeInformation [1] { timeIfNoTariffSwitch [0] }, legActive [2] } }."""
    result = bytes.fromhex("a003810101") + tlv(0xA1, tlv(0x80, used.to_bytes(2, "big")))
    if leg_active is not None:
        result += tlv(0x82, [0xFF if leg_active else 0x00])
    return tlv(0x04, tlv(0xA0, result))


# ── The call ──────────────────────────────────────────────────────────────────
SSF = bytes.fromhex("2a2b2c01")

# 1. The trigger. The script reads who is calling and from where, arms the
#    events and grants the first period.
out = from_ssf(begin(SSF, PHASE3, invoke(1, 0, INITIAL_DP)))
assert len(out) == 1
first = node.decode(out[0])
assert first.kind == "continue" and list(first.app_context) == [0, 4, 0, 0, 1, 21, 3, 4]
assert [op for (op, _) in first.invokes] == [23, 35, 31]
scf = bytes(first.otid)
assert seen["phase"] == 3 and seen["context"] == (0, 4, 0, 0, 1, 21, 3, 4)
assert seen["trigger"] == (100, 2, "001010000000001", bytes.fromhex("041351551010"), 10)
assert seen["where"] == ("15550180", CELL, CELL[:5], 0)
assert seen["record"] == (bytes.fromhex("01020304"), "15550180", bytes.fromhex("0262011180510300"))
assert seen["state"] == ("assumed-idle", ("teleservice", b"\x11"), False)
# The first grant, by hand: phase 3 characteristics { timeDurationCharging [0] {
# maxCallPeriodDuration [0] 600 } }, partyToCharge [2] { sendingSideID [0] 01 }.
assert bytes(first.invokes[1][1]) == bytes.fromhex("300d" "8006a00480020258" "a203800101")

# 2. The answer, a notification: read, and nothing to say to it.
assert from_ssf(cont(SSF, scf, invoke(2, 24, ANSWER))) == []
assert seen["events"] == [(7, 2, "notification", "o-answer")]
assert calls[scf]["answered"] and node.open_dialogues() == 1

# 3. The first period is used up and the leg is still there: 60 s billed, 30 s of
#    credit left, granted with a warning tone (`tone [3] BOOLEAN` in phase 3).
out = from_ssf(cont(SSF, scf, invoke(3, 36, charging_report(600))))
assert len(out) == 1
second = node.decode(out[0])
assert second.kind == "continue" and [op for (op, _) in second.invokes] == [35]
assert bytes(second.invokes[0][1]) == bytes.fromhex("3010" "8009a0078002012c8301ff" "a203800101")
assert seen["reports"] == [(1, 600, True)] and credit["001010000000001"] == 300

# 4. The second report: 90 s since the answer, 30 of them new. The credit is
#    gone and the leg is not: the script releases the call.
out = from_ssf(cont(SSF, scf, invoke(4, 36, charging_report(900, leg_active=True))))
assert len(out) == 1
last = node.decode(out[0])
assert last.kind == "end" and bytes(last.dtid) == SSF
assert [(op, bytes(arg)) for (op, arg) in last.invokes] == [(22, bytes.fromhex("04028090"))]
assert seen["reports"] == [(1, 600, True), (1, 900, True)]
assert credit["001010000000001"] == 0 and node.open_dialogues() == 0
CALL = list(FRAMES)

# ── A subscriber with no credit left is refused at the trigger ────────────────
out = from_ssf(begin(bytes.fromhex("2a2b2c02"), PHASE4, invoke(1, 0, INITIAL_DP)))
refused = node.decode(out[0])
assert refused.kind == "end" and [op for (op, _) in refused.invokes] == [22]
assert seen["phase"] == 4 and node.open_dialogues() == 0

# ── A report that does not decode is rejected by its own invoke id ────────────
# A charging report that reads, and with it in the same Continue an event report
# whose legID is a primitive [2] where the ASN.1 has an explicit [3]. The script
# lets MistypedParameter go, and the Reject names invoke 6, not the first
# component of the turn. Nothing the script staged for the first component is
# sent: half an answer is not an answer.
credit["001010000000001"] = 900
SSF2 = bytes.fromhex("2a2b2c03")
scf2 = bytes(node.decode(from_ssf(begin(SSF2, PHASE3, invoke(1, 0, INITIAL_DP)))[0]).otid)
DAMAGED_EVENT = bytes.fromhex("3006" "800109" "820101")
start = len(FRAMES)
out = from_ssf(cont(SSF2, scf2, invoke(5, 36, charging_report(600)), invoke(6, 24, DAMAGED_EVENT)))
assert len(out) == 1
rejected = node.decode(out[0])
assert rejected.kind == "end" and rejected.rejects == [(6, "invoke", 2)] and rejected.invokes == []
assert node.open_dialogues() == 0
REJECTED_EVENT = FRAMES[start:]

# A charging report whose OCTET STRING holds no CAMEL-CallResult, alone in its
# Continue: rejected, mistyped parameter, in an End.
SSF3 = bytes.fromhex("2a2b2c04")
scf3 = bytes(node.decode(from_ssf(begin(SSF3, PHASE3, invoke(1, 0, INITIAL_DP)))[0]).otid)
start = len(FRAMES)
out = from_ssf(cont(SSF3, scf3, invoke(9, 36, bytes.fromhex("0402a100"))))
rejected = node.decode(out[0])
assert rejected.kind == "end" and rejected.rejects == [(9, "invoke", 2)]
assert node.open_dialogues() == 0
REJECTED_REPORT = FRAMES[start:]

# An InitialDP whose IMSI is cut short of its length: the getter raises, and the
# opening Invoke is rejected.
start = len(FRAMES)
out = from_ssf(begin(bytes.fromhex("2a2b2c05"), PHASE3,
                     invoke(1, 0, tlv(0x30, bytes.fromhex("800164" "9f32080001")))))
rejected = node.decode(out[0])
assert rejected.kind == "end" and rejected.rejects == [(1, "invoke", 2)] and rejected.invokes == []
REJECTED_TRIGGER = FRAMES[start:]

# A script that catches the exception decides for itself, and can read which
# Invoke it is about.
caught = {}


@gsm_cap.on_operation("initial-dp")
def careful(dlg, event):
    if not event.is_peer_turn:
        dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(9, 0, 1)]))
        dlg.send()
        return
    for component in event.components:
        try:
            component.event_report_bcsm
        except siphon.MistypedParameter as error:
            caught["invoke_id"] = error.invoke_id
            dlg.error(component.invoke_id, 15)     # unexpectedDataValue, its choice
            dlg.end()


SSF4 = bytes.fromhex("2a2b2c06")
scf4 = bytes(node.decode(from_ssf(begin(SSF4, PHASE3, invoke(1, 0, INITIAL_DP)))[0]).otid)
answered = node.decode(from_ssf(cont(SSF4, scf4, invoke(8, 24, DAMAGED_EVENT)))[0])
assert caught == {"invoke_id": 8}
assert answered.kind == "end" and answered.rejects == [] and answered.error == (8, 15)
