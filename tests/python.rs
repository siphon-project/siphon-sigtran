//! The siphon addon face, driven end to end against siphon-sip.
//!
//! This integration test compiles only with `--features python`, so siphon-sip
//! (the host the addon slots into) is in the build graph and the crate is
//! genuinely built against it. It mirrors how a composing siphon binary wires
//! the addon: build a `siphon` module, call `python::register(py, parent)`, and
//! let a script reach the mounted `ss7` / `gsm_map` / `gsm_cap` namespaces with
//! `from siphon import ...`. The script then programs the Rust routing tables,
//! registers MAP/CAP termination handlers, and drives a genuine MAP dialogue
//! through the engine, so the addon's handlers run for real, not in a mock.
//!
//! All node state is process-wide, so the script-driving assertions live in one
//! sequential test (the interpreter is shared across the binary's tests).

#![cfg(feature = "python")]

use std::ffi::CString;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

/// Mount the addon onto a throwaway `siphon` module and register it in
/// `sys.modules`, so `from siphon import ss7` resolves exactly as it does inside
/// a composing siphon binary that called `register(py, parent)` at startup.
fn mount(py: Python<'_>) -> PyResult<()> {
    let siphon = PyModule::new(py, "siphon")?;
    siphon_sigtran::python::register(py, &siphon)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("siphon", &siphon)?;
    Ok(())
}

// A minimal single-tenant node: PC 1000 (ITU), owning HLR (6) + MSC (8), with an
// M3UA AS `hlr` reachable at DPC 2000. Synthetic (test PLMN 001/01).
const DRIVE: &str = r#"
import asyncio
import inspect

import siphon
from siphon import ss7, gsm_map, gsm_cap, inap

CONFIG = """
node: { point_code: 1000, variant: ITU }
associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
application_servers:
  - { name: hlr, traffic_mode: override, routing_context: 100, asps: [hlr-a] }
mtp3_routes:
  - { dpc: 2000, as: hlr, priority: 1 }
sccp:
  local_ssns: [6, 8, 106]
"""

# ── Import surface: the four namespaces + the node API + the exception ─────────
assert hasattr(siphon, "ss7")
assert hasattr(siphon, "gsm_map")
assert hasattr(siphon, "gsm_cap")
assert hasattr(siphon, "inap")
assert callable(siphon.configure)
assert callable(siphon.metrics)
assert issubclass(siphon.SigtranError, Exception)
assert "sigtran_active_dialogues" in siphon.metrics()

# ── configure builds the node ─────────────────────────────────────────────────
node = siphon.configure(CONFIG)
assert "default" in ss7.tenants
assert node.open_dialogues() == 0

# ── Program the Rust routing tables live ──────────────────────────────────────
ss7.routes.add(dpc=2000, linkset="transit", priority=3)
ss7.routes.cache("155502", dpc=2006, ssn=6, ttl=3600)
ss7.gtt.add(match={"gt_prefix": "155503"}, to={"dpc": 2007, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")
ss7.content.add_rule(
    name="steer-partner-x",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"screen": True},
)

# A route naming neither an AS nor a linkset is rejected up front.
try:
    ss7.routes.add(dpc=2000)
    raise AssertionError("expected SigtranError for a route with no target")
except siphon.SigtranError:
    pass
# A malformed GTT match (wrong field type) fails the typed deserialiser.
try:
    ss7.gtt.add(match={"gti": "not-a-number"}, to={"dpc": 2000, "ssn": 6})
    raise AssertionError("expected SigtranError for a malformed GTT match")
except siphon.SigtranError:
    pass

# ── A MO-ForwardSM Begin driven through the engine reaches the handler ────────
replied = {}

@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    replied["op"] = arg.operation_code
    dlg.reply(gsm_map.mo_forward_sm_res())
    dlg.end()

begin = node.assemble_begin(
    op="mo-forward-sm",
    called_gt="15550100",
    called_ssn=8,
    calling_gt="15550142",
    ac=gsm_map.AC.short_msg_mo_relay,
)
frames = node.deliver(begin, opc=2000, dpc=1000)
assert replied["op"] == 46          # MO-ForwardSM operation code
assert len(frames) == 1             # a single closing End
assert node.open_dialogues() == 0   # the End closed it
# MO-ForwardSM returns nothing: the ack is a ReturnResultLast with the invoke id
# and no result sequence (Q.773), and it is on the wire.
mo_end = node.decode(frames[0])
assert mo_end.kind == "end" and mo_end.result is None and mo_end.result_invoke_id == 1

# ── Full HLR: updateLocation held open for an insertSubscriberData leg ─────────
# The engine terminates updateLocation; the HLR pushes subscriber data to the
# VLR (a Continue that holds the dialogue open), then closes with the
# updateLocation result once the VLR acks the ISD. One Python handler drives both
# legs, branching on `event.is_peer_turn`.
HLR_GT = "15550190"   # an E.164 digit string; the builder TBCD-encodes it
UL_IMSI = b"\x00\x11\x10\x00\x00\x00\x00\x14"
UL_MSISDN = b"\x91\x15\x55\x01\x70"

@gsm_map.on_operation("update-location")
async def on_ul(dlg, event):
    if event.is_peer_turn:
        # The VLR acked the insertSubscriberData; finish with the UL result.
        if event.is_result:
            assert event.operation_code == 7      # the ISD op the result answers
            dlg.reply(gsm_map.update_location_res(hlr_number=HLR_GT))
            dlg.end()
        return
    # Opening leg (event is the updateLocation IncomingOp): push subscriber data.
    assert event.is_peer_turn is False
    dlg.invoke(gsm_map.insert_subscriber_data(imsi=UL_IMSI, msisdn=UL_MSISDN))
    dlg.send()

ul_begin = node.assemble_begin(
    op="update-location", called_gt="15550100", called_ssn=6, calling_gt="15550180",
)
leg1 = node.deliver(ul_begin, opc=2000, dpc=1000)
assert len(leg1) == 1
d1 = node.decode(leg1[0])
assert d1.kind == "continue"           # the ISD leg held the dialogue open
isd_op, _isd_arg = d1.invoke
assert isd_op == 7                      # insertSubscriberData
assert node.open_dialogues() == 1
our_tid = d1.otid

# The VLR acks the ISD; the HLR must close with the updateLocation result.
ack = node.assemble_continue(dtid=our_tid, staged=gsm_map.insert_subscriber_data_res())
leg2 = node.deliver(ack, opc=2000, dpc=1000)
assert len(leg2) == 1
d2 = node.decode(leg2[0])
assert d2.kind == "end"                 # the UL result closes in an End
assert d2.dtid == b"\x11\x22\x33\x44"   # echoes the VLR's original OTID (assemble_begin's)
ul_op, ul_param = d2.result
assert ul_op == 2                       # updateLocation
assert ul_param                         # carries the HLR number
# The hlr_number digit string "15550190" rode the wire as a TBCD ISDN-AddressString
# (0x91 international/E.164 + swapped-nibble digits): the builder encoded it.
assert bytes([0x91, 0x51, 0x55, 0x10, 0x09]) in ul_param
assert node.open_dialogues() == 0       # dialogue closed on the result

# ── sendAuthenticationInfo answered with a quintuplet vector, single shot ─────
@gsm_map.on_operation("send-auth-info")
async def on_sai(dlg, arg):
    dlg.reply(gsm_map.send_authentication_info_res(
        quintuplets=[(b"\x00" * 16, b"\x11" * 8, b"\x22" * 16, b"\x33" * 16, b"\x44" * 16)]
    ))
    dlg.end()

sai_begin = node.assemble_begin(
    op="send-auth-info", called_gt="15550100", called_ssn=6, calling_gt="15550180",
)
sai_out = node.deliver(sai_begin, opc=2000, dpc=1000)
assert len(sai_out) == 1
ds = node.decode(sai_out[0])
assert ds.kind == "end"
sai_op, sai_param = ds.result
assert sai_op == 56                     # sendAuthenticationInfo
assert sai_param                        # the auth vectors
assert node.open_dialogues() == 0

# ── A fuller CAMEL SCP: initialDP answered with RequestReportBCSMEvent + Connect
@gsm_cap.on_operation("initial-dp")
async def on_idp(dlg, idp):
    # Arm the answer / disconnect detection points, then connect the call onward.
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 0), (9, 1)]))
    dlg.invoke(gsm_cap.connect(destination_routing_address=["15550199"]))
    dlg.end()

# An SCP that also receives EventReportBCSM registers a handler for it.
@gsm_cap.on_operation("event-report-bcsm")
async def on_erb(dlg, arg):
    dlg.end()

assert on_erb is not None
assert gsm_cap.release_call(cause=b"\x90\x03") is not None
assert gsm_cap.apply_charging(charging_characteristics=b"\x01\x02\x03") is not None

idp_begin = node.assemble_begin(
    op="initial-dp", called_gt="15550100", called_ssn=6, calling_gt="15550170",
)
idp_out = node.deliver(idp_begin, opc=2000, dpc=1000)
assert len(idp_out) == 1
di = node.decode(idp_out[0])
assert di.kind == "end"                 # both invokes ride the closing End
idp_ops = [op for (op, _) in di.invokes]
assert 23 in idp_ops and 20 in idp_ops  # RequestReportBCSMEvent + Connect
# The connect destination "15550199" rode the wire as a Q.763 Called Party Number
# (0x04 international + 0x10 ISDN plan + swapped-nibble digits): the builder encoded it.
connect_arg = next(arg for (op, arg) in di.invokes if op == 20)
assert bytes([0x04, 0x10, 0x51, 0x55, 0x10, 0x99]) in connect_arg
assert node.open_dialogues() == 0

# ── An INAP CS-1 SCP: initialDP answered with RequestReportBCSMEvent + Connect ─
# INAP is a TCAP-user peer to CAMEL; the SCP terminates the SSF-SCF dialogue the
# same way, under the Core INAP CS-1 application context, on the SCP subsystem
# (SSN 106). The decoded initialDP exposes the fixed-network INAP fields.
INAP_IDP = b"\x30\x11\x80\x01\x64\x82\x05\x91\x51\x55\x10\x24\x83\x05\x91\x51\x55\x10\x10"
INAP_CALLED = b"\x91\x51\x55\x10\x24"
inap_seen = {}

@inap.on_operation("initial-dp")
async def on_inap_idp(dlg, idp):
    inap_seen["service_key"] = idp.inap_service_key
    inap_seen["called"] = idp.inap_called_party_number
    # Arm the answer / disconnect detection points, then route the call onward.
    dlg.invoke(inap.request_report_bcsm_event(events=[(7, 0), (9, 1)]))
    dlg.invoke(inap.connect(destination_routing_address=[b"\x00\x11\x22"]))
    dlg.end()

# An SCP that also fields the follow-up reports registers those handlers too.
@inap.on_operation("event-report-bcsm")
async def on_inap_erb(dlg, arg):
    dlg.end()

@inap.on_operation("apply-charging-report")
async def on_inap_acr(dlg, arg):
    dlg.end()

# Every originating builder produces a staged invoke dlg.invoke() consumes.
assert on_inap_erb is not None and on_inap_acr is not None
assert inap.continue_() is not None
assert inap.release_call(cause=b"\x90\x03") is not None
assert inap.apply_charging(charging_characteristics=b"\x01\x02\x03") is not None
assert inap.apply_charging(charging_characteristics=b"\x01", party_to_charge=b"\x01") is not None
assert inap.connect_to_resource() is not None
# What the SRF is told to send is a typed choice, built from keywords or handed
# over as the BER of an InformationToSend value (here a tone: [1] { [0] 7 }).
assert inap.play_announcement(message_id=7) is not None
assert inap.play_announcement(tone_id=3, tone_duration=10) is not None
assert inap.play_announcement(information_to_send=b"\xa1\x03\x80\x01\x07") is not None
assert inap.prompt_and_collect_user_information(maximum_digits=4) is not None
assert inap.prompt_and_collect_user_information(maximum_digits=4, minimum_digits=4, message_id=9) is not None
for bad in (lambda: inap.play_announcement(),
            lambda: inap.play_announcement(information_to_send=b"\x0a\x0b"),
            lambda: inap.play_announcement(message_id=1, tone_id=2),
            lambda: inap.prompt_and_collect_user_information(),
            lambda: inap.prompt_and_collect_user_information(collected_info=b"\x01\x02"),
            lambda: inap.connect(destination_routing_address=[]),
            lambda: inap.request_report_bcsm_event(events=[(7,)])):
    try:
        bad()
        raise AssertionError("expected SigtranError")
    except siphon.SigtranError:
        pass
assert list(inap.AC.ssp_to_scp.arcs) == [0, 4, 0, 1, 1, 1, 0, 0]
assert list(inap.AC.assist_handoff_ssp_to_scp.arcs) == [0, 4, 0, 1, 1, 1, 1, 0]
assert list(inap.AC.ip_to_scp.arcs) == [0, 4, 0, 1, 1, 1, 2, 0]

inap_begin = node.assemble_begin(
    op="initial-dp",
    called_gt="15550100",
    called_ssn=106,
    calling_gt="15550170",
    arg=INAP_IDP,
    ac=inap.AC.ssp_to_scp,
)
inap_out = node.deliver(inap_begin, opc=2000, dpc=1000)
assert len(inap_out) == 1
dinap = node.decode(inap_out[0])
assert dinap.kind == "end"                            # both invokes ride the closing End
assert list(dinap.app_context) == [0, 4, 0, 1, 1, 1, 0, 0]  # IN AC echoed in the AARE, not a CAMEL one
inap_ops = [op for (op, _) in dinap.invokes]
assert 23 in inap_ops and 20 in inap_ops              # RequestReportBCSMEvent + Connect
assert inap_seen["service_key"] == 100                # the decoded INAP serviceKey
assert inap_seen["called"] == INAP_CALLED             # the decoded INAP calledPartyNumber
assert node.open_dialogues() == 0

# ── on_operation: alternation, catch-all precedence, and typo-raises ──────────
# The siphon-family decorator shape: one handler over several operations
# (pipe-separated, like @proxy.on_request("INVITE|SUBSCRIBE")), a bare catch-all
# (like a bare @proxy.on_request), and a typo that raises at decoration time. A
# specific handler always beats a catch-all, whichever registered first.
def drive(op_name):
    begin = node.assemble_begin(op=op_name, called_gt="15550100", called_ssn=6,
                                calling_gt="15550180")
    return node.deliver(begin, opc=2000, dpc=1000)

specific_ops = []

@gsm_map.on_operation("purge-ms|ready-for-sm")     # one handler, two operations
async def on_specific(dlg, arg):
    specific_ops.append(arg.operation_code)
    dlg.reply(gsm_map.purge_ms_res() if arg.operation_code == 67
              else gsm_map.ready_for_sm_res())
    dlg.end()

for op_name in ("purge-ms", "ready-for-sm"):        # both assemble via the shared vocabulary
    out = drive(op_name)
    assert len(out) == 1 and node.decode(out[0]).kind == "end"
assert set(specific_ops) == {67, 66}                # one handler fired for both (purgeMS=67, readyForSM=66)

# A bare catch-all fires only where no specific handler is registered. It is
# registered AFTER the specific handler above, yet must not shadow it.
catchall_ops = []

@gsm_map.on_operation
async def on_any(dlg, arg):
    catchall_ops.append(arg.operation_code)
    dlg.abort()

drive("report-sm-delivery-status")                  # no specific handler -> catch-all fires
assert catchall_ops == [47]
specific_ops.clear()
drive("ready-for-sm")                               # specific still wins over the later catch-all
assert specific_ops == [66] and 66 not in catchall_ops

# A specific handler registered AFTER the catch-all still wins for its op.
late_ops = []

@gsm_map.on_operation("report-sm-delivery-status")
async def on_late(dlg, arg):
    late_ops.append(arg.operation_code)
    dlg.abort()

catchall_ops.clear()
drive("report-sm-delivery-status")
assert late_ops == [47] and catchall_ops == []      # specific beats the earlier catch-all

# ── Abnormal procedures reach the script as what they are ──────────────────────
# A handler that holds the dialogue open with a class 1 invoke (ISD) and records
# every later call. TCAP is assembled by hand below: tag, length, content.
def tlv(tag, content):
    assert len(content) < 128
    return bytes([tag, len(content)]) + bytes(content)

events = []

@gsm_map.on_operation("cancel-location")
def on_cl(dlg, event):
    if not event.is_peer_turn:
        assert event.further == []
        dlg.invoke(gsm_map.insert_subscriber_data(imsi=UL_IMSI, msisdn=UL_MSISDN))
        dlg.send()
        return
    events.append(event)
    if event.is_reject and not event.reject_is_local:
        dlg.end()

def open_cl():
    events.clear()
    out = node.deliver(node.assemble_begin(
        op="cancel-location", called_gt="15550100", called_ssn=6, calling_gt="15550180",
    ), opc=2000, dpc=1000)
    d = node.decode(out[0])
    assert d.kind == "continue"
    return bytes(d.otid)

def cont(dtid, components):
    return node.assemble_tcap(tlv(0x65, tlv(0x48, b"\x22\x22\x22\x22") + tlv(0x49, dtid)
                                  + tlv(0x6C, components)))

# The builders know the class of their operation.
assert gsm_map.insert_subscriber_data(imsi=UL_IMSI, msisdn=UL_MSISDN).operation_class == 1
assert gsm_cap.release_call(cause=b"\x90\x03").operation_class == 4
assert gsm_cap.continue_().operation_class == 4
assert inap.continue_().operation_class == 4
assert inap.connect_to_resource().operation_class == 2

# A Reject from the peer is a reject, not an error with code -1: the invoke id and
# the typed problem. `A4 { 02 01 01, 81 01 02 }` = invoke 1, invokeProblem,
# mistypedParameter (2).
tid = open_cl()
out = node.deliver(cont(tid, tlv(0xA4, b"\x02\x01\x01" + b"\x81\x01\x02")), opc=2000, dpc=1000)
turn = events[0]
assert turn.is_reject and not turn.reject_is_local and not turn.is_error
assert turn.error_code is None
assert turn.reject_invoke_id == 1
assert (turn.reject_problem_class, turn.reject_problem_code) == ("invoke", 2)
assert turn.reject_problem_name == "mistypedParameter"
comp = turn.components[0]
assert (comp.kind, comp.invoke_id, comp.problem_class, comp.problem_code) == ("reject", 1, "invoke", 2)
assert node.decode(out[0]).kind == "end"
assert node.open_dialogues() == 0

# A Reject whose invoke id the peer could not derive (NULL): `A4 { 05 00, 80 01 02 }`.
tid = open_cl()
node.deliver(cont(tid, tlv(0xA4, b"\x05\x00" + b"\x80\x01\x02")), opc=2000, dpc=1000)
assert events[0].is_reject and events[0].reject_invoke_id is None
assert (events[0].reject_problem_class, events[0].reject_problem_name) == ("general", "badlyStructuredComponent")

# A component this node cannot read (an Invoke that stops after its invoke id) is
# rejected here: the handler is told, and the Reject leaves with its next flush.
tid = open_cl()
out = node.deliver(cont(tid, tlv(0xA1, b"\x02\x01\x09")), opc=2000, dpc=1000)
assert out == [] and node.open_dialogues() == 1     # the handler said nothing: it waits
assert events[0].is_reject and events[0].reject_is_local
assert (events[0].reject_invoke_id, events[0].reject_problem_class, events[0].reject_problem_code) == (9, "general", 1)
out = node.deliver(cont(tid, tlv(0xA4, b"\x02\x01\x01" + b"\x81\x01\x02")), opc=2000, dpc=1000)
d = node.decode(out[0])
assert d.kind == "end" and d.rejects == [(9, "general", 1)]

# A P-Abort from the peer: `67 { 49 dtid, 4A 01 04 }`, resource limitation.
tid = open_cl()
out = node.deliver(node.assemble_tcap(tlv(0x67, tlv(0x49, tid) + b"\x4a\x01\x04")), opc=2000, dpc=1000)
assert out == [] and node.open_dialogues() == 0
assert len(events) == 1                              # told once
e = events[0]
assert e.is_peer_turn and e.is_end and e.is_abort and e.components == []
assert (e.closed, e.abort_kind, e.p_abort_cause, e.abort_cause) == ("peer-abort", "p-abort", 4, "resource-limitation")

# A U-Abort with no information, and one with an ABRT from the dialogue-service-user.
tid = open_cl()
node.deliver(node.assemble_tcap(tlv(0x67, tlv(0x49, tid))), opc=2000, dpc=1000)
assert (events[0].closed, events[0].abort_kind, events[0].p_abort_cause, events[0].abort_cause) == ("peer-abort", "u-abort", None, "none")
tid = open_cl()
abrt = tlv(0x28, tlv(0x06, b"\x00\x11\x86\x05\x01\x01\x01") + tlv(0xA0, tlv(0x64, b"\x80\x01\x00")))
node.deliver(node.assemble_tcap(tlv(0x67, tlv(0x49, tid) + tlv(0x6B, abrt))), opc=2000, dpc=1000)
assert (events[0].abort_kind, events[0].abort_cause) == ("u-abort", "dialogue-service-user")

# A damaged Continue for the dialogue (one octet after the message): the node
# answers with a P-Abort and tells the handler the dialogue is gone.
tid = open_cl()
damaged = bytes(node.assemble_tcap(tlv(0x65, tlv(0x48, b"\x22\x22") + tlv(0x49, tid)) + b"\x00"))
out = node.deliver(damaged, opc=2000, dpc=1000)
d = node.decode(out[0])
assert (d.kind, d.abort_kind, d.p_abort_cause) == ("abort", "p-abort", 2)
assert bytes(d.dtid) == b"\x22\x22"
assert (events[0].closed, events[0].abort_kind, events[0].abort_cause) == ("provider-abort", "p-abort", "badly-formatted-transaction-portion")
assert node.open_dialogues() == 0

# A Continue for a transaction id the node does not know is answered, not dropped.
out = node.deliver(node.assemble_tcap(tlv(0x65, tlv(0x48, b"\x33") + tlv(0x49, b"\x80\x00\x7f\x7f"))), opc=2000, dpc=1000)
d = node.decode(out[0])
assert (d.kind, d.abort_kind, d.p_abort_cause, bytes(d.dtid)) == ("abort", "p-abort", 1, b"\x33")

# The class 1 invoke gets no reply: the handler is told (is_timeout), and since it
# stages nothing the node aborts as the dialogue's user and says why.
tid = open_cl()
out = node.sweep(ahead=20)
assert len(events) == 2
assert events[0].is_timeout and not events[0].is_abort
assert (events[0].invoke_id, events[0].operation_code, events[0].operation_class) == (1, 7, 1)
assert (events[1].closed, events[1].abort_kind) == ("invoke-timeout", "u-abort")
d = node.decode(out[0])
assert (d.kind, d.abort_kind, d.p_abort_cause) == ("abort", "u-abort", None)
assert node.open_dialogues() == 0

# A class 2 operation (CAP RequestReportBCSMEvent) answered by silence succeeded:
# the handler is told and the dialogue lives on, for as long as it says it may.
scp_events = []

@gsm_cap.on_operation("initial-dp")
def on_idp_held(dlg, event):
    if not event.is_peer_turn:
        dlg.set_idle_timeout(7200)
        dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 1)]))
        dlg.send()
        return
    scp_events.append(event)

out = node.deliver(node.assemble_begin(
    op="initial-dp", called_gt="15550100", called_ssn=6, calling_gt="15550142",
    arg=bytes.fromhex("3003800101"),
), opc=2000, dpc=1000)
assert node.decode(out[0]).kind == "continue" and node.open_dialogues() == 1
assert node.sweep(ahead=3600) == []                  # an hour later: no abort
assert node.open_dialogues() == 1
assert len(scp_events) == 1 and scp_events[0].is_timeout
assert scp_events[0].operation_class == 2 and scp_events[0].operation_code == 23
out = node.sweep(ahead=7300)                         # past its own idle timeout
assert node.decode(out[0]).abort_kind == "u-abort"
assert scp_events[-1].closed == "idle-timeout" and node.open_dialogues() == 0

# A handler rejects an Invoke whose argument it cannot use: Reject, invokeProblem,
# mistypedParameter, in the closing End.
@gsm_map.on_operation("report-sm-delivery-status")
def on_rsds(dlg, op):
    dlg.reject(op.invoke_id, "invoke", 2)
    dlg.end()

out = node.deliver(node.assemble_begin(
    op="report-sm-delivery-status", called_gt="15550100", called_ssn=6, calling_gt="15550180",
), opc=2000, dpc=1000)
d = node.decode(out[0])
assert d.kind == "end" and d.rejects == [(1, "invoke", 2)]

# Invoke ids are INTEGER (-128..127), and an unknown problem class is refused, at
# the call that passes them.
class _Probe:
    seen = None
@gsm_map.on_operation("ready-for-sm")
def on_rfs(dlg, op):
    errors = []
    for call in (lambda: dlg.reply_to(300, gsm_map.ready_for_sm_res()),
                 lambda: dlg.error(-129, 34),
                 lambda: dlg.reject(1, "bogus", 0),
                 lambda: dlg.invoke(gsm_map.insert_subscriber_data(imsi=UL_IMSI, msisdn=UL_MSISDN), operation_class=5)):
        try:
            call()
        except siphon.SigtranError as e:
            errors.append(str(e))
    _Probe.seen = errors
    dlg.reply(gsm_map.ready_for_sm_res())
    dlg.end()

out = drive("ready-for-sm")
assert len(_Probe.seen) == 4, _Probe.seen
assert node.decode(out[0]).kind == "end"

# ── An argument that does not decode is a mistyped parameter ──────────────────
# MO-ForwardSM-Arg ::= SEQUENCE { sm-RP-DA, sm-RP-OA, sm-RP-UI, ... }, by hand:
# serviceCentreAddressDA [4] 15550100, msisdn [2] 15550142, a two-octet TPDU.
MO_DA = tlv(0x84, b"\x91\x51\x55\x10\x00")
MO_OA = tlv(0x82, b"\x91\x51\x55\x10\x24")
MO_UI = tlv(0x04, b"\xaa\xbb")
mo_seen = {}

@gsm_map.on_operation("mo-forward-sm")
def on_mo_strict(dlg, arg):
    mo_seen["ui"] = bytes(arg.sm_rp_ui)        # raises MistypedParameter if unreadable
    dlg.reply(gsm_map.mo_forward_sm_res())
    dlg.end()

def mo(argument):
    return node.deliver(node.assemble_begin(
        op="mo-forward-sm", called_gt="15550100", called_ssn=8, calling_gt="15550142",
        arg=argument,
    ), opc=2000, dpc=1000)

assert issubclass(siphon.MistypedParameter, siphon.SigtranError)

# A member this node does not model, after the ones it does, is skipped
# (TS 29.002 17.1.4): the argument is read.
out = mo(tlv(0x30, MO_DA + MO_OA + MO_UI + b"\x9d\x01\x2a"))
assert mo_seen.pop("ui") == b"\xaa\xbb"
d = node.decode(out[0])
assert d.kind == "end" and d.rejects == [] and d.result_invoke_id == 1

# Without its sm-RP-UI the argument does not decode. The getter raises instead of
# answering None, and the uncaught exception becomes the Reject it stands for:
# invokeProblem, mistypedParameter, in an End.
out = mo(tlv(0x30, MO_DA + MO_OA))
assert "ui" not in mo_seen
d = node.decode(out[0])
assert d.kind == "end" and d.rejects == [(1, "invoke", 2)] and d.result_invoke_id is None
assert node.open_dialogues() == 0

# A handler that catches the exception decides for itself.
@gsm_map.on_operation("mo-forward-sm")
def on_mo_catching(dlg, arg):
    try:
        _ = arg.sm_rp_da
    except siphon.MistypedParameter:
        dlg.error(arg.invoke_id, 36)           # unexpectedDataValue, its own choice
    dlg.end()

d = node.decode(mo(tlv(0x30, MO_DA + MO_OA))[0])
assert d.rejects == [] and d.error == (1, 36)

# Any other operation has no forward-SM fields: None, not an error.
@gsm_map.on_operation("purge-ms")
def on_purge_fields(dlg, arg):
    assert arg.sm_rp_ui is None and arg.sm_rp_oa is None
    dlg.reply(gsm_map.purge_ms_res())
    dlg.end()

assert node.decode(drive("purge-ms")[0]).rejects == []

# ── INAP: the argument is decoded strictly, a leg is an explicit choice ───────
# RequestReportBCSMEvent with a leg: `legID [2]` wraps the LegID CHOICE, so the
# event is `30 0B { 80 01 09, 81 01 01, A2 03 { 80 01 02 } }` (oDisconnect,
# notifyAndContinue, sendingSideID leg 2; 3 + 3 + 5 = 11 octets). The primitive `82 01 02` of the
# earlier encoding is what a conforming SSF rejects.
inap_rrbe = {}

@inap.on_operation("initial-dp")
def on_inap_strict(dlg, idp):
    if idp.is_peer_turn:
        return
    inap_rrbe["key"] = idp.inap_service_key          # raises MistypedParameter if unreadable
    dlg.invoke(inap.request_report_bcsm_event(events=[(7, 0), (9, 1, 2)]))
    dlg.send()

def inap_idp(argument):
    return node.deliver(node.assemble_begin(
        op="initial-dp", called_gt="15550100", called_ssn=106, calling_gt="15550170",
        arg=argument, ac=inap.AC.ssp_to_scp,
    ), opc=2000, dpc=1000)

d = node.decode(inap_idp(INAP_IDP)[0])
assert d.kind == "continue" and inap_rrbe.pop("key") == 100
assert list(d.app_context) == [0, 4, 0, 1, 1, 1, 0, 0]
rrbe = d.invokes[0][1]
assert bytes.fromhex("300b800109810101" "a203800102") in bytes(rrbe)
assert bytes.fromhex("3006800107810100") in bytes(rrbe)   # the event without a leg
node.deliver(node.assemble_tcap(tlv(0x67, tlv(0x49, bytes(d.otid)))), opc=2000, dpc=1000)

# An InitialDP whose serviceKey [0] announces four octets and holds one does not
# decode: Reject, invokeProblem mistypedParameter, in an End.
out = inap_idp(tlv(0x30, b"\x80\x04\x64"))
assert "key" not in inap_rrbe
d = node.decode(out[0])
assert d.kind == "end" and d.rejects == [(1, "invoke", 2)] and d.invokes == []
# So does one without its mandatory serviceKey, and one carrying a member the
# argument does not have ([45]).
assert node.decode(inap_idp(tlv(0x30, b"\x82\x05\x91\x51\x55\x10\x24"))[0]).rejects == [(1, "invoke", 2)]
assert node.decode(inap_idp(tlv(0x30, b"\x80\x01\x64" + b"\x9f\x2d\x01\x00"))[0]).rejects == [(1, "invoke", 2)]

# The new metric families are exposed.
text = siphon.metrics()
assert 'sigtran_tcap_abort_total{dir="rx",kind="p-abort",cause="resource-limitation"}' in text
assert 'sigtran_tcap_reject_total{dir="rx",problem="invoke"}' in text

# An unknown operation name raises at decoration time, before any dialogue runs.
try:
    gsm_map.on_operation("bogus-op")
    raise AssertionError("expected SigtranError for an unknown operation name")
except siphon.SigtranError:
    pass
# A typo inside an alternation raises the same way.
try:
    gsm_map.on_operation("mo-forward-sm|bogus")
    raise AssertionError("expected SigtranError for an unknown operation in an alternation")
except siphon.SigtranError:
    pass
"#;

/// Mount the addon and drive every namespace end to end through the Rust engine.
#[test]
fn addon_drives_handlers_against_siphon_sip() {
    Python::attach(|py| {
        mount(py).expect("mount the addon namespaces");
        let globals = PyDict::new(py);
        let code = CString::new(DRIVE).expect("no NUL in the drive script");
        if let Err(err) = py.run(code.as_c_str(), Some(&globals), None) {
            err.print(py);
            panic!("the addon drive script failed: {err}");
        }
    });
}

/// Linkage proof: the addon face is compiled against siphon-sip and can name the
/// host type it is built to slot into.
#[test]
fn addon_links_against_siphon_sip() {
    let handle = std::any::type_name::<siphon::script::ScriptHandle>();
    assert!(
        handle.contains("ScriptHandle"),
        "unexpected type name: {handle}"
    );
}
