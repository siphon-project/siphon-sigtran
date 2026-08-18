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
assert inap.play_announcement(information_to_send=b"\x0a\x0b") is not None
assert inap.prompt_and_collect_user_information(collected_info=b"\x01\x02") is not None
assert inap.connect_to_resource() is not None
assert list(inap.AC.ssp_to_scp.arcs) == [0, 4, 0, 1, 1, 0, 3, 0]

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
assert list(dinap.app_context) == [0, 4, 0, 1, 1, 0, 3, 0]  # IN AC echoed in the AARE, not a CAMEL one
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
