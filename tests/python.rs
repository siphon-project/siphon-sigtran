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
from siphon import ss7, gsm_map, gsm_cap

CONFIG = """
node: { point_code: 1000, variant: ITU }
associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
application_servers:
  - { name: hlr, traffic_mode: override, routing_context: 100, asps: [hlr-a] }
mtp3_routes:
  - { dpc: 2000, as: hlr, priority: 1 }
sccp:
  local_ssns: [6, 8]
"""

# ── Import surface: the three namespaces + the node API + the exception ───────
assert hasattr(siphon, "ss7")
assert hasattr(siphon, "gsm_map")
assert hasattr(siphon, "gsm_cap")
assert callable(siphon.configure)
assert callable(siphon.metrics)
assert issubclass(siphon.SigtranError, Exception)
assert "sigtran_active_dialogues" in siphon.metrics()

# ── configure builds the node; the decision constructors round-trip ───────────
node = siphon.configure(CONFIG)
assert "default" in ss7.tenants
assert node.open_dialogues() == 0

d = ss7.route(dpc=2000, ssn=6)
assert d.kind == "route" and d.dpc == 2000 and d.ssn == 6
assert ss7.drop(reason="untrusted").kind == "drop"
assert ss7.route_default().kind == "default"
assert ss7.allow().kind == "allow"

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

# ── A content hook decorator registers an async hook the engine runs ──────────
seen = {}

@ss7.content.on("on_np_dip")
async def np_dip(msg):
    seen["msisdn"] = msg.msisdn
    return ss7.route(dpc=2005, ssn=6)

view = siphon.MapView(operation="sri-sm", msisdn="15550142")
decision = node.dispatch_content("on_np_dip", view)
assert decision.kind == "route" and decision.dpc == 2005
assert seen["msisdn"] == "15550142"

# ── A MO-ForwardSM Begin driven through the engine reaches the handler ────────
replied = {}

@gsm_map.on_mo_forward_sm
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
HLR_GT = b"\x91\x15\x55\x01\x90"
UL_IMSI = b"\x00\x11\x10\x00\x00\x00\x00\x14"
UL_MSISDN = b"\x91\x15\x55\x01\x70"

@gsm_map.on_update_location
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
assert node.open_dialogues() == 0       # dialogue closed on the result

# ── sendAuthenticationInfo answered with a quintuplet vector, single shot ─────
@gsm_map.on_send_authentication_info
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
@gsm_cap.on_initial_dp
async def on_idp(dlg, idp):
    # Arm the answer / disconnect detection points, then connect the call onward.
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(7, 0), (9, 1)]))
    dlg.invoke(gsm_cap.connect(destination_routing_address=[b"\x00\x11\x22"]))
    dlg.end()

# An SCP that also receives EventReportBCSM registers a handler for it.
@gsm_cap.on_event_report_bcsm
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
assert node.open_dialogues() == 0

# ── The originating helper returns an awaitable bridged onto tokio ────────────
# Awaiting it needs a live SCTP transport (a running node); without one it
# resolves to a clear error. This exercises the pyo3-async-runtimes bridge.
async def _probe():
    aw = gsm_map.send_routing_info_for_sm(
        msisdn=b"\x15\x55\x01\x42", sc_addr=b"\x15\x55\x01\x00"
    )
    assert inspect.isawaitable(aw)
    try:
        await asyncio.wait_for(aw, timeout=5)
    except siphon.SigtranError:
        return "raised"
    except asyncio.TimeoutError:
        return "timeout"
    return "no-raise"

assert asyncio.run(_probe()) == "raised"
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
