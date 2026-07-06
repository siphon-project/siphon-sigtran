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

# ── The CAP namespace stages a Connect and registers an initialDP handler ─────
@gsm_cap.on_initial_dp
async def on_idp(dlg, idp):
    dlg.invoke(gsm_cap.connect(destination_routing_address=[b"\x00\x11\x22"]))
    dlg.end()

staged = gsm_cap.connect(destination_routing_address=[b"\x00\x11\x22"])
assert staged is not None

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
