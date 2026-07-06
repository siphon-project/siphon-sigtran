"""stp.py, a thin STP: routing stays in Rust, Python overrides it three ways.

Per-MSU routing always runs in Rust (the line-rate guarantee). `sigtran.yaml`
is the declarative default; this script overrides it. Load it into a siphon
binary that has mounted the siphon-sigtran namespaces (it configures the node,
then runs this module).

The three override styles:

1. Program the Rust tables live (preferred, routing stays in Rust).
2. A deferred rule hook (`@ss7.content.on(name)`, matched by a config rule whose
   action is `{python: <name>}`).
3. A general routing override (`@ss7.on_route(when=...)`); the `when=` selector
   keeps it off the hot path for everything else.
"""

from siphon import ss7

# A live number-portability database the deferred hook dips into. Replace with
# your own client; here it is a tiny in-memory stand-in.
_ported = {"15550142": 2006}
trusted_carriers = {"15551000", "15552000"}


# ── 1. Program the Rust tables live ──────────────────────────────────────────
# Runs when the script loads (after the node is configured). Ideal for external
# feeds, portal edits, learned routes, or seeding a cache. No per-MSU Python cost.
ss7.routes.add(dpc=2000, linkset="transit", priority=3)  # extra alternate path
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")
ss7.content.add_rule(
    name="steer-partner-x",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"route": {"group": "ag-router"}},
)


# ── 2. Deferred rule hooks ───────────────────────────────────────────────────
# `msg` is the decoded MAP view, read-only: .operation, .cgpa_gt, .cdpa_gt,
# .imsi, .msisdn, .opc, .dpc. Return a routing decision; optionally write it
# back to Rust so subsequent MSUs route without the hook.
@ss7.content.on("on_np_dip")
async def np_dip(msg):
    pc = _ported.get(msg.msisdn)
    if pc is not None:
        # Cache the dip so subsequent MSUs for this GT route in Rust.
        ss7.routes.cache(msg.cdpa_gt, dpc=pc, ssn=6, ttl=3600)
        return ss7.route(dpc=pc, ssn=6)
    return ss7.route_default()


@ss7.content.on("on_screen")
async def screen(msg):
    if msg.cgpa_gt not in trusted_carriers:
        return ss7.drop(reason="untrusted SRI-SM origin")
    return ss7.allow()


# ── 3. General routing override ──────────────────────────────────────────────
# The `when=` selector keeps this off the hot path for everything else. Drop
# `when=` and it sees every routing decision (fine for a low-volume node, caps
# throughput on a transit STP).
@ss7.on_route(when="operation == 'sri-sm' and dpc == 2000")
async def override(msg):
    if maintenance_mode():
        return ss7.route(linkset="transit")  # force this class via the alternate
    return ss7.route_default()  # else let the Rust tables / config decide


def maintenance_mode():
    return False
