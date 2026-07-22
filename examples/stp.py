"""stp.py, a thin STP: routing stays in Rust, programmed from Python.

Per-MSU routing always runs in Rust (the line-rate guarantee). `sigtran.yaml`
is the declarative default; this script programs the same Rust tables live at
load time. Load it into a siphon binary that has mounted the siphon-sigtran
namespaces (it configures the node, then runs this module).

Programming the tables live is ideal for external feeds, portal edits, learned
routes, or seeding a cache: the decision then stays in Rust, with no per-MSU
Python cost. Every value is synthetic (test PLMN 001/01, +1-555-01xx addresses).
"""

from siphon import ss7

# ── Program the Rust routing tables live ─────────────────────────────────────
# Runs once when the script loads, after the node is configured.

# An extra alternate path to DPC 2000 over the transit linkset.
ss7.routes.add(dpc=2000, linkset="transit", priority=3)

# A GTT prefix rule: route 155502... global titles to DPC 2006, SSN 6.
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})

# A content rule on the decoded MAP layer: SRI-SM from a home-subscriber GT
# routes to a GTT group. Content rules route, rewrite the called-party GT, or
# screen; they run entirely in Rust.
ss7.content.address_table("home-subs").add("15550199")
ss7.content.add_rule(
    name="steer-home-sri-sm",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"route": {"group": "ag-router"}},
)

# Screen SRI-SM from a blocked origin (GSMA FS.11 category-3 style): a content
# rule matches membership in a GT table, so list the origins to block.
ss7.content.address_table("blocked-carriers").add("15550190")
ss7.content.add_rule(
    name="screen-blocked-sri-sm",
    match={"operation": "sri-sm", "cgpa_gt_in": "blocked-carriers"},
    action={"screen": True},
)
