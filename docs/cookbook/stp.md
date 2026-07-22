# Building an STP

A Signal Transfer Point relays SS7: it routes messages toward their
destination and never terminates them. On siphon-sigtran that is mostly config,
the route table and the GTT rules, with Python for the decisions the static
tables can't make. This recipe is
[`examples/stp.py`](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/stp.py),
walked section by section.

```
   peer A ──MSU──▶  ┌─────────────────┐  ──MSU──▶  destination
                    │   this STP      │
   peer B ◀──MSU──  │  (siphon-sigtran) │  ◀──MSU──  transit / alt
                    └─────────────────┘
              routes in Rust; Python overrides where you opt in
```

The **crate** owns transit: MTP3 route resolution, GTT, availability and
failover, the loop guards, all at line rate. Your **script** owns the
overrides: what routes exist, and the handful of decisions the tables defer.

## The config

The route table and GTT are the bulk of an STP, and they are config. A trimmed
`sigtran.yaml` (full field reference in [Configuration](../configuration.md)):

```yaml
node:
  point_code: 1000
  variant: itu

associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
  - { id: hlr-b, adaptation: m3ua, role: server, addrs: [10.1.0.11], port: 2905 }
  - { id: xit-1, adaptation: m2pa, role: client, addrs: [10.0.1.1], port: 3565, adjacent_pc: 3000 }

application_servers:
  - { name: hlr, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a, hlr-b] }

linksets:
  - { name: transit, links: [{assoc: xit-1}] }

mtp3_routes:
  - { dpc: 2000, as: hlr,          priority: 1 }
  - { dpc: 2000, linkset: transit, priority: 2 }   # alternate via M2PA transit

sccp:
  gtt_groups:
    - { name: ag-router, mode: share, members: [{dpc: 2003, ssn: 8, weight: 1}, {dpc: 2004, ssn: 8, weight: 1}] }
  gtt:
    - { match: {gt_prefix: "1555"}, to: {dpc: 2000, ssn: 6} }

content_routing:
  protocol: gsm-map
  address_tables:
    - { name: home-subs,        addrs: ["15550142", "15550143"] }
    - { name: blocked-carriers, addrs: ["15550190"] }
  rules:
    - name: screen-blocked-sri-sm       # GSMA FS.11 category-3 style screen
      match:  { operation: sri-sm, cgpa_gt_in: blocked-carriers }
      action: { screen: true }
    - name: home-sri-sm
      match:  { operation: sri-sm, cgpa_gt_in: home-subs }
      action: { route: {group: ag-router} }
```

Note this STP owns no subsystems: no `local_ssns`, so nothing terminates. DPC
2000 has a primary AS route and an M2PA alternate; if the AS drops, the
resolver fails over to the transit linkset automatically.

## Program the Rust tables live

Per-MSU routing always runs in Rust. Beyond the static `sigtran.yaml`, a script
programs the same Rust tables at load time, so the decision stays in Rust with no
per-MSU Python cost. Ideal for external feeds, portal edits, learned routes, or
seeding a cache.

```python
from siphon import ss7

# An extra alternate path, a GTT prefix rule, and a content rule, all live.
ss7.routes.add(dpc=2000, linkset="transit", priority=3)
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")
ss7.content.add_rule(
    name="steer-home-sri-sm",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"route": {"group": "ag-router"}},
)
```

A content rule's action is `route` (to a `dpc`+`ssn` or a `group`),
`rewrite_cdpa_gt`, or `screen`. Programming these live prepends them over the
static config rules (first match wins), and every subsequent decision runs in
Rust at line rate.

## What you get for free

Because the STP relays rather than terminates, the runtime does the load-bearing
work with no script involvement:

- **Availability failover** across the priority routes as ASPs and links come
  and go ([Routing → availability](../routing.md#availability)).
- **Service-Indicator-agnostic transit**: call-control and other non-SCCP SIs
  transit by DPC with no codec needed.
- **Loop guards**: own-opc and route-reflect drop-and-count a looping MSU
  ([Routing → loop guards](../routing.md#loop-guards)).

## Next

- **Terminate instead of relay**: [Building an HLR](hlr.md),
  [Building an SMSC](smsc.md), [Building a CAMEL SCP](scp.md).
- **The full override surface**: [Script API](../script-api.md).
- **Ship it**: [Deployment](../deployment.md),
  [Kubernetes & scaling](../kubernetes.md).
