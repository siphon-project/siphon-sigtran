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
  - { name: transit, links: [{assoc: xit-1, slc: 0}] }

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
    - { name: home-subs, addrs: ["15550142", "15550143"] }
  rules:
    - name: fs11-cat3-sri-sm
      match:  { operation: sri-sm }
      action: { python: on_screen }
    - name: np-dip
      match:  { operation: sri-sm }
      action: { python: on_np_dip }
```

Note this STP owns no subsystems: no `local_ssns`, so nothing terminates. DPC
2000 has a primary AS route and an M2PA alternate; if the AS drops, the
resolver fails over to the transit linkset automatically.

## Three ways to override

Per-MSU routing always runs in Rust. Python overrides it three ways, in rising
hot-path cost. Pick the cheapest that fits.

### 1. Program the Rust tables live

Runs once at script load, after the node is configured. Ideal for external
feeds, portal edits, or learned routes; no per-MSU Python cost because the
decision stays in the Rust tables.

```python
from siphon import ss7

ss7.routes.add(dpc=2000, linkset="transit", priority=3)   # an extra alternate path
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")
ss7.content.add_rule(
    name="steer-partner-x",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"route": {"group": "ag-router"}},
)
```

### 2. Deferred rule hooks

A content rule whose action is `{python: <name>}` hands the matching messages
to a named hook. `msg` is the read-only decoded [`MapView`](../script-api.md#mapview):
`.operation`, `.cgpa_gt`, `.cdpa_gt`, `.imsi`, `.msisdn`, `.opc`, `.dpc`. The
hook returns a [decision](../script-api.md#decisions).

```python
_ported = {"15550142": 2006}          # a live NP database in production
trusted_carriers = {"15551000", "15552000"}

@ss7.content.on("on_np_dip")
async def np_dip(msg):
    pc = _ported.get(msg.msisdn)
    if pc is not None:
        ss7.routes.cache(msg.cdpa_gt, dpc=pc, ssn=6, ttl=3600)   # subsequent MSUs route in Rust
        return ss7.route(dpc=pc, ssn=6)
    return ss7.route_default()

@ss7.content.on("on_screen")
async def screen(msg):
    if msg.cgpa_gt not in trusted_carriers:
        return ss7.drop(reason="untrusted SRI-SM origin")   # GSMA FS.11 category-3 screen
    return ss7.allow()
```

The number-portability hook writes its answer back with
`ss7.routes.cache(...)`, so it dips the external database once per GT and every
later message for that title routes in Rust.

### 3. A selector-gated general override

The broadest hook. The `when=` selector keeps it off the hot path for
everything it does not match.

```python
@ss7.on_route(when="operation == 'sri-sm' and dpc == 2000")
async def override(msg):
    if maintenance_mode():
        return ss7.route(linkset="transit")   # force this class via the alternate
    return ss7.route_default()                # else let the Rust tables / config decide
```

!!! warning "Mind the selector"
    Drop `when=` and this hook sees **every** routing decision, capping an
    STP's throughput at the interpreter. On a transit node, keep the selector
    tight, or push the decision into config or a live table instead. See
    [the cost ladder](../concepts.md#the-cost-ladder).

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
