# Quickstart

Stand up the smallest possible node: one point code, one M3UA peer, one owned
subsystem, and a handler that terminates MO-ForwardSM. Then prove the whole
termination path without any peer at all, using the built-in loopback seam.

!!! note "You bring the SIPhon binary"
    siphon-sigtran is a library, not a server. It runs inside a
    [SIPhon](https://siphon-sip.org/) binary that registers the addon at
    startup; see [Using it in a SIPhon build](integration.md). This page
    assumes you have that binary (call it `siphon`). The pure-Rust crate works
    without SIPhon entirely; see [the Rust quickstart](#the-rust-quickstart)
    below.

## 1. The config

One file describes the node. Minimal, single node, every value synthetic
(test PLMN 001/01, `+1-555-01xx` global titles, decimal point codes):

```yaml
# sigtran.yaml
node:
  point_code: 1000
  variant: itu

associations:
  - { id: msc-1, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }

application_servers:
  - { name: msc, traffic_mode: override, routing_context: 100, asps: [msc-1] }

mtp3_routes:
  - { dpc: 2000, as: msc, priority: 1 }

sccp:
  local_ssns: [8]        # we own SSN 8; inbound for it terminates locally
```

See [Configuration](configuration.md) for every field.

## 2. The script

```python
import siphon
from siphon import gsm_map

node = siphon.configure("sigtran.yaml")

@gsm_map.on_mo_forward_sm
async def on_mo(dlg, arg):
    # arg.sm_rp_oa / arg.sm_rp_da / arg.sm_rp_ui are the raw address + TPDU bytes.
    dlg.reply(gsm_map.mo_forward_sm_res())   # returnResultLast, in a closing End
    dlg.end()
```

Two lines of policy: configure the node, terminate mobile-originated SMS with
an ack. `siphon.configure` accepts a path, an inline YAML string, or a dict;
it validates the config the same way the Rust loader does and returns a
[`Node`](script-api.md#node) handle.

## 3. Run it

Load the script into your composing siphon binary the way you load any SIPhon
script, and start it:

```bash
./siphon -c siphon.yaml
```

The node binds its associations, runs the M3UA handshake as peers connect, and
routes. Edit the script, save, and SIPhon hot-reloads it; routing state lives
in Rust, so nothing is dropped ([Concepts](concepts.md#hot-reload)).

## 4. Prove the path, no peer needed

You do not need a live SS7 peer to see termination work. The `Node` handle can
assemble a genuine inbound `Begin` (real TCAP in a real SCCP UDT) and push it
through the dialogue engine:

```python
# Append to the script above.
begin = node.assemble_begin(op="mo-forward-sm",
                            called_gt="15550100", called_ssn=8,
                            calling_gt="15550142")
replies = node.deliver(begin, opc=2000, dpc=1000)
print(f"terminated MO-ForwardSM, {len(replies)} reply MSU(s)")
```

`deliver` returns the SCCP payloads the node would send back: here one `End`
carrying the `returnResultLast` your handler staged. The same seam is how the
crate's own integration tests drive the engine.

## Next

- **Do something real**: the [Cookbook](cookbook/index.md) has the four worked
  recipes (STP, HLR, SMSC, CAMEL SCP).
- **Understand the model**: [Concepts & architecture](concepts.md).
- **All the knobs**: [Configuration](configuration.md) and the
  [Script API](script-api.md).
- **Ship it**: [Deployment](deployment.md) and
  [Kubernetes & scaling](kubernetes.md).

## The Rust quickstart

The default crate build pulls neither pyo3 nor SIPhon, so the routing brain is
usable from any Rust program:

```rust
use siphon_sigtran::{Config, Router};
use siphon_sigtran::routing::{Inbound, RouteDecision};

let config = Config::load("sigtran.yaml")?;
let router = Router::new(&config);

// A message addressed to a point code the node doesn't own transits: the
// route resolver picks the egress.
let decision = router.route(&Inbound { dpc: 2000, ..Default::default() });
assert!(matches!(decision, RouteDecision::Route { .. }));
# Ok::<(), siphon_sigtran::Error>(())
```

The [API docs on docs.rs](https://docs.rs/siphon-sigtran) cover the pure-Rust
surface: `Config`, `Router`, the transport, and the dialogue engine.
