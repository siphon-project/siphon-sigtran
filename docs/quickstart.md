# Quickstart

Stand up the smallest possible node: one point code, one M3UA peer, one owned
subsystem, and a handler that terminates MO-ForwardSM. Then prove the whole
termination path without any peer at all, using the built-in loopback seam.

!!! note "You bring the SIPhon binary"
    siphon-sigtran is a library, not a server. It runs inside a
    [SIPhon](https://siphon-sip.org/) binary that registers the addon at
    startup; see [Using it in a SIPhon build](integration.md). This page
    assumes you have that binary (call it `siphon`).

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

See [Configuration](configuration.md) for every field. Point your main SIPhon
config at it, so the binary loads and configures the node at startup:

```yaml
# siphon.yaml (main config)
extensions:
  sigtran: sigtran.yaml
```

## 2. The script

```python
from siphon import gsm_map

@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    # arg.sm_rp_oa / arg.sm_rp_da / arg.sm_rp_ui are the raw address + TPDU bytes.
    dlg.reply(gsm_map.mo_forward_sm_res())   # returnResultLast, in a closing End
    dlg.end()
```

One handler of policy: terminate mobile-originated SMS with an ack. The binary
configured the node from `sigtran.yaml`; the script just registers handlers.
`@gsm_map.on_operation("<name>")` names the operation by its kebab-case name (the
same `on_<message>("<name>")` shape as `@smpp.on_pdu`); it takes several
pipe-separated, and a bare `@gsm_map.on_operation` is a catch-all. See the full
selector list in the [Script API](script-api.md#on_operation).

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

You do not need a live SS7 peer to test the handler. In a test, `siphon.configure`
builds a node and hands back a `Node` you can drive: assemble a genuine inbound
`Begin` (real TCAP in a real SCCP UDT) and push it through the dialogue engine.

```python
# In a test (not the live script — the binary configures the live node).
node = siphon.configure("sigtran.yaml")
begin = node.assemble_begin(op="mo-forward-sm",
                            called_gt="15550100", called_ssn=8,
                            calling_gt="15550142")
replies = node.deliver(begin, opc=2000, dpc=1000)
print(f"terminated MO-ForwardSM, {len(replies)} reply MSU(s)")
```

`deliver` returns the SCCP payloads the node would send back: here one `End`
carrying the `returnResultLast` your handler staged. This is the same seam the
crate's own integration tests drive; see
[Testing your handlers](script-api.md#testing).

## Next

- **Do something real**: the [Cookbook](cookbook/index.md) has the four worked
  recipes (STP, HLR, SMSC, CAMEL SCP).
- **Understand the model**: [Concepts & architecture](concepts.md).
- **All the knobs**: [Configuration](configuration.md) and the
  [Script API](script-api.md).
- **Ship it**: [Deployment](deployment.md) and
  [Kubernetes & scaling](kubernetes.md).
