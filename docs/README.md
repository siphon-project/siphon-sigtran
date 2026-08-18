# siphon-sigtran

**A SIGTRAN/SS7 addon for [SIPhon](https://siphon-sip.org/). Build an STP, an
HLR, an SMSC or a CAMEL SCP in hot-reloaded Python, with the SCTP transport,
the SS7 codecs and every per-message routing decision in Rust.**

`siphon-sigtran` turns a declarative `sigtran.yaml` into a running signalling
node: SCTP transport (M3UA / M2PA), MTP3 routing, SCCP Global Title Translation
with E.214/E.164 conversion, **content routing** on the decoded MAP/CAP layer,
and MAP/CAP dialogue termination. The addon mounts `ss7`, `gsm_map`, `gsm_cap`
and `inap` namespaces into a SIPhon binary. The binary configures the node from
your `sigtran.yaml` (`extensions.sigtran`); your script programs it:

```python
from siphon import ss7, gsm_map

# 1. Program the Rust routing tables live (routing stays in Rust at line rate).
ss7.routes.add(dpc=2000, linkset="transit", priority=3)
ss7.gtt.add(match={"gt_prefix": "155502"}, to={"dpc": 2006, "ssn": 6})
ss7.content.address_table("home-subs").add("15550199")
ss7.content.add_rule(
    name="steer-home-sri-sm",
    match={"operation": "sri-sm", "cgpa_gt_in": "home-subs"},
    action={"route": {"group": "ag-router"}},
)

# 2. Terminate a MAP dialogue (name the operation; several take a pipe).
@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    await forward_somewhere(arg.sm_rp_oa, arg.sm_rp_da, arg.sm_rp_ui)
    dlg.reply(gsm_map.mo_forward_sm_res())
    dlg.end()
```

That is a scriptable SS7 node: routing in config or programmed live from Python
(the decision stays in Rust), termination in Python. The worked recipes (a thin
STP, an HLR, a store-and-forward SMSC, a CAMEL SCP) are in the
[Cookbook](cookbook/index.md).

## The boundary

**Rust decides per message; Python decides what the rules are.** Scripts never
touch a socket, and no MSU waits on the interpreter unless you explicitly defer
a rule to a hook.

| The crate owns (Rust) | Your script owns (Python) |
|---|---|
| SCTP associations, M3UA ASPSM/ASPTM handshake, M2PA link alignment | which routes, GTT rules and content rules exist (it programs the tables) |
| MTP3 route resolution, availability, priority failover | deferred decisions: number-portability dips, per-subscriber steering |
| SCCP GTT, E.214/E.164 conversion, cost / weighted-share groups | screening policy (what gets dropped, and why) |
| content-rule matching on the decoded MAP/CAP view | termination logic: what your SMSC, HLR or SCP actually does |
| TCAP transactions, dialogue/invoke timers, wire encoding of replies | origination flows (SRI-SM, multi-segment MT delivery) |

Rule of thumb: **per-MSU work runs in Rust; your script writes the policy the
Rust tables execute**, and takes the hot path only where you opt in.

## The stack

```
   content routing        routes/screens on the decoded MAP/CAP layer
        |
   gsm_map / gsm_cap      MAP/CAP termination (dialogue engine, TCAP)
        |
   sccp                   GTT + E.214/E.164 conversion
        |
   mtp3                   route resolver, DPC to AS/linkset
        |
   m3ua / m2pa over sctp  transport, real kernel SCTP
```

Every layer below the script is one of the published SS7 codec crates (`mtp3`,
`m3ua`, `m2pa`, `sccp`, `tcap`, `gsm_map`, `gsm_cap`, `async-sctp`, all on
crates.io); siphon-sigtran adds the runtime a node needs on top of them. See
[Concepts & architecture](concepts.md).

## Where to start

<div class="grid cards" markdown>

- **[Concepts & architecture](concepts.md)** describes the stack, the routing
  cost ladder, and what runs where.
- **[Quickstart](quickstart.md)** stands up a minimal node and terminates a
  MAP operation in a few minutes.
- **[Configuration](configuration.md)** is the full `sigtran.yaml` reference.
- **[Cookbook](cookbook/index.md)** has the four worked recipes: STP, HLR,
  SMSC, CAMEL SCP.
- **[Script API](script-api.md)** covers the `ss7` / `gsm_map` / `gsm_cap`
  namespaces, decisions, hooks and the `Dialogue` handle.
- **[Kubernetes & scaling](kubernetes.md)** explains the HA model for a
  stateful signalling protocol.

</div>

## What it is (and isn't)

`siphon-sigtran` is a **library**, not a standalone server. As an addon it runs
inside a [SIPhon](https://siphon-sip.org/) binary that you build and compose;
see [Using it in a SIPhon build](integration.md). There is no wheel, no PyPI
package, and no `siphon-sigtran` daemon. The same crate also works as a plain
Rust dependency: the default build pulls neither pyo3 nor SIPhon, so the
routing brain and the dialogue engine are usable from any Rust program.

Standards it implements against: M3UA (RFC 4666), M2PA (RFC 4165), SCTP
(RFC 4960), MTP3 (ITU-T Q.704), SCCP GTT (ITU-T Q.714), TCAP (ITU-T
Q.771 to Q.775), MAP (3GPP TS 29.002), CAMEL (3GPP TS 29.078).

!!! info "Wire-proven"
    The transport is tested end to end with genuinely assembled SS7 MSUs driven
    over real kernel SCTP through a running node, including load-share across an
    AS's ASPs, failover to an M2PA linkset, loop guards, and a MAP operation
    terminated in the dialogue engine with the result read back off the wire.

## License

MIT. siphon-sigtran is an addon for [SIPhon](https://siphon-sip.org/); need a
hand building on it? See [Commercial support](support.md).
