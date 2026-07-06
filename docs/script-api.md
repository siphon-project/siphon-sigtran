# Script API

Everything your script can call, imported from the `siphon` package the addon
mounts its namespaces onto:

```python
import siphon
from siphon import ss7, gsm_map, gsm_cap
```

There are five groups: [`configure`](#configure) and the [`Node`](#node)
handle; the [`ss7`](#ss7) routing namespace (live tables, decisions, hooks);
the [`gsm_map`](#gsm-map) / [`gsm_cap`](#gsm-cap) termination decorators and
originating helpers; the [`Dialogue`](#dialogue) handle a termination handler
drives; and the [decoded views](#views) handlers and hooks receive. Handlers
and hooks may be `async def`; they run to completion on SIPhon's runtime.

## `siphon.configure(source)` { #configure }

(Re)build the process-wide node from a `sigtran.yaml`. `source` is a filesystem
path, an inline YAML string, or a dict mirroring the file schema. It parses and
**validates** exactly as the Rust loader does (a bad reference or an
out-of-range point code raises `SigtranError`), then returns a [`Node`](#node).
Call it once at script load, before programming tables.

```python
node = siphon.configure("sigtran.yaml")
node = siphon.configure({"node": {"point_code": 1000, "variant": "itu"},
                         "associations": []})
```

`siphon.metrics()` renders the Prometheus text exposition for the whole node
(see [Routing model & coverage](routing.md#metrics)).

## `ss7` { #ss7 }

The routing namespace. It programs the Rust tables, builds decisions, and
registers routing hooks.

### Live tables

| Call | Effect |
|---|---|
| `ss7.routes.add(dpc, as_=…\|linkset=…, priority=1)` | Add or extend an MTP3 route. Name exactly one of `as_` / `linkset`. |
| `ss7.routes.cache(gt, dpc=…, ssn=…, ttl=None)` | Cache a dip result as a GTT prefix rule, so later MSUs for `gt` route in Rust without the hook. `ttl` is accepted for API stability; the rule persists until reprogrammed. |
| `ss7.gtt.add(match={…}, to={…})` | Prepend a GTT rule. `match` / `to` are dicts mirroring the config [`gtt`](configuration.md#gtt) schema. |
| `ss7.content.add_rule(name, match={…}, action={…})` | Prepend a content rule (config [`content_routing`](configuration.md#content-routing) schema). |
| `ss7.content.address_table(name).add(gt)` | Add a GT digit string to an address table live, creating it if absent. Idempotent. |
| `ss7.gt(digits, ssn=None)` | Build an SCCP [`Address`](#address) (E.164, GTI-4) for an originating helper. |

Prepending means a live rule wins over the static config rules (first match
wins). Programming a table at script load is the preferred override style: it
keeps every subsequent decision in Rust at line rate.

### Decisions

A hook returns one of these. They are plain value objects the async override
layer resolves.

| Call | Meaning |
|---|---|
| `ss7.route(dpc=…, ssn=…, linkset=…)` | Route onward. Name one of `dpc` / `linkset` (with an optional `ssn`). |
| `ss7.drop(reason=…)` | Drop / fail a screen, with a reason (logged, counted). |
| `ss7.route_default()` | Let the Rust tables / config decide (the hook declines to override). |
| `ss7.allow()` | Pass a screen. |

### Hooks { #hooks }

Two override styles beyond programming tables:

#### `@ss7.content.on("<name>")`

Register a **deferred** hook: the target of a content rule whose action is
`{python: <name>}`. It fires only for messages that rule matches. The hook
receives a decoded [`MapView`](#mapview) and returns a decision.

```python
@ss7.content.on("on_np_dip")
async def np_dip(msg):
    pc = await portability_lookup(msg.msisdn)
    if pc is not None:
        ss7.routes.cache(msg.cdpa_gt, dpc=pc, ssn=6, ttl=3600)  # next MSU routes in Rust
        return ss7.route(dpc=pc, ssn=6)
    return ss7.route_default()
```

#### `@ss7.on_route(when="<selector>")`

Register a **general** routing override, gated by a `when=` selector
expression over the view fields (`operation`, `dpc`, and so on). The selector
keeps the hook off the hot path for everything it does not match.

```python
@ss7.on_route(when="operation == 'sri-sm' and dpc == 2000")
async def override(msg):
    return ss7.route(linkset="transit") if maintenance() else ss7.route_default()
```

!!! warning "A hook with no selector sees every decision"
    Drop `when=` and the hook intercepts every routing decision. That is fine
    for a low-volume HLR or SMSC; on a transit STP it caps throughput at the
    interpreter. Prefer a selector, or program the tables live instead. See
    [the cost ladder](concepts.md#the-cost-ladder).

## `gsm_map` { #gsm-map }

MAP (TS 29.002): termination decorators, result and invoke builders, and
originating helpers. Termination decorators register a handler for their
operation on **every** owned SSN (`sccp.local_ssns`), so the handler fires
whichever subsystem the message was addressed to.

### Termination decorators

| Decorator | Terminates |
|---|---|
| `@gsm_map.on_mo_forward_sm` | MO-ForwardSM |
| `@gsm_map.on_mt_forward_sm` | MT-ForwardSM |
| `@gsm_map.on_send_routing_info_for_sm` | SendRoutingInfoForSM (SRI-SM) |
| `@gsm_map.on_update_location` | updateLocation |

Each handler is `def on(dlg, arg)` where `dlg` is a [`Dialogue`](#dialogue) and
`arg` is the decoded [`IncomingOp`](#incomingop).

### Builders and helpers

| Call | Returns / effect |
|---|---|
| `gsm_map.mo_forward_sm_res()` | A [`Result`](#staged) to `dlg.reply(...)` with. |
| `gsm_map.mt_forward_sm_res()` | Same, for MT-ForwardSM. |
| `gsm_map.mt_forward_sm(imsi=…, sc_addr=…, tpdu=…, more_messages_to_send=False)` | A staged [`Invoke`](#staged) to `dlg.invoke(...)`. Set `more_messages_to_send` on all but the last segment. |
| `gsm_map.send_routing_info_for_sm(msisdn=…, sc_addr=…)` | An **awaitable** resolving to the HLR's routing info (`.imsi`, `.network_node_number`). Needs a running node (a live SCTP transport driven by the siphon binary). |
| `gsm_map.begin(to=…, ssn=8, ac=…)` | Open an originating [`Dialogue`](#dialogue). `to` is an [`Address`](#address); `ac` is an application context from `gsm_map.AC`. |
| `gsm_map.AC.short_msg_mt_relay` / `.short_msg_gateway` / `.short_msg_mo_relay` | MAP application-context handles (version 3) for `gsm_map.begin`. |

## `gsm_cap` { #gsm-cap }

CAMEL CAP (TS 29.078).

| Call | Returns / effect |
|---|---|
| `@gsm_cap.on_initial_dp` | Terminate a CAMEL initialDP. Handler is `def on(dlg, idp)`, `idp` a decoded [`IncomingOp`](#incomingop) (with `.called_party_number`). |
| `gsm_cap.connect(destination_routing_address=[…])` | A staged [`Invoke`](#staged): reroute the call to a list of called-party-number byte strings. |

## The `Dialogue` handle { #dialogue }

Passed to every termination handler (and returned by `gsm_map.begin`). The
handler **stages** components and then **flushes** them; the engine replays the
staged commands onto the real Rust dialogue and encodes the wire TCAP, so the
handler's view stays simple and the encoding stays in Rust.

| Method | Stages / does |
|---|---|
| `dlg.invoke(staged)` | Stage an `Invoke` from an originating helper (`gsm_map.mt_forward_sm(...)`, `gsm_cap.connect(...)`). |
| `dlg.reply(result)` | Stage a `ReturnResultLast` answering the opening invoke. |
| `dlg.reply_to(invoke_id, result)` | Stage a result answering a specific invoke id. |
| `dlg.error(invoke_id, error_code)` | Stage a `ReturnError`. |
| `dlg.send()` | Flush as a `Continue` (dialogue stays open). |
| `dlg.end()` | Flush as an `End` (dialogue closes). |
| `dlg.abort()` | Abort (a dialogue-service-user abort). |
| `await dlg.result()` | Await this leg's `returnResultLast` (originating multi-leg flows). Needs a running node. |

`dlg.otid` and `dlg.dtid` expose the originating and peer transaction ids as
bytes.

!!! note "Awaitables need the live node"
    `await dlg.result()` and `await gsm_map.send_routing_info_for_sm(...)` are
    bridged onto tokio the same way the sibling addons' send helpers are.
    Awaiting one drives the SCTP transport, which the composing siphon binary
    owns; without a running node it resolves to a clear error rather than
    blocking. In-process termination (reply / invoke / send / end) needs no
    transport and is exercised by [`node.deliver`](#node).

## Decoded views { #views }

### `IncomingOp` { #incomingop }

The decoded opening operation a termination handler receives as its second
argument (`arg` / `idp`).

| Field / getter | Meaning |
|---|---|
| `operation_code` | The local MAP/CAP operation code. |
| `invoke_id` | The invoke id the peer used. |
| `calling_gt` / `called_gt` | Calling / called global-title digits, if present. |
| `argument` | The raw BER argument bytes, if the Invoke carried a parameter. |
| `sm_rp_oa` / `sm_rp_da` / `sm_rp_ui` | For MO/MT-ForwardSM: the originating address, destination address, and TPDU bytes, decoded where present. |
| `called_party_number` | For a CAMEL initialDP: the dialled number bytes. |

!!! note "`sm_rp_ui` is an opaque SMS TPDU"
    siphon-sigtran handles the MAP and transaction layers; it does not decode
    the SMS content. `sm_rp_ui` (and the `tpdu=` argument of
    `gsm_map.mt_forward_sm`) is the raw SMS transfer-layer PDU. To read or build
    it (SMS-SUBMIT / SMS-DELIVER per 3GPP TS 23.040, GSM 7-bit packing per
    TS 23.038, the User-Data-Header for concatenation, TON/NPI addresses), use
    the sibling [`tpdu`](https://crates.io/crates/tpdu) crate, which also ships
    as a Python wheel. See [Building an SMSC](cookbook/smsc.md).

### `MapView` { #mapview }

The read-only decoded view handed to a content / route hook.

| Field | Meaning |
|---|---|
| `operation` | The operation name (kebab-case), if recognised. |
| `cgpa_gt` / `cdpa_gt` | Calling / called-party GT digits. |
| `imsi` / `msisdn` | The subscriber IMSI / MSISDN carried in the MAP argument, if present. |
| `opc` / `dpc` | The routing-label point codes. |

### `Address` { #address }

Built with `ss7.gt(digits, ssn=…)`, handed to an originating helper as a
destination. Exposes `.digits` and `.ssn`.

### Staged components { #staged }

`Invoke` and `Result` are opaque staged components produced by the builders
above and consumed by `dlg.invoke(...)` / `dlg.reply(...)`. You do not
construct them directly.

## `Node` { #node }

Returned by [`configure`](#configure). Beyond running the node it exposes the
in-process termination seam used for local testing and the
[Quickstart](quickstart.md#4-prove-the-path-no-peer-needed):

| Method | Effect |
|---|---|
| `node.open_dialogues()` | Count of currently open TCAP dialogues. |
| `node.metrics()` | The Prometheus text exposition. |
| `node.assemble_begin(op, called_gt, called_ssn, calling_gt, arg=None, ac=None)` | Build a genuine inbound `Begin(AARQ, Invoke)` SCCP payload for `op` (a kebab-case operation name). Returns the SCCP bytes. |
| `node.deliver(payload, opc=…, dpc=…)` | Deliver one inbound SCCP payload to the dialogue engine and return the SCCP payloads to send back. |
| `node.dispatch_content(name, view)` | Run a registered content hook against a [`MapView`](#mapview) and return its decision. |

## Hot reload, restated

Routing state lives in Rust, so reloading the script does not drop routes, GTT
entries or open dialogues. On reload the script re-registers its hooks and
termination handlers. Program tables with idempotent calls
(`address_table(...).add`, prepend-on-`add_rule`) so a reload mid-traffic is
safe. See [Concepts](concepts.md#hot-reload).
