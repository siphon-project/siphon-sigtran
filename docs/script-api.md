# Script API

Everything your script can call, imported from the `siphon` package the addon
mounts its namespaces onto:

```python
import siphon
from siphon import ss7, gsm_map, gsm_cap, inap
```

There are four groups: the [`ss7`](#ss7) routing namespace (live tables); the
[`gsm_map`](#gsm-map) / [`gsm_cap`](#gsm-cap) / [`inap`](#inap) termination
decorators, result builders, and invoke builders; the [`Dialogue`](#dialogue)
handle a termination handler drives; and the [decoded views](#views) a handler
receives. Handlers may be `async def`; they run to completion on SIPhon's runtime.
For unit-testing a script off the wire, see [Testing your handlers](#testing).

## The node { #node-config }

The composing siphon binary owns the node. At startup it reads its
`extensions.sigtran` config and builds the process-wide node, then loads your
script (see [Using it in a SIPhon build](integration.md)). A script **does not**
configure the node; it just imports the namespaces and programs them. The config
is [`sigtran.yaml`](configuration.md).

`siphon.metrics()` renders the Prometheus text exposition for the whole node
(see [Routing model & coverage](routing.md#metrics)).

## `ss7` { #ss7 }

The routing namespace. It programs the Rust routing tables live.

### Live tables

| Call | Effect |
|---|---|
| `ss7.routes.add(dpc, as_=…\|linkset=…, priority=1)` | Add or extend an MTP3 route. Name exactly one of `as_` / `linkset`. |
| `ss7.routes.cache(gt, dpc=…, ssn=…, ttl=None)` | Cache a translation as a GTT prefix rule, so later MSUs for `gt` route in Rust. `ttl` is accepted for API stability; the rule persists until reprogrammed. |
| `ss7.gtt.add(match={…}, to={…})` | Prepend a GTT rule. `match` / `to` are dicts mirroring the config [`gtt`](configuration.md#gtt) schema. |
| `ss7.content.add_rule(name, match={…}, action={…})` | Prepend a content rule (config [`content_routing`](configuration.md#content-routing) schema). |
| `ss7.content.address_table(name).add(gt)` | Add a GT digit string to an address table live, creating it if absent. Idempotent. |
| `ss7.gt(digits, ssn=None)` | Build an SCCP [`Address`](#address) (E.164, GTI-4). |

Prepending means a live rule wins over the static config rules (first match
wins). Programming a table at script load keeps every subsequent decision in Rust
at line rate. A content rule's action is `route`, `rewrite_cdpa_gt`, or `screen`
(see [`content_routing`](configuration.md#content-routing)).

## `gsm_map` { #gsm-map }

MAP (TS 29.002): termination decorators plus result and invoke builders.
Termination decorators register a handler for their
operation on **every** owned SSN (`sccp.local_ssns`), so the handler fires
whichever subsystem the message was addressed to.

### Terminating operations: `@gsm_map.on_operation` { #on_operation }

`@gsm_map.on_operation("<name>")` registers a handler for one or more MAP
operations, named by their kebab-case operation name, the same
`on_<message>("<name>")` shape as the sibling `@smpp.on_pdu`. As with the SIP
proxy's `@proxy.on_request`, a handler can take several operations pipe-separated,
and a bare decorator is a catch-all over every MAP operation.

```python
@gsm_map.on_operation("mo-forward-sm")                # one operation
@gsm_map.on_operation("mo-forward-sm|mt-forward-sm")  # several, pipe-separated
@gsm_map.on_operation                                 # bare: every MAP operation
```

A handler registers on **every** owned SSN (`sccp.local_ssns`), so it fires
whichever subsystem the message was addressed to. An unknown operation name
raises `SigtranError` at decoration time. The selector names:

| Name | Operation | Op code |
|---|---|---|
| `mo-forward-sm` | MO-ForwardSM | 46 |
| `mt-forward-sm` | MT-ForwardSM | 44 |
| `sri-sm` | SendRoutingInfoForSM | 45 |
| `report-sm-delivery-status` | reportSM-DeliveryStatus | 47 |
| `ready-for-sm` | readyForSM | 66 |
| `update-location` | updateLocation | 2 |
| `cancel-location` | cancelLocation | 3 |
| `purge-ms` | purgeMS | 67 |
| `send-auth-info` | sendAuthenticationInfo | 56 |
| `provide-subscriber-info` | provideSubscriberInfo | 70 |

!!! note "`mo-forward-sm` also covers the legacy forwardSM"
    Op code 46 is both v3 mo-forwardSM and the v1/v2 combined forwardSM, so a
    `mo-forward-sm` handler receives a legacy forwardSM(46) as well; mt-forwardSM
    is a distinct op (44). The MAP version and, for a v1/v2 forwardSM, the MO/MT
    direction live in the TCAP application context and the SM-RP-DA/OA, not the op
    code, so the op-code-keyed dispatch does not split on them.

On the opening leg the handler is `def on(dlg, arg)` where `dlg` is a
[`Dialogue`](#dialogue) and `arg` is the decoded [`IncomingOp`](#incomingop). On a
follow-up leg of a held-open dialogue the same handler is re-entered with a
[`PeerTurn`](#peerturn) in place of `arg`; branch on `arg.is_peer_turn`. See the
[HLR held-open flow](cookbook/hlr.md#the-held-open-success-flow).

### Result builders

Each returns a [`Result`](#staged) to `dlg.reply(...)` with. It builds and encodes
the real MAP result argument.

| Call | Result |
|---|---|
| `gsm_map.mo_forward_sm_res()` | MO-ForwardSM ack. |
| `gsm_map.mt_forward_sm_res()` | MT-ForwardSM ack. |
| `gsm_map.send_routing_info_for_sm_res(imsi=…, network_node_number=…, lmsi=None)` | SRI-SM: the recipient IMSI and serving MSC/SGSN. |
| `gsm_map.update_location_res(hlr_number=…)` | updateLocation: the HLR number. |
| `gsm_map.send_authentication_info_res(quintuplets=None, triplets=None)` | Authentication vectors (each quintuplet `(rand, xres, ck, ik, autn)`, each triplet `(rand, sres, kc)`). |
| `gsm_map.insert_subscriber_data_res()` | The VLR accepting pushed subscriber data. |
| `gsm_map.cancel_location_res()` | cancelLocation ack. |
| `gsm_map.purge_ms_res(freeze_tmsi=False, freeze_p_tmsi=False)` | purgeMS ack. |
| `gsm_map.ready_for_sm_res()` | readyForSM ack. |

### Invoke builders and helpers

| Call | Returns / effect |
|---|---|
| `gsm_map.insert_subscriber_data(imsi=None, msisdn=None)` | A staged [`Invoke`](#staged): the HLR pushing subscriber data inside a held-open updateLocation. |
| `gsm_map.mt_forward_sm(imsi=…, sc_addr=…, tpdu=…, more_messages_to_send=False)` | A staged [`Invoke`](#staged) to `dlg.invoke(...)`. Set `more_messages_to_send` on all but the last segment. |
| `gsm_map.mo_forward_sm(sc_addr=…, msisdn=…, tpdu=…, imsi=None)` | A staged [`Invoke`](#staged): relay a mobile-originated TPDU on to the service centre. |
| `gsm_map.AC.short_msg_mt_relay` / `.short_msg_gateway` / `.short_msg_mo_relay` | MAP application-context handles (version 3). |

The address arguments (`sc_addr`, `msisdn`, `hlr_number`, `network_node_number`,
`imsi`, a CAP `destination_routing_address`) take an **E.164 digit string** and
are encoded for you (TBCD for MAP AddressStrings, Q.763 for the CAP called party),
exactly as [`ss7.gt`](#ss7) does; a raw already-encoded `bytes` is also accepted
(e.g. a value decoded off the wire). The `tpdu=` argument of `mt_forward_sm` /
`mo_forward_sm` is different: it is an opaque SMS transfer-layer PDU that
siphon-sigtran never inspects, built with the `tpdu` crate. See
[Building an SMSC](cookbook/smsc.md).

## `gsm_cap` { #gsm-cap }

CAMEL CAP (TS 29.078). Termination via `@gsm_cap.on_operation("<name>")` (the same
shape as [`@gsm_map.on_operation`](#on_operation)), then the gsmSCF invoke builders
an SCP stages toward the gsmSSF.

| Name | Operation | Op code |
|---|---|---|
| `initial-dp` | A CAMEL initialDP. Handler is `def on(dlg, idp)`, `idp` a decoded [`IncomingOp`](#incomingop) (with `.called_party_number`). | 0 |
| `event-report-bcsm` | An EventReportBCSM the gsmSSF sends when an armed detection point fires. | 24 |

| Invoke builder | Stages |
|---|---|
| `gsm_cap.connect(destination_routing_address=[…])` | Connect: reroute the call to a list of called-party numbers (each an E.164 digit string or raw bytes). |
| `gsm_cap.release_call(cause=…)` | ReleaseCall: tear the call down with a Q.850 cause. |
| `gsm_cap.request_report_bcsm_event(events=[(event_type, monitor_mode), …])` | RequestReportBCSMEvent: arm detection points (integers per TS 29.078). |
| `gsm_cap.apply_charging(charging_characteristics=…, party_to_charge=None)` | ApplyCharging: an online-charging control. |

Stage several in one dialogue (a RequestReportBCSMEvent then a Connect) with
repeated `dlg.invoke(...)`, then `dlg.end()`. See
[Building a CAMEL SCP](cookbook/scp.md#beyond-a-fixed-connect).

## `inap` { #inap }

INAP CS-1 (ITU-T Q.1218), the fixed-network TCAP-user peer to CAMEL. Termination
via `@inap.on_operation("<name>")`, the same shape as
[`@gsm_map.on_operation`](#on_operation); an `initial-dp` handler reads the decoded
argument off the [`IncomingOp`](#incomingop) `inap_*` getters (`inap_service_key`,
`inap_called_party_number`, …).

| Name | Operation | Op code |
|---|---|---|
| `initial-dp` | InitialDP: the SSF reports a triggered call | 0 |
| `event-report-bcsm` | EventReportBCSM: an armed detection point fired | 24 |
| `apply-charging-report` | ApplyChargingReport: metered call result | 36 |
| `assist-request-instructions` | AssistRequestInstructions | 16 |
| `call-information-report` | CallInformationReport | 44 |
| `specialized-resource-report` | SpecializedResourceReport | 49 |

The SCF invoke builders an SCP stages toward the SSF (`inap.connect`,
`inap.request_report_bcsm_event`, `inap.apply_charging`, `inap.release_call`,
`inap.play_announcement`, `inap.prompt_and_collect_user_information`,
`inap.connect_to_resource`, `inap.continue_()`) stage the same way as `gsm_cap`'s,
with `inap.AC` supplying the application contexts.

## The `Dialogue` handle { #dialogue }

Passed to every termination handler. The handler **stages** components and then
**flushes** them; the engine replays the staged commands onto the real Rust
dialogue and encodes the wire TCAP, so the handler's view stays simple and the
encoding stays in Rust.

| Method | Stages / does |
|---|---|
| `dlg.invoke(staged)` | Stage an `Invoke` from an invoke builder (`gsm_map.insert_subscriber_data(...)`, `gsm_cap.connect(...)`), e.g. the ISD leg of a held-open updateLocation. |
| `dlg.reply(result)` | Stage a `ReturnResultLast` answering the opening invoke. |
| `dlg.reply_to(invoke_id, result)` | Stage a result answering a specific invoke id. |
| `dlg.error(invoke_id, error_code)` | Stage a `ReturnError`. |
| `dlg.send()` | Flush as a `Continue` (dialogue stays open). |
| `dlg.end()` | Flush as an `End` (dialogue closes). |
| `dlg.abort()` | Abort (a dialogue-service-user abort). |

`dlg.otid` and `dlg.dtid` expose the originating and peer transaction ids as
bytes. In-process termination (reply / invoke / send / end) needs no transport and
is exercised by [`node.deliver`](#testing).

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

### `PeerTurn` { #peerturn }

On a follow-up leg of a held-open dialogue the termination handler is re-entered
with a `PeerTurn` in place of the [`IncomingOp`](#incomingop): the decoded view of
what the peer sent back (its `Continue` or `End`). Tell the two apart with
`is_peer_turn` (false on the opening `IncomingOp`, true here). See the
[HLR held-open flow](cookbook/hlr.md#the-held-open-success-flow).

| Field / getter | Meaning |
|---|---|
| `is_peer_turn` | Always `True` (the opening `IncomingOp` is `False`). |
| `is_end` | The peer closed the dialogue with a TCAP `End`. |
| `is_result` / `is_invoke` / `is_error` | What the first component is. |
| `operation_code` | The operation code of the first component (a result echoes the one it answers). |
| `invoke_id` | The invoke id of the first component. |
| `error_code` | The MAP/CAP error code, if the peer sent a `returnError`. |
| `result` | The raw BER result parameter of the first `returnResultLast`, if present. |
| `argument` | The raw BER argument of the first `Invoke` the peer sent, if present. |

### `Address` { #address }

Built with `ss7.gt(digits, ssn=…)`: an SCCP address (E.164, GTI-4). Exposes
`.digits` and `.ssn`.

### Staged components { #staged }

`Invoke` and `Result` are opaque staged components produced by the builders
above and consumed by `dlg.invoke(...)` / `dlg.reply(...)`. You do not
construct them directly.

## Testing your handlers { #testing }

You can unit-test a script off the wire, with no peer and no SCTP. `siphon.configure`
rebuilds the process-wide node from a `sigtran.yaml` (a path, an inline YAML string,
or a dict) and returns a `Node` round-trip handle: it assembles genuine inbound MSUs
(real TCAP in a real SCCP UDT) and drives them through the same dialogue engine the
live node uses, so your `@gsm_map.on_operation(...)` handlers run for real. This is
the seam the crate's own integration tests drive; a live script never calls it (the
binary configures the node, see [The node](#node-config)).

```python
node = siphon.configure("sigtran.yaml")   # test-only: build a node to drive

begin = node.assemble_begin(op="mo-forward-sm", called_gt="15550100",
                            called_ssn=8, calling_gt="15550142")
replies = node.deliver(begin, opc=2000, dpc=1000)   # SCCP payloads sent back
assert node.decode(replies[0]).kind == "end"        # the closing End your handler staged
```

| Method | Effect |
|---|---|
| `siphon.configure(source)` | Rebuild the node from a `sigtran.yaml` (path / YAML string / dict), validating as the Rust loader does (a bad reference raises `SigtranError`); returns a `Node`. |
| `node.open_dialogues()` | Count of currently open TCAP dialogues. |
| `node.metrics()` | The Prometheus text exposition. |
| `node.assemble_begin(op, called_gt, called_ssn, calling_gt, arg=None, ac=None)` | Build a genuine inbound `Begin(AARQ, Invoke)` SCCP payload for `op` (a kebab-case operation name). Returns the SCCP bytes. |
| `node.assemble_continue(dtid, staged, invoke_id=1, otid=None)` | Build an inbound `Continue` for a held-open dialogue keyed to `dtid` (read off the first reply with `decode`), carrying a staged [`Result`](#staged) or [`Invoke`](#staged). |
| `node.deliver(payload, opc=…, dpc=…)` | Deliver one inbound SCCP payload to the dialogue engine and return the SCCP payloads to send back. |
| `node.decode(payload)` | Decode an outbound SCCP payload into a read-only `Decoded` view: `.kind`, `.otid` / `.dtid`, `.app_context`, `.invoke` / `.invokes`, `.result`, `.error`. |

## Hot reload, restated

Routing state lives in Rust, so reloading the script does not drop routes, GTT
entries or open dialogues. On reload the script re-registers its termination
handlers. Program tables with idempotent calls
(`address_table(...).add`, prepend-on-`add_rule`) so a reload mid-traffic is
safe. See [Concepts](concepts.md#hot-reload).

Termination registrations update **in place** by `(SSN, operation)`, which keeps a
reload from dropping in-flight messages. Two consequences: a handler you delete
from the script keeps running until overwritten, and moving an operation between a
specific `on_operation("<name>")` and a bare catch-all does not take full effect on
a hot reload (the prior registration still wins for that operation). Restart the
node (or reconfigure it) to apply either change cleanly.
