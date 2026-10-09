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

The SCF invoke builders an SCP stages toward the SSF stage the same way as
`gsm_cap`'s:

| Call | Stages |
|---|---|
| `inap.connect(destination_routing_address=[…], original_called_party_id=None)` | Connect. ETS 300 374-1 allows one destination, Q.1218 up to three. |
| `inap.request_report_bcsm_event(events=[…])` | RequestReportBCSMEvent. Each event is `(event_type_bcsm, monitor_mode)` or `(event_type_bcsm, monitor_mode, leg)`; the leg goes out as `legID [2] { sendingSideID [0] }`. Event types 1 to 18 of Q.1218, including `origAttemptAuthorized` (1), `oMidCall` (8) and `tMidCall` (16). |
| `inap.apply_charging(charging_characteristics=…, party_to_charge=None)` | ApplyCharging. |
| `inap.release_call(cause=…)` | ReleaseCall with a Q.850 cause. |
| `inap.continue_()` | Continue. |
| `inap.play_announcement(message_id=… \| tone_id=…, tone_duration=… \| information_to_send=…)` | PlayAnnouncement. What to send is a typed choice: an elementary announcement id, a tone, or the BER of an `InformationToSend` value (decoded and refused if it is not one). |
| `inap.prompt_and_collect_user_information(maximum_digits=…, minimum_digits=None \| collected_info=…, …)` | PromptAndCollectUserInformation, with an optional prompt given as for `play_announcement`. |
| `inap.connect_to_resource(ip_routing_address=None)` | ConnectToResource, to that address or to the SRF colocated with the SSF. |

`inap.AC` supplies the application contexts of ETS 300 374-1 clause 6.5:
`inap.AC.ssp_to_scp` (`0.4.0.1.1.1.0.0`), `inap.AC.assist_handoff_ssp_to_scp`
(`0.4.0.1.1.1.1.0`) and `inap.AC.ip_to_scp` (`0.4.0.1.1.1.2.0`). A terminated
dialogue answers with the context the SSF proposed.

The `inap_*` getters decode the InitialDP strictly and raise
[`MistypedParameter`](#mistyped) when it does not decode: a member that cannot be
read, a member the argument does not have, a missing `serviceKey`.

## The `Dialogue` handle { #dialogue }

Passed to every termination handler. The handler **stages** components and then
**flushes** them; the engine replays the staged commands onto the real Rust
dialogue and encodes the wire TCAP, so the handler's view stays simple and the
encoding stays in Rust.

| Method | Stages / does |
|---|---|
| `dlg.invoke(staged, *, operation_class=None, timeout=None)` | Stage an `Invoke` from an invoke builder (`gsm_map.insert_subscriber_data(...)`, `gsm_cap.connect(...)`), e.g. the ISD leg of a held-open updateLocation. The builder knows the class of its operation (`staged.operation_class`); `operation_class=` (1 to 4) overrides it, `timeout=` is the invocation timer in seconds (default `tcap.invoke_timer_ms`). |
| `dlg.reply(result)` | Stage a `ReturnResultLast` answering the opening invoke. |
| `dlg.reply_to(invoke_id, result)` | Stage a result answering a specific invoke id. |
| `dlg.error(invoke_id, error_code)` | Stage a `ReturnError`: the operation failed. |
| `dlg.reject(invoke_id, problem_class, problem_code)` | Stage a `Reject`: the component the peer sent is a protocol error. `problem_class` is `general` / `invoke` / `return-result` / `return-error`, `problem_code` the code within it (Q.773 Tables 26 to 29). An Invoke whose argument does not decode is `dlg.reject(arg.invoke_id, "invoke", 2)`, mistyped parameter. |
| `dlg.set_idle_timeout(seconds)` | How long this dialogue may go without a message before the node aborts it, overriding `tcap.dialogue_timer_ms`. `None` waits until the peer ends it. |
| `dlg.send()` | Flush as a `Continue` (dialogue stays open). |
| `dlg.end()` | Flush as an `End` (dialogue closes). |
| `dlg.abort()` | Abort as the dialogue's user: a U-Abort, carrying an ABRT (dialogue-service-user) when the dialogue has an application context. |

`dlg.otid` and `dlg.dtid` expose the originating and peer transaction ids as
bytes. In-process termination (reply / invoke / send / end) needs no transport and
is exercised by [`node.deliver`](#testing).

Invoke ids are `INTEGER (-128..127)`: `reply_to`, `error` and `reject` raise
`SigtranError` for anything else. A flush the encoder refuses (a parameter that is
not one BER element, say) is logged at error level with the dialogue's transaction
ids and counted in `sigtran_tcap_send_errors_total`; when that leaves a `Begin`
unanswered the node aborts the dialogue, so the peer is told instead of waiting.

### Operation classes and timers { #operation-classes }

Every invoke has a class (Q.774 Table 2) that says which outcomes its performer
reports, and an invocation timer.

| Class | Reports | When the timer expires |
|---|---|---|
| 1 | success and failure | No reply came: an abnormal situation. The handler is called with a `PeerTurn` whose `is_timeout` is true. If it stages nothing the node aborts the dialogue (a U-Abort); staging an answer (`dlg.error(...)`, `dlg.end()`, `dlg.send()`) keeps or closes it as the script decides. |
| 2 | failure only | The operation succeeded. The handler is told (`is_timeout`, `operation_class == 2`) and the dialogue goes on. |
| 3 | success only | The operation failed. Told the same way; the dialogue goes on. |
| 4 | nothing | Nothing is reported. |

The MAP builders are class 1. The CAP and INAP builders carry the class of their
operation: `connect`, `request_report_bcsm_event`, `apply_charging`,
`play_announcement` and `connect_to_resource` are class 2,
`prompt_and_collect_user_information` is class 1, `continue_` and `release_call`
are class 4.

A handler that stages nothing on a follow-up leg leaves the dialogue open: an SCP
that armed a detection point simply waits for the next event. Give such a dialogue
the idle timeout the call can last (`dlg.set_idle_timeout(...)`); the default
`tcap.dialogue_timer_ms` is sized for request / response dialogues.

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
| `further` | Every other component of the `Begin`, in order, as [`Component`](#component) objects. Empty for the usual single Invoke. |
| `sm_rp_oa` / `sm_rp_da` / `sm_rp_ui` | For MO-ForwardSM (46) and MT-ForwardSM (44): the originating address, destination address, and TPDU bytes. `None` for any other operation. Raise [`MistypedParameter`](#mistyped) when the argument does not decode. |
| `called_party_number` | For a CAMEL initialDP: the dialled number bytes. |

!!! note "`sm_rp_ui` is an opaque SMS TPDU"
    siphon-sigtran handles the MAP and transaction layers; it does not decode
    the SMS content. `sm_rp_ui` (and the `tpdu=` argument of
    `gsm_map.mt_forward_sm`) is the raw SMS transfer-layer PDU. To read or build
    it (SMS-SUBMIT / SMS-DELIVER per 3GPP TS 23.040, GSM 7-bit packing per
    TS 23.038, the User-Data-Header for concatenation, TON/NPI addresses), use
    the sibling [`tpdu`](https://crates.io/crates/tpdu) crate, which also ships
    as a Python wheel. See [Building an SMSC](cookbook/smsc.md).

### An argument that does not decode { #mistyped }

The decoded getters read the argument strictly. A member that is on the wire and
cannot be read, a list element that cannot be read, or a missing mandatory member
is an error, never a field that reads as absent; a member a later release of the
protocol added after an extension marker is skipped, as TS 29.002 17.1.4 requires
of a receiver. When the argument does not decode the getter raises
`siphon.MistypedParameter` (a `SigtranError`).

Let it propagate and the node answers for the script: the component is rejected
(`Reject`, mistyped parameter: `invoke` problem 2 for an Invoke, `return-result`
problem 2 for a result) in an `End`, and whatever the handler had staged is
discarded. Catch it to decide otherwise:

```python
@gsm_map.on_operation("mo-forward-sm")
async def on_mo(dlg, arg):
    try:
        tpdu = arg.sm_rp_ui
    except siphon.MistypedParameter:
        dlg.reject(arg.invoke_id, "invoke", 2)   # what the node does by default
        dlg.end()
        return
    ...
```

A handler that raises anything else has staged nothing, and a `Begin` left
unanswered that way is aborted.

### `PeerTurn` { #peerturn }

On a follow-up leg of a held-open dialogue the termination handler is re-entered
with a `PeerTurn` in place of the [`IncomingOp`](#incomingop): the decoded view of
what the peer sent back (its `Continue` or `End`). Tell the two apart with
`is_peer_turn` (false on the opening `IncomingOp`, true here). See the
[HLR held-open flow](cookbook/hlr.md#the-held-open-success-flow).

| Field / getter | Meaning |
|---|---|
| `is_peer_turn` | Always `True` (the opening `IncomingOp` is `False`). |
| `is_end` | The dialogue is over: the peer closed it with a TCAP `End`, or it ended otherwise (`closed`). |
| `is_result` / `is_invoke` / `is_error` | Whether the turn carries a result, an invoke, a `returnError`. |
| `operation_code` | The operation code of the first component (a result echoes the one it answers). |
| `invoke_id` | The invoke id of the first component. |
| `error_code` | The MAP/CAP error code, if the peer sent a `returnError`. |
| `result` | The raw BER result parameter of the first `returnResultLast`, if present. |
| `argument` | The raw BER argument of the first `Invoke` the peer sent, if present. |
| `components` | Every component of the turn, in order, as [`Component`](#component) objects. |
| `is_reject` | The turn carries a `Reject`. A Reject is a protocol error, not a MAP/CAP error: `is_error` is false and `error_code` is `None`. |
| `reject_is_local` | The Reject was raised by this node for a component of the peer's that could not be read or did not fit the dialogue. It is sent with the next `send()` / `end()`; components after an unreadable one were discarded. |
| `reject_invoke_id` | The invoke id the Reject names, `None` if it could not be derived. |
| `reject_problem_class` / `reject_problem_code` / `reject_problem_name` | The typed problem: the class (`general` / `invoke` / `return-result` / `return-error`), the code within it, and the name Q.773 gives it (`mistypedParameter`). |
| `is_timeout` | Not a message: the invocation timer of one of our invokes expired. `invoke_id`, `operation_code` and `operation_class` name it. See [operation classes](#operation-classes). |
| `closed` | Not a message: the dialogue ended without the script ending it. `peer-abort`, `provider-abort` (a damaged message arrived for it), `abnormal-dialogue`, `invoke-timeout`, `idle-timeout`, `no-answer` (the handler answered nothing to a `Begin`) or `not-sent`. Told exactly once; nothing can be sent any more. |
| `is_abort` | `closed` is set. |
| `abort_kind` | `p-abort` (a transaction sub-layer aborted) or `u-abort` (a TC-user or a component sub-layer did); `None` if no Abort message was involved. |
| `p_abort_cause` | The P-Abort cause value (0 unrecognized message type, 1 unrecognized transaction ID, 2 badly formatted transaction portion, 3 incorrect transaction portion, 4 resource limitation). |
| `abort_cause` | What the abort carried, as a fixed label: a P-Abort cause name, or `none`, `dialogue-service-user`, `abnormal-dialogue`, `no-common-dialogue-portion`, `application-context-not-supported`, `dialogue-refused`, `user-defined`. |

A handler written before these existed keeps working: a turn that is a timeout or
a closure has no components, so `is_result` / `is_invoke` / `is_error` are all
false. Release whatever the script tied to the dialogue (a charging session, a
pending delivery) when `closed` is set or `is_end` is true.

### `Component` { #component }

One component of a turn (`turn.components`, `arg.further`).

| Field | Meaning |
|---|---|
| `kind` | `invoke`, `result`, `error`, `reject` (from the peer) or `local-reject` (raised here). |
| `invoke_id` | The invoke id; `None` only for a reject whose invoke id could not be derived. |
| `operation_code` | Of an invoke, or the one a result echoes. |
| `parameter` | The raw BER argument of an invoke or parameter of a result. |
| `error_code` | Of an error. |
| `problem_class` / `problem_code` / `problem_name` | Of a reject. |

### `Address` { #address }

Built with `ss7.gt(digits, ssn=…)`: an SCCP address (E.164, GTI-4). Exposes
`.digits` and `.ssn`.

### Staged components { #staged }

`Invoke` and `Result` are opaque staged components produced by the builders
above and consumed by `dlg.invoke(...)` / `dlg.reply(...)`. You do not
construct them directly. An `Invoke` exposes `operation_code` and
`operation_class`.

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
| `node.assemble_tcap(tcap, called_ssn=6)` | Wrap raw TCAP octets in an inbound SCCP UDT, for what the other helpers cannot build: a damaged message, a `Reject`, an `Abort`. |
| `node.deliver(payload, opc=…, dpc=…)` | Deliver one inbound SCCP payload to the dialogue engine and return the SCCP payloads to send back. |
| `node.sweep(ahead=0.0)` | Run the dialogue timers as the live node does once a second, with the clock moved `ahead` seconds forward, and return the SCCP payloads to send. |
| `node.decode(payload)` | Decode an outbound SCCP payload into a read-only `Decoded` view: `.kind`, `.otid` / `.dtid`, `.app_context`, `.invoke` / `.invokes`, `.result`, `.result_invoke_id`, `.error`, `.rejects` (a list of `(invoke_id, problem_class, problem_code)`), and for an abort `.abort_kind`, `.p_abort_cause`, `.abort_source`. |

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
