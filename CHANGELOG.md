# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [Unreleased]

### Changed

- Moved to `gsm_map` 3 and `gsm_cap` 3, which depend on `tcap` 2 and `inap` 2.
  The dependency graph now holds one `tcap` and one `inap`; 2.0.0 carried
  both majors of each. No emitted octet and no public item changes.

## [2.0.0] — 2026-10-10

A major release: public items of the dialogue engine change type, and the
Python layer changes with them. The engine moves to `tcap` 2, whose decoder no
longer returns a message that lost part of itself, and with that this crate stops
doing three things that were wrong on the wire.

**What was wrong in 1.0.0**

- **Every Abort the node sent was malformed.** It was built as an opaque value
  under the P-Abort tag (`6A` around an `EXTERNAL`), which no peer reads: neither
  a P-Abort cause nor user abort information. That covered every abort there was:
  no handler for the operation, the dialogue ceiling, a handler that answered
  nothing, an invoke timer, an idle timer.
- **A damaged or unexpected message was dropped without the answer ITU-T Q.774
  requires.** A message that failed to decode was discarded in silence, whatever
  was wrong with it. A `Continue` for a transaction the node did not know was
  discarded too. And a message whose last component was malformed was not even
  seen as damaged: it was processed without that component.
- **A reply without a result parameter was not a valid ReturnResult.**
  `dlg.reply(...)` with a result that carries no parameter
  (`mo_forward_sm_res()`, `mt_forward_sm_res()`) went out with a result sequence
  holding the operation code alone (`30 03 02 01 2E`), which Q.773 does not
  have: the sequence is there with its parameter or not at all. And the send
  path swallowed encode errors, so the day the encoder refused that (it does in
  `tcap` 2) the reply would have vanished without a trace.

### Fixed

- **Damaged messages are answered** as Q.774 3.2.2 and 3.3.4 lay down. A fault in
  the transaction portion of a `Begin`, a `Continue` or a message of unknown type
  whose originating transaction ID can be read gets an Abort with the P-Abort
  cause. A fault in the dialogue portion gets an Abort carrying an ABRT APDU,
  abort-source dialogue-service-provider. A fault in a component gets a `Reject`
  component: the components before it are delivered as a normal turn, those after
  it are discarded, and the Reject leaves with the next `Continue` or `End` of the
  dialogue. Where Q.774 calls for no response (a damaged `End` or `Abort`, an
  originating transaction ID that cannot be read) there is none, and the message
  is counted in `sigtran_tcap_discarded_total`.
- **A `Continue` for an unknown transaction ID** is answered with a P-Abort,
  cause unrecognized transaction ID, addressed to its originating transaction ID
  (Q.774 Table 7). An `End` or an `Abort` for one is discarded.
- **Aborts are well-formed and say what they are.** The dialogue ceiling is a
  P-Abort, cause resource limitation. Everything the node aborts on behalf of the
  dialogue's user (no handler for the operation, a handler that answers nothing to
  a `Begin`, a class 1 invoke that got no reply, an idle dialogue, `dlg.abort()`)
  is a U-Abort: with an ABRT APDU, abort-source dialogue-service-user, when the
  dialogue was opened with an application context, and with no reason otherwise.
  An AARQ that does not list version 1 of the dialogue portion is refused with the
  AARE of Q.774 3.2.3.
- **A reply without a result parameter is a `ReturnResult` with no result
  sequence.**
- **Nothing on the send path fails silently.** A message the encoder refuses is
  logged at error level with the dialogue's transaction ids, counted in
  `sigtran_tcap_send_errors_total`, and returned to the caller (`Dialogue::send` /
  `end` / `abort` and `DialogueEngine::begin` return a `Result`). When it leaves a
  `Begin` unanswered the dialogue is aborted, so the peer is told.
- **A `Reject` from the peer reaches the handler as a Reject**: the invoke id,
  which may be absent, and the typed problem. It used to arrive as an error with
  code -1.
- **Invoke timers follow the operation class** (Q.774 3.2.1.1.3). The expiry of a
  timer is reported to the handler and is never an abort by the engine: for a
  class 1 operation it is an abnormal situation the handler decides on (the
  default aborts), for class 2 and 3 it is the normal outcome, class 4 just
  returns to idle. Every invoke used to be treated as class 1 and its timer
  aborted the dialogue, so an SCP that armed a detection point lost its dialogue
  after 15 seconds.
- **A handler that says nothing on a follow-up turn keeps the dialogue open.** It
  used to be aborted. (Saying nothing to a `Begin` still aborts it.)
- **The idle timeout is per dialogue** (`Dialogue::set_idle_timeout`,
  `dlg.set_idle_timeout(seconds)`), and `tcap.dialogue_timer_ms: 0` disables the
  default.
- **The handler is told when a dialogue ends, once, and why**
  (`TerminationHandler::on_closed`): a peer abort (P-Abort with its cause, or the
  kind of U-Abort), a damaged message, a timer. A peer abort or a timer used to
  remove the dialogue without a word, leaving whatever the handler had tied to it.
- **Every component of a `Begin` reaches the handler** (`IncomingOp::further`,
  `arg.further`). Only the first Invoke used to be looked at.
- **A result or an error that fits no operation in progress is rejected** (Q.774
  Table 5): an invoke id that names none of our invokes, a result for a class 2 or
  4 operation, an error for a class 3 or 4 operation, a linked id that is not an
  active invoke. They used to be delivered as if valid.
- **Nothing is sent after the peer's `End`.** A handler that staged components on
  the turn that carried the `End` had them sent to a transaction that no longer
  existed.
- **A MAP argument that does not decode is a mistyped parameter, not a missing
  field.** On `gsm_map` 2 every MAP decode goes through its strict decoder. The
  forward-SM getters (`arg.sm_rp_oa` / `sm_rp_da` / `sm_rp_ui`) returned `None`
  for an argument with a member that could not be read; they raise
  `siphon.MistypedParameter`, and a handler that lets it propagate has the Invoke
  rejected (Reject, invokeProblem mistypedParameter) in an End. The opposite
  defect is gone too: an argument carrying a member of a later release after an
  extension marker used to fail as a whole, and is now read (TS 29.002 17.1.4).
- **An IMSI rule is not skipped because the IMSI could not be read.** The content
  layer took a failed decode of the operation argument for "no IMSI", so the rule
  did not match and the message went on to the next rule or to GTT. The IMSI is
  now unknown rather than absent, the rule cannot be evaluated, and the message is
  dropped (`Action::Unevaluable`, counted as a hit of that rule with
  `action="unevaluable"`). `gsm_map` models the version 3 arguments only: the
  version 1 and 2 forms of cancelLocation, purgeMS and sendAuthenticationInfo do
  not decode, so an IMSI rule on those operations now drops them where it used to
  miss them.
- **The INAP application context was a module identifier.**
  `inap.AC.ssp_to_scp` was `0.4.0.1.1.0.3.0`, the object identifier of the ASN.1
  module `Core-INAP-CS1-Codes`. A dialogue the node opened with it named no
  application context an SSF knows. It is `0.4.0.1.1.1.0.0` (cs1-ssp-to-scp, ETS
  300 374-1 clause 6.5) on `inap` 2. Terminated dialogues were not affected:
  handlers are found by subsystem and operation, and the answer carries the
  context the peer proposed.
- **INAP encodings that a conforming SSF rejects are gone.** A leg in
  RequestReportBCSMEvent went out as a primitive `[2]` (`82 01 02`) where `legID`
  is an explicit tag around a CHOICE (`A2 03 80 01 02`); `informationToSend` and
  `collectedInfo` went out as opaque octets behind a primitive tag where both are
  constructed choices. See the `inap` 2.0.0 changelog for the full list.
- **An INAP InitialDP that does not decode is a mistyped parameter.** The
  `inap_service_key` / `inap_called_party_number` / `inap_calling_party_number`
  getters returned `None`; they raise `siphon.MistypedParameter`, answered with a
  Reject as for MAP. An InitialDP carrying the members a real SSF sends
  (`bearerCapability`, `extensions`, `redirectionInformation`, …) used to be
  refused as a whole, and decodes.
- **CAP encodings that a conforming gsmSSF rejects are gone**, on `gsm_cap` 2.
  `partyToCharge` in ApplyCharging went out as a primitive `[2]` where it is an
  explicit tag around `sendingSideID` (`A2 03 80 01 01`); a leg could not be
  given in RequestReportBCSMEvent at all, though a disconnect event needs one;
  Connect had its optional members on the wrong tags. See the `gsm_cap` 2.0.0
  changelog for the full list, which also covers what this crate decodes: an
  InitialDP as real equipment sends it (`bearerCapability`, `subscriberState`,
  `locationInformation` with a cell id, …) used to be refused as a whole.
- **ApplyCharging is encoded for the CAMEL phase of its dialogue.** The charging
  characteristics of phase 3 and phase 4 are different octets. The typed
  `gsm_cap.apply_charging(...)` is encoded when it is staged on a dialogue, from
  the dialogue's application context, and is not sent at all (nor is the rest of
  that turn's answer) when the context is neither.
- **A CAP InitialDP that does not decode is a mistyped parameter.**
  `arg.called_party_number` returned `None`; it raises `siphon.MistypedParameter`,
  answered with a Reject as for MAP and INAP.
- **A turn whose answer cannot be staged in full is not sent in part.** When one
  of the commands a Python handler staged fails, the ones staged before it in the
  same flush are dropped with it.
- **The MAP results and arguments the builders stage have the encodings `gsm_map`
  2 corrected.** `send_authentication_info_res` now carries the `[3]` tag of
  `SendAuthenticationInfoRes`; it went out as a bare SEQUENCE, which is the
  version 2 type. See the `gsm_map` 2.0.0 changelog for the full list.
- **Content rules no longer evaluate a message they could not read in full.** A
  `Begin` or `Continue` that does not decode completely is dropped in a domain
  with content rules and counted in `sigtran_content_unscreened_total`. Before, a
  message with a malformed last component was matched on its other components,
  and one that failed to decode outright was routed on unseen. Segments of a
  segmented XUDT / LUDT are still not evaluated (the node does not reassemble in
  transit); they are now counted, in the same family.

### Changed

- `tcap` 2 (was 1), `gsm_map` 2 (was 1.1), `inap` 2 (was 1.1), `gsm_cap` 2 (was
  1.2). `gsm_map` 2.0.0 still depends on `tcap` 1 and `gsm_cap` 2.0.0 on `inap`
  1, so the graph holds two versions of each until those are released against
  the new majors; no type of one version crosses to the other in this crate.
- `content::MapView` has `imsi_unreadable`; `content::Action` has `Unevaluable`.
- A Python handler that raises has what it staged before the exception discarded
  (an `async def` handler used to have it sent).
- `dialogue::Dialogue`: `invoke` returns `Result<InvokeId, DialogueError>`;
  `send`, `end` and `abort` return `Result<(), DialogueError>`; `abort` takes no
  argument (a handler aborts as the TC-user and cannot claim to be the provider);
  invoke ids are `i8` (`InvokeIdType ::= INTEGER (-128..127)`), allocated in a ring
  over 0..=127 that skips ids still in progress.
- `dialogue::PeerComponent` is `#[non_exhaustive]` and has `Reject` and
  `LocalReject`; its invoke ids are `i8`. `dialogue::IncomingOp` has `further` and
  an `i8` invoke id.
- `DialogueEngine::begin` returns `Result<(Tid, Vec<Msu>), DialogueError>`.
- `DialogueEngine::sweep` returns whatever the handlers flushed on a timer, not
  only aborts.
- `routing::Inbound` has `content_undecodable`.
- `sigtran_abort_total{source}` keeps its three values with a corrected meaning:
  `user` is a U-Abort from the peer's TC-user, `provider` a P-Abort or an ABRT /
  refusing AARE from the peer's TCAP, `local` an abort this node sent. A received
  Abort used to count as `provider` whatever it was.
- `sigtran_invoke_timeouts_total` counts class 1 expiries only.

### Added

- `dialogue::TerminationHandler::on_invoke_timeout` and `on_closed`;
  `OperationClass`, `InvokeTimeout`, `DialogueClosed`, `CloseReason`, `PeerAbort`,
  `UserAbort`, `DialogueError`; `Dialogue::invoke_with`, `reject`,
  `set_idle_timeout`, `idle_timeout`, `outstanding_invokes`.
- `content::screen` and `content::Screening`.
- `dialogue::PeerComponent::mistyped_parameter` and
  `IncomingOp::mistyped_parameter`: the invoke id and problem to `reject` a
  component with when its parameter does not decode.
- `dialogue::Dialogue::discard_staged`; `dialogue::DialogueError::Argument`.
- Python: `arg.service_key` and `arg.called_party_bcd_number` for a CAP
  InitialDP; `gsm_cap.AC.gsm_ssf_scf_phase4`; a leg in
  `gsm_cap.request_report_bcsm_event` events; the CAP event types 8, 16, 19, 27
  and 50 to 53; `original_called_party_id=` on `gsm_cap.connect`.
- Python: `siphon.MistypedParameter`; `inap.AC.assist_handoff_ssp_to_scp` and
  `inap.AC.ip_to_scp`; a leg in `inap.request_report_bcsm_event` events; INAP
  event types 1, 8 and 16.
- Metrics: `sigtran_tcap_abort_total{dir,kind,cause}` (`kind` is `p-abort` or
  `u-abort`; `cause` is a closed set, a P-Abort cause value Q.773 does not name
  counts as `other`), `sigtran_tcap_reject_total{dir,problem}`,
  `sigtran_tcap_discarded_total{reason}`, `sigtran_tcap_send_errors_total`,
  `sigtran_content_unscreened_total{reason,action}`.
- Tests: the abnormal procedures of Q.774 case by case (`tests/abnormal.rs`), with
  the damaged messages assembled by hand from Q.773 and every message the engine
  emits in response dissected by Wireshark, asserting on the fields it reads.

### What a script has to change

- **A Reject is no longer an error.** `turn.is_error` is false and
  `turn.error_code` is `None` for a `Reject`; test `turn.is_reject` and read
  `turn.reject_invoke_id`, `turn.reject_problem_class`, `turn.reject_problem_code`.
  A handler that aborted on `is_error` and should also give up on a rejected
  invoke needs `if turn.is_error or turn.is_reject`.
- **The handler is called for two things that are not messages.** A `PeerTurn`
  with `is_timeout` reports an invocation timer; one with `closed` set reports
  that the dialogue ended without the script ending it. Both have no components,
  so a handler that only tests `is_result` / `is_invoke` / `is_error` ignores them
  correctly. Use `closed` (and `is_end`) to release what the script tied to the
  dialogue.
- **`arg.sm_rp_oa` / `sm_rp_da` / `sm_rp_ui` raise `siphon.MistypedParameter`**
  for an argument that does not decode, and are `None` for any operation other
  than MO-ForwardSM (46) and MT-ForwardSM (44). A handler that tested them for
  `None` to detect a bad argument has to catch the exception, or let it propagate
  to have the Invoke rejected.
- **`gsm_cap.apply_charging` takes the charging as typed keywords**
  (`max_call_period_duration=` in units of 100 ms, `release_if_duration_exceeded=`,
  `tone=`, `tariff_switch_interval=`), and `party_to_charge=` is the leg number,
  not octets. `charging_characteristics=` still takes an already encoded value,
  which now has to be a CAMEL-AChBillingChargingCharacteristics value of the
  right phase for the gsmSSF to read it.
- **`gsm_cap.connect` takes exactly one destination**, as TS 29.078 has it.
- **`arg.called_party_number` raises `siphon.MistypedParameter`** for an InitialDP
  that does not decode, and is `None` for a mobile-originated call, which carries
  what was dialled in `arg.called_party_bcd_number`.
- **`inap.play_announcement` and `inap.prompt_and_collect_user_information` take
  typed arguments.** `information_to_send=` used to be opaque octets put on the
  wire as given; it is now the BER of an `InformationToSend` value and is refused
  if it is not one, and `message_id=` / `tone_id=` build the common cases.
  `collected_info=` likewise, with `maximum_digits=` for the common case.
- **`inap.AC.ssp_to_scp` has another value** (`0.4.0.1.1.1.0.0`). A script that
  compared an application context with the old arcs has to compare with the new.
- **The `inap_*` getters raise `siphon.MistypedParameter`** for an InitialDP that
  does not decode, and are `None` for any operation other than initialDP.
- **Saying nothing on a follow-up turn no longer aborts.** A handler that relied
  on that to get rid of a dialogue has to call `dlg.abort()` or `dlg.end()`.
- **Set an idle timeout on a dialogue that waits** (`dlg.set_idle_timeout(...)`):
  with its invoke timers no longer aborting it, a call-control dialogue now lives
  until `tcap.dialogue_timer_ms` of silence, 30 seconds by default.
- **`dlg.reply_to` and `dlg.error` raise `SigtranError`** for an invoke id outside
  -128..127 instead of putting it on the wire.
- **Nothing staged after the peer's `End` is sent.** `dlg.send()` / `dlg.end()` on
  a turn with `is_end` is logged as an error; drop the call.
- **`await gsm_map.begin(...)` raises `SigtranError`** saying why when the dialogue
  ends before an answer (a peer abort with its kind and cause, a timeout, a `Begin`
  that could not be encoded) instead of the one "closed with no response".
- New: `dlg.reject(invoke_id, problem_class, problem_code)`, `dlg.invoke(...,
  operation_class=, timeout=)`, `arg.further`, `turn.components`, the `Component`
  view, `node.sweep`, `node.assemble_tcap`, and `rejects` / `abort_kind` /
  `p_abort_cause` / `abort_source` / `result_invoke_id` on `node.decode(...)`.

## [1.0.0] — 2026-07-21

Initial release. A SIGTRAN/SS7 runtime that turns a declarative `sigtran.yaml`
into a running signalling node, plus a siphon addon for scripting it in Python.

### Transport

- **SCTP over M3UA (RFC 4666), M2PA (RFC 4165), and SUA (RFC 3868)**, on real
  kernel SCTP. M3UA runs the ASPSM/ASPTM handshake (ASP-UP, ASP-ACTIVE honouring
  the AS traffic mode of load-share / override / broadcast, ASP-INACTIVE/DOWN,
  BEAT); M2PA aligns links; SUA carries connectionless SCCP-user traffic
  (CLDT/CLDR) bridged one-for-one to SCCP so any-to-any interworking
  (SUA ↔ M3UA ↔ M2PA) falls out of the egress framing. SSNM (DUNA/DAVA → route
  state, DAUD answered from live state) folds into the router.

### Routing

- **MTP3 routing**: implicit adjacent routes, explicit routes by priority,
  availability from Pause/Resume/Status and linkset up/down, with failover.
- **SCCP GTT**: ordered prefix + gti/tt/np/nai matching, cost and weighted-share
  groups, local termination, and the E.214 → E.164 pre-step from a PLMN map.
- **Content routing** on the decoded MAP/CAP layer (operation, calling/called GT,
  IMSI/MSISDN), first-match, evaluated on the live wire: **route**, **rewrite the
  called-party GT**, or **screen**. The decode runs only for a tenant that has
  content rules, so a pure-transit node adds no per-message cost.
- **Loop guards** (own-OPC, route-reflect, SCCP hop-counter) and **SCCP
  return-on-error** (UDTS/XUDTS/LUDTS) on undeliverable connectionless messages.
- Optional **ISUP-aware screening** on the SI=5 transit path (block/allow rules
  on message type + called/calling prefix), counted under
  `sigtran_isup_screened_total`.

### Dialogue termination

- A synchronous **TCAP transaction engine** (Begin/Continue/End + AARQ/AARE):
  single request/response, held-open multi-leg (updateLocation with an
  insertSubscriberData leg), invoke and dialogue timers, a dialogue ceiling, and
  aborts. The TCAP + SCCP bytes are wire-real, built with the published codecs.

### The siphon addon (feature = "python")

- Two startup seams a composing siphon binary calls: `configure_from(cfg)` builds
  the node from its `extensions.sigtran` config, and `register(py, parent)` mounts
  the `ss7` / `gsm_map` / `gsm_cap` / `inap` namespaces.
- **Live table programming** from Python (`ss7.routes` / `ss7.gtt` / `ss7.content`),
  so routing is shaped from a script at load time while every per-message decision
  stays in Rust.
- **MAP/CAP/INAP termination** via one decorator per namespace,
  `@ns.on_operation("<name>")` (pipe-separated for several, bare for a catch-all),
  covering a full HLR, a terminating SMSC front end, and a CAMEL/INAP SCP; with the
  MAP result and invoke builders and the CAP/INAP invoke builders, driving a
  `Dialogue` handle that observes a decoded `PeerTurn` on held-open follow-up legs.
- An in-process test seam (`siphon.configure` → a `Node` that assembles genuine
  inbound MSUs and drives them through the dialogue engine off the wire).

### Observability

- The full Prometheus metric family (association / ASP / linkset state, route
  availability, MSU rate, GTT / content / MTP3-management counters, active
  dialogues, dialogue / invoke timeouts, aborts, loop guards, ISUP screening) with
  a text renderer.

### Not in this release (planned)

- **Per-message Python routing overrides** — dispatching a routing decision into a
  script hook on the live wire. Route from Python by programming the tables live
  instead; static content-rule actions (route / rewrite / screen) run in Rust.
- **Dialogue origination** — opening a dialogue the node initiates (an SMSC's MT
  delivery, an SMS-GMSC) and correlating the peer's response over SCTP. Termination
  of inbound dialogues is fully supported.

[1.0.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v1.0.0
