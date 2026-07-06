# Concepts & architecture

siphon-sigtran is a **library** that adds an SS7 runtime and the `ss7` /
`gsm_map` / `gsm_cap` namespaces to a [SIPhon](https://siphon-sip.org/) binary.
This page explains the model you program against: the stack, the routing cost
ladder, where Rust ends and Python begins, and how a message travels through
the node.

## The stack, and where each crate sits

The node is a composition. Every codec layer is a published crate; the runtime
glue on top is what this crate adds.

| Layer | Published crate | What siphon-sigtran adds |
|---|---|---|
| Point codes + the MTP3-user SAP | `mtp3` | the route resolver: DPC to AS/linkset by priority + availability |
| M3UA (RFC 4666) / M2PA (RFC 4165) | `m3ua`, `m2pa` | the transport serving loop, ASPSM/ASPTM handshake, link alignment, linkset state |
| SCTP (RFC 4960) | `async-sctp` | association binding + demultiplexing |
| SCCP addresses / GTT / UDT (ITU-T Q.714) | `sccp` | the GTT rule engine + the E.214/E.164 converter |
| TCAP (ITU-T Q.771 to Q.775) | `tcap` | the dialogue engine: transactions, timers, termination handlers |
| MAP (TS 29.002) / CAMEL (TS 29.078) | `gsm_map`, `gsm_cap` | the decoded view content routing matches on, and the operation surface scripts terminate |

On top of all of that sits **content routing**: an ordered, first-match rule
set that routes, rewrites, screens or defers on the decoded application layer.

## The path of one inbound message

1. **SCTP + adaptation.** The MSU arrives on an association. M3UA DATA is
   unwrapped; M2PA carries MTP3 directly.
2. **MTP3 transfer.** If the destination point code is not one of the node's
   own, the message transits: the route resolver picks the best available
   route (implicit adjacent route, then explicit routes by priority) and the
   MSU leaves. No SCCP decode, no Python. This works for **any** Service
   Indicator; a non-SCCP MSU transits by DPC alone.
3. **Content routing.** For a message addressed to us that carries SCCP + TCAP,
   the decoded MAP/CAP view is evaluated against the content rules first,
   because they decide on the richest layer. A rule can route, rewrite the
   called-party GT, screen, or defer to a named Python hook.
4. **SCCP GTT.** Otherwise the called-party global title is translated (after
   an E.214 to E.164 pre-step) to a concrete `(dpc, ssn)`, a group member, or
   local termination.
5. **Termination.** A message for a subsystem the node owns is handed to the
   TCAP dialogue engine, which dispatches the decoded MAP/CAP operation to the
   handler your script registered.

Steps 2 through 4 are synchronous Rust with no I/O. That is the line-rate
guarantee: routing a transit MSU costs tens of nanoseconds
([Performance](performance.md)), and nothing about a busy interpreter can slow
it down.

## The cost ladder

Route a message at the cheapest layer that can answer. The ladder, top to
bottom, in rising cost:

| Decision | Layer | Cost |
|---|---|---|
| destination point code | MTP3 route table | ~28 ns, no SCCP decode |
| GT prefix (+ gti/tt/np/nai) | SCCP GTT | ~40 ns |
| subscriber's home network | E.214 conversion + GT prefix | still SCCP; the MCC+MNC is right there in the mobile global title |
| full IMSI, operation, GT-table membership | content routing | ~50 ns, needs the MAP/CAP decode |
| anything the tables can't answer | a Python hook | microseconds and up: yours |

Two consequences worth internalising:

- **PLMN-level steering is an SCCP problem, not a content problem.** A roaming
  subscriber's MCC+MNC is the leading digits of the E.214 called party, so
  "everything for network X goes to Y" is a GTT prefix rule. Save content
  rules for decisions that genuinely need the decoded IMSI or operation.
- **A hook is a scalpel.** A deferred rule (`action: {python: ...}`) puts
  Python on the hot path *for the messages that rule matches* and nothing
  else. The general override `@ss7.on_route(when=...)` is gated by its
  selector for the same reason. Drop the selector and every routing decision
  waits on your coroutine; fine for a low-volume HLR, ruinous for a transit
  STP.

Hooks that dip an external database should write the answer back with
`ss7.routes.cache(...)`, so the next message for that GT routes in Rust
without re-entering Python.

## Config and script are peers

`sigtran.yaml` is the declarative default; the script is the imperative
override. Both program the same Rust tables:

- **Config** carries the static bulk: the transport plane, the route table,
  GTT, conversion, the standing content rules.
- **The script** programs tables live (`ss7.routes.add`, `ss7.gtt.add`,
  `ss7.content.add_rule`), answers deferred rules, and terminates dialogues.
  Live content rules are prepended, so a freshly programmed override wins
  over the static config (first match wins).

You choose per node where a decision lives. A pure STP might be all config
plus two hooks. An SMSC is mostly termination handlers with a minimal route
table.

## Termination: the dialogue engine

When routing says *local*, the TCAP engine takes over. It decodes the
transaction, matches the operation to a registered handler, and hands your
handler two things: the decoded [`IncomingOp`](script-api.md#incomingop) and a
[`Dialogue`](script-api.md#dialogue) handle. The handler stages components
(`reply`, `invoke`, `error`) and flush points (`send` to continue, `end` to
close, `abort`); the engine replays them into real TCAP and the transport
sends the result. Three shapes cover MAP and CAMEL practice:

- **single request/response**: SRI-SM in, result in a closing End;
- **held-open multi-leg**: updateLocation answered with an
  insertSubscriberData Continue, closed after the ack
  ([Building an HLR](cookbook/hlr.md));
- **originating**: the node opens the dialogue itself, an SMSC delivering
  multi-segment MT traffic ([Building an SMSC](cookbook/smsc.md)).

Invoke and dialogue timers (with a dialogue ceiling) come from the
[`tcap:` config block](configuration.md#tcap) and are enforced by the engine,
never by your script.

The engine stops at the MAP transaction layer deliberately. The SMS payload it
carries, the `sm_rp_ui` of a ForwardSM, is an opaque octet string: the SMS
transfer-layer PDU. Decoding or building that (SMS-SUBMIT / SMS-DELIVER,
GSM 7-bit packing, UDH concatenation) is a separate layer, and a separate
crate, the sibling [`tpdu`](https://crates.io/crates/tpdu). siphon-sigtran owns
the signalling; `tpdu` owns the message bytes. See
[Building an SMSC](cookbook/smsc.md).

## Hot reload

Scripts are ordinary SIPhon scripts: edit, save, and SIPhon reloads them.
Because routing state lives in Rust, a reload does not drop routes, GTT
entries or open dialogues; the script re-registers its hooks and handlers and
traffic keeps flowing. Keep module-level side effects idempotent
(`ss7.content.address_table(...).add` and friends are), and a reload
mid-traffic is safe.

## Next

- [Quickstart](quickstart.md): run a minimal node and terminate an operation.
- [Configuration](configuration.md): every `sigtran.yaml` field.
- [Routing model & coverage](routing.md): the resolution rules in detail.
- [Cookbook](cookbook/index.md): the four worked recipes.
