# Performance

The design premise: a routing decision is Rust, synchronous, allocation-light,
and touches no I/O. That is what lets a node hold line rate. This page has the
numbers, how to reproduce them, and how to read them.

!!! note "Reproduce your own"
    The numbers below are illustrative: a single core, a developer machine, a
    synthetic single-domain node. They show *shape*, not a spec sheet. Every
    tool is in the repo; run `cargo bench` on your hardware.

## The routing brain (`cargo bench`)

[`benches/routing.rs`](https://github.com/siphon-project/siphon-sigtran/blob/main/benches/routing.rs)
measures the per-decision Rust work. Indicative single-core numbers:

| Operation | Time |
|---|---|
| config load (parse + validate) | ~28 µs |
| MTP3 route resolve (with a failover alternate) | ~28 ns |
| SCCP GTT lookup | ~40 ns |
| content-rule match | ~50 ns |

A full config reload is microseconds; a per-message routing decision is tens of
nanoseconds. Nothing on that path allocates per message or waits on a lock held
by I/O.

```bash
cargo bench                                 # criterion benches
cargo run --release --example leak_check    # counting-allocator leak gate -> PASS
```

The [leak gate](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/leak_check.rs)
hammers the routing paths and asserts live bytes stay flat. It runs in CI.

## Where the cost actually is

Three layers, in rising cost, and where each runs:

| Layer | Cost | Runs in |
|---|---|---|
| MTP3 transit (route by DPC) | ~28 ns | Rust |
| SCCP GTT / E.214 conversion | ~40 ns | Rust |
| content-rule match on the decoded view | ~50 ns | Rust |

Every per-message routing decision is pure Rust. A script shapes routing from
Python at load time by programming the tables (`ss7.routes` / `ss7.gtt` /
`ss7.content`), so no coroutine sits on the per-message path.

## Keeping Python off the hot path

Program the routing tables once, at script load, and let the decision run in
Rust:

- Add routes, GTT rules, and content rules live with `ss7.routes.add` /
  `ss7.gtt.add` / `ss7.content.add_rule`; they prepend over the static config.
- When an answer comes from an external source, dip it once and write it back
  with `ss7.routes.cache(...)`, so later messages for that GT route in Rust.

Termination handlers (`@gsm_map.on_operation`) do run per dialogue, but they fire
only for messages addressed to a subsystem the node owns, not on the transit path.

The metric families make this visible: watch `sigtran_content_rule_hits_total`
by rule and action. If a `python`-action rule's hit rate tracks your MSU rate,
that hook is on the hot path, and it belongs in config or a live table instead.

## The interpreter and free-threaded CPython

The routing decisions are Rust and scale with cores regardless of the
interpreter. Where the interpreter matters is termination and hooks: a
per-message Python handler on a standard (GIL) CPython build serialises to
roughly one core. A composing siphon binary built against **free-threaded
CPython** (3.13t / 3.14t) runs those handler bodies across cores. This whole
stack targets it. For a node that is mostly transit routing, the interpreter
barely enters the picture; for a termination-heavy node (an SMSC, an SCP under
load), it is the throughput unlock, the same story as the sibling addons.

## What is proven on the wire

Beyond micro-benchmarks, the transport is exercised end to end in
[`tests/wire.rs`](https://github.com/siphon-project/siphon-sigtran/blob/main/tests/wire.rs):
genuinely assembled SS7 MSUs (SRI-SM, updateLocation, MO/MT-ForwardSM,
initialDP) driven over real kernel SCTP loopback through a running node. It
asserts load-share across an AS's ASPs, failover to an M2PA linkset when an ASP
drops, Service-Indicator-agnostic transfer of a non-SCCP MSU, both loop guards,
and a MAP operation terminated in the dialogue engine with the result read back
off the wire, with a tshark gate over the forwarded frames. The dialogue engine
is driven against assembled TCAP end to end in
[`tests/dialogue.rs`](https://github.com/siphon-project/siphon-sigtran/blob/main/tests/dialogue.rs).

The wire tests need kernel SCTP (`sudo modprobe sctp`); they print a SKIP and
pass if it is unavailable, and the tshark dissection gate skips if `tshark` is
not installed.

## Interpreting your numbers

- **Routing flat, host busy on a transit node**: you are terminating or hooking
  more than you think. Check `sigtran_content_rule_hits_total` for `python`
  actions and `sigtran_active_dialogues`.
- **A hook's hit rate tracks the MSU rate**: it is on the hot path. Move it into
  a GTT prefix or a live table, or gate it with a tighter selector.
- **Termination throughput plateaus with cores idle**: you are GIL-bound in the
  handler. Minimise handler work, `await` I/O, or move to free-threaded CPython.
