# siphon-sigtran, overview

A SIGTRAN/SS7 runtime that turns a declarative `sigtran.yaml` into a running
signalling node. It does not reimplement the SS7 codecs; it composes the
published ones and adds the parts a node needs on top of them: a config model, a
routing brain, and (in later phases) the SCTP transport and dialogue
termination.

## The stack

```
   ┌────────────────────────────────────────────────────────────────┐
   │  content routing        routes/screens on the decoded MAP/CAP    │  src/content.rs
   │                         application layer                        │
   ├────────────────────────────────────────────────────────────────┤
   │  MAP / CAP termination  dialogue SAP (phase-2)                   │  src/dialogue.rs
   │      gsm_map · gsm_cap  operation arguments (BER)                │
   ├────────────────────────────────────────────────────────────────┤
   │  TCAP                   transactions + components (Q.773)         │  tcap
   ├────────────────────────────────────────────────────────────────┤
   │  SCCP                   GTT + E.214/E.164 conversion (Q.714)      │  src/sccp/gtt.rs · sccp
   ├────────────────────────────────────────────────────────────────┤
   │  MTP3                   route resolver, DPC to linkset (Q.704)    │  src/mtp3/route.rs · mtp3
   ├────────────────────────────────────────────────────────────────┤
   │  M3UA (RFC 4666)  ·  M2PA (RFC 4165)  IP adaptation             │  src/transport (phase-2) · m3ua · m2pa
   ├────────────────────────────────────────────────────────────────┤
   │  SCTP (RFC 4960)        Linux lksctp                             │  async-sctp (phase-2)
   └────────────────────────────────────────────────────────────────┘
```

## Where each crate sits

| Layer | Published crate | What siphon-sigtran adds |
|---|---|---|
| Point codes + MTP3-user SAP | `mtp3` | the route resolver: DPC to linkset by priority + availability |
| M3UA / M2PA | `m3ua`, `m2pa` | (phase-2) the transport serving loop and linkset state |
| SCTP | `async-sctp` | (phase-2) the association binding + demux |
| SCCP addresses/GTT/UDT | `sccp` | the GTT rule engine + E.214/E.164 converter |
| TCAP | `tcap` | (phase-2) the dialogue coordinator |
| MAP / CAMEL operations | `gsm_map`, `gsm_cap` | the decoded view content routing matches on |

## The routing brain (phase 1)

Everything the node decides per message lives in Rust and runs synchronously with
no I/O. That is the throughput guarantee. The flow for an inbound message:

1. **MTP3 transfer.** If the destination point code is not one of the node's own,
   the message transits: the route resolver picks the best available linkset
   (implicit adjacent route, then explicit routes by priority), or the message is
   dropped when there is no route.
2. **Content routing.** When the MAP/CAP layer has been decoded, an ordered
   first-match rule set can route, rewrite, screen, or defer to a hook. It runs
   before GTT because it decides on the richer application layer.
3. **SCCP GTT.** Otherwise the called-party global title is translated (after an
   E.214 to E.164 pre-step) to a concrete destination, a group member, or local
   termination.

## What is deferred

The SCTP transport (`src/transport`), the dialogue-termination SAP
(`src/dialogue`), the on-the-wire loopback test harness, and the Python bindings
are later phases. Phase 1 is the config loader and the resolvers, fully tested
against genuinely-assembled SS7 traffic.
