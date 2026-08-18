# Cookbook

Worked recipes for the nodes people actually build on siphon-sigtran. Each one
pairs a `sigtran.yaml` with a script and walks the interesting parts. They use
only the [Script API](../script-api.md), and every value is synthetic (test
PLMN 001/01, `+1-555-01xx` global titles, decimal point codes).

<div class="grid cards" markdown>

- **[Building an STP](stp.md)** is the routing recipe: config-driven transit
  routing with three Python override styles (program the tables live, defer a
  rule, take a selector-gated general hook). The node relays, never terminates.

- **[Building an HLR](hlr.md)** terminates the mobility operations:
  updateLocation with a held-open insertSubscriberData leg, an
  insertSubscriberData ack, sendAuthenticationInfo.

- **[Building an SMSC](smsc.md)** terminates MO-ForwardSM and originates MT
  delivery: SRI-SM to the HLR, then a multi-segment MT-ForwardSM held open
  across segments with moreMessagesToSend. The SMS TPDU content is decoded and
  built with the sibling `tpdu` crate.

- **[Building a CAMEL SCP](scp.md)** terminates a CAMEL initialDP and answers
  with a Connect in the closing dialogue: the smallest useful service-control
  node.

</div>

## The example scripts in the repo

Each recipe is based on a runnable script under
[`examples/`](https://github.com/siphon-project/siphon-sigtran/tree/main/examples):

| Script | Recipe |
|---|---|
| [`stp.py`](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/stp.py) | [Building an STP](stp.md) |
| [`smsc.py`](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/smsc.py) | [Building an SMSC](smsc.md) |
| [`scp.py`](https://github.com/siphon-project/siphon-sigtran/blob/main/examples/scp.py) | [Building a CAMEL SCP](scp.md) |

## Patterns you'll reuse

These show up across the recipes:

- **Program tables at load, not per message.** `ss7.routes.add`,
  `ss7.gtt.add`, `ss7.content.add_rule` and `ss7.content.address_table(...).add`
  run when the script loads and keep the decision in Rust afterward; they cost
  nothing per MSU.
- **Cache an external answer once.** When routing needs a live source (number
  portability, per-subscriber steering), dip it and write the answer back with
  `ss7.routes.cache(...)`, so the next MSU for that GT routes in Rust.
- **Stage then flush.** A termination handler stages components on the
  [`Dialogue`](../script-api.md#dialogue) (`reply` / `invoke` / `error`) and
  flushes with `send` (continue) or `end` (close). The engine builds the wire
  TCAP; you never encode bytes.
- **Answer every request.** On the wire, always answer or abort a dialogue.
  Silently dropping a Begin is a bug; return a result, an error, or an abort.

Start with [Building an STP](stp.md).
