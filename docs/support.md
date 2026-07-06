# Commercial support

siphon-sigtran is MIT-licensed and free to run in production. No open-core
holdbacks, no paid tier of the SS7 engine: the routing brain, the transport,
and the dialogue engine are all in the open-source crate. If you would rather
not carry the integration and operations alone, commercial support is available
from the addon's maintainers.

## What support can cover

- **Node design & deployment**: sizing and topology for an STP, HLR, SMSC or
  CAMEL SCP, from a single node to an HA pair or N+1. See
  [Deployment](deployment.md) and [Kubernetes & scaling](kubernetes.md) for the
  shape it builds on.
- **Interconnect integration**: getting associations, routing, GTT, E.214
  conversion and screening working reliably against real peers and their quirks.
- **Custom scripting & feature development**: Python handlers and routing logic
  built to your call and message flows (portability dips, per-subscriber
  steering, termination logic), upstreamed into the project where it fits.
- **Performance tuning**: profiling and capacity planning against your real
  traffic mix, including free-threaded CPython builds. See
  [Performance](performance.md).
- **SLA-backed support**: production response commitments.

## Sponsor the project

Want a particular feature built or fast-tracked? Feature sponsorship funds work
that lands in the open-source project, so your use case ships sooner and
everyone downstream benefits. Use the **Sponsor** button on the
[GitHub repository](https://github.com/siphon-project/siphon-sigtran), or reach
out through [SIPhon](https://siphon-sip.org/) to scope it.

siphon-sigtran is an addon for [SIPhon](https://siphon-sip.org/); it is built on
the published SS7 codec crates (`mtp3`, `m3ua`, `m2pa`, `sccp`, `tcap`,
`gsm_map`, `gsm_cap`, `async-sctp`) and the SMS transfer-layer codec
[`tpdu`](https://crates.io/crates/tpdu).
