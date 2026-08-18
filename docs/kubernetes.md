# Kubernetes & scaling

How to run a signalling node built on siphon-sigtran with high availability on
Kubernetes, and, just as important, **what "scaling" means for SS7**. Read
[the model](#ha-first-throughput-second) before you touch `replicas`.

SS7 fits Kubernetes better than SIP does, because SS7 is itself a routing
protocol: inter-pod routing is not a hack, it is more SS7 routing. But the
identity model is strict, so the YAML in this guide is a **template** for *your*
composing siphon binary and your cluster, not a shipped runnable image; see
[Deployment](deployment.md).

## HA first, throughput second

One pod already routes millions of MSU per second ([Performance](performance.md)),
because per-message routing is Rust with no I/O. You do **not** add pods for
load. You add them for redundancy and node-failure tolerance. The realistic
shape is an active-standby pair or a small N+1, each pod with a stable identity,
all advertising one capability point code, not an autoscaled Deployment chasing
CPU.

Internalise this before scaling: for SS7, replicas buy availability, not
throughput.

## One logical node, N pods

- **Shared capability point code.** Every replica advertises the same
  capability PC, so peers see a single node at one PC. This is the mated-pair
  capability-PC idea generalised from two boxes to N pods.
- **An internal signalling domain.** Give each pod an internal PC and let the
  pods peer over M3UA among themselves. An MSU that arrives on pod A but must
  leave over a link owned by pod B is routed to B over the same engine and
  transport. Inter-pod forwarding is the router doing its job.
- **StatefulSet, not Deployment.** Identity matters (which pod owns which
  outbound association, which internal PC), so pods need stable ordinals and
  stable IPs across restart and reschedule.

## The signalling plane

The SS7 plane does **not** ride the cluster SDN.

- **Provisioned signalling IPs via Multus.** Each pod gets stable signalling IPs
  on the SS7 VLAN through Multus secondary interfaces (macvlan / SR-IOV), under
  a StatefulSet so identity and IPs survive reschedule. Multihoming is two
  Multus interfaces per pod. The cluster SDN carries only inbound-from-LB and
  inter-pod traffic. This is the standard telco-CNF wiring.
- **Outbound associations are pinned by config, not balanced.** You initiate an
  association and the peer has it provisioned to originate from a specific IP
  presenting a specific PC, so a random pod egressing through a node IP will not
  match, and SNAT breaks multihoming. Instead the StatefulSet ordinal owns a
  defined set of outbound associations: pod-0 owns the link to HLR-A on its
  provisioned Multus IP, pod-1 owns HLR-B, and so on. On restart the same
  ordinal with the same IP re-establishes the same links.
- **Inbound associations pin to pods too.** SCTP is stateful and long-lived; it
  cannot be round-robined. Use a headless service plus an SCTP-aware,
  association-sticky load balancer (MetalLB speaks SCTP), or land inbound
  directly on the Multus IPs.

## Affinity lives in the identifiers

A TCAP dialogue spans Begin / Continue / End, so a follow-up leg must reach the
pod holding that dialogue. Put the origin pod id in the originating transaction
id, so the Continue / End routes back deterministically, with no shared lookup
on the per-message path. Outbound-link ownership is a route attribute, not a
hot-path query. A shared store (for example Redis) is for slow-path config and
AS-state sync, never the per-message path.

Bake the seam in early: the transaction id needs room for a pod discriminator,
routes carry an owning-pod attribute, and the transport needs the internal-peer
mode. It all collapses to a no-op for a single-pod deploy, so one box stays
simple.

## Two topologies

| Topology | How | When |
|---|---|---|
| **Active/standby** | one active binder + a fast-reschedule standby (StatefulSet + PDB + spread), sharing the capability PC | Peers provision a single origin, or you want the simplest correct HA. |
| **Active/active N+1** | N pods, each owning a slice of the outbound associations, internal M3UA mesh, shared capability PC | Peers provision your set of pod IPs (or a mated pair); you need to survive a node loss with zero rebind on the survivors. |

Both are for redundancy. Neither is a throughput play.

## Rolling updates and disruption

- **`maxUnavailable: 0`** on the rolling update so you never dip below desired
  capacity mid-roll.
- **A PodDisruptionBudget** (`minAvailable: 1`, or N-1 for an N+1) so voluntary
  drains never remove the last binder.
- **`topologySpreadConstraints`** across nodes so one node loss cannot take the
  whole node down.
- **Readiness** gated on the signalling ports accepting associations, so the LB
  only steers to a replica that can actually bind a peer.

## Graceful shutdown

On rollout / scale-down Kubernetes sends `SIGTERM`. The pod should stop
accepting new associations, let in-flight dialogues finish or age out on their
[TCAP timers](configuration.md#tcap), and exit. Give it room: a `preStop` delay
so the LB stops sending new associations first, plus
`terminationGracePeriodSeconds` before `SIGKILL`. Tune the grace period to your
drain time.

## Checklist before scaling out

- [ ] Each pod has stable, provisioned **signalling IPs** (Multus), not a shared
      egress.
- [ ] Outbound associations are **pinned by StatefulSet ordinal**, and peers are
      provisioned for that set of IPs / the mated pair.
- [ ] The originating transaction id carries a **pod discriminator** so
      follow-up legs route home.
- [ ] Inbound SCTP is **association-sticky** at the LB (or lands on Multus IPs).
- [ ] The shared store is **slow-path only**, never on the per-message path.
- [ ] You are scaling for **redundancy**, having confirmed one pod already
      carries the load.
