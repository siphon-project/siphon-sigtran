# Deployment

!!! warning "A library, not a runnable product"
    siphon-sigtran is a Rust **library** that plugs the `ss7` / `gsm_map` /
    `gsm_cap` namespaces and an SS7 runtime into a
    [SIPhon](https://siphon-sip.org/) binary **you** build and compose. There is
    no siphon-sigtran server to run on its own. Everything here is parameterised
    on *your* image and *your* binary crate; see
    [Using it in a SIPhon build](integration.md).

## What ships in the image

A signalling node built on siphon-sigtran needs, in the runtime image:

- **Your composing siphon binary** (the one that calls `register` at startup).
- **libpython** for the embedded interpreter pyo3 runs, present in the runtime
  image.
- **Your script** (`ss7.py` or whatever you name it) mounted at runtime so
  handlers [hot-reload](concepts.md#hot-reload) without a rebuild.
- **Your `sigtran.yaml`** mounted alongside it.
- **Kernel SCTP.** The node speaks SCTP; the host/container needs the `sctp`
  module loaded (`modprobe sctp`) and the SCTP ports reachable.

## The runtime split

```
                    ┌──────── your signalling node (a SIPhon binary) ────────┐
   peers  ──SCTP──▶ │  siphon-sigtran runtime (Rust):                        │ ──SCTP──▶ peers
                    │    • associations (M3UA / M2PA over kernel SCTP)       │
                    │    • MTP3 routing + SCCP GTT + content routing         │
                    │    • TCAP dialogue engine                             │
                    │    • dispatch ──▶ your script (Python)                 │
                    └────────────────────────────────────────────────────────┘
                              your script owns:
                        overrides · deferred dips · MAP/CAP termination
```

## Signalling addressing

SS7 is addressed by point code and global title, not by the pod's IP. Two
consequences for any deployment:

- **The node's point code is config**, not a runtime discovery. Peers are
  provisioned to reach you at that PC; keep it stable across restarts.
- **Outbound associations originate from a specific, provisioned IP.** A peer
  that you connect to has your source IP and PC provisioned, so the node's
  signalling IPs must be stable and cannot be NATed behind a shared egress
  (SNAT also breaks SCTP multihoming). This shapes the Kubernetes model; see
  [Kubernetes & scaling](kubernetes.md#the-signalling-plane).

## Wiring config

Two ways, combinable, both covered in [Configuration](configuration.md):

1. **File**: `sigtran.yaml`, passed to
   [`siphon.configure(...)`](script-api.md#configure) as a path.
2. **Inline / dict**: build the config in the script (a dict or an inline YAML
   string) and pass it to `configure`, for a node whose topology is computed at
   startup.

The associations, routes, GTT, and content rules all reload with the script, so
editing the config and letting SIPhon reload takes effect without a restart.

## Graceful shutdown

On rollout or scale-down the orchestrator sends `SIGTERM`. The node should stop
accepting new associations, let in-flight dialogues finish or age out on their
[TCAP timers](configuration.md#tcap), and exit. Give it room to drain before
`SIGKILL` (a `preStop` delay plus `terminationGracePeriodSeconds` in
[Kubernetes](kubernetes.md#graceful-shutdown)).

## Next

- **Run it HA**: [Kubernetes & scaling](kubernetes.md), the failover model for
  a stateful signalling protocol.
- **Understand the throughput story**: [Performance](performance.md).
