# Using it in a SIPhon build

siphon-sigtran is a **library**, not a standalone server. The runnable artifact
is a [SIPhon](https://siphon-sip.org/) binary that has the addon registered.
This page explains how the addon is consumed; the details of composing
extensions into a binary live in the
**[SIPhon documentation](https://siphon-sip.org/)**.

## A register-only addon

siphon-sigtran is **not a Python package**. There is no wheel and no PyPI
release. It is a Rust crate a composing siphon binary depends on and calls once
at startup. That one call mounts the namespaces:

```rust
// once, with the siphon package module as `parent`
siphon_sigtran::python::register(py, parent)?;
```

`register` mounts the `ss7` / `gsm_map` / `gsm_cap` namespace singletons, the
`configure` and `metrics` functions, the `SigtranError` exception, and the
shared types onto the `siphon` module, so a hot-reloaded script reaches them
with:

```python
from siphon import ss7, gsm_map, gsm_cap
```

This is the same shape as the sibling addons `siphon-smpp` and `siphon-http`:
built and tested against siphon-sip, consumed by git from a composing binary,
not published to crates.io as a runnable thing.

## The `python` feature

The addon face is behind the `python` feature. The **default** crate build
pulls neither pyo3 nor siphon-sip, so a pure-Rust consumer of the routing brain
(`cargo add siphon-sigtran`) stays lean; it gets `Config`, `Router`, the
transport and the dialogue engine with no Python at all.

```toml
# in the composing binary's Cargo.toml
siphon-sigtran = { git = "https://github.com/siphon-project/siphon-sigtran", features = ["python"] }
```

- **Feature on**: the crate links siphon-sip + pyo3 and compiles the `python`
  module, and the composing binary can `register` it.
- **Feature off**: only the pure-Rust surface compiles. This is the mode for
  embedding the router in a non-siphon Rust program.

## Version pinning

Enabling `python` links siphon-sip and pyo3. Both link the `python` native
library, and Cargo allows only one version of a `links` crate per dependency
graph, so:

- siphon-sigtran pins **pyo3 0.29**, tracking siphon-sip's pyo3 major. When
  siphon-sip bumps pyo3, siphon-sigtran bumps in lockstep.
- The `siphon-sip` git URL must be **byte-identical** across every crate that
  depends on it in one build graph, or Cargo resolves two separate copies (a
  `links` conflict). The manifest tracks `branch = "main"`; the composing
  binary's `Cargo.lock` pins the concrete commit.

A mismatch surfaces as a build error, not a runtime surprise.

## Putting it together

```
your composing SIPhon binary  (cargo build --features python)
        │  register(py, parent) at startup
        ├── ss7 / gsm_map / gsm_cap namespaces  ──▶  from siphon import ...
        └── SS7 runtime (associations, routing, dialogue engine)
                                        ▲
   sigtran.yaml  ──siphon.configure(...)──▶  the node the namespaces program
```

- **Build**: this page + the SIPhon extension docs.
- **Configure**: [Configuration](configuration.md).
- **Write handlers**: [Script API](script-api.md), [Cookbook](cookbook/index.md).
- **Deploy**: [Deployment](deployment.md),
  [Kubernetes & scaling](kubernetes.md).

## Using it as a plain Rust crate

Without the `python` feature, siphon-sigtran is an ordinary Rust dependency. The
[API docs on docs.rs](https://docs.rs/siphon-sigtran) cover `Config`, `Router`,
`TransportHandle`, and `DialogueEngine`, so you can embed the routing brain or
the dialogue engine directly. See [the Rust quickstart](quickstart.md#the-rust-quickstart).
