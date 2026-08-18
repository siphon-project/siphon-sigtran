# Using it in a SIPhon build

siphon-sigtran is a **library**, not a standalone server. The runnable artifact
is a [SIPhon](https://siphon-sip.org/) binary that has the addon registered.
This page explains how the addon is consumed; the details of composing
extensions into a binary live in the
**[SIPhon documentation](https://siphon-sip.org/)**.

## A register-only addon

siphon-sigtran is **not a Python package**. There is no wheel and no PyPI
release. It is a siphon addon a composing binary depends on and calls at startup,
with two seams: it reads its `extensions.sigtran` config and calls `configure_from`
to build the node, and it calls `register` to mount the namespaces.

```rust
// at startup: build the node from the addon config, then mount the namespaces
let cfg = /* the parsed extensions.sigtran config */;
siphon_sigtran::python::configure_from(&cfg);
siphon_sigtran::python::register(py, parent)?;
```

`register` mounts the `ss7` / `gsm_map` / `gsm_cap` / `inap` namespace singletons,
the `metrics` function, the `SigtranError` exception, and the shared types onto
the `siphon` module, so a hot-reloaded script reaches them with:

```python
from siphon import ss7, gsm_map, gsm_cap, inap
```

The script never configures the node; the binary did that with `configure_from`.
This is the same shape as the sibling addons `siphon-smpp` and `siphon-http`:
built and tested against siphon-sip, consumed by git from a composing binary,
not published to crates.io as a runnable thing.

## The `python` feature

The addon face is behind the `python` feature. Turn it on in the composing
binary's dependency:

```toml
# in the composing binary's Cargo.toml
siphon-sigtran = { git = "https://github.com/siphon-project/siphon-sigtran", features = ["python"] }
```

With the feature on, the crate links siphon-sip + pyo3, compiles the `python`
module, and the composing binary can `configure_from` and `register` it. (The
feature is optional only so the crate's own non-Python unit tests can build
without pyo3 in the graph; running the addon needs it on.)

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
        │  configure_from(cfg) + register(py, parent) at startup
        ├── ss7 / gsm_map / gsm_cap / inap namespaces  ──▶  from siphon import ...
        └── SS7 runtime (associations, routing, dialogue engine)
                                        ▲
   siphon.yaml ──extensions.sigtran──▶ sigtran.yaml ──configure_from──▶ the node
```

- **Build**: this page + the SIPhon extension docs.
- **Configure**: [Configuration](configuration.md).
- **Write handlers**: [Script API](script-api.md), [Cookbook](cookbook/index.md).
- **Deploy**: [Deployment](deployment.md),
  [Kubernetes & scaling](kubernetes.md).
