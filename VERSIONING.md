# Versioning

`siphon-sigtran` follows [Semantic Versioning 2.0.0](https://semver.org/). The
public API is the contract: the `Config` model and its `load`/`parse`, the
resolvers (`RouteResolver`/`RouteState`, `GttResolver`/`GtConverter`,
`ContentEngine`), the `Router` and its `RouteDecision`/`Inbound` types, and the
`sigtran.yaml` schema those parse.

## Pre-1.0

While the crate is `0.y`, the public API and the config schema may still change
between minor versions as the transport, dialogue, and Python layers land. A
`0.y.z` to `0.(y+1).0` bump may break; a `0.y.z` to `0.y.(z+1)` bump will not.

## The git tag is the source of truth

`Cargo.toml`'s `version` matches the release tag; the release workflow's
`verify-version` job refuses to publish if they disagree. Bump `version`, commit,
tag `vX.Y.Z`, push the tag.

## Post-1.0 rule

- **MAJOR**: remove/rename/re-signature a `pub` item, or change the meaning of an
  existing `sigtran.yaml` field.
- **MINOR**: backward-compatible additions (new config fields with defaults, new
  resolver methods, new `RouteDecision` variants behind `#[non_exhaustive]`).
- **PATCH**: bug fixes, docs, behaviour-neutral dependency bumps.
