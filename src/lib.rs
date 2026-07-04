//! # siphon-sigtran
//!
//! A **SIGTRAN/SS7 runtime** built on the published SS7 codec crates (mtp3,
//! m3ua, sccp, tcap, gsm_map, gsm_cap, async-sctp, m2pa). It turns a
//! declarative `sigtran.yaml` into a running signalling node: SCTP transport
//! (M3UA / M2PA), MTP3 routing, SCCP Global Title Translation, **content
//! routing** on the decoded MAP/CAP layer, and MAP/CAP dialogue termination.
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────────┐
//!   │  content routing        (routes/screens on the decoded MAP/CAP │  src/content.rs
//!   │                          application layer)                    │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  MAP / CAP termination  (dialogue SAP, phase-2)              │  src/dialogue.rs
//!   │      gsm_map · gsm_cap                                         │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  TCAP  transactions + components            tcap              │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  SCCP  GTT + E.214/E.164 conversion         sccp             │  src/sccp/gtt.rs
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  MTP3  route resolver (DPC to linkset)      mtp3             │  src/mtp3/route.rs
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  M3UA (RFC 4666)  ·  M2PA (RFC 4165)        m3ua · m2pa      │  src/transport (phase-2)
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  SCTP  (Linux lksctp)                       async-sctp       │  (phase-2)
//!   └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Phase 1 (this release): the routing brain
//!
//! - [`config`]: the typed `sigtran.yaml` model, its serde, and validation.
//! - [`point_code`]: decimal-first helpers over [`mtp3::PointCode`].
//! - [`mtp3::route`]: the MTP3 route resolver and its availability state.
//! - [`sccp::gtt`]: the GTT resolver and the E.214/E.164 converter.
//! - [`content`]: the content-routing engine over a decoded MAP/CAP view.
//! - [`tenant`]: the tenancy model (implicit default).
//! - [`routing`]: the shared [`RouteDecision`](routing::RouteDecision) type plus
//!   the top-level [`Router`](routing::Router) that ties the layers together.
//!
//! All of that is pure Rust, synchronous, no I/O. That is the line-rate routing
//! guarantee. It is unit- and integration-tested against genuinely assembled
//! SS7 traffic.
//!
//! ## Phase 2 / 3 (stubs)
//!
//! - [`transport`]: the SCTP-backed M3UA/M2PA serving loop (trait shapes only).
//! - [`dialogue`]: the MAP/CAP dialogue-termination SAP (trait shapes only).
//! - Python bindings (pyo3) are phase-3. The plan is to expose the same routing
//!   brain so a script can program the Rust tables live, defer a rule to a hook,
//!   or take a selector-gated general override. That is the three-way override
//!   from the spec.
//!
//! ## Quickstart
//!
//! ```no_run
//! use siphon_sigtran::{Config, Router};
//! use siphon_sigtran::routing::{Inbound, RouteDecision};
//!
//! let config = Config::load("sigtran.yaml")?;
//! let router = Router::new(&config);
//!
//! // Route a transit MSU addressed to a non-local DPC.
//! let decision = router.route(&Inbound { dpc: 2000, ..Default::default() });
//! assert!(matches!(decision, RouteDecision::Route { .. }));
//! # Ok::<(), siphon_sigtran::Error>(())
//! ```
//!
//! ## Data hygiene
//!
//! Every value in the tests, benches, and examples is synthetic: test PLMN
//! MCC `001` / MNC `01`, `+1-555-01xx` global titles, and decimal point codes
//! (1000/2000/3000-style) that resemble nothing real. No captured traffic.

#![warn(missing_docs)]

pub mod config;
pub mod content;
pub mod dialogue;
pub mod error;
pub mod mtp3;
pub mod point_code;
pub mod routing;
pub mod sccp;
pub mod tenant;
pub mod transport;

pub use config::Config;
pub use error::{Error, Result};
pub use routing::{RouteDecision, Router};
