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
//!   │  MAP / CAP termination  (dialogue SAP)                         │  src/dialogue.rs
//!   │      gsm_map · gsm_cap                                         │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  TCAP  transactions + components            tcap              │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  SCCP  GTT + E.214/E.164 conversion         sccp             │  src/sccp/gtt.rs
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  MTP3  route resolver (DPC to AS/linkset)   mtp3             │  src/mtp3/route.rs
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  M3UA (RFC 4666)  ·  M2PA (RFC 4165)        m3ua · m2pa      │  src/transport
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  SCTP  (Linux lksctp)                       async-sctp       │  src/transport
//!   └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## The routing brain (phase 1)
//!
//! - [`config`]: the typed `sigtran.yaml` model, its serde, and validation.
//! - [`point_code`]: decimal-first helpers over [`mtp3::PointCode`].
//! - [`mtp3::route`]: the MTP3 route resolver, its availability state, and the
//!   [`Destination`](mtp3::route::Destination) it resolves to (an M3UA
//!   Application Server or an M2PA linkset).
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
//! ## The transport plane (phase 2, this release)
//!
//! - [`transport`]: a working SIGTRAN transport over real kernel SCTP. It binds
//!   / connects each association, runs the M3UA ASPSM/ASPTM handshake (so an AS
//!   goes active) or the M2PA link alignment, translates SSNM into route-state
//!   events, and routes + forwards inbound DATA through the [`Router`](routing::Router).
//!   Transfer is Service-Indicator-agnostic (any non-SCCP MSU transits by DPC),
//!   and two loop guards drop-and-count a message that looped. Start it with
//!   [`TransportHandle::start`](transport::TransportHandle::start).
//! - [`metrics`]: the full Prometheus family set the transport, router, and
//!   dialogue engine maintain (association / ASP / linkset state, route
//!   availability, MSU rate, GTT translations/errors, content-rule hits, active
//!   dialogues, dialogue / invoke timeouts, aborts, loop guards), plus a text
//!   renderer.
//!
//! ## The dialogue-termination SAP (phase 3, this release)
//!
//! - [`dialogue`]: a synchronous TCAP transaction engine. When the router returns
//!   [`RouteDecision::Local`](routing::RouteDecision::Local) the transport hands
//!   the MSU to a [`DialogueEngine`](dialogue::DialogueEngine): it decodes the
//!   SCCP UDT + TCAP, dispatches the decoded MAP/CAP operation to a registered
//!   [`TerminationHandler`](dialogue::TerminationHandler), and the handler answers
//!   through a [`Dialogue`](dialogue::Dialogue) handle (`reply` / `invoke` +
//!   `send` / `end` / `abort`). It drives single request/response, held-open
//!   multi-leg, and originating flows, with the config
//!   [`Tcap`](config::Tcap) invoke / dialogue timers.
//!
//! ## The siphon addon surface (phase 4, this release)
//!
//! - [`python`] (feature `python`): the siphon addon face, built and tested
//!   against siphon-sip the way the sibling addons `siphon-smpp` and
//!   `siphon-http` are. A composing siphon binary calls `python::register(py,
//!   parent)` at startup to mount the `ss7` / `gsm_map` / `gsm_cap` namespaces
//!   onto the `siphon` package module. Scripts then program the Rust routing
//!   tables live (`ss7.routes` / `ss7.gtt` / `ss7.content`), defer a rule to a
//!   hook (`@ss7.content.on` / `@ss7.on_route`), and terminate MAP/CAP dialogues
//!   (`@gsm_map.on_*` / `@gsm_cap.on_*`). There is no wheel and no PyPI package;
//!   the default crate build pulls neither pyo3 nor siphon.
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
pub mod isup;
pub mod metrics;
pub mod mtp3;
pub mod point_code;
#[cfg(feature = "python")]
pub mod python;
pub mod routing;
pub mod sccp;
pub mod tenant;
pub mod transport;

pub use config::Config;
pub use dialogue::{
    Dialogue, DialogueEngine, IncomingOp, OutgoingBegin, PeerComponent, PeerTurn, Role,
    TerminationHandler,
};
pub use error::{Error, Result};
pub use mtp3::route::Destination;
pub use routing::{RouteDecision, Router};
pub use transport::{LocalDelivery, TransportHandle};
