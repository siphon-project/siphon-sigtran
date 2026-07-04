//! Transport plane, **phase-2 stub**.
//!
//! This module defines the shape of the SCTP-backed transport that will drive
//! the [routing brain](crate::routing) at runtime, but does **not** implement
//! any SCTP yet. The routing brain (config + resolvers + [`Router`]) is complete
//! and tested on its own; wiring it to real associations is the next milestone.
//!
//! [`Router`]: crate::routing::Router
//!
//! # What phase-2 fills in
//!
//! - An [`Asp`] per M3UA association drives the RFC 4666 **ASPSM** (ASP Up /
//!   Down) and **ASPTM** (ASP Active / Inactive) state machines; an
//!   [`ApplicationServer`] groups the ASPs of a linkset with its traffic mode.
//! - An M2PA link drives its own alignment / in-service state machine
//!   (RFC 4165) and, on state changes, calls
//!   [`RouteState::set_linkset_up`](crate::mtp3::route::RouteState::set_linkset_up)
//!   / `set_linkset_down`.
//! - Inbound MSUs are decoded (M3UA Protocol Data or MTP3-over-M2PA), the
//!   [`Router`] is consulted, and the message is forwarded on the chosen
//!   linkset's association, or delivered to a local [dialogue
//!   SAP](crate::dialogue) when the decision is `Local`.
//! - Network-management indications (DUNA/DAVA/SCON → PAUSE/RESUME/STATUS) are
//!   folded into the per-tenant route state via
//!   [`RouteState::apply_event`](crate::mtp3::route::RouteState::apply_event).
//!
//! Everything below is a trait skeleton with doc-comments only.

use crate::config::{Adaptation, Role, TrafficMode};

/// The lifecycle state an association's adaptation layer exposes.
///
/// For **M3UA** this is the composite ASPSM/ASPTM state (RFC 4666 §4); for
/// **M2PA** it is the link alignment state (RFC 4165 §8). The router only cares
/// whether the carrying linkset is *in service*, which the transport derives
/// from these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// SCTP association down / not established.
    Down,
    /// SCTP up, adaptation not yet active (M3UA ASP-Inactive / M2PA aligning).
    Inactive,
    /// Active and carrying traffic (M3UA ASP-Active / M2PA in-service).
    Active,
}

/// One SCTP-backed transport binding for an association.
///
/// **Phase-2**: implementations wrap `async_sctp::SctpAssociation` (or the
/// one-to-many `SctpServer`) and pump the adaptation-layer state machine.
pub trait Transport: Send + Sync {
    /// The association id this transport serves.
    fn assoc_id(&self) -> &str;

    /// The adaptation layer carried (m3ua / m2pa).
    fn adaptation(&self) -> Adaptation;

    /// server (listen) or client (connect).
    fn role(&self) -> Role;

    /// The current link/ASP state.
    fn state(&self) -> LinkState;

    // TODO(phase-2): async-sctp serving loop.
    //   async fn run(self, router: Arc<Router>, tenancy events…) -> Result<()>;
    //   async fn send(&self, msu: &[u8], stream: u16) -> Result<()>;
    //   async fn recv(&self) -> Result<Inbound>;
    // M3UA: bind SctpServer on the node addr:port, accept ASPs, drive ASPSM
    // (ASPUP/ASPDN) + ASPTM (ASPAC/ASPIA), demux by network appearance → tenant.
    // M2PA: SctpAssociation, stream 0 Link Status FSM, stream 1 User Data MSUs.
}

/// A group of ASPs serving one linkset with a traffic mode: the M3UA
/// **Application Server** (RFC 4666 §1.3). **Phase-2 stub.**
pub trait ApplicationServer: Send + Sync {
    /// The linkset name this AS realises.
    fn linkset(&self) -> &str;

    /// The traffic mode (loadshare / override / broadcast).
    fn traffic_mode(&self) -> TrafficMode;

    /// Whether at least one ASP is Active (the linkset is in service).
    fn is_available(&self) -> bool;

    // TODO(phase-2): pick_asp(sls) honouring traffic_mode; NTFY handling;
    // update the tenant RouteState on availability changes.
}

/// One Application Server Process: an M3UA peer on an association. **Phase-2
/// stub** driving the ASPSM + ASPTM state machines (RFC 4666 §4).
pub trait Asp: Send + Sync {
    /// The association this ASP rides.
    fn assoc_id(&self) -> &str;

    /// The current ASP state.
    fn state(&self) -> LinkState;

    // TODO(phase-2): drive ASP Up/Down (ASPSM) and ASP Active/Inactive (ASPTM);
    // on ASP-Active, mark the owning linkset up in the tenant RouteState.
    // The published `m3ua::Asp` / `m3ua::AspState` state machine is the engine.
}
