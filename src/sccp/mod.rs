//! SCCP routing, Global Title Translation (GTT) and E.214 ↔ E.164 conversion.
//!
//! [`gtt::GttResolver`] matches an incoming global title against the ordered
//! `gtt` rules and produces a [`gtt::GttResult`] (a concrete dpc/ssn, a group
//! selection, local termination, or a cross-tenant hand-off). A
//! [`gtt::GtConverter`] applies the E.214 mobile-global-title ↔ E.164
//! transform as a pre-step, using the `plmn_map`.

pub mod gtt;

pub use gtt::{GtConverter, GttResolver, GttResult, GttSelector};
