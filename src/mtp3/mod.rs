//! MTP3 routing, the route resolver and its availability state.
//!
//! This module owns the answer to "given a DPC and a tenant, which egress
//! [`Destination`](route::Destination) (M3UA Application Server or M2PA linkset)
//! do we send on?" It combines the config's static [`mtp3_routes`] with the
//! **implicit** routes that an m2pa link's `adjacent_pc` creates, filters by
//! current availability (fed from [`mtp3::Mtp3Event`](mtp3::Mtp3Event) and
//! AS / linkset up/down), and picks the lowest-priority (primary-first) route.
//!
//! [`mtp3_routes`]: crate::config::Mtp3Route

pub mod route;

pub use route::{Destination, LinksetId, RouteResolver, RouteState};
