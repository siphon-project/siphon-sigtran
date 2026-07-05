//! The transport plane: SIGTRAN over real kernel SCTP (async-sctp).
//!
//! [`TransportHandle::start`] turns a validated [`Config`] into a running node:
//! it binds/connects every association, runs the per-association adaptation-layer
//! task (M3UA ASPSM/ASPTM or M2PA link alignment), and wires each one to the
//! shared [`Router`] so live ASP/link/SSNM state drives route availability and
//! inbound DATA is routed and forwarded.
//!
//! ```text
//!   peer ──SCTP──▶ association task ──▶ framing::extract ──▶ Router::route_in
//!                                                                 │
//!                    ┌────────────────────────────────────────────┤
//!                    ▼                          ▼                  ▼
//!             Route/RouteTo{via}            Local            Drop/Python/…
//!             registry::select →         local_tx →           logged
//!             framing::wrap → SCTP       dialogue SAP
//! ```
//!
//! ## What the M3UA subset does
//!
//! It runs the ASPSM + ASPTM handshake so an AS becomes active (ASP-UP ↔ -ACK,
//! ASP-ACTIVE ↔ -ACK honouring the AS traffic mode), acks BEAT, carries DATA in
//! both directions, and folds SSNM (DUNA/DAVA → PAUSE/RESUME, DAUD answered from
//! the live route state, SCON/DUPU noted) into the router. It does **not** do
//! Routing Key Management (dynamic REG/DEREG), the ERR round-trip, or multiple
//! ASPs multiplexed on one SCTP association, those are out of scope this phase.
//!
//! ## What the M2PA subset does
//!
//! It aligns a link to in-service (Alignment → Proving → Ready) with the
//! published state machine and then carries MTP3 MSUs in User Data. Link
//! up/down feeds the resolver. Retransmission/flow-control on BSN/FSN is not
//! modelled (the SCTP association already gives reliable, ordered delivery).
//!
//! ## Transfer is Service-Indicator-agnostic
//!
//! The transfer path routes by point code for **any** Service Indicator. An ISUP
//! (`SI=5`), MTP3-management, or any non-SCCP MSU addressed to a point code we do
//! not own transits natively, its payload untouched. Only an SCCP MSU (`SI=3`)
//! addressed to us is decoded up the stack for GTT / content / termination.
//!
//! ## Loop guards
//!
//! Two guards sit in the transfer path and drop-and-count a looping MSU
//! (`sigtran_loops_detected_total`, see [`crate::metrics`]): **own-opc** (the
//! MSU's OPC is our own point code, so we originated it and it came back) and
//! **route-reflect** (the resolved egress is the very AS / linkset the MSU
//! arrived on). Both warn-log the OPC/DPC and the inbound association.
//!
//! ## Reserved
//!
//! `sua` associations parse but are **not implemented**: [`TransportHandle::start`]
//! returns [`TransportError::Unsupported`] listing them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_sctp::{SctpAssociation, SctpConfig, SctpListener};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::{Adaptation, Association, Config, Role, DEFAULT_TENANT};
use crate::routing::Router;

mod forward;
pub mod framing;
mod m2pa;
mod m3ua;
pub mod registry;

pub use framing::Msu;
pub use m2pa::next_status;
pub use registry::Registry;

/// The lifecycle state an association's adaptation layer exposes.
///
/// For **M3UA** this is the composite ASPSM/ASPTM state (RFC 4666 §4); for
/// **M2PA** it is the link alignment state (RFC 4165 §8). The router only cares
/// whether the carrying destination is *in service*, which the transport derives
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

/// Errors from starting or running the transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// An SCTP bind/connect/send failed.
    #[error("sctp: {0}")]
    Sctp(#[from] async_sctp::SctpError),
    /// An M3UA decode failed.
    #[error("m3ua: {0}")]
    M3ua(#[from] ::m3ua::M3uaError),
    /// An M2PA encode/decode failed.
    #[error("m2pa: {0}")]
    M2pa(#[from] ::m2pa::M2paError),
    /// A routing-label framing error.
    #[error("framing: {0}")]
    Framing(String),
    /// A config problem surfaced at transport start (bad address, unknown tenant).
    #[error("config: {0}")]
    Config(String),
    /// A configured adaptation is reserved but not implemented (SUA).
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Transport result alias.
pub type Result<T> = std::result::Result<T, TransportError>;

/// A message the router decided terminates locally, handed to the (phase-4)
/// dialogue SAP over the transport's local-delivery channel. Carries the decoded
/// MSU; the SCCP/TCAP dialogue coordinator consumes it.
#[derive(Debug, Clone)]
pub struct LocalDelivery {
    /// The MSU that terminated locally (its `payload` is the SCCP bytes for SI=3).
    pub msu: Msu,
}

/// Shared context handed to every association task.
#[derive(Clone)]
pub(crate) struct TaskCtx {
    pub router: Arc<Router>,
    pub registry: Arc<Registry>,
    pub tenant: String,
    pub local_tx: mpsc::Sender<LocalDelivery>,
}

/// A running transport: the spawned association tasks plus the seams to observe
/// it (bound addresses, the local-delivery receiver) and to stop it.
pub struct TransportHandle {
    router: Arc<Router>,
    registry: Arc<Registry>,
    bound: HashMap<String, SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
    local_rx: Option<mpsc::Receiver<LocalDelivery>>,
}

impl TransportHandle {
    /// Start the transport for the implicit `default` tenant.
    pub async fn start(config: &Config, router: Arc<Router>) -> Result<Self> {
        Self::start_tenant(config, DEFAULT_TENANT, router).await
    }

    /// Start the transport for a named tenant (the associations are shared; this
    /// selects which tenant's routing tables the node drives).
    pub async fn start_tenant(
        config: &Config,
        tenant_id: &str,
        router: Arc<Router>,
    ) -> Result<Self> {
        // SUA is reserved: refuse to start if any association uses it.
        let sua: Vec<&str> = config
            .associations
            .iter()
            .filter(|a| a.adaptation == Adaptation::Sua)
            .map(|a| a.id.as_str())
            .collect();
        if !sua.is_empty() {
            return Err(TransportError::Unsupported(format!(
                "sua adaptation is reserved and not implemented (associations: {sua:?})"
            )));
        }

        let registry = Arc::new(
            Registry::build(config, tenant_id)
                .ok_or_else(|| TransportError::Config(format!("unknown tenant `{tenant_id}`")))?,
        );
        // Real availability starts here: nothing is in service until a handshake
        // completes, so clear the config-only "all up" default.
        router.reset_availability_down(tenant_id);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (local_tx, local_rx) = mpsc::channel(1024);
        let sctp_cfg = SctpConfig::new().nodelay(true);

        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        let mut bound = HashMap::new();

        for assoc in &config.associations {
            let slot = registry
                .slot(&assoc.id)
                .cloned()
                .ok_or_else(|| TransportError::Config(format!("no slot for `{}`", assoc.id)))?;
            let addrs = socket_addrs(assoc)?;
            let ctx = TaskCtx {
                router: router.clone(),
                registry: registry.clone(),
                tenant: tenant_id.to_string(),
                local_tx: local_tx.clone(),
            };

            match (assoc.adaptation, assoc.role) {
                (Adaptation::M3ua, Role::Server) | (Adaptation::M2pa, Role::Server) => {
                    let listener = bind(&addrs, &sctp_cfg)?;
                    bound.insert(assoc.id.clone(), listener.local_addr()?);
                    tasks.push(tokio::spawn(accept_loop(
                        listener,
                        slot,
                        ctx,
                        shutdown_rx.clone(),
                        assoc.adaptation,
                    )));
                }
                (Adaptation::M3ua, Role::Client) => {
                    let conn = Arc::new(connect(&addrs, &sctp_cfg).await?);
                    slot.set_sender(conn.clone());
                    let membership = registry.as_membership(&assoc.id);
                    tasks.push(tokio::spawn(m3ua::run_asp(
                        conn,
                        slot,
                        membership,
                        ctx,
                        shutdown_rx.clone(),
                    )));
                }
                (Adaptation::M2pa, Role::Client) => {
                    let conn = Arc::new(connect(&addrs, &sctp_cfg).await?);
                    slot.set_sender(conn.clone());
                    tasks.push(tokio::spawn(m2pa::run_link(
                        conn,
                        slot,
                        ctx,
                        shutdown_rx.clone(),
                    )));
                }
                (Adaptation::Sua, _) => unreachable!("sua rejected above"),
            }
        }

        Ok(Self {
            router,
            registry,
            bound,
            tasks,
            shutdown_tx,
            local_rx: Some(local_rx),
        })
    }

    /// The actual bound address of a `server` association (useful when the config
    /// binds an ephemeral port `:0`).
    pub fn bound_addr(&self, assoc_id: &str) -> Option<SocketAddr> {
        self.bound.get(assoc_id).copied()
    }

    /// The shared router (read its route state, or drive it directly in tests).
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// The transport registry (egress selection, availability recompute).
    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Take the local-delivery receiver: the stream of MSUs the router decided
    /// terminate here, for the dialogue SAP (phase-4) to consume. `None` after
    /// the first call.
    pub fn take_local_rx(&mut self) -> Option<mpsc::Receiver<LocalDelivery>> {
        self.local_rx.take()
    }

    /// Signal every task to stop and abort them. Idempotent.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Accept loop for a `server` association: each accepted peer gets its own
/// adaptation task and becomes the association's live sender.
async fn accept_loop(
    listener: SctpListener,
    slot: Arc<registry::AssocSlot>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
    adaptation: Adaptation,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = listener.accept() => {
                let (assoc, _peer) = match r {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let assoc = Arc::new(assoc);
                slot.set_sender(assoc.clone());
                let child_ctx = ctx.clone();
                let child_slot = slot.clone();
                let child_sd = shutdown.clone();
                match adaptation {
                    Adaptation::M3ua => {
                        tokio::spawn(m3ua::run_sg(assoc, child_slot, child_ctx, child_sd));
                    }
                    Adaptation::M2pa => {
                        tokio::spawn(m2pa::run_link(assoc, child_slot, child_ctx, child_sd));
                    }
                    Adaptation::Sua => {}
                }
            }
        }
    }
}

/// Parse an association's `addrs` + `port` into socket addresses.
fn socket_addrs(a: &Association) -> Result<Vec<SocketAddr>> {
    a.addrs
        .iter()
        .map(|s| {
            format!("{s}:{}", a.port)
                .parse::<SocketAddr>()
                .map_err(|e| TransportError::Config(format!("bad address `{s}:{}`: {e}", a.port)))
        })
        .collect()
}

/// Bind a listener, single- or multi-homed.
fn bind(addrs: &[SocketAddr], cfg: &SctpConfig) -> Result<SctpListener> {
    let listener = if addrs.len() == 1 {
        SctpListener::bind_config(addrs[0], cfg)?
    } else {
        SctpListener::bind_multi_with(addrs, cfg)?
    };
    Ok(listener)
}

/// Connect an association, single- or multi-homed.
async fn connect(addrs: &[SocketAddr], cfg: &SctpConfig) -> Result<SctpAssociation> {
    let conn = if addrs.len() == 1 {
        SctpAssociation::connect_with(addrs[0], cfg).await?
    } else {
        SctpAssociation::connect_multi_with(addrs, cfg).await?
    };
    Ok(conn)
}
