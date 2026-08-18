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
//! ## What the SUA subset does
//!
//! SUA (RFC 3868) is M3UA's sibling: the same ASPSM/ASPTM handshake brings an
//! Application Server up, but it carries the **SCCP user** (TCAP) addressed by
//! GT/SSN/PC in a **CLDT** (connectionless data transfer), not the MTP3 user on a
//! routing label. An inbound CLDT is bridged one-for-one to an SCCP UDT and
//! routed through the *same* GTT / content / local-termination engine as
//! SCCP-over-M3UA; an egress to a `sua` AS re-wraps the routed SCCP-user in a
//! CLDT (SCTP PPID 4). Only the **connectionless** set (CLDT/CLDR) is carried;
//! the connection-oriented set (CORE/COAK/CODT/CODA/…) is out of scope this
//! phase. See [`sua`](self) and [`framing`].
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_sctp::{SctpAssociation, SctpConfig, SctpListener};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::{Adaptation, Association, Config, Role, DEFAULT_TENANT};
use crate::dialogue::{DialogueEngine, OutgoingBegin, TerminationHandler};
use crate::metrics;
use crate::mtp3::route::Destination;
use crate::routing::{Inbound, RouteDecision, Router};

mod forward;
pub mod framing;
mod m2pa;
mod m3ua;
pub mod registry;
mod sua;

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
    /// A SUA decode/encode failed.
    #[error("sua: {0}")]
    Sua(#[from] ::sua::SuaError),
    /// An SCCP encode/decode failed (in the SUA CLDT ⇄ SCCP-user bridge).
    #[error("sccp: {0}")]
    Sccp(#[from] ::sccp::SccpError),
    /// A routing-label framing error.
    #[error("framing: {0}")]
    Framing(String),
    /// A config problem surfaced at transport start (bad address, unknown tenant).
    #[error("config: {0}")]
    Config(String),
}

/// Transport result alias.
pub type Result<T> = std::result::Result<T, TransportError>;

/// A message the router decided terminates locally, handed to the dialogue SAP
/// over the transport's local-delivery channel. Carries the decoded MSU plus the
/// association it arrived on, so the dialogue engine's reply goes back to the
/// peer that asked.
#[derive(Debug, Clone)]
pub struct LocalDelivery {
    /// The MSU that terminated locally (its `payload` is the SCCP bytes for SI=3).
    pub msu: Msu,
    /// The id of the association the MSU arrived on (the reply egress).
    pub ingress_assoc: String,
}

/// An origination request handed to the transport's outbound seam: open a
/// dialogue the node itself initiates (an SMSC's MT delivery, an SMS-GMSC's
/// SRI-SM). The engine allocates the transaction and the handler stages the
/// opening `Invoke` in [`TerminationHandler::on_start`] and observes the peer's
/// response in [`TerminationHandler::on_continue`]; the transport routes the
/// resulting `Begin` MSU(s) out by DPC. The peer's response arrives inbound and
/// correlates through [`TransportHandle::serve_dialogues`] on the same engine.
pub struct Origination {
    /// The parameterised opening request (application context, addressing, DPC).
    pub req: OutgoingBegin,
    /// The handler driving the originated dialogue.
    pub handler: Arc<dyn TerminationHandler>,
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
    tenant: String,
    bound: HashMap<String, SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
    local_rx: Option<mpsc::Receiver<LocalDelivery>>,
    origin_tx: mpsc::UnboundedSender<Origination>,
    origin_rx: Option<mpsc::UnboundedReceiver<Origination>>,
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
        let registry = Arc::new(
            Registry::build(config, tenant_id)
                .ok_or_else(|| TransportError::Config(format!("unknown tenant `{tenant_id}`")))?,
        );
        // Real availability starts here: nothing is in service until a handshake
        // completes, so clear the config-only "all up" default.
        router.reset_availability_down(tenant_id);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (local_tx, local_rx) = mpsc::channel(1024);
        let (origin_tx, origin_rx) = mpsc::unbounded_channel();
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
                (Adaptation::M3ua, Role::Server)
                | (Adaptation::M2pa, Role::Server)
                | (Adaptation::Sua, Role::Server) => {
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
                (Adaptation::Sua, Role::Client) => {
                    let conn = Arc::new(connect(&addrs, &sctp_cfg).await?);
                    slot.set_sender(conn.clone());
                    let membership = registry.as_membership(&assoc.id);
                    tasks.push(tokio::spawn(sua::run_asp(
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
            }
        }

        Ok(Self {
            router,
            registry,
            tenant: tenant_id.to_string(),
            bound,
            tasks,
            shutdown_tx,
            local_rx: Some(local_rx),
            origin_tx,
            origin_rx: Some(origin_rx),
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
    /// terminate here, for a custom consumer. `None` after the first call (and
    /// after [`serve_dialogues`](Self::serve_dialogues), which takes it).
    pub fn take_local_rx(&mut self) -> Option<mpsc::Receiver<LocalDelivery>> {
        self.local_rx.take()
    }

    /// Attach a [`DialogueEngine`] to the running node: spawn a task that pumps
    /// every locally-terminated MSU into [`DialogueEngine::deliver`], sends the
    /// engine's replies back to the peer that asked (over the ingress
    /// association), and periodically ages out expired dialogues via
    /// [`DialogueEngine::sweep`]. Takes the local-delivery receiver, so call it
    /// once, after registering the engine's handlers.
    pub fn serve_dialogues(&mut self, engine: Arc<DialogueEngine>) {
        let Some(mut rx) = self.local_rx.take() else {
            return;
        };
        let registry = self.registry.clone();
        let router = self.router.clone();
        let tenant = self.tenant.clone();
        let mut shutdown = self.shutdown_tx.subscribe();
        let task = tokio::spawn(async move {
            // Age dialogues once a second; the timers themselves are seconds.
            let mut sweep = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    maybe = rx.recv() => {
                        let Some(delivery) = maybe else { break };
                        for out in engine.deliver(&delivery.msu, &delivery.ingress_assoc) {
                            send_reply(&registry, &delivery.ingress_assoc, &out).await;
                        }
                    }
                    _ = sweep.tick() => {
                        for (assoc, out) in engine.sweep(Instant::now()) {
                            send_sweep_abort(&registry, &router, &tenant, &assoc, &out).await;
                        }
                    }
                }
            }
        });
        self.tasks.push(task);
    }

    /// A cloneable sender onto the transport's origination seam. A composing
    /// addon hands this to its script-facing originating helper
    /// (`gsm_map.begin(...)`), which pushes an [`Origination`] to open a dialogue
    /// the node initiates. `None`-free: always available once the transport is up.
    pub fn origin_sender(&self) -> mpsc::UnboundedSender<Origination> {
        self.origin_tx.clone()
    }

    /// Attach the origination drain to the running node: spawn a task that pulls
    /// each [`Origination`], opens the dialogue via [`DialogueEngine::begin`]
    /// (whose handler stages the opening `Invoke`), and sends the resulting
    /// `Begin` MSU(s) out on the association its DPC routes to. The peer's
    /// response arrives inbound and correlates through
    /// [`serve_dialogues`](Self::serve_dialogues) on the **same** engine, so pass
    /// the identical [`DialogueEngine`] to both. Takes the origination receiver,
    /// so call it once.
    pub fn serve_originations(&mut self, engine: Arc<DialogueEngine>) {
        let Some(mut rx) = self.origin_rx.take() else {
            return;
        };
        let registry = self.registry.clone();
        let router = self.router.clone();
        let tenant = self.tenant.clone();
        let mut shutdown = self.shutdown_tx.subscribe();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    maybe = rx.recv() => {
                        let Some(origination) = maybe else { break };
                        let dpc = origination.req.dpc;
                        let (_tid, frames) = engine.begin(origination.req, origination.handler);
                        let Some(via) = resolve_egress(&router, &tenant, dpc) else {
                            eprintln!(
                                "siphon-sigtran: originated dialogue to dpc {dpc} has no MTP3 route, dropped"
                            );
                            continue;
                        };
                        for msu in &frames {
                            forward::send_via(&via, msu, &registry).await;
                        }
                    }
                }
            }
        });
        self.tasks.push(task);
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
                    Adaptation::Sua => {
                        tokio::spawn(sua::run_sg(assoc, child_slot, child_ctx, child_sd));
                    }
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

/// Resolve the egress [`Destination`] a DPC routes to within a tenant, for the
/// origination path: an originated `Begin` is addressed by DPC and routed like
/// any transit MSU. Returns `None` when the DPC has no route (or resolves to
/// local termination, which an origination never should).
fn resolve_egress(router: &Router, tenant: &str, dpc: u32) -> Option<Destination> {
    match router.route_in(
        tenant,
        &Inbound {
            dpc,
            ..Default::default()
        },
    ) {
        RouteDecision::Route { via } => Some(via),
        RouteDecision::RouteTo { via: Some(via), .. } => Some(via),
        _ => None,
    }
}

/// Send a swept dialogue's timeout Abort back to the peer, never silently
/// dropping it. A responder dialogue carries the ingress association it arrived
/// on, so the Abort egresses there; an **originated** (initiator) dialogue has no
/// ingress association (it went out by DPC), so its Abort is routed by the
/// destination point code instead — the peer is always told the transaction died.
async fn send_sweep_abort(
    registry: &Registry,
    router: &Router,
    tenant: &str,
    assoc_id: &str,
    msu: &Msu,
) {
    if !assoc_id.is_empty() && registry.slot(assoc_id).is_some() {
        send_reply(registry, assoc_id, msu).await;
    } else if let Some(via) = resolve_egress(router, tenant, msu.dpc) {
        forward::send_via(&via, msu, registry).await;
    } else {
        eprintln!(
            "siphon-sigtran: swept dialogue abort to dpc {} has no egress association, dropped",
            msu.dpc
        );
    }
}

/// Send one dialogue-engine reply MSU back on the association it should egress
/// (the ingress association of the request), framing it for that adaptation.
async fn send_reply(registry: &Registry, assoc_id: &str, msu: &Msu) {
    let Some(slot) = registry.slot(assoc_id) else {
        eprintln!("siphon-sigtran: dialogue reply for unknown association `{assoc_id}`");
        return;
    };
    let Some(sender) = slot.sender() else {
        eprintln!("siphon-sigtran: dialogue reply but `{assoc_id}` has no live sender");
        return;
    };
    let (bytes, stream, ppid) = match slot.adaptation {
        Adaptation::M3ua => {
            let rc = registry.as_membership(assoc_id).map(|(rc, _)| rc);
            (framing::wrap_m3ua(msu, rc), 1u16, 3u32)
        }
        Adaptation::M2pa => match framing::wrap_m2pa(msu) {
            Ok(b) => (b, 1u16, 5u32),
            Err(e) => {
                eprintln!("siphon-sigtran: dialogue reply m2pa framing failed: {e}");
                return;
            }
        },
        Adaptation::Sua => {
            let rc = registry
                .as_membership(assoc_id)
                .map(|(rc, _)| rc)
                .unwrap_or(0);
            match framing::wrap_sua(msu, rc) {
                Ok(b) => (b, 1u16, 4u32),
                Err(e) => {
                    eprintln!("siphon-sigtran: dialogue reply sua framing failed: {e}");
                    return;
                }
            }
        }
    };
    if let Err(e) = sender.send(&bytes, stream, ppid).await {
        eprintln!("siphon-sigtran: dialogue reply send on `{assoc_id}` failed: {e}");
    } else {
        metrics::msu(metrics::Dir::Tx, msu.si);
    }
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
