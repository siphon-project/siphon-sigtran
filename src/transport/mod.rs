//! The transport plane: SIGTRAN over real kernel SCTP (async-sctp).
//!
//! [`TransportHandle::start`] turns a validated [`Config`] into a running node:
//! it binds every listening endpoint, starts a task that dials each `client`
//! association (until it is up, and again after it is lost: see [`dial`]),
//! runs the per-association adaptation-layer task (M3UA ASPSM/ASPTM or M2PA
//! link alignment), and wires each one to the
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
//! ## What M3UA does
//!
//! Toward the ASPs of its application servers the node is a signalling
//! gateway as RFC 4666 has one. One task per routing domain keeps the state of
//! every ASP and every Application Server ([`Aspm`] is the state machine):
//! ASP Up, Down, Active and Inactive are answered, the routing contexts and
//! the traffic mode of a request are checked, a server whose last active ASP
//! left is pending for T(r) with its traffic queued, and every change is told
//! to the ASPs in a Notify. What level 3 finds out about a destination reaches
//! the active ASPs as DUNA, DAVA, DRST or SCON, and what an ASP says about one
//! reaches the adjacent points; a message that cannot be acted on is answered
//! with the Error of 3.8.1 that says why. On a `client` association the node
//! is the ASP. It does **not** do Routing Key Management (REG/DEREG), the
//! Network Appearance parameter, the IPSP models, or several ASPs on one SCTP
//! association.
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
//! It runs level 2 of a signalling link as RFC 4165 and ITU-T Q.703 have it:
//! the Link Status exchange with its timers, numbered and acknowledged User
//! Data with a retransmission buffer kept for changeover, remote processor
//! outage and remote congestion, link failure and realignment. On top of it,
//! the signalling link test of Q.707: a link is an egress only after its test
//! passed, and a test message from the peer is always answered. See
//! [`M2paLink`] for the state machine.
//!
//! ## Level 3 of a transfer point
//!
//! Signalling network management as ITU-T Q.704 has it runs in one task per
//! routing domain ([`crate::mtp3::management`] is the state machine): changeover
//! and changeback when a link fails and returns, forced and controlled
//! rerouting when an adjacent point prohibits or allows a route,
//! transfer-prohibited and transfer-allowed toward the adjacent points when a
//! destination becomes inaccessible or accessible here, the signalling route
//! set test, management inhibiting at the far end's request, and the MTP
//! restart procedure. A management message for this node (service indicator 0)
//! from a link goes there, not to SCCP.
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
use crate::mtp3::management::{Management, Timers, Topology};
use crate::mtp3::route::Destination;
use crate::routing::{Inbound, RouteDecision, Router};

pub mod dial;
mod forward;
pub mod framing;
pub mod identity;
mod m2pa;
mod m3ua;
mod management;
pub mod registry;
mod sua;

pub(crate) use forward::sccp_return;
pub use framing::Msu;
pub use m2pa::link::{
    Discard as M2paDiscard, Failure as M2paFailure, Link as M2paLink, LinkTimers as M2paTimers,
    Proving as M2paProving, State as M2paLinkState,
};
#[allow(deprecated)]
pub use m2pa::next_status;
pub use m3ua::aspm::{
    Action as AspmAction, AsState, AspSpec as AspmAsp, AspState, Aspm, Input as AspmInput,
    Layout as AspmLayout, Message as AspmMessage, ServerSpec as AspmServer, Status as NotifyStatus,
    Timer as AspmTimer,
};
pub use m3ua::{Discard as M3uaDiscard, Event as M3uaEvent};
pub use registry::{DestinationChange, Membership, Registry};

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

/// Lanes [`TransportHandle::serve_dialogues`] terminates dialogues on: how many
/// handlers can run at once.
const DIALOGUE_LANES: usize = 32;
/// Deliveries a lane holds before the transport waits for it.
const LANE_DEPTH: usize = 256;

/// What a dialogue lane of [`TransportHandle::serve_dialogues`] runs.
enum LaneWork {
    /// An inbound message for a dialogue on this lane.
    Deliver(LocalDelivery),
    /// Timers due on the dialogue with this (our) transaction id, claimed by
    /// [`DialogueEngine::claim_expired`].
    Timers(crate::dialogue::Tid),
}

/// How long a handler turn runs before its lane says so, and again every time
/// that long passes. A handler on a blocking thread cannot be stopped from
/// outside, and what it returns (an answer, the Abort of a timer) must still be
/// sent, so the lane keeps waiting; the log names the lane that is held up.
const TURN_STALL: Duration = Duration::from_secs(10);

/// Run one handler turn of `lane` on a blocking thread, off the runtime's
/// workers, and wait for it. A turn that runs past [`TURN_STALL`] is logged as
/// an error each time that passes; the other lanes, and the dispatch of
/// inbound messages to them, carry on meanwhile.
async fn handler_turn<T, F>(
    lane: usize,
    what: &str,
    turn: F,
) -> std::result::Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let started = Instant::now();
    let mut running = tokio::task::spawn_blocking(turn);
    loop {
        match tokio::time::timeout(TURN_STALL, &mut running).await {
            Ok(done) => return done,
            Err(_) => eprintln!(
                "siphon-sigtran: ERROR: a dialogue {what} handler on lane {lane} has run for {}s; the dialogues of that lane wait for it",
                started.elapsed().as_secs()
            ),
        }
    }
}

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

        // Signalling network management of the domain (ITU-T Q.704): one task,
        // fed by the link tasks and the transfer path.
        let tenant = config
            .tenant(tenant_id)
            .ok_or_else(|| TransportError::Config(format!("unknown tenant `{tenant_id}`")))?;
        let machine = Management::new(
            Topology::build(tenant, &config.associations),
            Timers::from(&tenant.mtp3),
            tenant.mtp3.tfp_for_unknown_destination,
        );
        let (inputs, input_rx) = mpsc::unbounded_channel();
        let (unroutable, unroutable_rx) = mpsc::channel(256);
        registry.attach_management(inputs, unroutable);
        let management_ctx = TaskCtx {
            router: router.clone(),
            registry: registry.clone(),
            tenant: tenant_id.to_string(),
            local_tx: local_tx.clone(),
        };
        tasks.push(tokio::spawn(management::run(
            machine,
            input_rx,
            unroutable_rx,
            management_ctx,
            shutdown_rx.clone(),
        )));

        // ASP state maintenance of the domain (RFC 4666 4.3): one task, fed by
        // the M3UA association tasks.
        let (requests, request_rx) = mpsc::unbounded_channel();
        registry.attach_layer(requests);
        tasks.push(tokio::spawn(m3ua::run_layer(
            Aspm::new(AspmLayout::build(tenant, &config.associations)),
            request_rx,
            TaskCtx {
                router: router.clone(),
                registry: registry.clone(),
                tenant: tenant_id.to_string(),
                local_tx: local_tx.clone(),
            },
            shutdown_rx.clone(),
        )));

        let ctx = TaskCtx {
            router: router.clone(),
            registry: registry.clone(),
            tenant: tenant_id.to_string(),
            local_tx: local_tx.clone(),
        };

        // One listener per local endpoint. Associations that share one are
        // told apart by the address of the peer.
        let groups = crate::config::listen_groups(&config.associations)
            .map_err(|e| TransportError::Config(e.to_string()))?;
        for group in groups {
            let members: Vec<&Association> = group
                .iter()
                .filter_map(|index| config.associations.get(*index))
                .collect();
            let Some(first) = members.first() else {
                continue;
            };
            let listener = bind(&socket_addrs(first)?, &sctp_cfg)?;
            let local = listener.local_addr()?;
            let mut doors = Vec::new();
            for assoc in members {
                let slot = registry
                    .slot(&assoc.id)
                    .cloned()
                    .ok_or_else(|| TransportError::Config(format!("no slot for `{}`", assoc.id)))?;
                let addrs = assoc
                    .peer_ips()
                    .map_err(|e| TransportError::Config(e.to_string()))?;
                if addrs.is_empty() {
                    eprintln!(
                        "siphon-sigtran: WARNING: association `{}` listens on {local} without \
                         `peer_addrs`: WHOEVER CONNECTS FIRST IS TAKEN FOR ITS PEER. List the \
                         addresses of the peer.",
                        assoc.id
                    );
                }
                // A link nobody has connected to yet still has its queue
                // served.
                if assoc.adaptation == Adaptation::M2pa {
                    tasks.push(tokio::spawn(m2pa::idle_link(
                        slot.clone(),
                        ctx.clone(),
                        shutdown_rx.clone(),
                        0,
                    )));
                }
                bound.insert(assoc.id.clone(), local);
                doors.push(Door {
                    slot,
                    rule: identity::Rule {
                        addrs,
                        port: assoc.peer_port,
                    },
                });
            }
            tasks.push(tokio::spawn(accept_loop(
                listener,
                Arc::new(Endpoint::new(local, doors)),
                ctx.clone(),
                shutdown_rx.clone(),
            )));
        }

        // Every association this node opens is dialled by a task of its own,
        // until it is up and again after it is lost: an absent peer delays
        // nothing and stops nothing.
        for assoc in &config.associations {
            if assoc.role != Role::Client {
                continue;
            }
            let slot = registry
                .slot(&assoc.id)
                .cloned()
                .ok_or_else(|| TransportError::Config(format!("no slot for `{}`", assoc.id)))?;
            // A link that is not connected yet still has its queue served.
            if assoc.adaptation == Adaptation::M2pa {
                tasks.push(tokio::spawn(m2pa::idle_link(
                    slot.clone(),
                    ctx.clone(),
                    shutdown_rx.clone(),
                    0,
                )));
            }
            let dialled = Dialled {
                peer: socket_addrs(assoc)?,
                local: local_addrs(assoc)?,
                settings: dial_settings(assoc),
                sctp: sctp_cfg.clone(),
                membership: registry.as_membership(&assoc.id),
                slot,
            };
            tasks.push(tokio::spawn(dial_association(
                dialled,
                ctx.clone(),
                shutdown_rx.clone(),
            )));
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
    /// association), and once a second runs the dialogue timers that are due
    /// (what [`DialogueEngine::sweep`] does, split into
    /// [`DialogueEngine::claim_expired`] and [`DialogueEngine::expire`] so that
    /// every handler, a timeout callback included, runs on a blocking thread and
    /// never on the task that dispatches inbound messages). Takes the
    /// local-delivery receiver, so call it once, after registering the engine's
    /// handlers.
    pub fn serve_dialogues(&mut self, engine: Arc<DialogueEngine>) {
        let Some(mut rx) = self.local_rx.take() else {
            return;
        };
        let registry = self.registry.clone();
        let router = self.router.clone();
        let tenant = self.tenant.clone();
        let mut shutdown = self.shutdown_tx.subscribe();
        // Dialogues are terminated side by side on lanes. A lane takes one
        // dialogue's messages in order (keyed on its transaction ID, see
        // `dialogue_lane`), and runs each on a blocking thread, since a handler
        // (a script among them) may take as long as it likes. One task for all
        // of them made every dialogue wait for the slowest handler before it.
        // The timers of a dialogue run on its lane too (see `tid_lane`): a
        // timeout callback is a handler like any other, and the task below,
        // which hands every inbound message to its lane, never waits for one.
        let mut lanes = Vec::with_capacity(DIALOGUE_LANES);
        for lane in 0..DIALOGUE_LANES {
            let (lane_tx, mut lane_rx) = mpsc::channel::<LaneWork>(LANE_DEPTH);
            let engine = Arc::clone(&engine);
            let registry = registry.clone();
            let router = router.clone();
            let tenant = tenant.clone();
            self.tasks.push(tokio::spawn(async move {
                while let Some(work) = lane_rx.recv().await {
                    let engine = Arc::clone(&engine);
                    match work {
                        LaneWork::Deliver(delivery) => {
                            let ingress = delivery.ingress_assoc.clone();
                            let delivered = handler_turn(lane, "message", move || {
                                engine.deliver(&delivery.msu, &delivery.ingress_assoc)
                            })
                            .await;
                            match delivered {
                                Ok(outs) => {
                                    for out in outs {
                                        send_reply(&registry, &ingress, &out).await;
                                    }
                                }
                                Err(error) => eprintln!(
                                    "siphon-sigtran: ERROR: a dialogue handler on `{ingress}` panicked: {error}"
                                ),
                            }
                        }
                        LaneWork::Timers(tid) => {
                            let expired = handler_turn(lane, "timeout", move || {
                                engine.expire(&tid, Instant::now())
                            })
                            .await;
                            match expired {
                                Ok(outs) => {
                                    for (assoc, out) in outs {
                                        send_sweep_abort(&registry, &router, &tenant, &assoc, &out)
                                            .await;
                                    }
                                }
                                Err(error) => eprintln!(
                                    "siphon-sigtran: ERROR: a dialogue timeout handler panicked: {error}"
                                ),
                            }
                        }
                    }
                }
            }));
            lanes.push(lane_tx);
        }
        let task = tokio::spawn(async move {
            // Age dialogues once a second; the timers themselves are seconds.
            let mut sweep = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    maybe = rx.recv() => {
                        let Some(delivery) = maybe else { break };
                        let lane = (crate::dialogue::dialogue_lane(&delivery.msu)
                            % DIALOGUE_LANES as u64) as usize;
                        if lanes[lane].send(LaneWork::Deliver(delivery)).await.is_err() {
                            break;
                        }
                    }
                    _ = sweep.tick() => {
                        // Only the claim runs here, which looks at the timers
                        // and calls no handler. A lane that is full still has
                        // its earlier work to get through: the dialogue is given
                        // back and claimed again on a later tick, never dropped.
                        for tid in engine.claim_expired(Instant::now()) {
                            let lane = (crate::dialogue::tid_lane(&tid)
                                % DIALOGUE_LANES as u64) as usize;
                            if let Err(
                                mpsc::error::TrySendError::Full(LaneWork::Timers(tid))
                                | mpsc::error::TrySendError::Closed(LaneWork::Timers(tid)),
                            ) = lanes[lane].try_send(LaneWork::Timers(tid))
                            {
                                engine.release_claim(&tid);
                            }
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
                        // An error is already logged with the dialogue's
                        // identifiers, and the handler's `on_closed` has told
                        // whoever is waiting on it.
                        let Ok((_tid, frames)) =
                            engine.begin(origination.req, origination.handler)
                        else {
                            continue;
                        };
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

/// One association of a listening endpoint: its slot, and whom it accepts.
struct Door {
    slot: Arc<registry::AssocSlot>,
    rule: identity::Rule,
}

/// A listening endpoint: one local address set and port, and the associations
/// configured on it.
struct Endpoint {
    local: SocketAddr,
    doors: Vec<Door>,
    rules: Vec<identity::Rule>,
    /// A refused peer is counted every time and logged at most this often:
    /// anyone can connect as often as they like.
    refusals: std::sync::Mutex<identity::Throttle>,
}

/// How often a listening endpoint writes a line about a refused association.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(1);
/// How long an accepted association waits for the slot while another
/// association has it: the time the shutdown of the one before may take when
/// a peer closes and dials again at once, with room for a SHUTDOWN that is
/// lost and sent again after one retransmission timeout (RFC 9260 9.2 and
/// 16: RTO.Initial is 1 second). An association that is still established
/// after that is not going away.
const HANDOVER: Duration = Duration::from_secs(2);

impl Endpoint {
    fn new(local: SocketAddr, doors: Vec<Door>) -> Self {
        Self {
            local,
            rules: doors.iter().map(|door| door.rule.clone()).collect(),
            doors,
            refusals: std::sync::Mutex::new(identity::Throttle::new(REFUSAL_LOG_INTERVAL)),
        }
    }

    /// Refuse an association the kernel has established already: count it,
    /// log it, and abort it. Nothing it sent is read. The peer sees its
    /// association come up and then an SCTP ABORT.
    async fn refuse(
        &self,
        assoc: &SctpAssociation,
        from: SocketAddr,
        reason: identity::Refusal,
        detail: &str,
    ) {
        metrics::association_refused(reason);
        let line = self
            .refusals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .event(Instant::now());
        if let Some(left_out) = line {
            let more = if left_out > 0 {
                format!(" ({left_out} more refused here since the last line)")
            } else {
                String::new()
            };
            eprintln!(
                "siphon-sigtran: refused an association from {from} on {} ({}): {detail}{more}",
                self.local,
                reason.label()
            );
        }
        // An abort that cannot be sent leaves the close of the socket, which
        // ends the association as well.
        let _ = tokio::time::timeout(Duration::from_secs(1), assoc.abort()).await;
    }
}

/// Accept loop of a listening endpoint: every association the kernel hands
/// over is checked and served in a task of its own.
async fn accept_loop(
    listener: SctpListener,
    endpoint: Arc<Endpoint>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut failures = identity::Throttle::new(REFUSAL_LOG_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = listener.accept() => match r {
                Ok((assoc, from)) => {
                    tokio::spawn(admit(
                        Arc::new(assoc),
                        from,
                        endpoint.clone(),
                        ctx.clone(),
                        shutdown.clone(),
                    ));
                }
                Err(error) => {
                    // The endpoint keeps listening: an association that
                    // could not be taken (no descriptor left, a peer that
                    // was gone already) says nothing about the next.
                    if failures.event(Instant::now()).is_some() {
                        eprintln!(
                            "siphon-sigtran: accept on {} failed: {error}",
                            endpoint.local
                        );
                    }
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    }
                }
            },
        }
    }
}

/// Decide whose peer an accepted association is, and serve it as that
/// association until it ends; or refuse it.
async fn admit(
    assoc: Arc<SctpAssociation>,
    from: SocketAddr,
    endpoint: Arc<Endpoint>,
    ctx: TaskCtx,
    shutdown: watch::Receiver<bool>,
) {
    // Every address of a multihomed peer, as its INIT listed them.
    let presented = assoc.peer_addrs().unwrap_or_default();
    let door = match identity::admit(&endpoint.rules, &presented)
        .map(|position| endpoint.doors.get(position))
    {
        Ok(Some(door)) => door,
        Ok(None) => return,
        Err(reason) => {
            let detail = match reason {
                identity::Refusal::Closed => {
                    "it was gone before its addresses were read".to_string()
                }
                identity::Refusal::PeerPort => {
                    format!("the association that lists {presented:?} has another `peer_port`")
                }
                identity::Refusal::UnlistedAddress => format!(
                    "of the addresses {presented:?} an association lists some and not all: \
                     a peer is known by every address it has"
                ),
                _ => format!("no association here lists {presented:?}"),
            };
            endpoint.refuse(&assoc, from, reason, &detail).await;
            return;
        }
    };
    let slot = &door.slot;

    // The slot is one association at a time. One that is established is not
    // displaced. The newcomer is not a restart of it: an INIT from the same
    // addresses and port is processed inside the association the endpoint
    // has (RFC 9260 5.2, "the endpoint processes such a chunk as part of its
    // current association"; 5.2.4 A, "A RESTART notification SHOULD be sent
    // to the ULP") and `accept` returns nothing for it. So the newcomer came
    // from another port and is another association. A peer that closed its
    // association and dials again at once is not refused for that: the
    // newcomer waits, unread, for as long as the shutdown of the one before
    // may take.
    let deadline = tokio::time::Instant::now() + HANDOVER;
    let occupancy = loop {
        if *shutdown.borrow() {
            return;
        }
        if let Some(occupancy) = slot.occupy(&assoc) {
            break occupancy;
        }
        let freed = tokio::time::timeout_at(deadline, slot.vacated()).await;
        if freed.is_err() {
            endpoint
                .refuse(
                    &assoc,
                    from,
                    identity::Refusal::Duplicate,
                    &format!(
                        "association `{}` is established already and is not displaced",
                        slot.id
                    ),
                )
                .await;
            return;
        }
    };

    // Not an egress by being accepted: the adaptation layer makes it one.
    ctx.registry.quiesce(slot);
    slot.set_sender(assoc.clone());
    eprintln!(
        "siphon-sigtran: association `{}` accepted from {presented:?} on {}",
        slot.id, endpoint.local
    );
    match slot.adaptation {
        Adaptation::M3ua => m3ua::run_sg(assoc, slot.clone(), ctx, shutdown).await,
        Adaptation::M2pa => m2pa::run_link(assoc, slot.clone(), ctx, shutdown).await,
        Adaptation::Sua => sua::run_sg(assoc, slot.clone(), ctx, shutdown).await,
    }
    drop(occupancy);
}

/// Count and log one message received on `assoc` and dropped before routing. A
/// received message is never dropped without both.
pub(crate) fn discard(reason: metrics::RxDiscard, assoc: &str, detail: impl std::fmt::Display) {
    metrics::rx_discard(reason);
    eprintln!(
        "siphon-sigtran: dropped a message received on `{assoc}` ({}): {detail}",
        reason.label()
    );
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
        Adaptation::M2pa => {
            forward::send_on_link(slot, msu);
            return;
        }
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

/// What the task of a dialled association needs.
struct Dialled {
    slot: Arc<registry::AssocSlot>,
    /// The addresses of the far end (`addrs` and `port`).
    peer: Vec<SocketAddr>,
    /// The addresses to dial from; empty leaves them to the kernel.
    local: Vec<SocketAddr>,
    settings: dial::Settings,
    sctp: SctpConfig,
    /// For a SUA association: the server it is an ASP of.
    membership: Option<(u32, crate::config::TrafficMode)>,
}

/// The timers of a `client` association from its `dial:` block.
fn dial_settings(a: &Association) -> dial::Settings {
    let block = a.dial.clone().unwrap_or_default();
    dial::Settings {
        connect_timeout: Duration::from_millis(block.connect_timeout_ms),
        initial: Duration::from_millis(block.backoff_initial_ms),
        max: Duration::from_millis(block.backoff_max_ms),
        jitter_percent: block.backoff_jitter_percent,
        log_every: dial::LOG_EVERY,
    }
}

/// The local addresses a `client` association is dialled from: `local_addrs`
/// with `local_port`, or every address when only the port is given.
fn local_addrs(a: &Association) -> Result<Vec<SocketAddr>> {
    let port = a.local_port.unwrap_or(0);
    let ips = a
        .local_ips()
        .map_err(|e| TransportError::Config(e.to_string()))?;
    if ips.is_empty() && port != 0 {
        let v6 = a
            .addrs
            .iter()
            .any(|text| text.parse::<std::net::Ipv6Addr>().is_ok());
        let any: std::net::IpAddr = if v6 {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        };
        return Ok(vec![SocketAddr::new(any, port)]);
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// One attempt to establish an association: the outcome of `connect` if it
/// has one within `limit`, a timeout otherwise. Dropping the attempt (the
/// limit, a shutdown) closes its socket.
pub(crate) async fn attempt<T>(
    connect: impl std::future::Future<Output = std::result::Result<T, async_sctp::SctpError>>,
    limit: Duration,
) -> std::result::Result<T, (dial::Failure, String)> {
    match tokio::time::timeout(limit, connect).await {
        Ok(Ok(established)) => Ok(established),
        Ok(Err(error)) => Err((failure(&error), error.to_string())),
        Err(_) => Err((
            dial::Failure::Timeout,
            format!("no answer within {limit:?}"),
        )),
    }
}

/// Why a connect failed, for the `reason` of the failure counter.
fn failure(error: &async_sctp::SctpError) -> dial::Failure {
    use std::io::ErrorKind;
    // The values every Linux architecture with the generic errno numbers
    // has for ENETDOWN, ENETUNREACH, EHOSTDOWN and EHOSTUNREACH. Elsewhere
    // such an error is counted as `other`, and logged with its text.
    const UNREACHABLE: [i32; 4] = [100, 101, 112, 113];
    match error {
        async_sctp::SctpError::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused => dial::Failure::Refused,
            ErrorKind::TimedOut => dial::Failure::Timeout,
            ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable | ErrorKind::PermissionDenied => {
                dial::Failure::Local
            }
            _ if io.raw_os_error().is_some_and(|n| UNREACHABLE.contains(&n)) => {
                dial::Failure::Unreachable
            }
            _ => dial::Failure::Other,
        },
        async_sctp::SctpError::InvalidAddress(_) => dial::Failure::Local,
        _ => dial::Failure::Other,
    }
}

/// Puts the back-off gauge of an association back to zero when its task
/// ends, however it ends.
struct BackoffGauge(String);

impl Drop for BackoffGauge {
    fn drop(&mut self) {
        metrics::set_dial_backoff(&self.0, Duration::ZERO);
    }
}

/// The task of one `client` association: dial it, serve it until it ends,
/// wait, and dial again, as [`dial::Dial`] says, until the node stops.
async fn dial_association(dialled: Dialled, ctx: TaskCtx, mut shutdown: watch::Receiver<bool>) {
    let Dialled {
        slot,
        peer,
        local,
        settings,
        sctp,
        membership,
    } = dialled;
    let id = slot.id.clone();
    let _gauge = BackoffGauge(id.clone());
    let mut machine = dial::Dial::new(settings, dial::Jitter::for_association(&id));
    let mut actions = machine.handle(dial::Input::Start, Instant::now());
    let mut established: Option<Arc<SctpAssociation>> = None;
    let mut error = String::new();
    loop {
        let mut input = None;
        for action in actions {
            match action {
                dial::Action::Log(line) => match line {
                    dial::Line::Established { failed } => {
                        let after = if failed > 0 {
                            format!(" after {failed} attempt(s) that failed")
                        } else {
                            String::new()
                        };
                        eprintln!(
                            "siphon-sigtran: association `{id}` is established with {peer:?}{after}"
                        );
                    }
                    dial::Line::Failing {
                        reason,
                        quiet,
                        next,
                    } => {
                        let more = if quiet > 0 {
                            format!(" ({quiet} more attempt(s) failed since the last line)")
                        } else {
                            String::new()
                        };
                        eprintln!(
                            "siphon-sigtran: association `{id}`: dialling {peer:?} failed ({}): {error}; \
                             the next attempt is in {next:?}{more}",
                            reason.label()
                        );
                    }
                    dial::Line::Lost { up, next } => eprintln!(
                        "siphon-sigtran: association `{id}` ended after {up:?}; it is dialled again in {next:?}"
                    ),
                },
                dial::Action::Connect => {
                    metrics::set_dial_backoff(&id, Duration::ZERO);
                    metrics::dial_attempt(&id);
                    let connect = SctpAssociation::connect_from(&local, &peer, &sctp);
                    let outcome = tokio::select! {
                        _ = shutdown.changed() => return,
                        outcome = attempt(connect, settings.connect_timeout) => outcome,
                    };
                    input = Some(match outcome {
                        Ok(association) => {
                            established = Some(Arc::new(association));
                            dial::Input::Connected
                        }
                        Err((reason, text)) => {
                            metrics::dial_failure(&id, reason);
                            error = text;
                            dial::Input::Failed(reason)
                        }
                    });
                }
                dial::Action::Wait(wait) => {
                    metrics::set_dial_backoff(&id, wait);
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        _ = tokio::time::sleep(wait) => {}
                    }
                    input = Some(dial::Input::Elapsed);
                }
                dial::Action::Serve => {
                    if let Some(association) = established.take() {
                        serve_dialled(association, &slot, membership, &ctx, &shutdown).await;
                    }
                    if *shutdown.borrow() || shutdown.has_changed().is_err() {
                        return;
                    }
                    input = Some(dial::Input::Lost);
                }
            }
        }
        let Some(input) = input else {
            return;
        };
        actions = machine.handle(input, Instant::now());
    }
}

/// Serve an association this node dialled until it ends: the ASP Up and ASP
/// Active sequence, or the alignment and the test of the link, run as on any
/// other first association.
async fn serve_dialled(
    association: Arc<SctpAssociation>,
    slot: &Arc<registry::AssocSlot>,
    membership: Option<(u32, crate::config::TrafficMode)>,
    ctx: &TaskCtx,
    shutdown: &watch::Receiver<bool>,
) {
    let Some(occupancy) = slot.occupy(&association) else {
        // Only this task dials the association: it cannot have one already.
        eprintln!(
            "siphon-sigtran: association `{}` has an association already, the new one is closed",
            slot.id
        );
        return;
    };
    // Not an egress by being established: the adaptation layer makes it one.
    ctx.registry.quiesce(slot);
    slot.set_sender(association.clone());
    ctx.registry.recompute(&ctx.router);
    let (slot, ctx, shutdown) = (slot.clone(), ctx.clone(), shutdown.clone());
    match slot.adaptation {
        Adaptation::M3ua => m3ua::run_asp(association, slot, ctx, shutdown).await,
        Adaptation::Sua => sua::run_asp(association, slot, membership, ctx, shutdown).await,
        Adaptation::M2pa => m2pa::run_link(association, slot, ctx, shutdown).await,
    }
    drop(occupancy);
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_sctp::SctpError;
    use std::io;

    fn refused() -> SctpError {
        SctpError::Io(io::Error::from(io::ErrorKind::ConnectionRefused))
    }

    /// An attempt ends with what the connect says, or with a timeout when
    /// the connect says nothing: a far end that answers no INIT.
    #[tokio::test]
    async fn an_attempt_ends_with_the_outcome_of_the_connect_or_at_its_limit() {
        let limit = Duration::from_millis(250);

        let up = attempt(async { Ok::<_, SctpError>(7u8) }, limit).await;
        assert_eq!(up.ok(), Some(7));

        let said_no = attempt(async { Err::<u8, _>(refused()) }, limit).await;
        assert_eq!(
            said_no.err().map(|(reason, _)| reason),
            Some(dial::Failure::Refused)
        );

        let began = Instant::now();
        let silent = attempt(
            std::future::pending::<std::result::Result<u8, SctpError>>(),
            limit,
        )
        .await
        .err();
        let waited = began.elapsed();
        assert!(waited >= limit, "given up before the limit: {waited:?}");
        assert!(waited < limit * 8, "given up long after it: {waited:?}");
        let (reason, text) = silent.expect("a failure");
        assert_eq!(reason, dial::Failure::Timeout);
        assert!(text.contains("250ms"), "{text}");
    }

    #[test]
    fn a_failed_connect_is_counted_by_what_went_wrong() {
        let os = |number: i32| SctpError::Io(io::Error::from_raw_os_error(number));
        let kind = |kind: io::ErrorKind| SctpError::Io(io::Error::from(kind));
        // (the error of the connect, the reason it is counted as)
        let table = [
            (refused(), dial::Failure::Refused),
            (kind(io::ErrorKind::TimedOut), dial::Failure::Timeout),
            (kind(io::ErrorKind::AddrInUse), dial::Failure::Local),
            (kind(io::ErrorKind::AddrNotAvailable), dial::Failure::Local),
            (kind(io::ErrorKind::PermissionDenied), dial::Failure::Local),
            (
                SctpError::InvalidAddress("two ports".to_string()),
                dial::Failure::Local,
            ),
            // ENETDOWN, ENETUNREACH, EHOSTDOWN, EHOSTUNREACH.
            (os(100), dial::Failure::Unreachable),
            (os(101), dial::Failure::Unreachable),
            (os(112), dial::Failure::Unreachable),
            (os(113), dial::Failure::Unreachable),
            (kind(io::ErrorKind::InvalidInput), dial::Failure::Other),
            (SctpError::NotConnected, dial::Failure::Other),
            (SctpError::PeerShutdown, dial::Failure::Other),
        ];
        for (error, reason) in table {
            assert_eq!(failure(&error), reason, "{error}");
        }
    }

    #[test]
    fn a_client_is_dialled_from_its_local_addresses_or_from_any() {
        let association = |keys: &str| {
            let yaml = format!(
                "node: {{ point_code: 1000, variant: ITU }}\nassociations:\n  - {{ id: c, adaptation: m3ua, role: client, {keys} }}\n"
            );
            crate::config::Config::parse(&yaml)
                .map(|cfg| cfg.associations[0].clone())
                .map_err(|e| e.to_string())
        };
        // (the keys, the addresses the socket is bound to)
        let table: [(&str, &[&str]); 5] = [
            ("addrs: [192.0.2.1], port: 2905", &[]),
            (
                "addrs: [192.0.2.1], port: 2905, local_addrs: [192.0.2.7, 198.51.100.7]",
                &["192.0.2.7:0", "198.51.100.7:0"],
            ),
            (
                "addrs: [192.0.2.1], port: 2905, local_addrs: [192.0.2.7], local_port: 2906",
                &["192.0.2.7:2906"],
            ),
            // The port alone: every address of the family of the far end.
            (
                "addrs: [192.0.2.1], port: 2905, local_port: 2906",
                &["0.0.0.0:2906"],
            ),
            (
                "addrs: [\"2001:db8::1\"], port: 2905, local_port: 2906",
                &["[::]:2906"],
            ),
        ];
        for (keys, expected) in table {
            let a = association(keys).unwrap_or_else(|e| panic!("{keys}: {e}"));
            let bound: Vec<String> = local_addrs(&a)
                .unwrap_or_else(|e| panic!("{keys}: {e}"))
                .iter()
                .map(|addr| addr.to_string())
                .collect();
            assert_eq!(bound, expected, "{keys}");
        }
    }
}
