//! ASP and AS state maintenance of a signalling gateway (RFC 4666 4.3), without
//! I/O.
//!
//! [`Aspm`] holds the state of every ASP in every Application Server it is
//! configured in (Figure 3 of the RFC) and the state of every Application
//! Server (Figure 4). It owns no socket and no clock: the caller reports an
//! [`Input`] (an ASP state maintenance or traffic maintenance message arrived,
//! an association was lost, the recovery timer ran out) and gets [`Action`]s
//! back: messages to send, the timer to start or stop, and the state changes
//! the transfer path has to follow.
//!
//! What it implements, by clause:
//!
//! * **ASP Up and ASP Down** (4.3.4.1, 4.3.4.2): always acknowledged; an ASP
//!   Up from an ASP that is active is acknowledged, answered with Error
//!   ("Unexpected Message") and takes the ASP out of traffic.
//! * **ASP Active** (4.3.4.3): the Routing Contexts are checked against the
//!   Application Servers the ASP is configured in, the Traffic Mode Type
//!   against the mode of each; in an Override server the ASP that was active
//!   is displaced and told ("Alternate ASP Active").
//! * **ASP Inactive** (4.3.4.4) and the recovery timer T(r): the server whose
//!   last active ASP left is pending until T(r) runs out.
//! * **Notify** (4.3.4.5): every change of the state of a server is told to
//!   its ASPs that are not down, after the acknowledgement it follows from;
//!   an ASP that comes up is told the state the server is in; the failure of
//!   an ASP is told to the others.
//!
//! The same machine follows the Application Servers this node reaches as an
//! ASP itself (a `client` association): there the far end acknowledges, and
//! the `Peer…` inputs report what it acknowledged. Nothing is sent to such an
//! association from here, and its server is never pending.

use std::time::Duration;

use crate::config::{Adaptation, Association, Role, Tenant, TrafficMode};

/// An ASP, by its position in [`Layout::asps`].
pub type AspId = usize;
/// An Application Server, by its position in [`Layout::servers`] (which is
/// its position in the configuration).
pub type ServerId = usize;

/// One Application Server as the configuration has it.
#[derive(Debug, Clone)]
pub struct ServerSpec {
    /// Its name.
    pub name: String,
    /// The Routing Context that identifies it.
    pub routing_context: u32,
    /// Its traffic mode.
    pub mode: TrafficMode,
    /// The ASPs configured in it. Empty for a server this layer does not
    /// manage (one served over another adaptation).
    pub asps: Vec<AspId>,
    /// "n", the number of ASPs that have to be active before the server is
    /// (4.3.2). 1 for an Override server.
    pub required: usize,
    /// T(r). `None` when the server is never pending: the timer is switched
    /// off, or this node is not the signalling gateway of the server.
    pub recovery: Option<Duration>,
}

/// One ASP as the configuration has it: an M3UA association.
#[derive(Debug, Clone)]
pub struct AspSpec {
    /// The association, which names it.
    pub name: String,
    /// The servers it is configured in.
    pub servers: Vec<ServerId>,
    /// The far end is the ASP and this node its signalling gateway (a
    /// `server` association). Otherwise this node is the ASP.
    pub gateway: bool,
}

/// The ASPs and Application Servers of a routing domain.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// Every M3UA association.
    pub asps: Vec<AspSpec>,
    /// Every Application Server, in configuration order.
    pub servers: Vec<ServerSpec>,
}

impl Layout {
    /// The layout of one tenant of the configuration.
    pub fn build(tenant: &Tenant, associations: &[Association]) -> Self {
        let mut asps: Vec<AspSpec> = associations
            .iter()
            .filter(|a| a.adaptation == Adaptation::M3ua)
            .map(|a| AspSpec {
                name: a.id.clone(),
                servers: Vec::new(),
                gateway: a.role == Role::Server,
            })
            .collect();
        let mut servers = Vec::new();
        for (index, server) in tenant.application_servers.iter().enumerate() {
            let members: Vec<AspId> = server
                .asps
                .iter()
                .filter_map(|id| asps.iter().position(|a| a.name == *id))
                .collect();
            for asp in &members {
                asps[*asp].servers.push(index);
            }
            let gateway = members.iter().any(|asp| asps[*asp].gateway);
            servers.push(ServerSpec {
                name: server.name.clone(),
                routing_context: server.routing_context,
                mode: server.traffic_mode,
                required: server.required_asps.max(1),
                recovery: (gateway && server.recovery_ms > 0)
                    .then(|| Duration::from_millis(server.recovery_ms)),
                asps: members,
            });
        }
        Self { asps, servers }
    }
}

/// The state of an ASP in one Application Server (RFC 4666 4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AspState {
    /// ASP-DOWN.
    Down,
    /// ASP-INACTIVE.
    Inactive,
    /// ASP-ACTIVE.
    Active,
}

/// The state of an Application Server (RFC 4666 4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsState {
    /// AS-DOWN.
    Down,
    /// AS-INACTIVE.
    Inactive,
    /// AS-ACTIVE.
    Active,
    /// AS-PENDING: the last active ASP left and T(r) runs.
    Pending,
}

impl AsState {
    /// The state as a label of a metric and a log line.
    pub fn label(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Pending => "pending",
        }
    }
}

/// What a Notify says (RFC 4666 3.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// AS-State_Change, AS-INACTIVE.
    AsInactive,
    /// AS-State_Change, AS-ACTIVE.
    AsActive,
    /// AS-State_Change, AS-PENDING.
    AsPending,
    /// Other, Insufficient ASP Resources Active in AS.
    InsufficientResources,
    /// Other, Alternate ASP Active.
    AlternateAspActive,
    /// Other, ASP Failure.
    AspFailure,
}

impl Status {
    /// Every status, for the counters.
    pub const ALL: [Status; 6] = [
        Self::AsInactive,
        Self::AsActive,
        Self::AsPending,
        Self::InsufficientResources,
        Self::AlternateAspActive,
        Self::AspFailure,
    ];

    /// The Status Type and Status Information of the Notify.
    pub fn code(self) -> (u16, u16) {
        use ::m3ua::status as s;
        match self {
            Self::AsInactive => (s::AS_STATE_CHANGE, s::AS_INACTIVE),
            Self::AsActive => (s::AS_STATE_CHANGE, s::AS_ACTIVE),
            Self::AsPending => (s::AS_STATE_CHANGE, s::AS_PENDING),
            Self::InsufficientResources => (s::OTHER, s::INSUFFICIENT_ASP_RESOURCES),
            Self::AlternateAspActive => (s::OTHER, s::ALTERNATE_ASP_ACTIVE),
            Self::AspFailure => (s::OTHER, s::ASP_FAILURE),
        }
    }

    /// The status a Notify carries, if it is one this layer knows.
    pub fn from_code(code: (u16, u16)) -> Option<Self> {
        Self::ALL.into_iter().find(|status| status.code() == code)
    }

    /// The status as a label of a metric and a log line.
    pub fn label(self) -> &'static str {
        match self {
            Self::AsInactive => "as-inactive",
            Self::AsActive => "as-active",
            Self::AsPending => "as-pending",
            Self::InsufficientResources => "insufficient-asp-resources",
            Self::AlternateAspActive => "alternate-asp-active",
            Self::AspFailure => "asp-failure",
        }
    }

    fn of(state: AsState) -> Option<Self> {
        match state {
            AsState::Down => None,
            AsState::Inactive => Some(Self::AsInactive),
            AsState::Active => Some(Self::AsActive),
            AsState::Pending => Some(Self::AsPending),
        }
    }
}

/// A message this layer has sent to an ASP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// ASP Up Ack.
    UpAck,
    /// ASP Down Ack.
    DownAck,
    /// ASP Active Ack, reflecting the Traffic Mode Type of the request and
    /// naming the Routing Contexts acknowledged (none when the request named
    /// none).
    ActiveAck {
        /// The Traffic Mode Type the request carried.
        mode: Option<u32>,
        /// The Routing Contexts acknowledged.
        contexts: Vec<u32>,
    },
    /// ASP Inactive Ack.
    InactiveAck {
        /// The Routing Contexts acknowledged.
        contexts: Vec<u32>,
    },
    /// Notify.
    Notify {
        /// What it says.
        status: Status,
        /// The ASP Identifier of the ASP it is about: the alternate ASP, or
        /// the one that failed.
        asp_identifier: Option<u32>,
        /// The Routing Context of the server it is about.
        context: u32,
    },
    /// Error.
    Error {
        /// The Error Code (RFC 4666 3.8.1).
        code: u32,
        /// The Routing Contexts the error is about.
        contexts: Vec<u32>,
    },
}

/// The timer of this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Timer {
    /// T(r) of an Application Server.
    Recovery(ServerId),
}

/// What happened, as the caller reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// ASP Up arrived.
    Up {
        /// The ASP it came from.
        asp: AspId,
        /// Its ASP Identifier parameter.
        identifier: Option<u32>,
    },
    /// ASP Down arrived.
    Down {
        /// The ASP it came from.
        asp: AspId,
    },
    /// ASP Active arrived.
    Active {
        /// The ASP it came from.
        asp: AspId,
        /// Its Traffic Mode Type parameter.
        mode: Option<u32>,
        /// Its Routing Context parameter; `None` when it had none.
        contexts: Option<Vec<u32>>,
    },
    /// ASP Inactive arrived.
    Inactive {
        /// The ASP it came from.
        asp: AspId,
        /// Its Routing Context parameter; `None` when it had none.
        contexts: Option<Vec<u32>>,
    },
    /// The association of an ASP was lost or restarted (SCTP CDI, SCTP RI).
    Lost {
        /// The ASP.
        asp: AspId,
    },
    /// The signalling gateway at the far end acknowledged this node's ASP Up.
    PeerUp {
        /// The association this node is the ASP of.
        asp: AspId,
    },
    /// The far end acknowledged this node's ASP Active.
    PeerActive {
        /// The association this node is the ASP of.
        asp: AspId,
        /// The Routing Contexts it acknowledged; `None` for all.
        contexts: Option<Vec<u32>>,
    },
    /// The far end has this node inactive: it acknowledged an ASP Inactive, or
    /// said that an alternate ASP is active.
    PeerInactive {
        /// The association this node is the ASP of.
        asp: AspId,
        /// The Routing Contexts concerned; `None` for all.
        contexts: Option<Vec<u32>>,
    },
    /// The timer ran out.
    Timeout(Timer),
}

/// What the caller has to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a message to an ASP.
    Send {
        /// The ASP.
        asp: AspId,
        /// The message.
        message: Message,
    },
    /// Start, or restart, a timer.
    Start(Timer, Duration),
    /// Stop a timer.
    Stop(Timer),
    /// The state of an ASP in a server changed.
    Asp {
        /// The ASP.
        asp: AspId,
        /// The server.
        server: ServerId,
        /// Its state there now.
        state: AspState,
    },
    /// The state of a server changed. Traffic for it is sent while it is
    /// active, queued while it is pending, and has no route otherwise.
    Server {
        /// The server.
        server: ServerId,
        /// Its state now.
        state: AsState,
    },
    /// An ASP became active in a server: it is owed the destinations that
    /// are not available (RFC 4666 4.5.1).
    Activated {
        /// The ASP.
        asp: AspId,
        /// The server.
        server: ServerId,
    },
}

#[derive(Debug, Clone)]
struct AspEntry {
    up: bool,
    identifier: Option<u32>,
    /// Active in the server at the same position of [`AspSpec::servers`].
    active: Vec<bool>,
}

/// ASP and AS state maintenance of one routing domain. See the module
/// documentation.
#[derive(Debug)]
pub struct Aspm {
    layout: Layout,
    asps: Vec<AspEntry>,
    servers: Vec<AsState>,
    out: Vec<Action>,
}

impl Aspm {
    /// The state maintenance of a domain in which every ASP is down.
    pub fn new(layout: Layout) -> Self {
        Self {
            asps: layout
                .asps
                .iter()
                .map(|a| AspEntry {
                    up: false,
                    identifier: None,
                    active: vec![false; a.servers.len()],
                })
                .collect(),
            servers: vec![AsState::Down; layout.servers.len()],
            out: Vec::new(),
            layout,
        }
    }

    /// The domain this was built for.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The state of an Application Server.
    pub fn server_state(&self, server: ServerId) -> AsState {
        self.servers.get(server).copied().unwrap_or(AsState::Down)
    }

    /// The state of an ASP in an Application Server it is configured in.
    pub fn asp_state(&self, asp: AspId, server: ServerId) -> AspState {
        let Some(entry) = self.asps.get(asp) else {
            return AspState::Down;
        };
        if !entry.up {
            return AspState::Down;
        }
        match self.position(asp, server) {
            Some(position) if entry.active[position] => AspState::Active,
            _ => AspState::Inactive,
        }
    }

    /// One event in, the actions it calls for out.
    pub fn handle(&mut self, input: Input) -> Vec<Action> {
        match input {
            Input::Up { asp, identifier } if self.known(asp) => self.up(asp, identifier),
            Input::Down { asp } if self.known(asp) => self.down(asp),
            Input::Active {
                asp,
                mode,
                contexts,
            } if self.known(asp) => self.active(asp, mode, contexts),
            Input::Inactive { asp, contexts } if self.known(asp) => self.inactive(asp, contexts),
            Input::Lost { asp } if self.known(asp) => self.lost(asp),
            Input::PeerUp { asp } if self.known(asp) => {
                if !self.asps[asp].up {
                    self.bring_up(asp, None);
                }
            }
            Input::PeerActive { asp, contexts } if self.known(asp) => {
                if self.asps[asp].up {
                    for server in self.concerned(asp, contexts.as_deref()) {
                        self.activate(asp, server);
                    }
                }
            }
            Input::PeerInactive { asp, contexts } if self.known(asp) => {
                for server in self.concerned(asp, contexts.as_deref()) {
                    self.deactivate(asp, server);
                }
            }
            Input::Timeout(Timer::Recovery(server)) if server < self.servers.len() => {
                self.recovery_expired(server)
            }
            // An ASP or a server this domain does not have.
            _ => {}
        }
        std::mem::take(&mut self.out)
    }

    // ── Reading the layout ───────────────────────────────────────────────────

    fn known(&self, asp: AspId) -> bool {
        asp < self.asps.len()
    }

    /// Where `server` is in the list of servers of `asp`.
    fn position(&self, asp: AspId, server: ServerId) -> Option<usize> {
        self.layout.asps[asp]
            .servers
            .iter()
            .position(|s| *s == server)
    }

    fn is_active(&self, asp: AspId, server: ServerId) -> bool {
        self.asp_state(asp, server) == AspState::Active
    }

    fn anywhere_active(&self, asp: AspId) -> bool {
        self.asps[asp].up && self.asps[asp].active.iter().any(|on| *on)
    }

    /// The ASPs of a server that are active, and those that are inactive.
    fn counts(&self, server: ServerId) -> (usize, usize) {
        let members = &self.layout.servers[server].asps;
        let active = members
            .iter()
            .filter(|a| self.is_active(**a, server))
            .count();
        let up = members.iter().filter(|a| self.asps[**a].up).count();
        (active, up - active)
    }

    /// The servers a request without Routing Contexts, or with these, is
    /// about, among those the ASP is configured in. Contexts it is not
    /// configured in are left out.
    fn concerned(&self, asp: AspId, contexts: Option<&[u32]>) -> Vec<ServerId> {
        let servers = &self.layout.asps[asp].servers;
        match contexts {
            None => servers.clone(),
            Some(wanted) => servers
                .iter()
                .copied()
                .filter(|s| wanted.contains(&self.layout.servers[*s].routing_context))
                .collect(),
        }
    }

    /// The Routing Contexts of a request that the ASP is not configured in.
    fn unconfigured(&self, asp: AspId, contexts: Option<&[u32]>) -> Vec<u32> {
        let servers = &self.layout.asps[asp].servers;
        contexts
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(|rc| {
                !servers
                    .iter()
                    .any(|s| self.layout.servers[*s].routing_context == *rc)
            })
            .collect()
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Send to an ASP this node is the signalling gateway of. Nothing is sent
    /// from here on an association where this node is the ASP.
    fn send(&mut self, asp: AspId, message: Message) {
        if self.layout.asps[asp].gateway {
            self.out.push(Action::Send { asp, message });
        }
    }

    fn error(&mut self, asp: AspId, code: u32, contexts: Vec<u32>) {
        self.send(asp, Message::Error { code, contexts });
    }

    /// 4.3.4.5: "A Notify message reflecting a change in the AS state MUST be
    /// sent to all ASPs in the AS, except those in the ASP-DOWN state". `to`
    /// narrows that further.
    fn notify(
        &mut self,
        server: ServerId,
        status: Status,
        about: Option<AspId>,
        to: impl Fn(&Self, AspId) -> bool,
    ) {
        let context = self.layout.servers[server].routing_context;
        let asp_identifier = about.and_then(|asp| self.asps[asp].identifier);
        for asp in self.layout.servers[server].asps.clone() {
            if self.asps[asp].up && to(self, asp) {
                self.send(
                    asp,
                    Message::Notify {
                        status,
                        asp_identifier,
                        context,
                    },
                );
            }
        }
    }

    // ── State of an ASP ──────────────────────────────────────────────────────

    fn bring_up(&mut self, asp: AspId, identifier: Option<u32>) {
        self.asps[asp].up = true;
        self.asps[asp].identifier = identifier;
        for server in self.layout.asps[asp].servers.clone() {
            self.out.push(Action::Asp {
                asp,
                server,
                state: AspState::Inactive,
            });
            // 4.3.4.5: "When an ASP moves from ASP-DOWN to ASP-INACTIVE
            // within a particular AS, a Notify message SHOULD be sent, by the
            // ASP-UP receptor, after sending the ASP-UP-ACK, in order to
            // inform the ASP of the current AS state."
            if !self.evaluate(server) {
                if let Some(status) = Status::of(self.servers[server]) {
                    self.notify(server, status, None, |_, other| other == asp);
                }
            }
        }
    }

    /// Take an ASP down in every server. `failed` when its association was
    /// lost, which the other ASPs are told.
    fn take_down(&mut self, asp: AspId, failed: bool) {
        if !self.asps[asp].up {
            return;
        }
        // The identifier is read by the failure notice before it is dropped.
        for server in self.layout.asps[asp].servers.clone() {
            if let Some(position) = self.position(asp, server) {
                self.asps[asp].active[position] = false;
            }
        }
        self.asps[asp].up = false;
        for server in self.layout.asps[asp].servers.clone() {
            self.out.push(Action::Asp {
                asp,
                server,
                state: AspState::Down,
            });
            if failed {
                self.notify(server, Status::AspFailure, Some(asp), |_, _| true);
            }
            self.evaluate(server);
            self.resources(server);
        }
        self.asps[asp].identifier = None;
    }

    fn activate(&mut self, asp: AspId, server: ServerId) {
        let Some(position) = self.position(asp, server) else {
            return;
        };
        if self.asps[asp].active[position] {
            return;
        }
        // 4.3.4.3: "In the case of an Override mode AS, receipt of an ASP
        // Active message at an SGP causes the (re)direction of all traffic
        // for the AS to the ASP that sent the ASP Active message. Any
        // previously active ASP in the AS is now considered to be in the
        // state ASP-INACTIVE ... The SGP or IPSP then MUST send a Notify
        // message ("Alternate ASP_Active") to the previously active ASP".
        let displaced: Vec<AspId> = if self.layout.servers[server].mode == TrafficMode::Override {
            self.layout.servers[server]
                .asps
                .iter()
                .copied()
                .filter(|other| *other != asp && self.is_active(*other, server))
                .collect()
        } else {
            Vec::new()
        };
        self.asps[asp].active[position] = true;
        self.out.push(Action::Asp {
            asp,
            server,
            state: AspState::Active,
        });
        for other in displaced {
            if let Some(position) = self.position(other, server) {
                self.asps[other].active[position] = false;
            }
            self.out.push(Action::Asp {
                asp: other,
                server,
                state: AspState::Inactive,
            });
            self.notify(server, Status::AlternateAspActive, Some(asp), |_, to| {
                to == other
            });
        }
        self.evaluate(server);
        self.out.push(Action::Activated { asp, server });
    }

    fn deactivate(&mut self, asp: AspId, server: ServerId) {
        let Some(position) = self.position(asp, server) else {
            return;
        };
        if !self.asps[asp].up || !self.asps[asp].active[position] {
            return;
        }
        self.asps[asp].active[position] = false;
        self.out.push(Action::Asp {
            asp,
            server,
            state: AspState::Inactive,
        });
        self.evaluate(server);
        self.resources(server);
    }

    // ── State of a server ────────────────────────────────────────────────────

    /// Move a server to the state its ASPs put it in (Figure 4), and tell its
    /// ASPs if that is another one. Returns whether it changed.
    fn evaluate(&mut self, server: ServerId) -> bool {
        let spec = &self.layout.servers[server];
        let (active, inactive) = self.counts(server);
        let old = self.servers[server];
        let new = match old {
            // DN2IA, IA2DN, IA2AC.
            AsState::Down | AsState::Inactive => {
                if active >= spec.required {
                    AsState::Active
                } else if active + inactive > 0 {
                    AsState::Inactive
                } else {
                    AsState::Down
                }
            }
            // "an AS keeps the AS-ACTIVE state till the last ASP turns to
            // another state different from ASP-ACTIVE"; then AC2PN.
            AsState::Active if active > 0 => AsState::Active,
            AsState::Active if spec.recovery.is_some() => AsState::Pending,
            AsState::Active if inactive > 0 => AsState::Inactive,
            AsState::Active => AsState::Down,
            // PN2AC; PN2IA and PN2DN wait for T(r).
            AsState::Pending if active > 0 => AsState::Active,
            AsState::Pending => AsState::Pending,
        };
        if new == old {
            return false;
        }
        let recovery = spec.recovery;
        self.servers[server] = new;
        if old == AsState::Pending {
            self.out.push(Action::Stop(Timer::Recovery(server)));
        }
        if let (AsState::Pending, Some(after)) = (new, recovery) {
            self.out.push(Action::Start(Timer::Recovery(server), after));
        }
        self.out.push(Action::Server { server, state: new });
        if let Some(status) = Status::of(new) {
            self.notify(server, status, None, |_, _| true);
        }
        true
    }

    /// 4.3.4.4: "A Notify message ("Insufficient ASP resources active in AS")
    /// MAY be sent to all inactive ASPs, if required", in a Loadshare or
    /// Broadcast server that has fewer active ASPs than it needs.
    fn resources(&mut self, server: ServerId) {
        let spec = &self.layout.servers[server];
        let (active, _) = self.counts(server);
        if spec.mode != TrafficMode::Override
            && self.servers[server] == AsState::Active
            && active < spec.required
        {
            self.notify(server, Status::InsufficientResources, None, |this, asp| {
                !this.is_active(asp, server)
            });
        }
    }

    /// 4.3.2: "If T(r) expires before an ASP becomes ASP-ACTIVE ... The AS
    /// will move to the AS-INACTIVE state if at least one ASP is in
    /// ASP-INACTIVE; otherwise, it will move to AS-DOWN state."
    fn recovery_expired(&mut self, server: ServerId) {
        if self.servers[server] != AsState::Pending {
            return;
        }
        let (_, inactive) = self.counts(server);
        let new = if inactive > 0 {
            AsState::Inactive
        } else {
            AsState::Down
        };
        self.servers[server] = new;
        self.out.push(Action::Server { server, state: new });
        if let Some(status) = Status::of(new) {
            self.notify(server, status, None, |_, _| true);
        }
    }

    // ── Requests of an ASP ───────────────────────────────────────────────────

    fn up(&mut self, asp: AspId, identifier: Option<u32>) {
        // 4.3.4.1: "The SGP MUST send an ASP Up Ack message in response to a
        // received ASP Up message even if the ASP is already marked as
        // ASP-INACTIVE at the SGP."
        self.send(asp, Message::UpAck);
        if !self.asps[asp].up {
            self.bring_up(asp, identifier);
            return;
        }
        if self.anywhere_active(asp) {
            // "If an ASP Up message is received and, internally, the remote
            // ASP is in the ASP-ACTIVE state, an ASP Up Ack message is
            // returned, as well as an Error message ("Unexpected Message").
            // In addition, the remote ASP state is changed to ASP-INACTIVE in
            // all relevant Application Servers".
            self.error(asp, ::m3ua::error_code::UNEXPECTED_MESSAGE, Vec::new());
            for server in self.layout.asps[asp].servers.clone() {
                self.deactivate(asp, server);
            }
        }
        if identifier.is_some() {
            self.asps[asp].identifier = identifier;
        }
    }

    fn down(&mut self, asp: AspId) {
        // 4.3.4.2: "The SGP MUST send an ASP Down Ack message in response to
        // a received ASP Down message from the ASP even if the ASP is already
        // marked as ASP-DOWN at the SGP."
        self.send(asp, Message::DownAck);
        self.take_down(asp, false);
    }

    fn lost(&mut self, asp: AspId) {
        self.take_down(asp, true);
    }

    /// Answer what a request with these Routing Contexts cannot be about.
    /// `None` when nothing of it can be acted on.
    fn admitted(&mut self, asp: AspId, contexts: Option<&[u32]>) -> Option<Vec<ServerId>> {
        use ::m3ua::error_code as code;
        if !self.asps[asp].up {
            // 3.8.1: a message "that is not expected in the current state".
            // "If the Unexpected message contained Routing Contexts, the
            // Routing Contexts SHOULD be included in the Error message."
            self.error(
                asp,
                code::UNEXPECTED_MESSAGE,
                contexts.unwrap_or_default().to_vec(),
            );
            return None;
        }
        // 3.8.1: "The "Invalid Routing Context" error is sent if a message is
        // received from a peer with an invalid (unconfigured) Routing Context
        // value. For this error, the invalid Routing Context(s) MUST be
        // included in the Error message."
        let unconfigured = self.unconfigured(asp, contexts);
        if !unconfigured.is_empty() {
            self.error(asp, code::INVALID_ROUTING_CONTEXT, unconfigured);
        }
        let servers = self.concerned(asp, contexts);
        if servers.is_empty() && contexts.is_none() {
            // "The "No Configured AS for ASP" error is sent if a message is
            // received from a peer without a Routing Context parameter and it
            // is not known by configuration data which Application Servers
            // are referenced."
            self.error(asp, code::NO_CONFIGURED_AS_FOR_ASP, Vec::new());
        }
        (!servers.is_empty()).then_some(servers)
    }

    fn active(&mut self, asp: AspId, mode: Option<u32>, contexts: Option<Vec<u32>>) {
        use ::m3ua::error_code as code;
        let named = contexts.is_some();
        let Some(servers) = self.admitted(asp, contexts.as_deref()) else {
            return;
        };
        // 4.3.4.3: "If the SGP determines that the mode indicated in an ASP
        // Active message is unsupported or incompatible with the mode
        // currently configured for the AS, the SGP responds with an Error
        // message".
        let (accepted, refused): (Vec<ServerId>, Vec<ServerId>) = servers
            .into_iter()
            .partition(|server| mode.is_none_or_eq(mode_value(self.layout.servers[*server].mode)));
        if !refused.is_empty() {
            let contexts = refused
                .iter()
                .map(|s| self.layout.servers[*s].routing_context)
                .collect();
            self.error(asp, code::UNSUPPORTED_TRAFFIC_MODE_TYPE, contexts);
        }
        if accepted.is_empty() {
            return;
        }
        // "The Routing Context parameter MUST be included in the ASP Active
        // Ack message(s) if the received ASP Active message contained any
        // Routing Contexts." Sent also to an ASP that is active already.
        let contexts = if named {
            accepted
                .iter()
                .map(|s| self.layout.servers[*s].routing_context)
                .collect()
        } else {
            Vec::new()
        };
        self.send(asp, Message::ActiveAck { mode, contexts });
        for server in accepted {
            self.activate(asp, server);
        }
    }

    fn inactive(&mut self, asp: AspId, contexts: Option<Vec<u32>>) {
        let named = contexts.is_some();
        let Some(servers) = self.admitted(asp, contexts.as_deref()) else {
            return;
        };
        // 4.3.4.4: "An ASP Inactive message MUST always be responded to by
        // the peer", before the Notify that follows from it.
        let contexts = if named {
            servers
                .iter()
                .map(|s| self.layout.servers[*s].routing_context)
                .collect()
        } else {
            Vec::new()
        };
        self.send(asp, Message::InactiveAck { contexts });
        for server in servers {
            self.deactivate(asp, server);
        }
    }
}

/// The Traffic Mode Type value of a mode (RFC 4666 3.7.1).
pub fn mode_value(mode: TrafficMode) -> u32 {
    match mode {
        TrafficMode::Override => ::m3ua::traffic_mode::OVERRIDE,
        TrafficMode::Loadshare => ::m3ua::traffic_mode::LOADSHARE,
        TrafficMode::Broadcast => ::m3ua::traffic_mode::BROADCAST,
    }
}

/// `Option::is_none_or` came after the minimum toolchain of this crate.
trait NoneOrEq {
    fn is_none_or_eq(&self, value: u32) -> bool;
}

impl NoneOrEq for Option<u32> {
    fn is_none_or_eq(&self, value: u32) -> bool {
        match self {
            None => true,
            Some(own) => *own == value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::m3ua::error_code as code;

    const T_R: Duration = Duration::from_millis(2000);

    /// One server with these gateway ASPs, and `spare`, an ASP configured in
    /// no server.
    fn layout(mode: TrafficMode, asps: usize, required: usize) -> Layout {
        let mut all: Vec<AspSpec> = (0..asps)
            .map(|i| AspSpec {
                name: format!("asp-{i}"),
                servers: vec![0],
                gateway: true,
            })
            .collect();
        all.push(AspSpec {
            name: "spare".into(),
            servers: Vec::new(),
            gateway: true,
        });
        Layout {
            asps: all,
            servers: vec![ServerSpec {
                name: "as".into(),
                routing_context: 100,
                mode,
                asps: (0..asps).collect(),
                required,
                recovery: Some(T_R),
            }],
        }
    }

    fn machine(mode: TrafficMode, asps: usize) -> Aspm {
        Aspm::new(layout(mode, asps, 1))
    }

    fn up(asp: AspId) -> Input {
        Input::Up {
            asp,
            identifier: Some(asp as u32 + 10),
        }
    }

    fn active(asp: AspId) -> Input {
        Input::Active {
            asp,
            mode: None,
            contexts: Some(vec![100]),
        }
    }

    fn inactive(asp: AspId) -> Input {
        Input::Inactive {
            asp,
            contexts: Some(vec![100]),
        }
    }

    /// What was sent to `asp`, in order.
    fn sent(actions: &[Action], asp: AspId) -> Vec<Message> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send { asp: to, message } if *to == asp => Some(message.clone()),
                _ => None,
            })
            .collect()
    }

    fn notify(status: Status, asp_identifier: Option<u32>) -> Message {
        Message::Notify {
            status,
            asp_identifier,
            context: 100,
        }
    }

    fn ack() -> Message {
        Message::ActiveAck {
            mode: None,
            contexts: vec![100],
        }
    }

    /// Bring an ASP to a state of Figure 3.
    fn in_state(state: AspState) -> Aspm {
        let mut m = machine(TrafficMode::Loadshare, 2);
        if state != AspState::Down {
            m.handle(up(0));
        }
        if state == AspState::Active {
            m.handle(active(0));
        }
        assert_eq!(m.asp_state(0, 0), state);
        m
    }

    #[test]
    fn the_asp_state_table_of_figure_3() {
        use AspState::{Active, Down, Inactive};
        // (state, event, state after, the first message back).
        let unexpected = |contexts: Vec<u32>| Message::Error {
            code: code::UNEXPECTED_MESSAGE,
            contexts,
        };
        let table: Vec<(AspState, Input, AspState, Message)> = vec![
            // ASP-DOWN.
            (Down, up(0), Inactive, Message::UpAck),
            (Down, Input::Down { asp: 0 }, Down, Message::DownAck),
            (Down, active(0), Down, unexpected(vec![100])),
            (Down, inactive(0), Down, unexpected(vec![100])),
            // ASP-INACTIVE.
            (Inactive, up(0), Inactive, Message::UpAck),
            (Inactive, active(0), Active, ack()),
            (
                Inactive,
                inactive(0),
                Inactive,
                Message::InactiveAck {
                    contexts: vec![100],
                },
            ),
            (Inactive, Input::Down { asp: 0 }, Down, Message::DownAck),
            // ASP-ACTIVE.
            (Active, active(0), Active, ack()),
            (
                Active,
                inactive(0),
                Inactive,
                Message::InactiveAck {
                    contexts: vec![100],
                },
            ),
            (Active, Input::Down { asp: 0 }, Down, Message::DownAck),
            // 4.3.4.1: acknowledged, an Error, and inactive.
            (Active, up(0), Inactive, Message::UpAck),
        ];
        for (state, event, after, first) in table {
            let mut m = in_state(state);
            let actions = m.handle(event.clone());
            assert_eq!(m.asp_state(0, 0), after, "{state:?} on {event:?}");
            assert_eq!(
                sent(&actions, 0).first(),
                Some(&first),
                "{state:?} on {event:?}"
            );
        }
        // The loss of the association (SCTP CDI, SCTP RI) takes every state
        // to ASP-DOWN and sends the ASP nothing.
        for state in [Down, Inactive, Active] {
            let mut m = in_state(state);
            let actions = m.handle(Input::Lost { asp: 0 });
            assert_eq!(m.asp_state(0, 0), Down);
            assert!(sent(&actions, 0).is_empty());
        }
        // ASP Up while active: the Error follows the acknowledgement.
        let mut m = in_state(Active);
        assert_eq!(
            sent(&m.handle(up(0)), 0)[..2],
            [Message::UpAck, unexpected(Vec::new())]
        );
    }

    #[test]
    fn the_as_state_table_of_figure_4() {
        let mut m = machine(TrafficMode::Loadshare, 2);
        assert_eq!(m.server_state(0), AsState::Down);

        // DN2IA: "One ASP moves from ASP-DOWN to ASP-INACTIVE state."
        let actions = m.handle(up(0));
        assert_eq!(m.server_state(0), AsState::Inactive);
        assert_eq!(
            sent(&actions, 0),
            [Message::UpAck, notify(Status::AsInactive, None)]
        );

        // IA2DN: "The last ASP in ASP-INACTIVE moves to ASP-DOWN".
        m.handle(Input::Down { asp: 0 });
        assert_eq!(m.server_state(0), AsState::Down);
        m.handle(up(0));
        m.handle(up(1));

        // IA2AC: "One ASP moves to ASP-ACTIVE". Every ASP that is not down is
        // told, after the acknowledgement.
        let actions = m.handle(active(0));
        assert_eq!(m.server_state(0), AsState::Active);
        assert_eq!(sent(&actions, 0), [ack(), notify(Status::AsActive, None)]);
        assert_eq!(sent(&actions, 1), [notify(Status::AsActive, None)]);
        assert!(actions.contains(&Action::Server {
            server: 0,
            state: AsState::Active
        }));
        assert!(actions.contains(&Action::Activated { asp: 0, server: 0 }));

        // AC2PN: "The last ASP in ASP-ACTIVE state moves to ASP-INACTIVE or
        // ASP-DOWN states". T(r) starts.
        let actions = m.handle(inactive(0));
        assert_eq!(m.server_state(0), AsState::Pending);
        assert!(actions.contains(&Action::Start(Timer::Recovery(0), T_R)));
        assert_eq!(
            sent(&actions, 0),
            [
                Message::InactiveAck {
                    contexts: vec![100]
                },
                notify(Status::AsPending, None)
            ]
        );
        assert_eq!(sent(&actions, 1), [notify(Status::AsPending, None)]);

        // PN2AC: "One ASP moves to ASP-ACTIVE." T(r) stops.
        let actions = m.handle(active(1));
        assert_eq!(m.server_state(0), AsState::Active);
        assert!(actions.contains(&Action::Stop(Timer::Recovery(0))));
        assert_eq!(sent(&actions, 0), [notify(Status::AsActive, None)]);

        // PN2IA: "T(r) expiry; an ASP is in ASP-INACTIVE state but no ASPs
        // are in ASP-ACTIVE state."
        m.handle(inactive(1));
        assert_eq!(m.server_state(0), AsState::Pending);
        let actions = m.handle(Input::Timeout(Timer::Recovery(0)));
        assert_eq!(m.server_state(0), AsState::Inactive);
        assert_eq!(sent(&actions, 0), [notify(Status::AsInactive, None)]);
        assert_eq!(sent(&actions, 1), [notify(Status::AsInactive, None)]);

        // PN2DN: "T(r) expiry; all the ASPs are in ASP-DOWN state."
        m.handle(active(0));
        m.handle(Input::Down { asp: 1 });
        m.handle(Input::Down { asp: 0 });
        assert_eq!(m.server_state(0), AsState::Pending);
        let actions = m.handle(Input::Timeout(Timer::Recovery(0)));
        assert_eq!(m.server_state(0), AsState::Down);
        assert!(sent(&actions, 0).is_empty() && sent(&actions, 1).is_empty());
        // A timer that runs out in any other state changes nothing.
        assert!(m.handle(Input::Timeout(Timer::Recovery(0))).is_empty());
        assert!(m.handle(Input::Timeout(Timer::Recovery(9))).is_empty());
    }

    #[test]
    fn an_asp_that_comes_up_is_told_the_state_the_server_is_in() {
        let mut m = machine(TrafficMode::Loadshare, 2);
        m.handle(up(0));
        m.handle(active(0));
        let actions = m.handle(up(1));
        assert_eq!(
            sent(&actions, 1),
            [Message::UpAck, notify(Status::AsActive, None)]
        );
        assert!(sent(&actions, 0).is_empty(), "the state did not change");
    }

    #[test]
    fn an_override_server_has_one_active_asp() {
        let mut m = machine(TrafficMode::Override, 2);
        m.handle(up(0));
        m.handle(up(1));
        m.handle(active(0));
        // The second ASP takes over; the first is told, with the identifier
        // of the alternate ASP.
        let actions = m.handle(active(1));
        assert_eq!(m.asp_state(0, 0), AspState::Inactive);
        assert_eq!(m.asp_state(1, 0), AspState::Active);
        assert_eq!(m.server_state(0), AsState::Active);
        assert_eq!(
            sent(&actions, 0),
            [notify(Status::AlternateAspActive, Some(11))]
        );
        assert_eq!(sent(&actions, 1), [ack()]);
        assert!(actions.contains(&Action::Asp {
            asp: 0,
            server: 0,
            state: AspState::Inactive
        }));
        // 4.3.4.4: the displaced ASP's own ASP Inactive is acknowledged and
        // changes nothing.
        let actions = m.handle(inactive(0));
        assert_eq!(
            sent(&actions, 0),
            [Message::InactiveAck {
                contexts: vec![100]
            }]
        );
        assert_eq!(m.server_state(0), AsState::Active);
    }

    #[test]
    fn the_traffic_mode_of_a_request_has_to_be_that_of_the_server() {
        let mut m = machine(TrafficMode::Override, 1);
        m.handle(up(0));
        for mode in [2, 3, 0, 99] {
            let actions = m.handle(Input::Active {
                asp: 0,
                mode: Some(mode),
                contexts: Some(vec![100]),
            });
            assert_eq!(
                sent(&actions, 0),
                [Message::Error {
                    code: code::UNSUPPORTED_TRAFFIC_MODE_TYPE,
                    contexts: vec![100]
                }],
                "mode {mode}"
            );
            assert_eq!(m.asp_state(0, 0), AspState::Inactive);
        }
        // Its own mode is reflected in the acknowledgement.
        let actions = m.handle(Input::Active {
            asp: 0,
            mode: Some(1),
            contexts: Some(vec![100]),
        });
        assert_eq!(
            sent(&actions, 0)[0],
            Message::ActiveAck {
                mode: Some(1),
                contexts: vec![100]
            }
        );
        assert_eq!(mode_value(TrafficMode::Loadshare), 2);
        assert_eq!(mode_value(TrafficMode::Broadcast), 3);
    }

    #[test]
    fn a_routing_context_has_to_be_one_the_asp_is_configured_in() {
        let mut m = machine(TrafficMode::Loadshare, 1);
        m.handle(up(0));
        m.handle(up(1));
        let invalid = |contexts: Vec<u32>| Message::Error {
            code: code::INVALID_ROUTING_CONTEXT,
            contexts,
        };
        // Unknown altogether.
        let actions = m.handle(Input::Active {
            asp: 0,
            mode: None,
            contexts: Some(vec![7]),
        });
        assert_eq!(sent(&actions, 0), [invalid(vec![7])]);
        assert_eq!(m.asp_state(0, 0), AspState::Inactive);
        // One known, two not: the known one is acknowledged by itself.
        let actions = m.handle(Input::Active {
            asp: 0,
            mode: None,
            contexts: Some(vec![7, 100, 9]),
        });
        assert_eq!(sent(&actions, 0)[..2], [invalid(vec![7, 9]), ack()]);
        assert_eq!(m.asp_state(0, 0), AspState::Active);
        // ASP Inactive likewise.
        let actions = m.handle(Input::Inactive {
            asp: 0,
            contexts: Some(vec![8]),
        });
        assert_eq!(sent(&actions, 0), [invalid(vec![8])]);
        assert_eq!(m.asp_state(0, 0), AspState::Active);
        // The context of a server the ASP is not configured in is as
        // unconfigured, for that ASP, as any other.
        let spare = 1;
        let actions = m.handle(Input::Active {
            asp: spare,
            mode: None,
            contexts: Some(vec![100]),
        });
        assert_eq!(sent(&actions, spare), [invalid(vec![100])]);
        // Without a Routing Context, an ASP configured in no server cannot be
        // meant for any.
        for request in [
            Input::Active {
                asp: spare,
                mode: None,
                contexts: None,
            },
            Input::Inactive {
                asp: spare,
                contexts: None,
            },
        ] {
            assert_eq!(
                sent(&m.handle(request), spare),
                [Message::Error {
                    code: code::NO_CONFIGURED_AS_FOR_ASP,
                    contexts: Vec::new()
                }]
            );
        }
    }

    #[test]
    fn a_request_without_a_routing_context_is_for_every_server_of_the_asp() {
        let mut m = machine(TrafficMode::Loadshare, 1);
        m.handle(up(0));
        let actions = m.handle(Input::Active {
            asp: 0,
            mode: None,
            contexts: None,
        });
        assert_eq!(
            sent(&actions, 0)[0],
            Message::ActiveAck {
                mode: None,
                contexts: Vec::new()
            }
        );
        assert_eq!(m.asp_state(0, 0), AspState::Active);
        let actions = m.handle(Input::Inactive {
            asp: 0,
            contexts: None,
        });
        assert_eq!(
            sent(&actions, 0)[0],
            Message::InactiveAck {
                contexts: Vec::new()
            }
        );
        assert_eq!(m.asp_state(0, 0), AspState::Inactive);
    }

    #[test]
    fn a_lost_asp_is_reported_to_the_others_before_the_state_of_the_server() {
        let mut m = machine(TrafficMode::Loadshare, 2);
        m.handle(up(0));
        m.handle(up(1));
        m.handle(active(0));
        let actions = m.handle(Input::Lost { asp: 0 });
        assert_eq!(
            sent(&actions, 1),
            [
                notify(Status::AspFailure, Some(10)),
                notify(Status::AsPending, None)
            ]
        );
        assert!(sent(&actions, 0).is_empty());
        assert_eq!(m.server_state(0), AsState::Pending);
        // An ASP that is down already is not lost again.
        assert!(m.handle(Input::Lost { asp: 0 }).is_empty());
    }

    #[test]
    fn a_server_that_needs_two_asps_is_active_with_two_and_says_when_one_is_missing() {
        let mut m = Aspm::new(layout(TrafficMode::Loadshare, 3, 2));
        for asp in 0..3 {
            m.handle(up(asp));
        }
        // 4.3.4.3: the Notify (AS-ACTIVE) is withheld "until there are
        // sufficient resources".
        let actions = m.handle(active(0));
        assert_eq!(m.server_state(0), AsState::Inactive);
        assert_eq!(sent(&actions, 0), [ack()]);
        let actions = m.handle(active(1));
        assert_eq!(m.server_state(0), AsState::Active);
        assert_eq!(sent(&actions, 2), [notify(Status::AsActive, None)]);
        // One leaves: the server stays active, the inactive ASPs are asked.
        let actions = m.handle(inactive(1));
        assert_eq!(m.server_state(0), AsState::Active);
        let insufficient = notify(Status::InsufficientResources, None);
        assert_eq!(sent(&actions, 2), std::slice::from_ref(&insufficient));
        assert_eq!(
            sent(&actions, 1),
            [
                Message::InactiveAck {
                    contexts: vec![100]
                },
                insufficient
            ]
        );
        assert!(sent(&actions, 0).is_empty(), "the active one is not asked");
    }

    #[test]
    fn a_server_reached_as_an_asp_follows_what_the_far_end_acknowledged() {
        // This node is the ASP: nothing is sent from here, and the server is
        // never pending.
        let layout = Layout {
            asps: vec![AspSpec {
                name: "to-gateway".into(),
                servers: vec![0],
                gateway: false,
            }],
            servers: vec![ServerSpec {
                name: "remote".into(),
                routing_context: 100,
                mode: TrafficMode::Override,
                asps: vec![0],
                required: 1,
                recovery: None,
            }],
        };
        let mut m = Aspm::new(layout);
        let only_state = |actions: &[Action]| {
            actions
                .iter()
                .all(|a| !matches!(a, Action::Send { .. } | Action::Start(..)))
        };
        // An acknowledgement of ASP Active before one of ASP Up is not one.
        assert!(m
            .handle(Input::PeerActive {
                asp: 0,
                contexts: None
            })
            .is_empty());
        assert!(only_state(&m.handle(Input::PeerUp { asp: 0 })));
        assert_eq!(m.server_state(0), AsState::Inactive);
        let actions = m.handle(Input::PeerActive {
            asp: 0,
            contexts: Some(vec![100]),
        });
        assert!(only_state(&actions));
        assert_eq!(m.server_state(0), AsState::Active);
        // "Alternate ASP Active": inactive, and the server with it at once.
        let actions = m.handle(Input::PeerInactive {
            asp: 0,
            contexts: None,
        });
        assert!(only_state(&actions));
        assert_eq!(m.server_state(0), AsState::Inactive);
        m.handle(Input::PeerActive {
            asp: 0,
            contexts: None,
        });
        assert!(only_state(&m.handle(Input::Lost { asp: 0 })));
        assert_eq!(m.server_state(0), AsState::Down);
        // Requests of the far end are not this node's to answer here.
        assert!(only_state(&m.handle(up(0))));
    }

    #[test]
    fn an_input_about_an_asp_the_domain_does_not_have_is_ignored() {
        let mut m = machine(TrafficMode::Loadshare, 1);
        for input in [
            up(9),
            Input::Down { asp: 9 },
            active(9),
            inactive(9),
            Input::Lost { asp: 9 },
            Input::PeerUp { asp: 9 },
        ] {
            assert!(m.handle(input).is_empty());
        }
        assert_eq!(m.asp_state(9, 0), AspState::Down);
        assert_eq!(m.server_state(9), AsState::Down);
    }

    #[test]
    fn every_status_has_the_code_of_3_8_2() {
        let codes: Vec<(u16, u16)> = Status::ALL.iter().map(|s| s.code()).collect();
        assert_eq!(codes, [(1, 2), (1, 3), (1, 4), (2, 1), (2, 2), (2, 3)]);
        for status in Status::ALL {
            assert_eq!(Status::from_code(status.code()), Some(status));
            assert!(!status.label().is_empty());
        }
        assert_eq!(Status::from_code((1, 1)), None);
        assert_eq!(AsState::Pending.label(), "pending");
    }
}
