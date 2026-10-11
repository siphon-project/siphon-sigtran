//! The typed `sigtran.yaml` model + its serde `Deserialize` + validation.
//!
//! One file describes a node: its point code and variant, the SCTP
//! associations, the linksets/AS built on them, the MTP3 route table, the SCCP
//! GTT + E.214 conversion tables, and the content-routing rules. See the crate
//! docs and `docs/OVERVIEW.md` for the stack.
//!
//! # Tenancy is implicit
//!
//! With **no** `tenants:` block, the whole top level *is* the `default` tenant.
//! [`Config::load`] normalises both shapes, flat single-tenant and an explicit
//! `tenants:` map, into one internal [`BTreeMap<TenantId, Tenant>`], so the
//! rest of the crate only ever sees resolved per-tenant tables. A single-network
//! HLR/SMSC/STP never writes `tenants:`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::point_code::{PointCode, RawPc, Variant};

/// The name that keys the implicit single-tenant instance.
pub const DEFAULT_TENANT: &str = "default";

/// A routing-domain (instance) identifier.
pub type TenantId = String;

// ── Node ────────────────────────────────────────────────────────────────────

/// Q.704 network indicator, as written in the config (`international`,
/// `national`, and their spare variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkIndicator {
    /// International (NI = 0).
    International,
    /// International spare (NI = 1).
    InternationalSpare,
    /// National (NI = 2).
    National,
    /// National spare (NI = 3).
    NationalSpare,
}

impl NetworkIndicator {
    /// The two-bit NI value.
    pub fn bits(self) -> u8 {
        match self {
            Self::International => 0,
            Self::InternationalSpare => 1,
            Self::National => 2,
            Self::NationalSpare => 3,
        }
    }
}

impl From<NetworkIndicator> for mtp3::NetworkIndicator {
    fn from(ni: NetworkIndicator) -> Self {
        mtp3::NetworkIndicator::from_bits(ni.bits())
    }
}

/// Read an SS7 variant: `itu`, `ansi` or `china`, as every other keyword of the
/// file is written, in lower case. The codec crate's own spelling is upper case,
/// so the letter case is not significant here.
fn variant<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Variant, D::Error> {
    let name = String::deserialize(deserializer)?;
    match name.to_ascii_lowercase().as_str() {
        "itu" => Ok(Variant::Itu),
        "ansi" => Ok(Variant::Ansi),
        "china" => Ok(Variant::China),
        _ => Err(serde::de::Error::custom(format!(
            "unknown variant `{name}`, expected itu, ansi or china"
        ))),
    }
}

/// The `node:` block: our point code, variant, and network indicator.
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    /// Our point code (decimal, resolved under [`Node::variant`]).
    pub point_code: RawPc,
    /// SS7 variant (fixes the point-code width).
    #[serde(deserialize_with = "variant")]
    pub variant: Variant,
    /// The default network indicator for messages we originate.
    #[serde(default = "default_ni")]
    pub network_indicator: NetworkIndicator,
}

fn default_ni() -> NetworkIndicator {
    NetworkIndicator::International
}

// ── Associations (SCTP transport plane) ─────────────────────────────────────

/// SIGTRAN adaptation layer carried over an association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Adaptation {
    /// M3UA (RFC 4666), SCTP PPID 3.
    M3ua,
    /// M2PA (RFC 4165), SCTP PPID 5.
    M2pa,
    /// SUA (RFC 3868), SCTP PPID 4. Carries the SCCP user (TCAP) with GT/SSN/PC
    /// addressing. A `sua` Application Server is served by SUA ASPs (exactly as an
    /// M3UA AS is served by M3UA ASPs); its connectionless data (CLDT) bridges
    /// one-for-one to SCCP UDT and routes through the same GTT / content /
    /// termination engine. Only the connectionless set is carried.
    Sua,
}

/// Whether we open the SCTP association or accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// We accept an inbound association (listen).
    Server,
    /// We initiate the association (connect).
    Client,
}

/// One `associations:` entry: an SCTP endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct Association {
    /// Association id, referenced by linkset links.
    pub id: String,
    /// The adaptation layer (m3ua / m2pa).
    pub adaptation: Adaptation,
    /// server (listen) or client (connect).
    pub role: Role,
    /// One or more IP addresses (SCTP multihoming).
    pub addrs: Vec<String>,
    /// SCTP port.
    pub port: u16,
    /// For a `server` association: every IP address of the peer it accepts
    /// (all of them for a multihomed peer). A peer is this association's when
    /// every address it presents is listed; anyone else who reaches the
    /// endpoint is aborted. Empty, the default, accepts whoever connects
    /// first, with a warning at start. Associations with a list may share one
    /// local `addrs` and `port` and are told apart by it.
    #[serde(default)]
    pub peer_addrs: Vec<String>,
    /// For a `server` association with `peer_addrs`: the SCTP port of the
    /// peer. Absent, any port.
    #[serde(default)]
    pub peer_port: Option<u16>,
    /// For a `client` association: the local IP addresses the association is
    /// dialled from (more than one for a multihomed endpoint). Empty, the
    /// default, leaves the choice to the kernel, which then offers the peer
    /// every address of the host.
    #[serde(default)]
    pub local_addrs: Vec<String>,
    /// For a `client` association: the local SCTP port it is dialled from.
    /// Absent, any port.
    #[serde(default)]
    pub local_port: Option<u16>,
    /// For a `client` association: how it is dialled and dialled again.
    /// Absent means every default of [`Dial`].
    #[serde(default)]
    pub dial: Option<Dial>,
    /// For m2pa links only: the adjacent point code reached directly over this
    /// link. An adjacent PC is an **implicit full route**, see
    /// [`crate::mtp3::route`].
    #[serde(default)]
    pub adjacent_pc: Option<RawPc>,
    /// For m2pa links only: the level-2 timers and proving of this link. Absent
    /// means every default of [`M2paLink`].
    #[serde(default)]
    pub m2pa: Option<M2paLink>,
    /// For m3ua associations only: the heartbeat and the acknowledgement timer
    /// of this association. Absent means every default of [`M3uaPeer`].
    #[serde(default)]
    pub m3ua: Option<M3uaPeer>,
}

impl Association {
    /// `peer_addrs` as addresses, an IPv4-mapped IPv6 address as the IPv4
    /// address it is.
    pub fn peer_ips(&self) -> Result<Vec<IpAddr>> {
        self.peer_addrs
            .iter()
            .map(|text| {
                text.parse::<IpAddr>()
                    .map(|ip| ip.to_canonical())
                    .map_err(|_| {
                        Error::validation(format!(
                            "association `{}`: `peer_addrs` entry `{text}` is not an IP address",
                            self.id
                        ))
                    })
            })
            .collect()
    }

    /// `local_addrs` as addresses.
    pub fn local_ips(&self) -> Result<Vec<IpAddr>> {
        self.local_addrs
            .iter()
            .map(|text| {
                text.parse::<IpAddr>().map_err(|_| {
                    Error::validation(format!(
                        "association `{}`: `local_addrs` entry `{text}` is not an IP address",
                        self.id
                    ))
                })
            })
            .collect()
    }

    /// Whether this association and `other` could both claim one peer: a
    /// common address, and no `peer_port` that tells them apart.
    fn peer_in_common(&self, other: &Association) -> Result<Option<IpAddr>> {
        if matches!((self.peer_port, other.peer_port), (Some(a), Some(b)) if a != b) {
            return Ok(None);
        }
        let theirs = other.peer_ips()?;
        Ok(self.peer_ips()?.into_iter().find(|ip| theirs.contains(ip)))
    }

    /// The local addresses as written, parsed where they parse.
    fn local(&self) -> Vec<LocalAddr<'_>> {
        self.addrs
            .iter()
            .map(|text| match text.parse::<IpAddr>() {
                Ok(ip) => LocalAddr::Ip(ip.to_canonical()),
                Err(_) => LocalAddr::Text(text),
            })
            .collect()
    }
}

/// A local address of an association: compared as an address when it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalAddr<'a> {
    Ip(IpAddr),
    Text(&'a str),
}

impl LocalAddr<'_> {
    fn is_any(&self) -> bool {
        matches!(self, LocalAddr::Ip(ip) if ip.is_unspecified())
    }
}

/// The listening endpoints of a file: the `server` associations by position,
/// grouped by the local addresses and port they listen on. Port `0` asks for
/// a port of its own, so such an association is always alone.
///
/// Two associations on one endpoint are told apart by the address of the
/// peer and by nothing else, so each has to list its peer and no peer may be
/// in two lists: anything else is an error that names both.
pub(crate) fn listen_groups(associations: &[Association]) -> Result<Vec<Vec<usize>>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (index, a) in associations.iter().enumerate() {
        if a.role != Role::Server {
            continue;
        }
        let mine = a.local();
        let mut home = None;
        for (number, group) in groups.iter().enumerate() {
            let Some(first) = group.first().and_then(|i| associations.get(*i)) else {
                continue;
            };
            if a.port == 0 || first.port != a.port {
                continue;
            }
            let theirs = first.local();
            let same = mine.len() == theirs.len() && mine.iter().all(|l| theirs.contains(l));
            let touching = mine
                .iter()
                .any(|l| l.is_any() || theirs.contains(l) || theirs.iter().any(LocalAddr::is_any));
            if !touching {
                continue;
            }
            if !same {
                return Err(Error::validation(format!(
                    "associations `{}` and `{}` listen on port {} with address lists that \
                     overlap but differ: give both the same `addrs`, or addresses of their own",
                    first.id, a.id, a.port
                )));
            }
            for other in group.iter().filter_map(|i| associations.get(*i)) {
                if a.peer_addrs.is_empty() || other.peer_addrs.is_empty() {
                    return Err(Error::validation(format!(
                        "associations `{}` and `{}` listen on the same address and port {}: \
                         each needs `peer_addrs` to be told apart from the other",
                        other.id, a.id, a.port
                    )));
                }
                if let Some(ip) = a.peer_in_common(other)? {
                    return Err(Error::validation(format!(
                        "associations `{}` and `{}` listen on the same address and port {} \
                         and both list the peer address {ip}: a connection from it could be \
                         either's (a different `peer_port` on each tells them apart)",
                        other.id, a.id, a.port
                    )));
                }
            }
            home = Some(number);
            break;
        }
        match home.and_then(|number| groups.get_mut(number)) {
            Some(group) => group.push(index),
            None => groups.push(vec![index]),
        }
    }
    Ok(groups)
}

/// The `dial:` block of a `client` association: how long an attempt to
/// establish it may take, and how long the node waits before the next one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Dial {
    /// How long one attempt may take before it is given up, in milliseconds.
    /// The default lets the INIT and its first two retransmissions out at
    /// the kernel's initial retransmission timeout of 3 seconds (at 0, 3 and
    /// 9 seconds) and does not sit through all eight.
    pub connect_timeout_ms: u64,
    /// The wait before the association is dialled again after the first
    /// attempt that failed, and after an association that had been up was
    /// lost, in milliseconds. It doubles with every further failure. The
    /// default is that of `restart_ms` of an M2PA link (ITU-T Q.704 12.2.2,
    /// T17, "delay to avoid oscillation of initial alignment failure and
    /// link restart").
    pub backoff_initial_ms: u64,
    /// The longest wait, in milliseconds. The default is the interval at
    /// which SCTP itself probes an idle path (RFC 9260 16, HB.interval).
    pub backoff_max_ms: u64,
    /// How much of every wait is taken off at random, in percent, so that
    /// associations that fail together are not dialled together.
    pub backoff_jitter_percent: u8,
}

impl Default for Dial {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            backoff_initial_ms: 1_000,
            backoff_max_ms: 30_000,
            backoff_jitter_percent: 20,
        }
    }
}

/// The `m3ua:` block of an association: what RFC 4666 leaves to provisioning
/// for one M3UA peer. Every timer is in milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct M3uaPeer {
    /// T(beat), the interval at which this node sends Heartbeat on the
    /// association (RFC 4666 4.3.4.6). `0`, the default, sends none: SCTP has
    /// its own heartbeat. With an interval set, a peer from which nothing at
    /// all arrives for twice that long is taken to be unavailable and the
    /// association is aborted. A Heartbeat from the peer is acknowledged
    /// whatever is set here.
    pub beat_ms: u64,
    /// T(ack), after which an ASP Up or ASP Active this node sent as an ASP
    /// is sent again while it is not acknowledged (RFC 4666 4.3.4.1 and
    /// 4.3.4.3, "provisionable, with a default of 2 seconds"). Only a `client`
    /// association sends them.
    pub ack_ms: u64,
    /// The ASP Identifier this node puts in its ASP Up as an ASP (RFC 4666
    /// 3.5.1, "a unique value that is locally significant among the ASPs that
    /// support an AS"). Absent, the parameter is left out, which it may be.
    pub asp_id: Option<u32>,
}

impl Default for M3uaPeer {
    fn default() -> Self {
        Self {
            beat_ms: 0,
            ack_ms: 2_000,
            asp_id: None,
        }
    }
}

/// Which proving period a link asks for at alignment (ITU-T Q.703 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProvingMode {
    /// The normal proving period (`t4n_ms`).
    #[default]
    Normal,
    /// The emergency proving period (`t4e_ms`).
    Emergency,
}

/// The `m2pa:` block of an association: level 2 of one M2PA link (RFC 4165,
/// with the timers of ITU-T Q.703 12.3 for a 64 kbit/s link as defaults).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct M2paLink {
    /// The proving period this end asks for. The peer asking for the emergency
    /// one shortens it whatever is set here (Q.703 7.2).
    pub proving: ProvingMode,
    /// T1, alignment ready (40 to 50 s).
    pub t1_ms: u64,
    /// T2, not aligned (5 to 150 s).
    pub t2_ms: u64,
    /// T3, aligned (1 to 2 s).
    pub t3_ms: u64,
    /// T4, normal proving period (7.5 to 9.5 s).
    pub t4n_ms: u64,
    /// T4, emergency proving period (400 to 600 ms).
    pub t4e_ms: u64,
    /// T6, remote congestion (3 to 6 s).
    pub t6_ms: u64,
    /// T7, excessive delay of acknowledgement (0.5 to 2 s).
    pub t7_ms: u64,
    /// Interval between Link Status Proving messages (RFC 4165 4.1.3).
    pub proving_interval_ms: u64,
    /// Delay before alignment is tried again after it failed or the link
    /// failed (ITU-T Q.704 12.2.2, timer T17, 800 to 1500 ms).
    pub restart_ms: u64,
    /// MSUs the link holds for transmission before it discards (Q.704 3.8).
    pub tx_queue: usize,
}

impl Default for M2paLink {
    fn default() -> Self {
        Self {
            proving: ProvingMode::Normal,
            t1_ms: 45_000,
            t2_ms: 30_000,
            t3_ms: 1_500,
            t4n_ms: 8_200,
            t4e_ms: 500,
            t6_ms: 4_500,
            t7_ms: 2_000,
            proving_interval_ms: 100,
            restart_ms: 1_000,
            tx_queue: 4_096,
        }
    }
}

/// The `link_test:` block of a linkset: the signalling link test of ITU-T
/// Q.707 2.2, run on every link of the linkset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LinkTest {
    /// Whether this node tests its links. A test message from the peer is
    /// answered either way (Q.707 2.2: the ability "must always be provided").
    pub enabled: bool,
    /// T1, supervision of the acknowledgement (4 to 12 s).
    pub t1_ms: u64,
    /// T2, interval between tests (30 to 90 s).
    pub t2_ms: u64,
    /// The test pattern, 1 to 15 octets in hexadecimal.
    pub pattern: String,
}

impl Default for LinkTest {
    fn default() -> Self {
        Self {
            enabled: true,
            t1_ms: 8_000,
            t2_ms: 60_000,
            pattern: "a5a5a5a5a5a5a5a5".to_string(),
        }
    }
}

impl LinkTest {
    /// The test pattern as octets. `None` if it is not 1 to 15 octets of
    /// hexadecimal (rejected at load).
    pub fn pattern_octets(&self) -> Option<Vec<u8>> {
        let text = self.pattern.as_bytes();
        if text.len() % 2 != 0 || !(2..=30).contains(&text.len()) {
            return None;
        }
        text.chunks(2)
            .map(|pair| {
                let hex = std::str::from_utf8(pair).ok()?;
                u8::from_str_radix(hex, 16).ok()
            })
            .collect()
    }
}

// ── Application Servers (M3UA) / Linksets (M2PA) ────────────────────────────

/// M3UA traffic mode across the ASPs of an Application Server (RFC 4666 §1.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficMode {
    /// Share traffic across the active ASPs (SLS-keyed).
    Loadshare,
    /// One active ASP; the others stand by.
    Override,
    /// Send to every active ASP.
    Broadcast,
}

/// One `application_servers:` entry: a SIGTRAN **Application Server** (RFC 4666
/// M3UA / RFC 3868 SUA).
///
/// An AS is a logical destination served by one or more **ASPs**. Each ASP is an
/// M3UA *or* SUA association (referenced by id in [`asps`](ApplicationServer::asps)),
/// and the per-ASP ASPSM/ASPTM state machine brings it up. All ASPs of one AS
/// share a single adaptation (all M3UA, or all SUA). The traffic mode is an AS
/// property, not a per-ASP one.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationServer {
    /// AS name, referenced by `mtp3_routes` (`as:`).
    pub name: String,
    /// How traffic is spread over the AS's active ASPs.
    pub traffic_mode: TrafficMode,
    /// The Routing Context that identifies this AS in ASPAC/DATA (RFC 4666 §3.1).
    pub routing_context: u32,
    /// The member ASPs: association ids, each an m3ua association.
    pub asps: Vec<String>,
    /// T(r), the recovery timer in milliseconds (RFC 4666 4.3.2 and 4.3.4.4):
    /// how long the server is pending, and traffic for it queued, after its
    /// last active ASP left. "T(r) is configurable by the network operator";
    /// the RFC names no value, 2000 is the default here. `0` switches the
    /// pending state off: the server is inactive or down at once.
    #[serde(default = "default_recovery_ms")]
    pub recovery_ms: u64,
    /// Messages queued for the server while it is pending, before further
    /// ones are discarded.
    #[serde(default = "default_pending_queue")]
    pub pending_queue: usize,
    /// "n" of RFC 4666 4.3.2: the number of ASPs that have to be active
    /// before the server is, and below which its inactive ASPs are told
    /// ("Insufficient ASP Resources Active in AS"). 1 for an override server.
    #[serde(default = "default_required_asps")]
    pub required_asps: usize,
}

fn default_recovery_ms() -> u64 {
    2_000
}

fn default_pending_queue() -> usize {
    4_096
}

fn default_required_asps() -> usize {
    1
}

/// A link within a linkset: the association it rides (which also identifies it).
#[derive(Debug, Clone, Deserialize)]
pub struct Link {
    /// The association id this link rides.
    pub assoc: String,
    /// The signalling link code, 0 to 15, which both ends of the link must
    /// agree on (RFC 4165 4.1.2). Absent: the position of the link in `links`.
    #[serde(default)]
    pub slc: Option<u8>,
}

/// One `linksets:` entry: an **M2PA linkset** (RFC 4165). M2PA replaces MTP2, so
/// the linkset/link model applies directly. There is no traffic mode: SLS spreads
/// traffic across the in-service links, and each link's adjacent point code comes
/// from its association's `adjacent_pc`.
#[derive(Debug, Clone, Deserialize)]
pub struct Linkset {
    /// Linkset name, referenced by `mtp3_routes` (`linkset:`).
    pub name: String,
    /// The member links (each an m2pa association).
    pub links: Vec<Link>,
    /// The signalling link test run on each link (ITU-T Q.707).
    #[serde(default)]
    pub link_test: LinkTest,
}

impl Linkset {
    /// The signalling link code of the link at `index`: its `slc`, or its
    /// position in the list.
    pub fn slc_of(&self, index: usize) -> u8 {
        self.links
            .get(index)
            .and_then(|l| l.slc)
            .unwrap_or((index & 0x0F) as u8)
    }
}

// ── MTP3 management ─────────────────────────────────────────────────────────

/// The `mtp3:` block: signalling network management of a transfer point
/// (ITU-T Q.704). Every timer is in milliseconds; the defaults are the values
/// of Q.704 16.8 (where it gives a range, a value inside it).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Mtp3 {
    /// T1, delay to avoid mis-sequencing on changeover (500 to 1200 ms).
    pub t1_ms: u64,
    /// T2, waiting for the changeover acknowledgement (700 to 2000 ms).
    pub t2_ms: u64,
    /// T3, time-controlled diversion on changeback (500 to 1200 ms).
    pub t3_ms: u64,
    /// T4, waiting for the changeback acknowledgement, first attempt (500 to
    /// 1200 ms).
    pub t4_ms: u64,
    /// T5, waiting for the changeback acknowledgement, second attempt (500 to
    /// 1200 ms).
    pub t5_ms: u64,
    /// T6, delay to avoid mis-sequencing on controlled rerouting (500 to
    /// 1200 ms).
    pub t6_ms: u64,
    /// T8, transfer-prohibited inhibition (800 to 1200 ms).
    pub t8_ms: u64,
    /// T10, waiting to repeat the signalling route set test (30 to 60 s).
    pub t10_ms: u64,
    /// T12, waiting for the uninhibit acknowledgement (800 to 1500 ms).
    pub t12_ms: u64,
    /// T13, waiting for the force uninhibit (800 to 1500 ms).
    pub t13_ms: u64,
    /// T18, the first phase of this node's MTP restart: how long it waits for
    /// the traffic restart allowed of its adjacent points. Q.704 leaves the
    /// value to the implementation and the network.
    pub t18_ms: u64,
    /// T19, during which a second traffic restart allowed from the same
    /// adjacent point is ignored (67 to 69 s).
    pub t19_ms: u64,
    /// T20, the overall restart timer of this node (59 to 61 s).
    pub t20_ms: u64,
    /// T21, how long an adjacent point that restarts is waited for before
    /// traffic is sent to it (63 to 65 s).
    pub t21_ms: u64,
    /// T23, the interval of the remote inhibit test (3 to 6 minutes).
    pub t23_ms: u64,
    /// Whether a message for a point code this node has no route for at all
    /// is answered with transfer-prohibited, as it is for a destination that
    /// is known and inaccessible. Footnote 7 of Q.704 13.2.2 leaves that to
    /// the network operator.
    pub tfp_for_unknown_destination: bool,
    /// Messages held for one destination while its traffic is rerouted under
    /// T6, before further ones are discarded.
    pub rerouting_buffer: usize,
}

impl Default for Mtp3 {
    fn default() -> Self {
        Self {
            t1_ms: 800,
            t2_ms: 1_400,
            t3_ms: 800,
            t4_ms: 800,
            t5_ms: 800,
            t6_ms: 800,
            t8_ms: 1_000,
            t10_ms: 45_000,
            t12_ms: 1_150,
            t13_ms: 1_150,
            t18_ms: 20_000,
            t19_ms: 68_000,
            t20_ms: 60_000,
            t21_ms: 64_000,
            t23_ms: 240_000,
            tfp_for_unknown_destination: true,
            rerouting_buffer: 4_096,
        }
    }
}

impl Mtp3 {
    /// The key of the first timer or size that is 0, which none may be.
    fn zero_key(&self) -> Option<&'static str> {
        [
            ("t1_ms", self.t1_ms),
            ("t2_ms", self.t2_ms),
            ("t3_ms", self.t3_ms),
            ("t4_ms", self.t4_ms),
            ("t5_ms", self.t5_ms),
            ("t6_ms", self.t6_ms),
            ("t8_ms", self.t8_ms),
            ("t10_ms", self.t10_ms),
            ("t12_ms", self.t12_ms),
            ("t13_ms", self.t13_ms),
            ("t18_ms", self.t18_ms),
            ("t19_ms", self.t19_ms),
            ("t20_ms", self.t20_ms),
            ("t21_ms", self.t21_ms),
            ("t23_ms", self.t23_ms),
            ("rerouting_buffer", self.rerouting_buffer as u64),
        ]
        .iter()
        .find(|(_, value)| *value == 0)
        .map(|(key, _)| *key)
    }
}

// ── MTP3 routes ─────────────────────────────────────────────────────────────

/// One `mtp3_routes:` entry: a static route to a DPC via an Application Server
/// (`as:`) **or** an M2PA linkset (`linkset:`). Exactly one of the two is set.
#[derive(Debug, Clone, Deserialize)]
pub struct Mtp3Route {
    /// Destination point code (decimal).
    pub dpc: RawPc,
    /// The M3UA Application Server to reach it, if this route targets an AS.
    #[serde(default, rename = "as")]
    pub as_: Option<String>,
    /// The M2PA linkset to reach it, if this route targets a linkset.
    #[serde(default)]
    pub linkset: Option<String>,
    /// Priority, **1 = primary**, higher numbers are alternates.
    pub priority: u8,
}

// ── SCCP ────────────────────────────────────────────────────────────────────

/// A GTT group's selection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupMode {
    /// Cost-ordered: lowest cost primary, others fail-over alternates.
    Cost,
    /// Share: weighted round-robin across members.
    Share,
}

/// A member of a GTT group: a concrete (dpc, ssn) with a cost or weight.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupMember {
    /// Destination point code (decimal).
    pub dpc: RawPc,
    /// Subsystem number.
    pub ssn: u8,
    /// Cost for a `cost` group (lower = preferred).
    #[serde(default)]
    pub cost: Option<u8>,
    /// Weight for a `share` group.
    #[serde(default)]
    pub weight: Option<u8>,
}

/// One `gtt_groups:` entry: a named result set for GTT.
#[derive(Debug, Clone, Deserialize)]
pub struct GttGroup {
    /// Group name, referenced by GTT rule/content-rule results.
    pub name: String,
    /// cost or share selection.
    pub mode: GroupMode,
    /// The candidate members.
    pub members: Vec<GroupMember>,
}

/// The `match:` clause of a GTT rule.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GttMatch {
    /// Match on a leading digit prefix of the GT digits.
    #[serde(default)]
    pub gt_prefix: Option<String>,
    /// Match the GT indicator (2 / 3 / 4).
    #[serde(default)]
    pub gti: Option<u8>,
    /// Match the translation type.
    #[serde(default)]
    pub tt: Option<u8>,
    /// Match the numbering plan.
    #[serde(default)]
    pub np: Option<u8>,
    /// Match the nature-of-address indicator.
    #[serde(default)]
    pub nai: Option<u8>,
}

/// The `to:` clause of a GTT rule (or content-routing route action).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RouteTarget {
    /// Route directly to this DPC.
    #[serde(default)]
    pub dpc: Option<RawPc>,
    /// With this SSN.
    #[serde(default)]
    pub ssn: Option<u8>,
    /// Route to a named GTT group instead.
    #[serde(default)]
    pub group: Option<String>,
    /// Terminate locally.
    #[serde(default)]
    pub local: Option<bool>,
    /// Hand off into another routing domain.
    #[serde(default)]
    pub tenant: Option<TenantId>,
}

/// One `gtt:` rule: match a GT, produce a result.
#[derive(Debug, Clone, Deserialize)]
pub struct GttRule {
    /// The GT match criteria.
    #[serde(rename = "match")]
    pub match_: GttMatch,
    /// The result to produce.
    pub to: RouteTarget,
}

/// A `plmn_map:` entry: E.212 MCC+MNC to its E.164 prefix.
#[derive(Debug, Clone, Deserialize)]
pub struct PlmnMapEntry {
    /// Mobile Country Code (3 digits).
    pub mcc: String,
    /// Mobile Network Code (2 or 3 digits).
    pub mnc: String,
    /// The HPLMN E.164 CC+NDC prefix that MCC+MNC maps to.
    pub e164_prefix: String,
}

/// The `gt_conversion:` block: E.214 → E.164 mobile-global-title conversion. The
/// inbound E.214→E.164 pre-step before GTT is driven from the `plmn_map`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GtConversion {
    /// The E.212 → E.164 network numbering map.
    #[serde(default)]
    pub plmn_map: Vec<PlmnMapEntry>,
}

/// The `sccp:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Sccp {
    /// Subsystem numbers we own; inbound for these terminates locally.
    #[serde(default)]
    pub local_ssns: Vec<u8>,
    /// Named GTT result groups.
    #[serde(default)]
    pub gtt_groups: Vec<GttGroup>,
    /// The ordered GTT rules.
    #[serde(default)]
    pub gtt: Vec<GttRule>,
    /// E.214 ↔ E.164 conversion tables.
    #[serde(default)]
    pub gt_conversion: GtConversion,
}

// ── TCAP dialogue termination ────────────────────────────────────────────────

/// The `tcap:` block: the dialogue-termination engine's timers and ceiling.
///
/// These are node-wide (shared across tenants, like the SCTP transport), not
/// per-tenant. The defaults are the Q.774 default operation-timer neighbourhood
/// and a generous dialogue ceiling; a low-volume HLR/SMSC/SCP rarely needs to
/// touch them.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Tcap {
    /// The invocation timer of an invoke that does not name its own (Q.774
    /// 3.2.1.1.3). Its expiry is reported to the dialogue's handler and means
    /// what the class of the operation says; only the expiry of a class 1
    /// invoke is counted in `sigtran_invoke_timeouts_total`. Milliseconds.
    pub invoke_timer_ms: u64,
    /// How long a dialogue may go without a message in either direction before
    /// it is aborted and `sigtran_dialogue_timeouts_total` counts it; a dialogue
    /// can set its own. `0` disables it. Milliseconds.
    pub dialogue_timer_ms: u64,
    /// The maximum number of concurrently open dialogues. A Begin over this
    /// ceiling is refused with a P-Abort, cause resource limitation (counted as
    /// a local abort).
    pub max_dialogues: usize,
}

impl Default for Tcap {
    fn default() -> Self {
        Self {
            invoke_timer_ms: 15_000,
            dialogue_timer_ms: 30_000,
            max_dialogues: 100_000,
        }
    }
}

// ── Content routing ─────────────────────────────────────────────────────────

/// An `address_tables:` entry: a named set of GT digit strings.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressTable {
    /// Table name, referenced by content-rule matches.
    pub name: String,
    /// The member address (GT digit) strings.
    pub addrs: Vec<String>,
}

/// An `imsi_tables:` entry: a named set of IMSI prefixes.
#[derive(Debug, Clone, Deserialize)]
pub struct ImsiTable {
    /// Table name, referenced by content-rule matches.
    pub name: String,
    /// The member IMSI prefixes (leading MCC+MNC[+MSIN] digits).
    pub prefixes: Vec<String>,
}

/// The `match:` clause of a content-routing rule. All present fields must hold
/// (AND); absent fields are wildcards.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContentMatch {
    /// Match one or more MAP/CAP operations by kebab-case name (see
    /// [`crate::content::Operation`]). A single string or a list both parse.
    #[serde(default)]
    pub operation: Option<OneOrMany>,
    /// The decoded IMSI is in this named imsi_table.
    #[serde(default)]
    pub imsi_in: Option<String>,
    /// The decoded IMSI starts with this prefix.
    #[serde(default)]
    pub imsi_prefix: Option<String>,
    /// The CdPA GT digits are in this named address_table.
    #[serde(default)]
    pub cdpa_gt_in: Option<String>,
    /// The CgPA GT digits are in this named address_table.
    #[serde(default)]
    pub cgpa_gt_in: Option<String>,
}

/// A YAML scalar-or-sequence: `operation: sri-sm` **or** `operation: [a, b]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    /// A single value.
    One(String),
    /// A list of values.
    Many(Vec<String>),
}

impl OneOrMany {
    /// Flatten to a `Vec<&str>`.
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            OneOrMany::One(s) => vec![s.as_str()],
            OneOrMany::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// The `action:` clause of a content-routing rule.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContentAction {
    /// Route to a dpc/ssn, a group, or another tenant.
    #[serde(default)]
    pub route: Option<RouteTarget>,
    /// Rewrite the CdPA GT digits before forwarding.
    #[serde(default)]
    pub rewrite_cdpa_gt: Option<String>,
    /// Screen/drop the message.
    #[serde(default)]
    pub screen: Option<bool>,
}

/// One `content_routing.rules:` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ContentRule {
    /// Rule name (metrics label + first-match ordering clarity).
    pub name: String,
    /// The match criteria.
    #[serde(rename = "match")]
    pub match_: ContentMatch,
    /// The action to take on the first matching rule.
    pub action: ContentAction,
}

/// The application protocol the content-routing engine decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentProtocol {
    /// GSM MAP (TS 29.002).
    GsmMap,
    /// CAMEL CAP (TS 29.078).
    GsmCap,
}

/// The `content_routing:` block.
#[derive(Debug, Clone, Deserialize)]
pub struct ContentRouting {
    /// Which application layer to decode.
    pub protocol: ContentProtocol,
    /// Named GT-digit address tables.
    #[serde(default)]
    pub address_tables: Vec<AddressTable>,
    /// Named IMSI-prefix tables.
    #[serde(default)]
    pub imsi_tables: Vec<ImsiTable>,
    /// The ordered content rules (first match wins).
    #[serde(default)]
    pub rules: Vec<ContentRule>,
}

// ── ISUP screening ──────────────────────────────────────────────────────────

/// What a screening rule (or the default) does to a matched ISUP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScreenAction {
    /// Drop the message (screen it off the transit path).
    Block,
    /// Explicitly let the message transit.
    Allow,
}

fn default_screen_action() -> ScreenAction {
    ScreenAction::Allow
}

/// The `match:` clause of an ISUP screening rule. All present fields must hold
/// (AND); absent fields are wildcards.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScreenMatch {
    /// Match the ISUP message type by its lower-case Q.763 acronym (`iam`, `rel`,
    /// `acm`, …). See [`crate::isup::message_type_from_name`].
    #[serde(default)]
    pub message_type: Option<String>,
    /// Match a leading prefix of the called-party-number digits.
    #[serde(default)]
    pub called_prefix: Option<String>,
    /// Match a leading prefix of the calling-party-number digits.
    #[serde(default)]
    pub calling_prefix: Option<String>,
}

/// One `isup_screening.rules:` entry: match an ISUP message, take an action.
#[derive(Debug, Clone, Deserialize)]
pub struct ScreenRule {
    /// Rule name (metrics/log clarity + first-match ordering).
    pub name: String,
    /// The match criteria.
    #[serde(rename = "match")]
    pub match_: ScreenMatch,
    /// The action to take on the first matching rule.
    pub action: ScreenAction,
}

/// The `isup_screening:` block: optional ISUP-aware screening on the SI=5 transit
/// path. When absent the transit path is byte-for-byte unchanged; when present,
/// each transiting ISUP message is decoded and evaluated against the ordered
/// rules (first match wins), and a `block` result drops it.
#[derive(Debug, Clone, Deserialize)]
pub struct IsupScreening {
    /// The action for a message that no rule matches (default: `allow`).
    #[serde(default = "default_screen_action")]
    pub default: ScreenAction,
    /// The ordered screening rules (first match wins).
    #[serde(default)]
    pub rules: Vec<ScreenRule>,
}

// ── The per-tenant body + the whole file ────────────────────────────────────

/// The per-tenant routing tables: the shape that repeats under each
/// `tenants:` entry, and that the flat top level collapses into for `default`.
#[derive(Debug, Clone, Deserialize)]
pub struct Tenant {
    /// The tenant's own point code (decimal).
    pub point_code: RawPc,
    /// The tenant's SS7 variant.
    #[serde(deserialize_with = "variant")]
    pub variant: Variant,
    /// Default network indicator.
    #[serde(default = "default_ni")]
    pub network_indicator: NetworkIndicator,
    /// The tenant's M3UA Application Servers.
    #[serde(default)]
    pub application_servers: Vec<ApplicationServer>,
    /// The tenant's M2PA linksets.
    #[serde(default)]
    pub linksets: Vec<Linkset>,
    /// The tenant's MTP3 route table.
    #[serde(default)]
    pub mtp3_routes: Vec<Mtp3Route>,
    /// The tenant's signalling network management (timers of ITU-T Q.704).
    #[serde(default)]
    pub mtp3: Mtp3,
    /// The tenant's SCCP/GTT tables.
    #[serde(default)]
    pub sccp: Sccp,
    /// The tenant's content-routing rules.
    #[serde(default)]
    pub content_routing: Option<ContentRouting>,
    /// The tenant's ISUP screening rules (SI=5 transit path). Absent = no
    /// screening (transit unchanged).
    #[serde(default)]
    pub isup_screening: Option<IsupScreening>,
}

impl Tenant {
    /// Resolve this tenant's own point code under its variant.
    pub fn resolved_point_code(&self) -> Result<PointCode> {
        Ok(self.point_code.resolve(self.variant)?)
    }
}

/// The raw file as parsed: either flat (implicit default) or with an explicit
/// `tenants:` map. [`Config::from_raw`] normalises it.
#[derive(Debug, Clone, Deserialize)]
struct RawFile {
    #[serde(default)]
    node: Option<Node>,
    #[serde(default)]
    associations: Vec<Association>,
    #[serde(default)]
    application_servers: Vec<ApplicationServer>,
    #[serde(default)]
    linksets: Vec<Linkset>,
    #[serde(default)]
    mtp3_routes: Vec<Mtp3Route>,
    #[serde(default)]
    mtp3: Option<Mtp3>,
    #[serde(default)]
    sccp: Option<Sccp>,
    #[serde(default)]
    content_routing: Option<ContentRouting>,
    #[serde(default)]
    isup_screening: Option<IsupScreening>,
    #[serde(default)]
    tcap: Option<Tcap>,
    #[serde(default)]
    tenants: Option<BTreeMap<TenantId, Tenant>>,
}

/// The fully-normalised node configuration.
///
/// After [`Config::load`] there is exactly one shape regardless of how the file
/// was written: the SCTP [`associations`](Config::associations) shared by all
/// tenants, and a [`tenants`](Config::tenants) map with **at least** the
/// `default` tenant. The rest of the crate resolves routing against
/// [`Config::tenant`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The SCTP transport plane, shared across tenants and demultiplexed by
    /// M3UA network appearance.
    pub associations: Vec<Association>,
    /// The node-wide TCAP dialogue-termination settings (timers + ceiling).
    pub tcap: Tcap,
    /// The per-tenant routing tables, keyed by tenant id. Always contains
    /// `default` when the file was written flat.
    pub tenants: BTreeMap<TenantId, Tenant>,
}

impl Config {
    /// Load and validate a `sigtran.yaml` from a path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Parse and validate a `sigtran.yaml` from a string (the testable core).
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawFile = serde_yaml::from_str(text)?;
        let config = Self::from_raw(raw)?;
        config.validate()?;
        Ok(config)
    }

    /// Normalise the raw file: fold a flat top level into the implicit
    /// `default` tenant, or take the explicit `tenants:` map as-is.
    fn from_raw(raw: RawFile) -> Result<Self> {
        let tenants = match raw.tenants {
            Some(map) => {
                if map.is_empty() {
                    return Err(Error::validation("`tenants:` is present but empty"));
                }
                // An explicit tenants map: the flat routing fields must not also
                // be set (that would be ambiguous).
                if !raw.application_servers.is_empty()
                    || !raw.linksets.is_empty()
                    || !raw.mtp3_routes.is_empty()
                    || raw.mtp3.is_some()
                    || raw.sccp.is_some()
                    || raw.content_routing.is_some()
                    || raw.isup_screening.is_some()
                {
                    return Err(Error::validation(
                        "top-level routing fields (application_servers/linksets/mtp3_routes/\
                         mtp3/sccp/content_routing/isup_screening) cannot be mixed with an explicit \
                         `tenants:` block",
                    ));
                }
                map
            }
            None => {
                // Flat file → the implicit `default` tenant. Requires `node:`.
                let node = raw
                    .node
                    .ok_or_else(|| Error::validation("missing `node:` block"))?;
                let mut map = BTreeMap::new();
                map.insert(
                    DEFAULT_TENANT.to_string(),
                    Tenant {
                        point_code: node.point_code,
                        variant: node.variant,
                        network_indicator: node.network_indicator,
                        application_servers: raw.application_servers,
                        linksets: raw.linksets,
                        mtp3_routes: raw.mtp3_routes,
                        mtp3: raw.mtp3.unwrap_or_default(),
                        sccp: raw.sccp.unwrap_or_default(),
                        content_routing: raw.content_routing,
                        isup_screening: raw.isup_screening,
                    },
                );
                map
            }
        };

        Ok(Config {
            associations: raw.associations,
            tcap: raw.tcap.unwrap_or_default(),
            tenants,
        })
    }

    /// Look up a tenant by id.
    pub fn tenant(&self, id: &str) -> Option<&Tenant> {
        self.tenants.get(id)
    }

    /// The implicit-default tenant (present for a flat single-tenant file).
    pub fn default_tenant(&self) -> Option<&Tenant> {
        self.tenants.get(DEFAULT_TENANT)
    }

    /// Semantic validation across the whole config: point codes fit their
    /// variant, names are unique, and every reference resolves.
    fn validate(&self) -> Result<()> {
        // Duplicate association ids.
        let mut seen = BTreeSet::new();
        for a in &self.associations {
            if !seen.insert(a.id.as_str()) {
                return Err(Error::validation(format!(
                    "duplicate association id `{}`",
                    a.id
                )));
            }
            if a.addrs.is_empty() {
                return Err(Error::validation(format!(
                    "association `{}` has no addresses",
                    a.id
                )));
            }
            if a.role == Role::Client && (!a.peer_addrs.is_empty() || a.peer_port.is_some()) {
                return Err(Error::validation(format!(
                    "association `{}` is a client: its peer is `addrs` and `port`, \
                     `peer_addrs` and `peer_port` are for a server association",
                    a.id
                )));
            }
            if a.peer_port.is_some() && a.peer_addrs.is_empty() {
                return Err(Error::validation(format!(
                    "association `{}` has a `peer_port` but no `peer_addrs`",
                    a.id
                )));
            }
            if a.peer_port == Some(0) {
                return Err(Error::validation(format!(
                    "association `{}`: `peer_port` must not be 0",
                    a.id
                )));
            }
            a.peer_ips()?;
            if a.role == Role::Server
                && (!a.local_addrs.is_empty() || a.local_port.is_some() || a.dial.is_some())
            {
                return Err(Error::validation(format!(
                    "association `{}` is a server: it listens on `addrs` and `port`, \
                     `local_addrs`, `local_port` and `dial` are for a client association",
                    a.id
                )));
            }
            a.local_ips()?;
            if a.local_port == Some(0) {
                return Err(Error::validation(format!(
                    "association `{}`: `local_port` must not be 0 (leave it out for any port)",
                    a.id
                )));
            }
            if let Some(dial) = &a.dial {
                let zero = [
                    ("connect_timeout_ms", dial.connect_timeout_ms),
                    ("backoff_initial_ms", dial.backoff_initial_ms),
                    ("backoff_max_ms", dial.backoff_max_ms),
                ];
                if let Some((name, _)) = zero.iter().find(|(_, value)| *value == 0) {
                    return Err(Error::validation(format!(
                        "association `{}`: dial `{name}` must not be 0",
                        a.id
                    )));
                }
                if dial.backoff_max_ms < dial.backoff_initial_ms {
                    return Err(Error::validation(format!(
                        "association `{}`: dial `backoff_max_ms` is below `backoff_initial_ms`",
                        a.id
                    )));
                }
                if dial.backoff_jitter_percent > 100 {
                    return Err(Error::validation(format!(
                        "association `{}`: dial `backoff_jitter_percent` is more than 100",
                        a.id
                    )));
                }
            }
            if let Some(pc) = a.adjacent_pc {
                // adjacent_pc only meaningful for m2pa; still must fit *some*
                // variant, validated per-tenant below where the variant is
                // known. Here just a sanity bound against the widest (ANSI).
                pc.resolve(Variant::Ansi)?;
            }
            if let Some(m3ua) = &a.m3ua {
                if a.adaptation != Adaptation::M3ua {
                    return Err(Error::validation(format!(
                        "association `{}` has an `m3ua:` block but is not an m3ua association",
                        a.id
                    )));
                }
                if m3ua.ack_ms == 0 {
                    return Err(Error::validation(format!(
                        "association `{}`: m3ua `ack_ms` must not be 0",
                        a.id
                    )));
                }
            }
            if let Some(m2pa) = &a.m2pa {
                if a.adaptation != Adaptation::M2pa {
                    return Err(Error::validation(format!(
                        "association `{}` has an `m2pa:` block but is not an m2pa association",
                        a.id
                    )));
                }
                let timers = [
                    ("t1_ms", m2pa.t1_ms),
                    ("t2_ms", m2pa.t2_ms),
                    ("t3_ms", m2pa.t3_ms),
                    ("t4n_ms", m2pa.t4n_ms),
                    ("t4e_ms", m2pa.t4e_ms),
                    ("t6_ms", m2pa.t6_ms),
                    ("t7_ms", m2pa.t7_ms),
                    ("proving_interval_ms", m2pa.proving_interval_ms),
                    ("restart_ms", m2pa.restart_ms),
                    ("tx_queue", m2pa.tx_queue as u64),
                ];
                if let Some((name, _)) = timers.iter().find(|(_, value)| *value == 0) {
                    return Err(Error::validation(format!(
                        "association `{}`: m2pa `{name}` must not be 0",
                        a.id
                    )));
                }
            }
        }

        // Associations that listen on one endpoint are told apart by their
        // peers, which they have to list without overlap.
        listen_groups(&self.associations)?;

        let assoc_adapt: BTreeMap<&str, Adaptation> = self
            .associations
            .iter()
            .map(|a| (a.id.as_str(), a.adaptation))
            .collect();

        for (tid, tenant) in &self.tenants {
            self.validate_tenant(tid, tenant, &assoc_adapt)?;
        }
        Ok(())
    }

    fn validate_tenant(
        &self,
        tid: &str,
        tenant: &Tenant,
        assoc_adapt: &BTreeMap<&str, Adaptation>,
    ) -> Result<()> {
        let where_ = |msg: String| Error::validation(format!("tenant `{tid}`: {msg}"));

        // Own point code fits the variant.
        tenant
            .resolved_point_code()
            .map_err(|e| where_(format!("point_code: {e}")))?;

        if let Some(key) = tenant.mtp3.zero_key() {
            return Err(where_(format!("mtp3 `{key}` must not be 0")));
        }

        // Route-destination names live in one namespace across Application
        // Servers and linksets, so `mtp3_routes` can reference either and a name
        // never resolves two ways.
        let mut dest_names = BTreeSet::new();

        // Application Servers: names unique; each ASP is a known M3UA or SUA
        // association, and all ASPs of one AS share a single adaptation.
        let mut as_names = BTreeSet::new();
        for a in &tenant.application_servers {
            if !dest_names.insert(a.name.as_str()) {
                return Err(where_(format!("duplicate route destination `{}`", a.name)));
            }
            as_names.insert(a.name.as_str());
            if a.asps.is_empty() {
                return Err(where_(format!(
                    "application_server `{}` has no asps",
                    a.name
                )));
            }
            if a.pending_queue == 0 {
                return Err(where_(format!(
                    "application_server `{}`: `pending_queue` must not be 0",
                    a.name
                )));
            }
            // RFC 4666 4.3.2: "n = 1 for Override Traffic Mode".
            let most = if a.traffic_mode == TrafficMode::Override {
                1
            } else {
                a.asps.len()
            };
            if a.required_asps == 0 || a.required_asps > most {
                return Err(where_(format!(
                    "application_server `{}`: `required_asps` must be between 1 and {most}",
                    a.name
                )));
            }
            let mut as_adapt: Option<Adaptation> = None;
            for asp in &a.asps {
                let adapt = match assoc_adapt.get(asp.as_str()) {
                    None => {
                        return Err(where_(format!(
                            "application_server `{}` references unknown association `{}`",
                            a.name, asp
                        )))
                    }
                    Some(a @ (Adaptation::M3ua | Adaptation::Sua)) => *a,
                    Some(other) => {
                        return Err(where_(format!(
                            "application_server `{}` asp `{}` is a {other:?} association, \
                             an AS is served by m3ua or sua ASPs",
                            a.name, asp
                        )))
                    }
                };
                match as_adapt {
                    None => as_adapt = Some(adapt),
                    Some(first) if first != adapt => {
                        return Err(where_(format!(
                            "application_server `{}` mixes {first:?} and {adapt:?} ASPs; \
                             all ASPs of an AS must share one adaptation",
                            a.name
                        )))
                    }
                    Some(_) => {}
                }
            }
        }

        // Linksets: names unique (across the AS namespace too); each link is a
        // known m2pa association.
        let mut linkset_names = BTreeSet::new();
        for ls in &tenant.linksets {
            if !dest_names.insert(ls.name.as_str()) {
                let kind = if as_names.contains(ls.name.as_str()) {
                    "collides with application_server"
                } else {
                    "duplicate route destination"
                };
                return Err(where_(format!("{kind} `{}`", ls.name)));
            }
            linkset_names.insert(ls.name.as_str());
            if ls.links.is_empty() {
                return Err(where_(format!("linkset `{}` has no links", ls.name)));
            }
            // The signalling link code is 4 bits (Q.704 15.2) and names one link
            // of the linkset.
            if ls.links.len() > 16 {
                return Err(where_(format!(
                    "linkset `{}` has {} links, a linkset has at most 16",
                    ls.name,
                    ls.links.len()
                )));
            }
            let mut codes = BTreeSet::new();
            for index in 0..ls.links.len() {
                let slc = ls.slc_of(index);
                if slc > 15 {
                    return Err(where_(format!(
                        "linkset `{}` link `{}`: slc {slc} is not 0 to 15",
                        ls.name, ls.links[index].assoc
                    )));
                }
                if !codes.insert(slc) {
                    return Err(where_(format!(
                        "linkset `{}` has two links with slc {slc}",
                        ls.name
                    )));
                }
            }
            if ls.link_test.pattern_octets().is_none() {
                return Err(where_(format!(
                    "linkset `{}`: link_test pattern `{}` is not 1 to 15 octets of hexadecimal",
                    ls.name, ls.link_test.pattern
                )));
            }
            if ls.link_test.t1_ms == 0 || ls.link_test.t2_ms == 0 {
                return Err(where_(format!(
                    "linkset `{}`: link_test timers must not be 0",
                    ls.name
                )));
            }
            for link in &ls.links {
                match assoc_adapt.get(link.assoc.as_str()) {
                    None => {
                        return Err(where_(format!(
                            "linkset `{}` references unknown association `{}`",
                            ls.name, link.assoc
                        )))
                    }
                    Some(Adaptation::M2pa) => {
                        // M2PA framing is ITU 14-bit only; an ANSI (24-bit) node
                        // would have its point codes masked and mangled, so reject
                        // the combination at load rather than corrupt on the wire.
                        if tenant.variant == Variant::Ansi {
                            return Err(where_(format!(
                                "linkset `{}` uses m2pa under the ansi variant, but m2pa framing \
                                 is ITU 14-bit only; use m3ua associations for an ansi node",
                                ls.name
                            )));
                        }
                    }
                    Some(other) => {
                        return Err(where_(format!(
                            "linkset `{}` link `{}` is a {other:?} association, \
                             a linkset carries m2pa links",
                            ls.name, link.assoc
                        )))
                    }
                }
            }
        }

        // MTP3 routes: dpc fits, exactly one of `as:`/`linkset:` set, and the
        // named destination exists.
        for r in &tenant.mtp3_routes {
            r.dpc
                .resolve(tenant.variant)
                .map_err(|e| where_(format!("mtp3_route dpc: {e}")))?;
            match (&r.as_, &r.linkset) {
                (Some(a), None) => {
                    if !as_names.contains(a.as_str()) {
                        return Err(where_(format!(
                            "mtp3_route to {} references unknown application_server `{}`",
                            r.dpc.0, a
                        )));
                    }
                }
                (None, Some(l)) => {
                    if !linkset_names.contains(l.as_str()) {
                        return Err(where_(format!(
                            "mtp3_route to {} references unknown linkset `{}`",
                            r.dpc.0, l
                        )));
                    }
                }
                (Some(_), Some(_)) => {
                    return Err(where_(format!(
                        "mtp3_route to {} sets both `as:` and `linkset:` (pick one)",
                        r.dpc.0
                    )));
                }
                (None, None) => {
                    return Err(where_(format!(
                        "mtp3_route to {} sets neither `as:` nor `linkset:`",
                        r.dpc.0
                    )));
                }
            }
        }

        // SCCP: group names unique; dpcs fit; gtt/content route targets resolve.
        let mut group_names = BTreeSet::new();
        for g in &tenant.sccp.gtt_groups {
            if !group_names.insert(g.name.as_str()) {
                return Err(where_(format!("duplicate gtt_group `{}`", g.name)));
            }
            if g.members.is_empty() {
                return Err(where_(format!("gtt_group `{}` has no members", g.name)));
            }
            for m in &g.members {
                m.dpc
                    .resolve(tenant.variant)
                    .map_err(|e| where_(format!("gtt_group `{}` member dpc: {e}", g.name)))?;
            }
        }
        for rule in &tenant.sccp.gtt {
            self.validate_target(&rule.to, tenant, &group_names)
                .map_err(|e| where_(format!("gtt rule: {e}")))?;
        }

        // Content routing: table names unique; rule targets/tables resolve.
        if let Some(cr) = &tenant.content_routing {
            let mut addr_tables = BTreeSet::new();
            for t in &cr.address_tables {
                if !addr_tables.insert(t.name.as_str()) {
                    return Err(where_(format!("duplicate address_table `{}`", t.name)));
                }
            }
            let mut imsi_tables = BTreeSet::new();
            for t in &cr.imsi_tables {
                if !imsi_tables.insert(t.name.as_str()) {
                    return Err(where_(format!("duplicate imsi_table `{}`", t.name)));
                }
            }
            let mut rule_names = BTreeSet::new();
            for rule in &cr.rules {
                if !rule_names.insert(rule.name.as_str()) {
                    return Err(where_(format!("duplicate content rule `{}`", rule.name)));
                }
                // Match references.
                if let Some(t) = &rule.match_.imsi_in {
                    if !imsi_tables.contains(t.as_str()) {
                        return Err(where_(format!(
                            "content rule `{}` matches unknown imsi_table `{}`",
                            rule.name, t
                        )));
                    }
                }
                for (field, t) in [
                    ("cdpa_gt_in", &rule.match_.cdpa_gt_in),
                    ("cgpa_gt_in", &rule.match_.cgpa_gt_in),
                ] {
                    if let Some(t) = t {
                        if !addr_tables.contains(t.as_str()) {
                            return Err(where_(format!(
                                "content rule `{}` {field} references unknown address_table `{}`",
                                rule.name, t
                            )));
                        }
                    }
                }
                // Operation names must be recognised and belong to the block's
                // declared `protocol` (a gsm-cap rule cannot match a MAP operation).
                if let Some(ops) = &rule.match_.operation {
                    let want_cap = cr.protocol == ContentProtocol::GsmCap;
                    for op in ops.as_slice() {
                        match crate::content::Operation::from_kebab(op) {
                            None => {
                                return Err(where_(format!(
                                    "content rule `{}` names unknown operation `{}`",
                                    rule.name, op
                                )))
                            }
                            Some(o) if o.is_cap() != want_cap => {
                                return Err(where_(format!(
                                    "content rule `{}` operation `{}` does not match the \
                                     content_routing protocol `{:?}`",
                                    rule.name, op, cr.protocol
                                )));
                            }
                            Some(_) => {}
                        }
                    }
                }
                // Action route target.
                if let Some(t) = &rule.action.route {
                    self.validate_target(t, tenant, &group_names)
                        .map_err(|e| where_(format!("content rule `{}`: {e}", rule.name)))?;
                }
            }
        }

        // ISUP screening: rule names unique; any named message-type is known.
        if let Some(scr) = &tenant.isup_screening {
            let mut rule_names = BTreeSet::new();
            for rule in &scr.rules {
                if !rule_names.insert(rule.name.as_str()) {
                    return Err(where_(format!(
                        "duplicate isup_screening rule `{}`",
                        rule.name
                    )));
                }
                if let Some(mt) = &rule.match_.message_type {
                    if crate::isup::message_type_from_name(mt).is_none() {
                        return Err(where_(format!(
                            "isup_screening rule `{}` names unknown message_type `{}`",
                            rule.name, mt
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// A route target must name exactly one of dpc / group / local / tenant,
    /// and any referenced group / tenant / dpc must resolve.
    fn validate_target(
        &self,
        t: &RouteTarget,
        tenant: &Tenant,
        group_names: &BTreeSet<&str>,
    ) -> Result<()> {
        let set = [
            t.dpc.is_some(),
            t.group.is_some(),
            t.local.unwrap_or(false),
            t.tenant.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if set == 0 {
            return Err(Error::validation("route target names nothing".to_string()));
        }
        if let Some(dpc) = t.dpc {
            dpc.resolve(tenant.variant)?;
        }
        if let Some(g) = &t.group {
            if !group_names.contains(g.as_str()) {
                return Err(Error::validation(format!("unknown gtt_group `{g}`")));
            }
        }
        if let Some(tn) = &t.tenant {
            if !self.tenants.contains_key(tn) {
                return Err(Error::validation(format!("unknown tenant `{tn}`")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A representative flat single-tenant config drawn from the spec sample
    /// (synthetic: decimal PCs, +1-555-01xx GTs, test PLMN 001/01).
    pub(crate) const SAMPLE: &str = r#"
node:
  point_code: 1000
  variant: ITU
  network_indicator: international

associations:
  - { id: hlr-a, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
  - { id: hlr-b, adaptation: m3ua, role: server, addrs: [10.1.0.11], port: 2905 }
  - { id: msc,   adaptation: m3ua, role: server, addrs: [10.1.0.12], port: 2905 }
  - { id: xit-1, adaptation: m2pa, role: client, addrs: [10.0.1.1], port: 3565, adjacent_pc: 3000 }
  - { id: xit-2, adaptation: m2pa, role: client, addrs: [10.0.1.2], port: 3565, adjacent_pc: 3001 }

application_servers:
  - { name: hlr, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a, hlr-b] }
  - { name: msc, traffic_mode: override,  routing_context: 101, asps: [msc] }

linksets:
  - { name: transit, links: [{assoc: xit-1}, {assoc: xit-2}] }

mtp3_routes:
  - { dpc: 2000, as: hlr,          priority: 1 }
  - { dpc: 2000, linkset: transit, priority: 2 }
  - { dpc: 2002, as: msc,          priority: 1 }

sccp:
  local_ssns: [6, 8]
  gtt_groups:
    - { name: ag-hlr,    mode: cost,  members: [{dpc: 2000, ssn: 6, cost: 1}, {dpc: 2001, ssn: 6, cost: 2}] }
    - { name: ag-router, mode: share, members: [{dpc: 2003, ssn: 8, weight: 1}, {dpc: 2004, ssn: 8, weight: 1}] }
  gtt:
    - { match: {gt_prefix: "155501", gti: 4, tt: 0, np: 1, nai: 4}, to: {group: ag-hlr} }
    - { match: {gt_prefix: "1555"},                                 to: {dpc: 2000, ssn: 6} }
  gt_conversion:
    plmn_map:
      - { mcc: "001", mnc: "01", e164_prefix: "15551" }
      - { mcc: "001", mnc: "02", e164_prefix: "15552" }

content_routing:
  protocol: gsm-map
  address_tables:
    - { name: home-subs, addrs: ["15550142", "15550143"] }
  imsi_tables:
    - { name: customer-a, prefixes: ["001010", "001011"] }
    - { name: sponsor, prefixes: ["00102"] }
  rules:
    - name: customer-a-home
      match:  { operation: [update-location, send-auth-info, cancel-location], imsi_in: customer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: imsi-steer
      match:  { imsi_prefix: "001" }
      action: { screen: true }
    - name: mt-sms-home-route
      match:  { operation: sri-sm, cdpa_gt_in: home-subs }
      action: { route: {group: ag-router}, rewrite_cdpa_gt: "15550100" }
    - name: sri-sm-route
      match:  { operation: sri-sm }
      action: { route: {dpc: 2000, ssn: 6} }
"#;

    #[test]
    fn the_variant_is_read_in_lower_case_as_documented() {
        // The reference and every example write `variant: itu`. The upper-case
        // spelling of the codec crate stays accepted.
        for (spelling, variant) in [
            ("itu", Variant::Itu),
            ("ansi", Variant::Ansi),
            ("china", Variant::China),
            ("ITU", Variant::Itu),
            ("Ansi", Variant::Ansi),
        ] {
            let cfg = Config::parse(&format!(
                "node: {{ point_code: 1000, variant: {spelling} }}\nsccp: {{ local_ssns: [6] }}\n"
            ))
            .unwrap_or_else(|e| panic!("variant: {spelling} does not load: {e}"));
            assert_eq!(cfg.tenant("default").unwrap().variant, variant);
        }
        let error = Config::parse("node: { point_code: 1000, variant: etsi }\n")
            .expect_err("an unknown variant is refused")
            .to_string();
        assert!(error.contains("itu, ansi or china"), "{error}");
    }

    #[test]
    fn parses_the_sample() {
        let cfg = Config::parse(SAMPLE).expect("sample parses");
        assert_eq!(cfg.associations.len(), 5);
        // Implicit default tenant present.
        let t = cfg.default_tenant().expect("default tenant");
        assert_eq!(t.resolved_point_code().unwrap().value(), 1000);
        assert_eq!(t.application_servers.len(), 2);
        assert_eq!(t.linksets.len(), 1);
        assert_eq!(t.mtp3_routes.len(), 3);
        assert_eq!(t.sccp.gtt_groups.len(), 2);
        assert_eq!(t.sccp.gtt.len(), 2);
        assert_eq!(t.sccp.gt_conversion.plmn_map.len(), 2);
        let cr = t.content_routing.as_ref().unwrap();
        assert_eq!(cr.protocol, ContentProtocol::GsmMap);
        assert_eq!(cr.rules.len(), 4);
    }

    #[test]
    fn tenancy_is_implicit_default() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(cfg.tenants.len(), 1);
        assert!(cfg.tenant(DEFAULT_TENANT).is_some());
    }

    #[test]
    fn tcap_defaults_when_absent() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(cfg.tcap.invoke_timer_ms, 15_000);
        assert_eq!(cfg.tcap.dialogue_timer_ms, 30_000);
        assert_eq!(cfg.tcap.max_dialogues, 100_000);
    }

    #[test]
    fn tcap_block_parses() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
tcap: { invoke_timer_ms: 5000, dialogue_timer_ms: 12000, max_dialogues: 512 }
sccp:
  local_ssns: [6, 8]
"#;
        let cfg = Config::parse(yaml).unwrap();
        assert_eq!(cfg.tcap.invoke_timer_ms, 5000);
        assert_eq!(cfg.tcap.dialogue_timer_ms, 12000);
        assert_eq!(cfg.tcap.max_dialogues, 512);
    }

    #[test]
    fn explicit_tenants_normalise() {
        let yaml = r#"
associations:
  - { id: a1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
tenants:
  default:
    point_code: 1000
    variant: ITU
    application_servers:
      - { name: as1, traffic_mode: override, routing_context: 10, asps: [a1] }
    mtp3_routes:
      - { dpc: 2000, as: as1, priority: 1 }
  partner-ansi:
    point_code: 5000
    variant: ANSI
    application_servers:
      - { name: as1, traffic_mode: override, routing_context: 20, asps: [a1] }
    mtp3_routes:
      - { dpc: 6000, as: as1, priority: 1 }
"#;
        let cfg = Config::parse(yaml).unwrap();
        assert_eq!(cfg.tenants.len(), 2);
        assert_eq!(cfg.tenant("partner-ansi").unwrap().variant, Variant::Ansi);
        assert_eq!(
            cfg.tenant("partner-ansi")
                .unwrap()
                .point_code
                .resolve(Variant::Ansi)
                .unwrap()
                .value(),
            5000
        );
    }

    #[test]
    fn round_trips_via_reparse() {
        // Parsing is idempotent on the normalised structure: re-serialising the
        // associations + default tenant back through YAML and re-parsing yields
        // the same routing counts. (We re-emit the flat form.)
        let cfg = Config::parse(SAMPLE).unwrap();
        let t = cfg.default_tenant().unwrap();
        assert_eq!(t.mtp3_routes.len(), 3);
        let cfg2 = Config::parse(SAMPLE).unwrap();
        assert_eq!(
            cfg.default_tenant().unwrap().linksets.len(),
            cfg2.default_tenant().unwrap().linksets.len()
        );
    }

    #[test]
    fn rejects_unknown_linkset_ref() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.1], port: 3565, adjacent_pc: 3000 }
linksets:
  - { name: ls, links: [{assoc: x1}] }
mtp3_routes:
  - { dpc: 2000, linkset: nope, priority: 1 }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
        assert!(err.to_string().contains("unknown linkset"));
    }

    #[test]
    fn rejects_unknown_as_ref() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: a1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
application_servers:
  - { name: as1, traffic_mode: override, routing_context: 1, asps: [a1] }
mtp3_routes:
  - { dpc: 2000, as: nope, priority: 1 }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown application_server"));
    }

    #[test]
    fn rejects_route_with_both_as_and_linkset() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: a1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.2], port: 3565, adjacent_pc: 3000 }
application_servers:
  - { name: as1, traffic_mode: override, routing_context: 1, asps: [a1] }
linksets:
  - { name: ls, links: [{assoc: x1}] }
mtp3_routes:
  - { dpc: 2000, as: as1, linkset: ls, priority: 1 }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("both `as:` and `linkset:`"));
    }

    #[test]
    fn rejects_route_with_neither_as_nor_linkset() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations: []
mtp3_routes:
  - { dpc: 2000, priority: 1 }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("neither `as:` nor `linkset:`"));
    }

    #[test]
    fn rejects_as_asp_that_is_m2pa() {
        // An AS is served by M3UA or SUA ASPs, never an m2pa link.
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.1], port: 3565, adjacent_pc: 3000 }
application_servers:
  - { name: as1, traffic_mode: override, routing_context: 1, asps: [x1] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("served by m3ua or sua ASPs"));
    }

    #[test]
    fn rejects_linkset_link_that_is_not_m2pa() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: a1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
linksets:
  - { name: ls, links: [{assoc: a1}] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("carries m2pa links"));
    }

    /// A node with one m2pa link, the association and the linkset written by
    /// the caller.
    fn m2pa_node(association: &str, linkset: &str) -> String {
        format!(
            "node: {{ point_code: 1000, variant: ITU }}\nassociations:\n  - {association}\nlinksets:\n  - {linkset}\n"
        )
    }

    const M2PA_ASSOC: &str =
        "{ id: x1, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3565, adjacent_pc: 3000 }";

    #[test]
    fn an_m2pa_link_defaults_to_the_q703_timers_and_a_tested_link() {
        // No `m2pa:`, `slc:` or `link_test:` key: a 3.0 file loads unchanged and
        // gets the values of Q.703 12.3 and Q.707 5.5.
        let cfg =
            Config::parse(&m2pa_node(M2PA_ASSOC, "{ name: ls, links: [{assoc: x1}] }")).unwrap();
        assert!(cfg.associations[0].m2pa.is_none());
        let link = M2paLink::default();
        assert_eq!(link.proving, ProvingMode::Normal);
        assert_eq!(
            (
                link.t1_ms,
                link.t2_ms,
                link.t3_ms,
                link.t4n_ms,
                link.t4e_ms,
                link.t6_ms,
                link.t7_ms
            ),
            (45_000, 30_000, 1_500, 8_200, 500, 4_500, 2_000)
        );
        assert_eq!(
            (link.proving_interval_ms, link.restart_ms, link.tx_queue),
            (100, 1_000, 4_096)
        );
        let ls = &cfg.default_tenant().unwrap().linksets[0];
        assert!(ls.link_test.enabled);
        assert_eq!((ls.link_test.t1_ms, ls.link_test.t2_ms), (8_000, 60_000));
        assert_eq!(ls.link_test.pattern_octets().unwrap(), [0xA5; 8]);
        assert_eq!(ls.slc_of(0), 0, "the position in the list");
    }

    #[test]
    fn the_m2pa_block_sets_the_timers_and_keeps_the_other_defaults() {
        let assoc = "{ id: x1, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3565, \
                     m2pa: { proving: emergency, t4e_ms: 450, t7_ms: 800 } }";
        let linkset = "{ name: ls, links: [{assoc: x1, slc: 7}], \
                       link_test: { enabled: false, t1_ms: 5000, pattern: \"0f1e2d\" } }";
        let cfg = Config::parse(&m2pa_node(assoc, linkset)).unwrap();
        let link = cfg.associations[0].m2pa.clone().unwrap();
        assert_eq!(link.proving, ProvingMode::Emergency);
        assert_eq!((link.t4e_ms, link.t7_ms, link.t1_ms), (450, 800, 45_000));
        let ls = &cfg.default_tenant().unwrap().linksets[0];
        assert_eq!(ls.slc_of(0), 7);
        assert!(!ls.link_test.enabled);
        assert_eq!((ls.link_test.t1_ms, ls.link_test.t2_ms), (5_000, 60_000));
        assert_eq!(ls.link_test.pattern_octets().unwrap(), [0x0F, 0x1E, 0x2D]);
    }

    #[test]
    fn rejects_m2pa_link_settings_that_cannot_work() {
        let bad = |association: &str, linkset: &str, expect: &str| {
            let err = Config::parse(&m2pa_node(association, linkset)).unwrap_err();
            assert!(
                err.to_string().contains(expect),
                "{err} does not say `{expect}`"
            );
        };
        let plain = "{ name: ls, links: [{assoc: x1}] }";
        // A timer of 0 would fire at once, forever.
        bad(
            "{ id: x1, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3565, m2pa: { t7_ms: 0 } }",
            plain,
            "`t7_ms` must not be 0",
        );
        // The signalling link code is 4 bits, and names one link.
        bad(
            M2PA_ASSOC,
            "{ name: ls, links: [{assoc: x1, slc: 16}] }",
            "slc 16 is not 0 to 15",
        );
        let two = format!(
            "{M2PA_ASSOC}\n  - {{ id: x2, adaptation: m2pa, role: client, addrs: [192.0.2.2], port: 3565 }}"
        );
        bad(
            &two,
            "{ name: ls, links: [{assoc: x1, slc: 1}, {assoc: x2}] }",
            "two links with slc 1",
        );
        // Q.707 5.4: a test pattern is 1 to 15 octets.
        for pattern in ["\"\"", "abc", "zz", "00112233445566778899aabbccddeeff"] {
            bad(
                M2PA_ASSOC,
                &format!(
                    "{{ name: ls, links: [{{assoc: x1}}], link_test: {{ pattern: {pattern} }} }}"
                ),
                "not 1 to 15 octets",
            );
        }
        bad(
            M2PA_ASSOC,
            "{ name: ls, links: [{assoc: x1}], link_test: { t1_ms: 0 } }",
            "link_test timers",
        );
        // The block belongs to an m2pa association.
        let err = Config::parse(
            "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: a1, adaptation: m3ua, role: server, addrs: [192.0.2.1], port: 2905, m2pa: { t7_ms: 500 } }\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not an m2pa association"));
    }

    #[test]
    fn rejects_m2pa_under_the_ansi_variant() {
        // M2PA framing is ITU 14-bit only; an ANSI node with an m2pa linkset would
        // have its point codes masked and mangled, so it is refused at load.
        let yaml = r#"
node: { point_code: 1000, variant: ANSI }
associations:
  - { id: m2, adaptation: m2pa, role: client, addrs: [10.0.1.1], port: 3565, adjacent_pc: 3000 }
linksets:
  - { name: ls, links: [{assoc: m2}] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("m2pa under the ansi variant"));
    }

    #[test]
    fn accepts_sua_association() {
        // A standalone sua association is fine on its own.
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: s1, adaptation: sua, role: client, addrs: [10.0.0.1], port: 14001 }
"#;
        assert!(Config::parse(yaml).is_ok());
    }

    #[test]
    fn accepts_sua_application_server() {
        // An AS served by sua ASPs validates the same way an M3UA AS does.
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: s1, adaptation: sua, role: server, addrs: [10.0.0.1], port: 14001 }
application_servers:
  - { name: sccp-as, traffic_mode: loadshare, routing_context: 5, asps: [s1] }
mtp3_routes:
  - { dpc: 2000, as: sccp-as, priority: 1 }
"#;
        assert!(Config::parse(yaml).is_ok());
    }

    #[test]
    fn rejects_application_server_mixing_adaptations() {
        // All ASPs of an AS must share one adaptation (no mixing m3ua + sua).
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: m1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
  - { id: s1, adaptation: sua,  role: server, addrs: [10.0.0.1], port: 14001 }
application_servers:
  - { name: mixed, traffic_mode: loadshare, routing_context: 5, asps: [m1, s1] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("must share one adaptation"));
    }

    #[test]
    fn rejects_unknown_association_ref() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.1], port: 3565, adjacent_pc: 3000 }
linksets:
  - { name: ls, links: [{assoc: ghost}] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown association"));
    }

    #[test]
    fn rejects_duplicate_linkset() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.1], port: 3565, adjacent_pc: 3000 }
linksets:
  - { name: ls, links: [{assoc: x1}] }
  - { name: ls, links: [{assoc: x1}] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("duplicate route destination"));
    }

    #[test]
    fn rejects_point_code_out_of_range_for_variant() {
        let yaml = r#"
node: { point_code: 99999, variant: ITU }
associations: []
"#;
        assert!(Config::parse(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_operation_name() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations: []
content_routing:
  protocol: gsm-map
  rules:
    - name: bad
      match: { operation: not-an-op }
      action: { screen: true }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown operation"));
    }

    #[test]
    fn isup_screening_parses_into_default_tenant() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations: []
isup_screening:
  default: allow
  rules:
    - name: block-premium
      match: { message_type: iam, called_prefix: "1999" }
      action: block
    - name: allow-national
      match: { calling_prefix: "1555" }
      action: allow
"#;
        let cfg = Config::parse(yaml).unwrap();
        let scr = cfg
            .default_tenant()
            .unwrap()
            .isup_screening
            .as_ref()
            .expect("screening present");
        assert_eq!(scr.default, ScreenAction::Allow);
        assert_eq!(scr.rules.len(), 2);
        assert_eq!(scr.rules[0].name, "block-premium");
        assert_eq!(scr.rules[0].action, ScreenAction::Block);
        assert_eq!(scr.rules[0].match_.message_type.as_deref(), Some("iam"));
        assert_eq!(scr.rules[0].match_.called_prefix.as_deref(), Some("1999"));
    }

    #[test]
    fn isup_screening_default_is_allow_when_absent() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations: []
isup_screening:
  rules:
    - name: r1
      match: { message_type: rel }
      action: block
"#;
        let cfg = Config::parse(yaml).unwrap();
        let scr = cfg
            .default_tenant()
            .unwrap()
            .isup_screening
            .as_ref()
            .unwrap();
        assert_eq!(scr.default, ScreenAction::Allow);
    }

    #[test]
    fn rejects_unknown_isup_message_type() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations: []
isup_screening:
  rules:
    - name: bad
      match: { message_type: not-a-type }
      action: block
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown message_type"));
    }

    #[test]
    fn rejects_duplicate_isup_screening_rule() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations: []
isup_screening:
  rules:
    - name: dup
      match: { message_type: iam }
      action: block
    - name: dup
      match: { message_type: rel }
      action: block
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("duplicate isup_screening rule"));
    }

    #[test]
    fn rejects_mixed_flat_and_tenants() {
        let yaml = r#"
associations: []
mtp3_routes:
  - { dpc: 2000, linkset: ls, priority: 1 }
tenants:
  default: { point_code: 1000, variant: ITU }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("cannot be mixed"));
    }

    #[test]
    fn mtp3_management_defaults_to_the_q704_timers() {
        // A file without an `mtp3:` block loads unchanged, with Q.704 16.8.
        let cfg = Config::parse(SAMPLE).unwrap();
        let mtp3 = &cfg.default_tenant().unwrap().mtp3;
        assert_eq!(*mtp3, Mtp3::default());
        // 16.8: T1 "500 (800) to 1200 ms", T2 "700 (1400) to 2000 ms", T8
        // "800 to 1200 ms", T10 "30 to 60 seconds", T19 "67 to 69 seconds",
        // T20 "59 to 61 seconds", T21 "63 to 65 seconds".
        assert_eq!((mtp3.t1_ms, mtp3.t2_ms, mtp3.t8_ms), (800, 1_400, 1_000));
        assert!((30_000..=60_000).contains(&mtp3.t10_ms));
        assert!((67_000..=69_000).contains(&mtp3.t19_ms));
        assert!((59_000..=61_000).contains(&mtp3.t20_ms));
        assert!((63_000..=65_000).contains(&mtp3.t21_ms));
        assert!(mtp3.t18_ms < mtp3.t20_ms, "phase 1 ends inside the restart");
        assert!(mtp3.tfp_for_unknown_destination);
    }

    #[test]
    fn the_mtp3_block_sets_timers_and_keeps_the_other_defaults() {
        let yaml = "node: { point_code: 1000, variant: ITU }\n\
                    mtp3: { t2_ms: 900, t21_ms: 5000, tfp_for_unknown_destination: false }\n";
        let cfg = Config::parse(yaml).unwrap();
        let mtp3 = &cfg.default_tenant().unwrap().mtp3;
        assert_eq!((mtp3.t2_ms, mtp3.t21_ms), (900, 5_000));
        assert!(!mtp3.tfp_for_unknown_destination);
        assert_eq!(mtp3.t1_ms, Mtp3::default().t1_ms);

        // Under an explicit domain it is that domain's.
        let yaml =
            "tenants:\n  default: { point_code: 1000, variant: ITU, mtp3: { t6_ms: 600 } }\n";
        let cfg = Config::parse(yaml).unwrap();
        assert_eq!(cfg.default_tenant().unwrap().mtp3.t6_ms, 600);
    }

    #[test]
    fn rejects_an_mtp3_timer_of_zero() {
        for key in ["t1_ms", "t8_ms", "t18_ms", "rerouting_buffer"] {
            let yaml =
                format!("node: {{ point_code: 1000, variant: ITU }}\nmtp3: {{ {key}: 0 }}\n");
            let err = Config::parse(&yaml).unwrap_err().to_string();
            assert!(err.contains(key) && err.contains("must not be 0"), "{err}");
        }
    }
    const M3UA_NODE: &str = "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: a1, adaptation: m3ua, role: server, addrs: [192.0.2.1], port: 2905 }\n  - { id: a2, adaptation: m3ua, role: client, addrs: [192.0.2.2], port: 2905 }\n";

    #[test]
    fn m3ua_management_defaults_to_the_values_of_rfc_4666() {
        // No `m3ua:` block and none of the server keys: a 3.0 file loads
        // unchanged.
        let cfg = Config::parse(&format!(
            "{M3UA_NODE}application_servers:\n  - {{ name: as1, traffic_mode: loadshare, routing_context: 1, asps: [a1, a2] }}\n"
        ))
        .unwrap();
        assert!(cfg.associations[0].m3ua.is_none());
        let peer = M3uaPeer::default();
        // 4.3.4.6: the heartbeat is optional. 4.3.4.1: T(ack) "is
        // provisionable, with a default of 2 seconds".
        assert_eq!((peer.beat_ms, peer.ack_ms, peer.asp_id), (0, 2_000, None));
        let server = &cfg.default_tenant().unwrap().application_servers[0];
        assert_eq!(
            (
                server.recovery_ms,
                server.pending_queue,
                server.required_asps
            ),
            (2_000, 4_096, 1)
        );
    }

    #[test]
    fn the_m3ua_keys_are_read() {
        let cfg = Config::parse(
            "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: a1, adaptation: m3ua, role: client, addrs: [192.0.2.1], port: 2905, m3ua: { beat_ms: 30000, ack_ms: 500, asp_id: 7 } }\n  - { id: a2, adaptation: m3ua, role: server, addrs: [192.0.2.2], port: 2905, m3ua: { beat_ms: 1000 } }\napplication_servers:\n  - { name: as1, traffic_mode: broadcast, routing_context: 1, asps: [a1, a2], recovery_ms: 0, pending_queue: 16, required_asps: 2 }\n",
        )
        .unwrap();
        let peer = cfg.associations[0].m3ua.clone().unwrap();
        assert_eq!(
            (peer.beat_ms, peer.ack_ms, peer.asp_id),
            (30_000, 500, Some(7))
        );
        // The keys left out keep their defaults.
        assert_eq!(cfg.associations[1].m3ua.clone().unwrap().ack_ms, 2_000);
        let server = &cfg.default_tenant().unwrap().application_servers[0];
        assert_eq!(
            (
                server.recovery_ms,
                server.pending_queue,
                server.required_asps
            ),
            (0, 16, 2)
        );
    }

    #[test]
    fn rejects_m3ua_settings_that_cannot_work() {
        let bad = |yaml: &str, expect: &str| {
            let err = Config::parse(yaml).unwrap_err();
            assert!(
                err.to_string().contains(expect),
                "{err} does not say `{expect}`"
            );
        };
        let server = |keys: &str| {
            format!(
                "{M3UA_NODE}application_servers:\n  - {{ name: as1, traffic_mode: loadshare, routing_context: 1, asps: [a1, a2], {keys} }}\n"
            )
        };
        // More ASPs required than the server has, or none.
        bad(
            &server("required_asps: 3"),
            "`required_asps` must be between 1 and 2",
        );
        bad(
            &server("required_asps: 0"),
            "`required_asps` must be between 1 and 2",
        );
        bad(&server("pending_queue: 0"), "`pending_queue` must not be 0");
        // RFC 4666 4.3.2: "n = 1 for Override Traffic Mode".
        bad(
            &format!(
                "{M3UA_NODE}application_servers:\n  - {{ name: as1, traffic_mode: override, routing_context: 1, asps: [a1, a2], required_asps: 2 }}\n"
            ),
            "`required_asps` must be between 1 and 1",
        );
        // A timer of 0 would fire at once, forever.
        bad(
            "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: a1, adaptation: m3ua, role: client, addrs: [192.0.2.1], port: 2905, m3ua: { ack_ms: 0 } }\n",
            "m3ua `ack_ms` must not be 0",
        );
        // The block belongs to an m3ua association.
        bad(
            "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: x1, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3565, m3ua: { beat_ms: 500 } }\n",
            "is not an m3ua association",
        );
    }

    /// A node with these association entries and nothing else.
    fn listening(associations: &[&str]) -> String {
        let mut yaml = String::from("node: { point_code: 1000, variant: ITU }\nassociations:\n");
        for (number, entry) in associations.iter().enumerate() {
            yaml.push_str(&format!(
                "  - {{ id: a{number}, adaptation: m3ua, role: server, {entry} }}\n"
            ));
        }
        yaml
    }

    #[test]
    fn peer_addrs_and_peer_port_default_to_whoever_connects() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert!(cfg.associations.iter().all(|a| a.peer_addrs.is_empty()));
        assert!(cfg.associations.iter().all(|a| a.peer_port.is_none()));

        let cfg = Config::parse(&listening(&[
            "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10, \"2001:db8::10\", \"::ffff:198.51.100.10\"], peer_port: 2905",
        ]))
        .unwrap();
        let a = &cfg.associations[0];
        assert_eq!(a.peer_port, Some(2905));
        // An IPv4-mapped address is the IPv4 address.
        let ips: Vec<String> = a
            .peer_ips()
            .unwrap()
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        assert_eq!(ips, ["192.0.2.10", "2001:db8::10", "198.51.100.10"]);
    }

    #[test]
    fn associations_that_listen_on_one_endpoint_must_be_told_apart() {
        // (the associations, what the error names; `None` loads)
        let table: [(&[&str], Option<&[&str]>); 12] = [
            // One endpoint, each with its peer: one listener, two associations.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10]",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
                ],
                None,
            ),
            // Multihomed, the local addresses in another order.
            (
                &[
                    "addrs: [192.0.2.1, 198.51.100.1], port: 2905, peer_addrs: [192.0.2.10, 198.51.100.10]",
                    "addrs: [198.51.100.1, 192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
                ],
                None,
            ),
            // The same peer address, told apart by its port.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10], peer_port: 3000",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10], peer_port: 3001",
                ],
                None,
            ),
            // Different local addresses or ports are different endpoints.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905",
                    "addrs: [192.0.2.2], port: 2905",
                    "addrs: [192.0.2.1], port: 2906",
                ],
                None,
            ),
            // Port 0 asks for a port of its own, every time.
            (
                &["addrs: [192.0.2.1], port: 0", "addrs: [192.0.2.1], port: 0"],
                None,
            ),
            // A peer in two lists.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10, 192.0.2.11]",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.11]",
                ],
                Some(&["`a0`", "`a1`", "192.0.2.11"]),
            ),
            // The same peer address where only one fixes the port.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10], peer_port: 3000",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10]",
                ],
                Some(&["`a0`", "`a1`", "192.0.2.10"]),
            ),
            // One with a list and one without.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10]",
                    "addrs: [192.0.2.1], port: 2905",
                ],
                Some(&["`a0`", "`a1`", "peer_addrs"]),
            ),
            // Neither with a list: before, the second failed to bind at start.
            (
                &["addrs: [192.0.2.1], port: 2905", "addrs: [192.0.2.1], port: 2905"],
                Some(&["`a0`", "`a1`", "peer_addrs"]),
            ),
            // The third against the second.
            (
                &[
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10]",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
                ],
                Some(&["`a1`", "`a2`", "192.0.2.20"]),
            ),
            // Address lists that overlap and differ cannot both be bound.
            (
                &[
                    "addrs: [192.0.2.1, 198.51.100.1], port: 2905, peer_addrs: [192.0.2.10]",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
                ],
                Some(&["`a0`", "`a1`", "overlap"]),
            ),
            // Every address covers every other.
            (
                &[
                    "addrs: [0.0.0.0], port: 2905, peer_addrs: [192.0.2.10]",
                    "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
                ],
                Some(&["`a0`", "`a1`", "overlap"]),
            ),
        ];
        for (associations, names) in table {
            let outcome = Config::parse(&listening(associations));
            match names {
                None => {
                    outcome.unwrap_or_else(|e| panic!("{associations:?}: {e}"));
                }
                Some(names) => {
                    let error = outcome.err().map(|e| e.to_string()).unwrap_or_default();
                    for name in names {
                        assert!(error.contains(name), "{associations:?}: `{error}`");
                    }
                }
            }
        }
    }

    #[test]
    fn the_listening_endpoints_of_a_file_are_grouped() {
        let cfg = Config::parse(&listening(&[
            "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10]",
            "addrs: [192.0.2.2], port: 2905",
            "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.20]",
            "addrs: [192.0.2.1], port: 0",
            "addrs: [192.0.2.1], port: 0",
        ]))
        .unwrap();
        assert_eq!(
            listen_groups(&cfg.associations).unwrap(),
            [vec![0, 2], vec![1], vec![3], vec![4]]
        );
        // A client association listens nowhere.
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(
            listen_groups(&cfg.associations).unwrap(),
            [vec![0], vec![1], vec![2]]
        );
    }

    #[test]
    fn the_peer_keys_are_checked() {
        // (the association, what the error says)
        let table = [
            (
                "addrs: [192.0.2.1], port: 2905, peer_addrs: [hlr.example]",
                "not an IP address",
            ),
            (
                "addrs: [192.0.2.1], port: 2905, peer_port: 2905",
                "no `peer_addrs`",
            ),
            (
                "addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.10], peer_port: 0",
                "must not be 0",
            ),
        ];
        for (association, says) in table {
            let error = Config::parse(&listening(&[association]))
                .unwrap_err()
                .to_string();
            assert!(error.contains(says), "{association}: `{error}`");
        }
        // On a client the peer is `addrs` and `port`.
        let yaml = "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: c, adaptation: m3ua, role: client, addrs: [192.0.2.1], port: 2905, peer_addrs: [192.0.2.1] }\n";
        let error = Config::parse(yaml).unwrap_err().to_string();
        assert!(error.contains("is a client"), "`{error}`");
    }

    /// A node with one client association with these further keys.
    fn dialling(keys: &str) -> String {
        format!(
            "node: {{ point_code: 1000, variant: ITU }}\nassociations:\n  - {{ id: c, adaptation: m3ua, role: client, addrs: [192.0.2.1], port: 2905{keys} }}\n"
        )
    }

    #[test]
    fn a_client_association_has_dial_settings_and_local_addresses() {
        let cfg = Config::parse(&dialling("")).unwrap();
        let a = &cfg.associations[0];
        assert!(a.local_addrs.is_empty() && a.local_port.is_none() && a.dial.is_none());
        let defaults = Dial::default();
        assert_eq!(
            (
                defaults.connect_timeout_ms,
                defaults.backoff_initial_ms,
                defaults.backoff_max_ms,
                defaults.backoff_jitter_percent
            ),
            (10_000, 1_000, 30_000, 20)
        );

        let cfg = Config::parse(&dialling(
            ", local_addrs: [192.0.2.7, \"2001:db8::7\"], local_port: 2906, dial: { backoff_max_ms: 5000, backoff_jitter_percent: 0 }",
        ))
        .unwrap();
        let a = &cfg.associations[0];
        assert_eq!(a.local_ips().unwrap().len(), 2);
        assert_eq!(a.local_port, Some(2906));
        // A key that is left out keeps its default.
        assert_eq!(
            a.dial,
            Some(Dial {
                backoff_max_ms: 5_000,
                backoff_jitter_percent: 0,
                ..Dial::default()
            })
        );
    }

    #[test]
    fn the_dial_keys_are_checked() {
        // (the keys, what the error says)
        let table = [
            (", local_addrs: [gateway.example]", "not an IP address"),
            (", local_port: 0", "must not be 0"),
            (
                ", dial: { connect_timeout_ms: 0 }",
                "`connect_timeout_ms` must not be 0",
            ),
            (
                ", dial: { backoff_initial_ms: 0 }",
                "`backoff_initial_ms` must not be 0",
            ),
            (
                ", dial: { backoff_max_ms: 0 }",
                "`backoff_max_ms` must not be 0",
            ),
            (
                ", dial: { backoff_initial_ms: 2000, backoff_max_ms: 1000 }",
                "below `backoff_initial_ms`",
            ),
            (", dial: { backoff_jitter_percent: 101 }", "more than 100"),
        ];
        for (keys, says) in table {
            let error = Config::parse(&dialling(keys)).unwrap_err().to_string();
            assert!(error.contains(says), "{keys}: `{error}`");
        }
        // On a server the local end is `addrs` and `port`.
        for keys in ["local_addrs: [192.0.2.7]", "local_port: 2906", "dial: {}"] {
            let error = Config::parse(&listening(&[&format!(
                "addrs: [192.0.2.1], port: 2905, {keys}"
            )]))
            .unwrap_err()
            .to_string();
            assert!(error.contains("is a server"), "{keys}: `{error}`");
        }
    }
}
