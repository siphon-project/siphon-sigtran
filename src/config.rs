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

/// The `node:` block: our point code, variant, and network indicator.
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    /// Our point code (decimal, resolved under [`Node::variant`]).
    pub point_code: RawPc,
    /// SS7 variant (fixes the point-code width).
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
    /// SUA (RFC 3868), SCTP PPID 4. **Reserved only** in this release: the
    /// config accepts it so a plan can name it, but no SUA transport exists yet
    /// (it needs a SUA codec crate that is not published). Starting a node with
    /// a `sua` association returns a clear "not implemented" from the transport.
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
    /// For m2pa links only: the adjacent point code reached directly over this
    /// link. An adjacent PC is an **implicit full route**, see
    /// [`crate::mtp3::route`].
    #[serde(default)]
    pub adjacent_pc: Option<RawPc>,
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

/// One `application_servers:` entry: an M3UA **Application Server** (RFC 4666).
///
/// An AS is a logical destination served by one or more **ASPs**. Each ASP is
/// an M3UA association (referenced by id in [`asps`](ApplicationServer::asps)),
/// and the per-ASP ASPSM/ASPTM state machine brings it up. The traffic mode is
/// an AS property, not a per-ASP one.
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
}

/// A link within a linkset: an association bound to a signalling-link code.
#[derive(Debug, Clone, Deserialize)]
pub struct Link {
    /// The association id this link rides.
    pub assoc: String,
    /// Signalling Link Selection code within the linkset.
    pub slc: u8,
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

/// The numbering plan a `gt_conversion` rule matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversionNp {
    /// E.214 (Mobile Global Title).
    E214,
    /// E.164 (ISDN).
    E164,
}

/// The `match:` clause of a gt_conversion rule.
#[derive(Debug, Clone, Deserialize)]
pub struct ConversionMatch {
    /// The numbering plan to match (e214 / e164).
    pub np: ConversionNp,
    /// Optional addressing hint (e.g. `imsi` for the outbound E.164→E.214 case).
    #[serde(default)]
    pub addressing: Option<String>,
}

/// The `action:` clause of a gt_conversion rule.
#[derive(Debug, Clone, Deserialize)]
pub struct ConversionAction {
    /// Convert E.214 → E.164 via the named map (`plmn_map`).
    #[serde(default)]
    pub to_e164_via: Option<String>,
    /// Convert E.164 → E.214 via the named map (`plmn_map`).
    #[serde(default)]
    pub to_e214_via: Option<String>,
}

/// One `gt_conversion.rules:` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ConversionRule {
    /// Rule name (for metrics + ordering clarity).
    pub name: String,
    /// The match criteria.
    #[serde(rename = "match")]
    pub match_: ConversionMatch,
    /// The conversion to apply.
    pub action: ConversionAction,
}

/// The `gt_conversion:` block: E.214 ↔ E.164 mobile-global-title conversion.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GtConversion {
    /// The E.212 → E.164 network numbering map.
    #[serde(default)]
    pub plmn_map: Vec<PlmnMapEntry>,
    /// The ordered conversion rules.
    #[serde(default)]
    pub rules: Vec<ConversionRule>,
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
    /// How long an outstanding invoke waits for its result before it is aged out
    /// and `sigtran_invoke_timeouts_total` counts it. Milliseconds.
    pub invoke_timer_ms: u64,
    /// How long a dialogue may sit with no activity before it is aged out and
    /// `sigtran_dialogue_timeouts_total` counts it. Milliseconds.
    pub dialogue_timer_ms: u64,
    /// The maximum number of concurrently open dialogues. A Begin over this
    /// ceiling is rejected with a P-Abort (counted as a local abort).
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
    /// Defer to a named Python hook (phase-3). The name is carried through.
    #[serde(default)]
    pub python: Option<String>,
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

// ── The per-tenant body + the whole file ────────────────────────────────────

/// The per-tenant routing tables: the shape that repeats under each
/// `tenants:` entry, and that the flat top level collapses into for `default`.
#[derive(Debug, Clone, Deserialize)]
pub struct Tenant {
    /// The tenant's own point code (decimal).
    pub point_code: RawPc,
    /// The tenant's SS7 variant.
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
    /// The tenant's SCCP/GTT tables.
    #[serde(default)]
    pub sccp: Sccp,
    /// The tenant's content-routing rules.
    #[serde(default)]
    pub content_routing: Option<ContentRouting>,
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
    sccp: Option<Sccp>,
    #[serde(default)]
    content_routing: Option<ContentRouting>,
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
                    || raw.sccp.is_some()
                    || raw.content_routing.is_some()
                {
                    return Err(Error::validation(
                        "top-level routing fields (application_servers/linksets/mtp3_routes/\
                         sccp/content_routing) cannot be mixed with an explicit `tenants:` block",
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
                        sccp: raw.sccp.unwrap_or_default(),
                        content_routing: raw.content_routing,
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
            if let Some(pc) = a.adjacent_pc {
                // adjacent_pc only meaningful for m2pa; still must fit *some*
                // variant, validated per-tenant below where the variant is
                // known. Here just a sanity bound against the widest (ANSI).
                pc.resolve(Variant::Ansi)?;
            }
        }

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

        // Route-destination names live in one namespace across Application
        // Servers and linksets, so `mtp3_routes` can reference either and a name
        // never resolves two ways.
        let mut dest_names = BTreeSet::new();

        // Application Servers: names unique; each ASP is a known m3ua association.
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
            for asp in &a.asps {
                match assoc_adapt.get(asp.as_str()) {
                    None => {
                        return Err(where_(format!(
                            "application_server `{}` references unknown association `{}`",
                            a.name, asp
                        )))
                    }
                    Some(Adaptation::M3ua) => {}
                    Some(other) => {
                        return Err(where_(format!(
                            "application_server `{}` asp `{}` is a {other:?} association, \
                             an AS is served by m3ua ASPs",
                            a.name, asp
                        )))
                    }
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
            for link in &ls.links {
                match assoc_adapt.get(link.assoc.as_str()) {
                    None => {
                        return Err(where_(format!(
                            "linkset `{}` references unknown association `{}`",
                            ls.name, link.assoc
                        )))
                    }
                    Some(Adaptation::M2pa) => {}
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
                // Operation names must be recognised.
                if let Some(ops) = &rule.match_.operation {
                    for op in ops.as_slice() {
                        if crate::content::Operation::from_kebab(op).is_none() {
                            return Err(where_(format!(
                                "content rule `{}` names unknown operation `{}`",
                                rule.name, op
                            )));
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
  - { name: transit, links: [{assoc: xit-1, slc: 0}, {assoc: xit-2, slc: 1}] }

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
    rules:
      - { name: e214-in,  match: {np: e214},                   action: {to_e164_via: plmn_map} }
      - { name: e214-out, match: {np: e164, addressing: imsi}, action: {to_e214_via: plmn_map} }

content_routing:
  protocol: gsm-map
  address_tables:
    - { name: home-subs, addrs: ["15550142", "15550143"] }
  imsi_tables:
    - { name: buyer-a, prefixes: ["001010", "001011"] }
    - { name: sponsor, prefixes: ["00102"] }
  rules:
    - name: buyer-a-home
      match:  { operation: [update-location, send-auth-info, cancel-location], imsi_in: buyer-a }
      action: { route: {dpc: 2005, ssn: 6} }
    - name: imsi-steer
      match:  { imsi_prefix: "001" }
      action: { python: on_imsi_route }
    - name: mt-sms-home-route
      match:  { operation: sri-sm, cdpa_gt_in: home-subs }
      action: { route: {group: ag-router}, rewrite_cdpa_gt: "15550100" }
    - name: sri-sm-np
      match:  { operation: sri-sm }
      action: { python: on_np_dip }
"#;

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
  - { name: ls, links: [{assoc: x1, slc: 0}] }
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
  - { name: ls, links: [{assoc: x1, slc: 0}] }
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
    fn rejects_as_asp_that_is_not_m3ua() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.1], port: 3565, adjacent_pc: 3000 }
application_servers:
  - { name: as1, traffic_mode: override, routing_context: 1, asps: [x1] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("served by m3ua ASPs"));
    }

    #[test]
    fn rejects_linkset_link_that_is_not_m2pa() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: a1, adaptation: m3ua, role: server, addrs: [10.0.0.1], port: 2905 }
linksets:
  - { name: ls, links: [{assoc: a1, slc: 0}] }
"#;
        let err = Config::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("carries m2pa links"));
    }

    #[test]
    fn accepts_reserved_sua_association() {
        // `sua` is reserved: parse/validate accept it (the transport rejects it
        // at start). An unreferenced sua association is fine on its own.
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: s1, adaptation: sua, role: client, addrs: [10.0.0.1], port: 14001 }
"#;
        assert!(Config::parse(yaml).is_ok());
    }

    #[test]
    fn rejects_unknown_association_ref() {
        let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: x1, adaptation: m2pa, role: client, addrs: [10.0.0.1], port: 3565, adjacent_pc: 3000 }
linksets:
  - { name: ls, links: [{assoc: ghost, slc: 0}] }
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
  - { name: ls, links: [{assoc: x1, slc: 0}] }
  - { name: ls, links: [{assoc: x1, slc: 1}] }
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
}
