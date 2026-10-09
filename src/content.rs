//! The **content-routing** engine: routing on the decoded application layer.
//!
//! A [`ContentRule`](crate::config::ContentRule) matches over a read-only,
//! decoded view of a MAP/CAP message, [`MapView`], and yields an [`Action`]:
//! route the message onward (optionally rewriting the called-party GT) or screen
//! it. The rules run entirely in Rust at line rate.
//!
//! The engine here is deliberately simple and synchronous: it takes an already
//! decoded [`MapView`] (the tests assemble a real MAP/CAP argument, wrap it in
//! TCAP/SCCP, and decode a view out of it) and walks the ordered rules
//! **first-match-wins**.

use sccp::SccpMessage;

use crate::config::{ContentAction, ContentRouting, ContentRule};

/// A MAP/CAP operation the content engine can match on, named in the config in
/// kebab-case. Maps to the published `gsm_map` / `gsm_cap` operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// MAP `sendRoutingInfoForSM` (45).
    SriSm,
    /// MAP `mo-ForwardSM` (46).
    MoForwardSm,
    /// MAP `mt-ForwardSM` (44).
    MtForwardSm,
    /// MAP `updateLocation` (2).
    UpdateLocation,
    /// MAP `cancelLocation` (3).
    CancelLocation,
    /// MAP `sendAuthenticationInfo` (56).
    SendAuthInfo,
    /// MAP `insertSubscriberData` (7).
    InsertSubscriberData,
    /// MAP `provideSubscriberInfo` / PSI-style query.
    ProvideSubscriberInfo,
    /// CAMEL `initialDP` (0).
    InitialDp,
    /// CAMEL `connect` (20).
    Connect,
}

impl Operation {
    /// Parse the kebab-case name used in the config, or `None` if unrecognised.
    pub fn from_kebab(s: &str) -> Option<Self> {
        Some(match s {
            "sri-sm" => Self::SriSm,
            "mo-forward-sm" => Self::MoForwardSm,
            "mt-forward-sm" => Self::MtForwardSm,
            "update-location" => Self::UpdateLocation,
            "cancel-location" => Self::CancelLocation,
            "send-auth-info" => Self::SendAuthInfo,
            "insert-subscriber-data" => Self::InsertSubscriberData,
            "provide-subscriber-info" => Self::ProvideSubscriberInfo,
            "initial-dp" => Self::InitialDp,
            "connect" => Self::Connect,
            _ => return None,
        })
    }

    /// The MAP (TS 29.002) / CAP (TS 29.078) local operation code. MAP and CAP
    /// codes overlap numerically; disambiguate with the surrounding SSN/AC.
    pub fn op_code(self) -> i64 {
        use gsm_cap::op_codes as cap;
        use gsm_map::types::op_codes as map;
        match self {
            Self::SriSm => map::SEND_ROUTING_INFO_FOR_SM,
            Self::MoForwardSm => map::MO_FORWARD_SM,
            Self::MtForwardSm => map::MT_FORWARD_SM,
            Self::UpdateLocation => map::UPDATE_LOCATION,
            Self::CancelLocation => map::CANCEL_LOCATION,
            Self::SendAuthInfo => map::SEND_AUTHENTICATION_INFO,
            Self::InsertSubscriberData => map::INSERT_SUBSCRIBER_DATA,
            // provideSubscriberInfo op code (TS 29.002) is 70.
            Self::ProvideSubscriberInfo => 70,
            Self::InitialDp => cap::INITIAL_DP,
            Self::Connect => cap::CONNECT,
        }
    }

    /// The recognised content [`Operation`] for a decoded local operation code, or
    /// `None` if it is not one this engine routes on. The reverse of
    /// [`op_code`](Self::op_code). The ten recognised codes are numerically
    /// distinct, so no SSN/AC disambiguation is needed here (a MAP message never
    /// carries the CAP `initial-dp`/`connect` codes 0/20).
    pub fn from_op_code(code: i64) -> Option<Self> {
        use gsm_cap::op_codes as cap;
        use gsm_map::types::op_codes as map;
        Some(match code {
            c if c == map::SEND_ROUTING_INFO_FOR_SM => Self::SriSm,
            c if c == map::MO_FORWARD_SM => Self::MoForwardSm,
            c if c == map::MT_FORWARD_SM => Self::MtForwardSm,
            c if c == map::UPDATE_LOCATION => Self::UpdateLocation,
            c if c == map::CANCEL_LOCATION => Self::CancelLocation,
            c if c == map::SEND_AUTHENTICATION_INFO => Self::SendAuthInfo,
            c if c == map::INSERT_SUBSCRIBER_DATA => Self::InsertSubscriberData,
            70 => Self::ProvideSubscriberInfo,
            c if c == cap::INITIAL_DP => Self::InitialDp,
            c if c == cap::CONNECT => Self::Connect,
            _ => return None,
        })
    }

    /// Whether this is a CAMEL CAP operation (as opposed to a MAP one). Used to
    /// check a content rule's operations against its declared `protocol`.
    pub fn is_cap(self) -> bool {
        matches!(self, Self::InitialDp | Self::Connect)
    }
}

/// A read-only, decoded view of a MAP/CAP message: the fields a content rule
/// can inspect. The runtime populates it from a decoded TCAP component (see the
/// integration tests, which assemble real bytes and decode a view back).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapView {
    /// The operation, if the op code was recognised.
    pub operation: Option<Operation>,
    /// The calling-party GT digits (SCCP CgPA).
    pub cgpa_gt: Option<String>,
    /// The called-party GT digits (SCCP CdPA).
    pub cdpa_gt: Option<String>,
    /// The subscriber IMSI carried in the MAP argument, decimal digits.
    pub imsi: Option<String>,
    /// The MSISDN carried in the MAP argument, decimal digits.
    pub msisdn: Option<String>,
}

// ── Decoding a wire message into a MapView ───────────────────────────────────

/// What the content layer can say about one connectionless SCCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screening {
    /// The message is a TCAP `Begin` or `Continue` that decoded in full, and
    /// this is the view the rules are evaluated on.
    View(MapView),
    /// The message is not one the content rules apply to: its payload is not a
    /// TCAP message, it is an `End`, an `Abort` or a `Unidirectional`, or it is
    /// a `Begin` / `Continue` without an `Invoke` of a local operation. It is
    /// routed as if the domain had no content rules.
    NotApplicable,
    /// The message is a TCAP `Begin` or `Continue` that could **not** be decoded
    /// in full: a damaged transaction or dialogue portion, a component that
    /// cannot be read, octets after the end of the message. Nothing can be said
    /// about what its receiver would do with it, so it has not passed the rules:
    /// the router drops it ([`Inbound::content_undecodable`]).
    ///
    /// [`Inbound::content_undecodable`]: crate::routing::Inbound::content_undecodable
    Undecodable,
    /// The message is one segment of a segmented XUDT / LUDT (Q.714 4.1.1): the
    /// TCAP message is not whole in it, and this node does not reassemble in
    /// transit. It is not evaluated against the rules.
    Segmented,
}

/// Decode a connectionless SCCP message (UDT/XUDT/LUDT carrying TCAP) for the
/// content rules: the [`MapView`] they match on, or why there is none.
///
/// The decode is strict. A message that is recognisably a `Begin` or a
/// `Continue` and cannot be decoded in full is [`Screening::Undecodable`], never
/// a view of the part that could be read and never "nothing to screen": a
/// message with a malformed last component must not get past a screening rule
/// by being looked at without that component, or by not being looked at.
///
/// The transport only calls this for a domain that has content rules, so a
/// pure-transit node decodes nothing extra.
pub fn screen(sccp: &SccpMessage) -> Screening {
    if is_segment(sccp) {
        return Screening::Segmented;
    }
    let (op_code, argument) = match first_invoke(sccp.data()) {
        Ok(Some(invoke)) => invoke,
        Ok(None) => return Screening::NotApplicable,
        Err(Unreadable) => return Screening::Undecodable,
    };
    let (imsi, msisdn) = argument
        .as_deref()
        .map(|a| subscriber_identity(op_code, a))
        .unwrap_or((None, None));
    Screening::View(MapView {
        operation: Operation::from_op_code(op_code),
        cgpa_gt: sccp
            .calling_party()
            .global_title
            .digits()
            .map(str::to_string),
        cdpa_gt: sccp
            .called_party()
            .global_title
            .digits()
            .map(str::to_string),
        imsi,
        msisdn,
    })
}

/// The [`MapView`] of a message that decoded in full, or `None` for every other
/// [`Screening`] outcome. Use [`screen`] to tell those apart: a `None` here does
/// not mean the message is clean.
pub fn decode_map_view(sccp: &SccpMessage) -> Option<MapView> {
    match screen(sccp) {
        Screening::View(view) => Some(view),
        _ => None,
    }
}

/// Whether the message is one segment of a segmented message: an XUDT or LUDT
/// whose optional part carries a Segmentation parameter (Q.713 3.17, parameter
/// name `0x10`, four octets) that is not "first segment, no segments remaining".
fn is_segment(sccp: &SccpMessage) -> bool {
    let optional = match sccp {
        SccpMessage::Xudt(m) => &m.optional_part,
        SccpMessage::Ludt(m) => &m.optional_part,
        _ => return false,
    };
    let mut rest = optional.as_slice();
    // name, length, value; the end-of-optional-parameters name is 0.
    while let [name, len, tail @ ..] = rest {
        let len = usize::from(*len);
        if *name == 0 || tail.len() < len {
            break;
        }
        if *name == 0x10 {
            // First octet: bit 8 = first segment, bits 4-1 = remaining segments.
            return match tail.first() {
                Some(first) => !(first & 0x80 != 0 && first & 0x0F == 0),
                None => true,
            };
        }
        rest = &tail[len..];
    }
    false
}

/// A TCAP `Begin` or `Continue` that could not be decoded in full.
struct Unreadable;

/// An `Invoke`'s local operation code and its raw BER argument.
type FirstInvoke = (i64, Option<Vec<u8>>);

/// The first `Invoke` component's (local operation code, raw BER argument) out of
/// a TCAP `Begin` or `Continue`; `Ok(None)` when the message is not one the
/// content rules apply to.
fn first_invoke(tcap_bytes: &[u8]) -> Result<Option<FirstInvoke>, Unreadable> {
    use tcap::{Component, Decoded, MessageType, OperationCode, TcapMessage};
    let components = match tcap::decode_detailed(tcap_bytes) {
        Decoded::Complete(TcapMessage::Begin(b)) => b.components,
        Decoded::Complete(TcapMessage::Continue(c)) => c.components,
        Decoded::Complete(_) => None,
        Decoded::Problem(problem) => {
            return match problem.message_type {
                Some(MessageType::Begin | MessageType::Continue) => Err(Unreadable),
                // Not a message type the rules look at, or not TCAP at all (an
                // SCCP management message, another SCCP user).
                _ => Ok(None),
            };
        }
    };
    Ok(components
        .unwrap_or_default()
        .into_iter()
        .find_map(|c| match c {
            Component::Invoke(inv) => match inv.operation_code {
                OperationCode::Local(op) => {
                    Some((op, inv.parameter.map(|p| p.as_bytes().to_vec())))
                }
                _ => None,
            },
            _ => None,
        }))
}

/// The subscriber IMSI / MSISDN a MAP operation argument carries, as decimal
/// digit strings, for the operations content rules key on. Operations that carry
/// no top-level subscriber identity (or a failed decode) yield `(None, None)`.
fn subscriber_identity(op_code: i64, arg: &[u8]) -> (Option<String>, Option<String>) {
    use gsm_map::op_codes as m;
    use gsm_map::operations as ops;
    use gsm_map::operations::subscriber_info::op_codes::PROVIDE_SUBSCRIBER_INFO;

    match op_code {
        c if c == m::UPDATE_LOCATION => decode_arg::<ops::location::UpdateLocationArg>(arg)
            .map(|a| (Some(tbcd_digits(&a.imsi)), None)),
        c if c == m::CANCEL_LOCATION => decode_arg::<ops::location::CancelLocationArg>(arg)
            .map(|a| (Some(tbcd_digits(&a.identity)), None)),
        c if c == m::PURGE_MS => {
            decode_arg::<ops::location::PurgeMsArg>(arg).map(|a| (Some(tbcd_digits(&a.imsi)), None))
        }
        c if c == m::SEND_AUTHENTICATION_INFO => {
            decode_arg::<ops::auth::SendAuthenticationInfoArg>(arg)
                .map(|a| (Some(tbcd_digits(&a.imsi)), None))
        }
        c if c == m::READY_FOR_SM => decode_arg::<ops::ready_for_sm::ReadyForSmArg>(arg)
            .map(|a| (Some(tbcd_digits(&a.imsi)), None)),
        c if c == PROVIDE_SUBSCRIBER_INFO => {
            decode_arg::<ops::subscriber_info::ProvideSubscriberInfoArg>(arg)
                .map(|a| (Some(tbcd_digits(&a.imsi)), None))
        }
        c if c == m::MO_FORWARD_SM => decode_arg::<ops::mo_forward_sm::MoForwardSmArg>(arg)
            .map(|a| (a.imsi.as_ref().map(tbcd_digits), None)),
        // MT-ForwardSM carries its destination identity inside `sm_rp_da` (a
        // CHOICE), not a top-level IMSI; operation + GTs still populate.
        c if c == m::SEND_ROUTING_INFO_FOR_SM => {
            decode_arg::<ops::sri_sm::RoutingInfoForSmArg>(arg)
                .map(|a| (None, Some(addr_digits(&a.msisdn))))
        }
        c if c == m::REPORT_SM_DELIVERY_STATUS => {
            decode_arg::<ops::report_sm::ReportSmDeliveryStatusArg>(arg)
                .map(|a| (None, Some(addr_digits(&a.msisdn))))
        }
        _ => None,
    }
    .unwrap_or((None, None))
}

fn decode_arg<T: rasn::Decode>(arg: &[u8]) -> Option<T> {
    rasn::ber::decode(arg).ok()
}

/// Decode TBCD digits (swapped nibbles, low then high, `0xF` filler), e.g. an
/// IMSI carried as a MAP `Imsi`.
fn tbcd_digits(bytes: &rasn::types::OctetString) -> String {
    tbcd_slice(bytes)
}

/// Decode an `IsdnAddressString`'s digits: a leading type-of-number/plan octet,
/// then TBCD digits.
fn addr_digits(bytes: &rasn::types::OctetString) -> String {
    match bytes.split_first() {
        Some((_toa, rest)) => tbcd_slice(rest),
        None => String::new(),
    }
}

fn tbcd_slice(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let lo = b & 0x0F;
        if lo > 9 {
            break;
        }
        out.push((b'0' + lo) as char);
        let hi = b >> 4;
        if hi > 9 {
            break;
        }
        out.push((b'0' + hi) as char);
    }
    out
}

/// A resolved action from a matched content rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Route the message onward per the target (dpc/ssn, group, tenant), with
    /// an optional CdPA GT rewrite applied first.
    Route {
        /// The route target clause (carried through to the router).
        target: crate::config::RouteTarget,
        /// The rewritten CdPA GT, if the rule set one.
        rewrite_cdpa_gt: Option<String>,
    },
    /// Screen/drop the message.
    Screen,
}

/// The content-routing engine: the compiled rules + their referenced tables.
#[derive(Debug, Clone)]
pub struct ContentEngine {
    rules: Vec<CompiledRule>,
    address_tables: std::collections::BTreeMap<String, Vec<String>>,
    imsi_tables: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    operations: Vec<Operation>,
    imsi_in: Option<String>,
    imsi_prefix: Option<String>,
    cdpa_gt_in: Option<String>,
    cgpa_gt_in: Option<String>,
    action: ContentAction,
}

/// The outcome of evaluating the engine against one message: the matched rule
/// name and its action, or `None` if nothing matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The name of the rule that matched.
    pub rule: String,
    /// The resolved action.
    pub action: Action,
}

impl ContentEngine {
    /// Compile a [`ContentRouting`] config block into an evaluatable engine.
    pub fn compile(cr: &ContentRouting) -> Self {
        let address_tables = cr
            .address_tables
            .iter()
            .map(|t| (t.name.clone(), t.addrs.clone()))
            .collect();
        let imsi_tables = cr
            .imsi_tables
            .iter()
            .map(|t| (t.name.clone(), t.prefixes.clone()))
            .collect();
        let rules = cr.rules.iter().map(CompiledRule::from).collect();
        Self {
            rules,
            address_tables,
            imsi_tables,
        }
    }

    /// An empty engine (no rules, no tables). A script can then program it live
    /// via [`add_rule`](Self::add_rule) / [`address_table_add`](Self::address_table_add),
    /// so a node whose config carried no `content_routing` block can still gain
    /// content rules from `ss7.content.*`.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            address_tables: std::collections::BTreeMap::new(),
            imsi_tables: std::collections::BTreeMap::new(),
        }
    }

    /// Prepend a content rule live (a script programming the table via
    /// `ss7.content.add_rule(...)`). New rules go to the front so a
    /// freshly-programmed override wins over the static config rules
    /// (first-match-wins).
    pub fn add_rule(&mut self, rule: &ContentRule) {
        self.rules.insert(0, CompiledRule::from(rule));
    }

    /// Add a global-title digit string to an address table live
    /// (`ss7.content.address_table(name).add(addr)`), creating the table if it
    /// did not exist. Idempotent.
    pub fn address_table_add(&mut self, table: &str, addr: impl Into<String>) {
        let addr = addr.into();
        let entries = self.address_tables.entry(table.to_string()).or_default();
        if !entries.contains(&addr) {
            entries.push(addr);
        }
    }

    /// Add an IMSI prefix to an imsi table live, creating it if absent. Idempotent.
    pub fn imsi_table_add(&mut self, table: &str, prefix: impl Into<String>) {
        let prefix = prefix.into();
        let entries = self.imsi_tables.entry(table.to_string()).or_default();
        if !entries.contains(&prefix) {
            entries.push(prefix);
        }
    }

    /// Whether any content rule is compiled. The transport decodes a [`MapView`]
    /// for a tenant only when this is true, so a node with no content rules pays
    /// nothing on the routing hot path.
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Evaluate the ordered rules against a decoded view. First match wins.
    pub fn evaluate(&self, view: &MapView) -> Option<Hit> {
        for rule in &self.rules {
            if self.matches(rule, view) {
                return Some(Hit {
                    rule: rule.name.clone(),
                    action: action_of(&rule.action),
                });
            }
        }
        None
    }

    fn matches(&self, rule: &CompiledRule, view: &MapView) -> bool {
        // operation ∈ set
        if !rule.operations.is_empty() {
            match view.operation {
                Some(op) if rule.operations.contains(&op) => {}
                _ => return false,
            }
        }
        // imsi_in table
        if let Some(table) = &rule.imsi_in {
            let Some(imsi) = &view.imsi else { return false };
            if !self.imsi_in_table(table, imsi) {
                return false;
            }
        }
        // imsi_prefix
        if let Some(prefix) = &rule.imsi_prefix {
            let Some(imsi) = &view.imsi else { return false };
            if !imsi.starts_with(prefix.as_str()) {
                return false;
            }
        }
        // cdpa/cgpa GT ∈ address table
        if let Some(table) = &rule.cdpa_gt_in {
            let Some(gt) = &view.cdpa_gt else {
                return false;
            };
            if !self.gt_in_table(table, gt) {
                return false;
            }
        }
        if let Some(table) = &rule.cgpa_gt_in {
            let Some(gt) = &view.cgpa_gt else {
                return false;
            };
            if !self.gt_in_table(table, gt) {
                return false;
            }
        }
        true
    }

    fn imsi_in_table(&self, table: &str, imsi: &str) -> bool {
        self.imsi_tables
            .get(table)
            .map(|prefixes| prefixes.iter().any(|p| imsi.starts_with(p.as_str())))
            .unwrap_or(false)
    }

    fn gt_in_table(&self, table: &str, gt: &str) -> bool {
        self.address_tables
            .get(table)
            .map(|addrs| addrs.iter().any(|a| a == gt))
            .unwrap_or(false)
    }
}

fn action_of(a: &ContentAction) -> Action {
    if a.screen.unwrap_or(false) {
        return Action::Screen;
    }
    // Route (possibly with a rewrite). If a rule only sets rewrite_cdpa_gt with
    // no route target, we still model it as a Route with an empty-but-rewrite
    // target so the router applies the rewrite and then falls through to GTT.
    Action::Route {
        target: a.route.clone().unwrap_or_default(),
        rewrite_cdpa_gt: a.rewrite_cdpa_gt.clone(),
    }
}

impl From<&ContentRule> for CompiledRule {
    fn from(r: &ContentRule) -> Self {
        let operations = r
            .match_
            .operation
            .as_ref()
            .map(|o| {
                o.as_slice()
                    .into_iter()
                    .filter_map(Operation::from_kebab)
                    .collect()
            })
            .unwrap_or_default();
        CompiledRule {
            name: r.name.clone(),
            operations,
            imsi_in: r.match_.imsi_in.clone(),
            imsi_prefix: r.match_.imsi_prefix.clone(),
            cdpa_gt_in: r.match_.cdpa_gt_in.clone(),
            cgpa_gt_in: r.match_.cgpa_gt_in.clone(),
            action: r.action.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn engine() -> ContentEngine {
        let cfg = Config::parse(crate::config::tests::SAMPLE).unwrap();
        let cr = cfg
            .default_tenant()
            .unwrap()
            .content_routing
            .as_ref()
            .unwrap();
        ContentEngine::compile(cr)
    }

    #[test]
    fn operation_kebab_roundtrip() {
        assert_eq!(Operation::from_kebab("sri-sm"), Some(Operation::SriSm));
        assert_eq!(Operation::SriSm.op_code(), 45);
        assert_eq!(Operation::UpdateLocation.op_code(), 2);
        assert_eq!(Operation::InitialDp.op_code(), 0);
        assert_eq!(Operation::from_kebab("bogus"), None);
    }

    #[test]
    fn imsi_in_table_match() {
        let e = engine();
        // updateLocation for a customer-a IMSI → customer-a-home route rule.
        let view = MapView {
            operation: Some(Operation::UpdateLocation),
            imsi: Some("001010000000042".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "customer-a-home");
        match hit.action {
            Action::Route { target, .. } => {
                assert_eq!(target.dpc.unwrap().0, 2005);
                assert_eq!(target.ssn, Some(6));
            }
            _ => panic!("expected Route"),
        }
    }

    #[test]
    fn content_routing_fires_on_a_wire_decoded_view() {
        // The live-transport path: assemble a real updateLocation Begin (IMSI
        // 001010000000042, test PLMN 001/01) inside an SCCP UDT, decode a MapView
        // straight off the bytes, and confirm the same IMSI content rule fires as
        // for a hand-built view — the decode the transport now performs before
        // routing. Previously this view was never built on the wire.
        use rasn::types::{Any, OctetString};
        use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
        use tcap::{Begin, Component, Invoke, OperationCode, TcapMessage};

        let imsi: OctetString = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x40, 0xF2].into();
        let number: OctetString = vec![0x91, 0x15, 0x55, 0x01, 0x80].into();
        let arg = gsm_map::operations::location::UpdateLocationArg {
            imsi,
            msc_number: number.clone(),
            vlr_number: number,
            lmsi: None,
            vlr_capability: None,
        };
        let begin = TcapMessage::Begin(Begin {
            otid: vec![0x11, 0x22, 0x33, 0x44].into(),
            dialogue_portion: None,
            components: Some(vec![Component::Invoke(Invoke {
                invoke_id: 1,
                linked_id: None,
                operation_code: OperationCode::Local(gsm_map::op_codes::UPDATE_LOCATION),
                parameter: Some(Any::new(rasn::ber::encode(&arg).unwrap())),
            })]),
        });
        let gt = |d: &str| GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: d.to_string(),
        };
        let payload = UnitData::new(
            SccpAddress::with_gt(gt("15550100"), Some(SubsystemNumber::Hlr)),
            SccpAddress::with_gt(gt("15550180"), Some(SubsystemNumber::Msc)),
            tcap::encode(&begin).unwrap(),
        )
        .encode()
        .unwrap();

        let sccp = SccpMessage::decode(&payload).unwrap();
        let view = decode_map_view(&sccp).expect("a MAP view decodes off the wire bytes");
        assert_eq!(view.operation, Some(Operation::UpdateLocation));
        assert_eq!(view.imsi.as_deref(), Some("001010000000042"));
        assert_eq!(view.cdpa_gt.as_deref(), Some("15550100"));
        assert_eq!(view.cgpa_gt.as_deref(), Some("15550180"));

        // The wire-decoded view drives the same content decision as a hand-built one.
        let hit = engine()
            .evaluate(&view)
            .expect("the customer-a-home rule fires");
        assert_eq!(hit.rule, "customer-a-home");
    }

    #[test]
    fn imsi_prefix_matches_and_screens() {
        let e = engine();
        // An IMSI starting "001" but NOT in customer-a and not update/cancel/auth
        // falls through customer-a-home to imsi-steer, which screens it.
        let view = MapView {
            operation: Some(Operation::SriSm),
            imsi: Some("001990000000001".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "imsi-steer");
        assert_eq!(hit.action, Action::Screen);
    }

    #[test]
    fn operation_set_match_first_wins() {
        let e = engine();
        // sri-sm with a cdpa GT in home-subs and no IMSI → mt-sms-home-route
        // (route to group + rewrite), before sri-sm-np.
        let view = MapView {
            operation: Some(Operation::SriSm),
            cdpa_gt: Some("15550142".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "mt-sms-home-route");
        match hit.action {
            Action::Route {
                target,
                rewrite_cdpa_gt,
            } => {
                assert_eq!(target.group.as_deref(), Some("ag-router"));
                assert_eq!(rewrite_cdpa_gt.as_deref(), Some("15550100"));
            }
            _ => panic!("expected Route"),
        }
    }

    #[test]
    fn plain_sri_sm_routes() {
        let e = engine();
        // sri-sm, no home-subs cdpa, no matching imsi → sri-sm-route (plain route).
        let view = MapView {
            operation: Some(Operation::SriSm),
            cdpa_gt: Some("19995550000".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "sri-sm-route");
        match hit.action {
            Action::Route { target, .. } => {
                assert_eq!(target.dpc.map(|d| d.0), Some(2000));
                assert_eq!(target.ssn, Some(6));
            }
            _ => panic!("expected Route"),
        }
    }

    #[test]
    fn no_match_returns_none() {
        let e = engine();
        let view = MapView {
            operation: Some(Operation::Connect),
            ..Default::default()
        };
        assert!(e.evaluate(&view).is_none());
    }

    // ── Messages that cannot be decoded in full ──────────────────────────────

    /// A UDT from GT 15550180 to GT 15550100 carrying `tcap`.
    fn udt(tcap: &[u8]) -> SccpMessage {
        use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
        let gt = |d: &str| GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: d.to_string(),
        };
        SccpMessage::Udt(UnitData::new(
            SccpAddress::with_gt(gt("15550100"), Some(SubsystemNumber::Hlr)),
            SccpAddress::with_gt(gt("15550180"), Some(SubsystemNumber::Msc)),
            tcap.to_vec(),
        ))
    }

    /// A Begin (otid 11 22) whose component portion is `components`, assembled
    /// by hand: `62 { 48 02 11 22, 6C { components } }`.
    fn begin(components: &[u8]) -> Vec<u8> {
        let mut body = vec![0x48, 0x02, 0x11, 0x22, 0x6C, components.len() as u8];
        body.extend_from_slice(components);
        let mut out = vec![0x62, body.len() as u8];
        out.extend(body);
        out
    }

    /// `[1] { INTEGER 1, INTEGER 45 }`: an Invoke of sendRoutingInfoForSM
    /// without an argument.
    const SRI_SM_INVOKE: [u8; 8] = [0xA1, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x2D];

    #[test]
    fn a_whole_message_gives_a_view() {
        match screen(&udt(&begin(&SRI_SM_INVOKE))) {
            Screening::View(view) => assert_eq!(view.operation, Some(Operation::SriSm)),
            other => panic!("expected a view, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_last_component_is_not_screened_on_the_components_before_it() {
        // The good Invoke, then an Invoke that stops after its invoke id. The
        // lenient decoder returned the message without the second component,
        // and the rules were evaluated as if it were the whole message.
        let mut components = SRI_SM_INVOKE.to_vec();
        components.extend_from_slice(&[0xA1, 0x03, 0x02, 0x01, 0x02]);
        let msg = udt(&begin(&components));
        assert_eq!(screen(&msg), Screening::Undecodable);
        assert_eq!(decode_map_view(&msg), None);
    }

    #[test]
    fn a_malformed_only_component_is_undecodable_not_absent() {
        let msg = udt(&begin(&[0xA1, 0x03, 0x02, 0x01, 0x02]));
        assert_eq!(screen(&msg), Screening::Undecodable);
    }

    #[test]
    fn octets_after_the_message_make_it_undecodable() {
        let mut tcap = begin(&SRI_SM_INVOKE);
        tcap.push(0x00);
        assert_eq!(screen(&udt(&tcap)), Screening::Undecodable);
    }

    #[test]
    fn a_damaged_continue_is_undecodable() {
        // 65 { 48 01 01, 49 01 02, 6C 00 }: a component portion with no
        // components.
        let tcap = [0x65, 0x08, 0x48, 0x01, 0x01, 0x49, 0x01, 0x02, 0x6C, 0x00];
        assert_eq!(screen(&udt(&tcap)), Screening::Undecodable);
    }

    #[test]
    fn what_the_rules_do_not_look_at_is_not_applicable() {
        // An End (damaged or not), an Abort, and a payload that is not TCAP (an
        // SCCP management message: SSA for SSN 6 at point code 1000).
        let end = [0x64, 0x03, 0x49, 0x01, 0x02];
        let damaged_end = [0x64, 0x05, 0x49, 0x01, 0x02, 0x6C, 0x00];
        let abort = [0x67, 0x03, 0x49, 0x01, 0x02];
        let scmg = [0x01, 0x06, 0xE8, 0x03, 0x00];
        for payload in [&end[..], &damaged_end[..], &abort[..], &scmg[..], &[][..]] {
            assert_eq!(
                screen(&udt(payload)),
                Screening::NotApplicable,
                "{payload:02x?}"
            );
        }
        // A Begin without components has nothing to match on either.
        let bare = [0x62, 0x04, 0x48, 0x02, 0x11, 0x22];
        assert_eq!(screen(&udt(&bare)), Screening::NotApplicable);
    }

    #[test]
    fn a_segment_of_a_segmented_xudt_is_told_apart_from_a_damaged_message() {
        use sccp::ExtendedUnitData;
        let whole = begin(&SRI_SM_INVOKE);
        let SccpMessage::Udt(u) = udt(&whole) else {
            unreachable!()
        };
        let xudt = |data: &[u8], optional: &[u8]| {
            let mut m = ExtendedUnitData::new(
                u.called_party.clone(),
                u.calling_party.clone(),
                data.to_vec(),
            );
            m.optional_part = optional.to_vec();
            SccpMessage::Xudt(m)
        };
        // No optional part: an XUDT carrying the whole message.
        assert!(matches!(screen(&xudt(&whole, &[])), Screening::View(_)));
        // Segmentation (0x10, length 4): first segment, none remaining. Whole.
        let single = [0x10, 0x04, 0x80, 0x01, 0x02, 0x03, 0x00];
        assert!(matches!(screen(&xudt(&whole, &single)), Screening::View(_)));
        // First segment, one remaining: the TCAP message is cut short.
        let first = [0x10, 0x04, 0x81, 0x01, 0x02, 0x03, 0x00];
        assert_eq!(screen(&xudt(&whole[..10], &first)), Screening::Segmented);
        // The last segment: not first, none remaining.
        let last = [0x10, 0x04, 0x00, 0x01, 0x02, 0x03, 0x00];
        assert_eq!(screen(&xudt(&whole[10..], &last)), Screening::Segmented);
        // The Segmentation parameter after another optional parameter
        // (Importance, 0x12, length 1).
        let after = [0x12, 0x01, 0x05, 0x10, 0x04, 0x81, 0x01, 0x02, 0x03, 0x00];
        assert_eq!(screen(&xudt(&whole[..10], &after)), Screening::Segmented);
    }
}
