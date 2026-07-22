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

/// Decode a connectionless SCCP message (UDT/XUDT/LUDT carrying TCAP) into the
/// [`MapView`] the content engine matches on: the operation, the calling/called
/// global titles, and the subscriber IMSI/MSISDN the first MAP `Invoke` carries.
///
/// Returns `None` when the payload is not a decodable SCCP-over-TCAP `Begin` /
/// `Continue` with a recognised operation; the router then skips content routing
/// and falls through to GTT / SSN routing. The transport only calls this for a
/// tenant that has content rules, so a pure-transit node decodes nothing extra.
pub fn decode_map_view(sccp: &SccpMessage) -> Option<MapView> {
    let (op_code, argument) = first_invoke(sccp.data())?;
    let (imsi, msisdn) = argument
        .as_deref()
        .map(|a| subscriber_identity(op_code, a))
        .unwrap_or((None, None));
    Some(MapView {
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

/// The first `Invoke` component's (local operation code, raw BER argument) out of
/// a TCAP `Begin` or `Continue`.
fn first_invoke(tcap_bytes: &[u8]) -> Option<(i64, Option<Vec<u8>>)> {
    use tcap::{Component, OperationCode, TcapMessage};
    let components = match tcap::decode(tcap_bytes).ok()? {
        TcapMessage::Begin(b) => b.components,
        TcapMessage::Continue(c) => c.components,
        _ => None,
    }?;
    components.into_iter().find_map(|c| match c {
        Component::Invoke(inv) => match inv.operation_code {
            OperationCode::Local(op) => Some((op, inv.parameter.map(|p| p.as_bytes().to_vec()))),
            _ => None,
        },
        _ => None,
    })
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
}
