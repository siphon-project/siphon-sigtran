//! The **content-routing** engine: routing on the decoded application layer.
//!
//! A [`ContentRule`](crate::config::ContentRule) matches over a read-only,
//! decoded view of a MAP/CAP message, [`MapView`], and yields an [`Action`].
//! Static rules run entirely in Rust at line rate; a rule can also *defer* to a
//! named Python hook (phase-3), in which case the engine returns the hook name
//! and the async layer above calls it.
//!
//! The engine here is deliberately simple and synchronous: it takes an already
//! decoded [`MapView`] (the tests assemble a real MAP/CAP argument, wrap it in
//! TCAP/SCCP, and decode a view out of it) and walks the ordered rules
//! **first-match-wins**.

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
    /// Defer to the named Python hook (phase-3): the async layer calls it.
    Python {
        /// The hook name from `action: { python: <name> }`.
        hook: String,
    },
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
    if let Some(hook) = &a.python {
        return Action::Python { hook: hook.clone() };
    }
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
        // updateLocation for a buyer-a IMSI → buyer-a-home route rule.
        let view = MapView {
            operation: Some(Operation::UpdateLocation),
            imsi: Some("001010000000042".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "buyer-a-home");
        match hit.action {
            Action::Route { target, .. } => {
                assert_eq!(target.dpc.unwrap().0, 2005);
                assert_eq!(target.ssn, Some(6));
            }
            _ => panic!("expected Route"),
        }
    }

    #[test]
    fn imsi_prefix_defers_to_python() {
        let e = engine();
        // An IMSI starting "001" but NOT in buyer-a and not update/cancel/auth
        // falls through buyer-a-home to imsi-steer (python).
        let view = MapView {
            operation: Some(Operation::SriSm),
            imsi: Some("001990000000001".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "imsi-steer");
        assert_eq!(
            hit.action,
            Action::Python {
                hook: "on_imsi_route".into()
            }
        );
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
    fn plain_sri_sm_defers_to_np_hook() {
        let e = engine();
        // sri-sm, no home-subs cdpa, no matching imsi → sri-sm-np python hook.
        let view = MapView {
            operation: Some(Operation::SriSm),
            cdpa_gt: Some("19995550000".into()),
            ..Default::default()
        };
        let hit = e.evaluate(&view).expect("hit");
        assert_eq!(hit.rule, "sri-sm-np");
        assert_eq!(
            hit.action,
            Action::Python {
                hook: "on_np_dip".into()
            }
        );
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
