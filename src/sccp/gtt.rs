//! Global Title Translation + E.214/E.164 conversion.
//!
//! # GTT
//!
//! An incoming GT (digits + gti/tt/np/nai) is matched against the ordered
//! `gtt` rules; the first rule whose criteria all hold produces a
//! [`GttResult`]. A result can be a concrete `(dpc, ssn)`, a **group**
//! (resolved to a concrete member by cost or weighted round-robin), local
//! termination, or a cross-tenant hand-off (`{tenant, dpc, ssn}`, internal).
//!
//! # E.214 ↔ E.164
//!
//! Roaming MAP addresses an HLR with an **E.214** Mobile Global Title: the
//! HPLMN's E.164 prefix (mapped from the subscriber IMSI's MCC+MNC) followed by
//! the MSIN. [`GtConverter`] rewrites E.214 → E.164 (`np` 0x03 → 0x01) before
//! the GTT lookup and the reverse outbound, purely from the `plmn_map`. It runs
//! in Rust at line rate, no per-message hook.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{GroupMode, GtConversion, GttGroup, GttRule, RouteTarget, Sccp, TenantId};

/// The read-only global-title fields a GTT rule matches on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GttSelector {
    /// The GT digits.
    pub digits: String,
    /// GT indicator (2 / 3 / 4).
    pub gti: Option<u8>,
    /// Translation type.
    pub tt: Option<u8>,
    /// Numbering plan.
    pub np: Option<u8>,
    /// Nature-of-address indicator.
    pub nai: Option<u8>,
}

impl GttSelector {
    /// A selector from just the digits (gti/tt/np/nai unspecified).
    pub fn from_digits(digits: impl Into<String>) -> Self {
        Self {
            digits: digits.into(),
            ..Default::default()
        }
    }
}

/// The result of a successful translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GttResult {
    /// Route to a concrete point code + subsystem.
    Dpc {
        /// Destination point code (decimal, tenant variant).
        dpc: u32,
        /// Subsystem number.
        ssn: u8,
    },
    /// Terminate locally (we own the subsystem).
    Local,
    /// Hand off into another routing domain, converting PC + GT when the
    /// variants differ.
    Tenant {
        /// The target domain.
        tenant: TenantId,
        /// The DPC within that domain.
        dpc: u32,
        /// The SSN within that domain.
        ssn: u8,
    },
}

/// A GTT group's runtime selection state (weighted round-robin cursor).
#[derive(Debug)]
struct GroupState {
    mode: GroupMode,
    /// Members expanded for selection: `(dpc, ssn)` repeated per weight (share)
    /// or ordered by cost (cost).
    members: Vec<(u32, u8)>,
    /// Round-robin cursor for share mode. Atomic so a shared `Arc<Router>` can
    /// advance it from concurrent transport tasks (`GttResolver` must be `Sync`).
    cursor: AtomicUsize,
}

impl GroupState {
    fn from(group: &GttGroup) -> Self {
        let members = match group.mode {
            GroupMode::Cost => {
                let mut m: Vec<(u8, u32, u8)> = group
                    .members
                    .iter()
                    .map(|x| (x.cost.unwrap_or(u8::MAX), x.dpc.0, x.ssn))
                    .collect();
                m.sort_by_key(|(cost, _, _)| *cost);
                m.into_iter().map(|(_, dpc, ssn)| (dpc, ssn)).collect()
            }
            GroupMode::Share => {
                let mut expanded = Vec::new();
                for x in &group.members {
                    let w = x.weight.unwrap_or(1).max(1);
                    for _ in 0..w {
                        expanded.push((x.dpc.0, x.ssn));
                    }
                }
                expanded
            }
        };
        Self {
            mode: group.mode,
            members,
            cursor: AtomicUsize::new(0),
        }
    }

    /// Pick a member. Cost → the primary (lowest cost, index 0). Share →
    /// the next member in weighted round-robin.
    fn select(&self) -> Option<(u32, u8)> {
        if self.members.is_empty() {
            return None;
        }
        match self.mode {
            GroupMode::Cost => Some(self.members[0]),
            GroupMode::Share => {
                let n = self.cursor.fetch_add(1, Ordering::Relaxed);
                Some(self.members[n % self.members.len()])
            }
        }
    }

    /// Cost mode: the ordered fail-over list (primary first).
    fn cost_order(&self) -> &[(u32, u8)] {
        &self.members
    }
}

/// The compiled GTT resolver for one tenant.
#[derive(Debug)]
pub struct GttResolver {
    rules: Vec<GttRule>,
    groups: BTreeMap<String, GroupState>,
    local_ssns: Vec<u8>,
}

impl GttResolver {
    /// Compile a tenant's `sccp` block into a resolver.
    pub fn compile(sccp: &Sccp) -> Self {
        let groups = sccp
            .gtt_groups
            .iter()
            .map(|g| (g.name.clone(), GroupState::from(g)))
            .collect();
        Self {
            rules: sccp.gtt.clone(),
            groups,
            local_ssns: sccp.local_ssns.clone(),
        }
    }

    /// Whether we own a subsystem (inbound for it terminates locally).
    pub fn owns_ssn(&self, ssn: u8) -> bool {
        self.local_ssns.contains(&ssn)
    }

    /// Translate a global title. Returns the first matching rule's result, or
    /// `None` for no-translation.
    pub fn translate(&self, sel: &GttSelector) -> Option<GttResult> {
        for rule in &self.rules {
            if rule_matches(rule, sel) {
                return self.result_of(&rule.to);
            }
        }
        None
    }

    /// The ordered cost-mode fail-over list for a group (primary first), if the
    /// group exists and is cost-mode. Used by the router to try alternates when
    /// the primary member is unavailable.
    pub fn group_cost_order(&self, group: &str) -> Option<&[(u32, u8)]> {
        self.groups
            .get(group)
            .filter(|g| g.mode == GroupMode::Cost)
            .map(GroupState::cost_order)
    }

    /// Select a `(dpc, ssn)` from a named group. Cost mode returns the primary
    /// (lowest cost); share mode advances the weighted round-robin cursor.
    /// `None` if the group is unknown or empty.
    pub fn select_group(&self, group: &str) -> Option<(u32, u8)> {
        self.groups.get(group)?.select()
    }

    /// Resolve a route target (from a GTT rule or a content-rule route action)
    /// into a [`GttResult`], selecting a group member where needed. This is the
    /// shared translation both GTT and content routing go through.
    pub fn resolve_target(&self, target: &RouteTarget) -> Option<GttResult> {
        self.result_of(target)
    }

    /// Prepend a GTT rule live: a script programming the table via
    /// `ss7.gtt.add(...)` (or caching a dip result with `ss7.routes.cache(...)`).
    /// New rules go to the front so a freshly-programmed override wins over the
    /// static rules compiled from config, matching first-match-wins.
    pub fn add_rule(&mut self, rule: GttRule) {
        self.rules.insert(0, rule);
    }

    fn result_of(&self, target: &RouteTarget) -> Option<GttResult> {
        if let Some(tenant) = &target.tenant {
            // Cross-tenant hand-off carries a concrete dpc/ssn in the target.
            return Some(GttResult::Tenant {
                tenant: tenant.clone(),
                dpc: target.dpc.map(|p| p.0).unwrap_or(0),
                ssn: target.ssn.unwrap_or(0),
            });
        }
        if target.local.unwrap_or(false) {
            return Some(GttResult::Local);
        }
        if let Some(group) = &target.group {
            let (dpc, ssn) = self.groups.get(group)?.select()?;
            return Some(GttResult::Dpc { dpc, ssn });
        }
        if let Some(dpc) = target.dpc {
            return Some(GttResult::Dpc {
                dpc: dpc.0,
                ssn: target.ssn.unwrap_or(0),
            });
        }
        None
    }
}

fn rule_matches(rule: &GttRule, sel: &GttSelector) -> bool {
    let m = &rule.match_;
    if let Some(prefix) = &m.gt_prefix {
        if !sel.digits.starts_with(prefix.as_str()) {
            return false;
        }
    }
    // gti/tt/np/nai are matched only when both the rule and the selector carry
    // the field. A rule field with no matching selector field is a non-match:
    // the caller didn't decode that field, so the stricter reading applies.
    for (rule_field, sel_field) in [
        (m.gti, sel.gti),
        (m.tt, sel.tt),
        (m.np, sel.np),
        (m.nai, sel.nai),
    ] {
        if let Some(want) = rule_field {
            if sel_field != Some(want) {
                return false;
            }
        }
    }
    true
}

/// E.214 ↔ E.164 converter driven by the `plmn_map`.
#[derive(Debug, Clone)]
pub struct GtConverter {
    /// MCC+MNC (concatenated) → E.164 prefix.
    e214_to_e164: BTreeMap<String, String>,
    /// E.164 prefix → MCC+MNC (concatenated). Longest-prefix wins.
    e164_to_e214: Vec<(String, String)>,
}

impl GtConverter {
    /// Build from a `gt_conversion` block's `plmn_map`.
    pub fn from(conv: &GtConversion) -> Self {
        let mut e214_to_e164 = BTreeMap::new();
        let mut e164_to_e214 = Vec::new();
        for e in &conv.plmn_map {
            let mccmnc = format!("{}{}", e.mcc, e.mnc);
            e214_to_e164.insert(mccmnc.clone(), e.e164_prefix.clone());
            e164_to_e214.push((e.e164_prefix.clone(), mccmnc));
        }
        // Longest E.164 prefix first so the most specific PLMN wins.
        e164_to_e214.sort_by_key(|(e164, _)| std::cmp::Reverse(e164.len()));
        Self {
            e214_to_e164,
            e164_to_e214,
        }
    }

    /// **Inbound** E.214 → E.164: replace the leading MCC+MNC of the MGT with
    /// the HPLMN E.164 prefix, preserving the MSIN tail. Returns `None` if no
    /// `plmn_map` entry's MCC+MNC prefixes the digits.
    pub fn e214_to_e164(&self, digits: &str) -> Option<String> {
        // Try each known MCC+MNC (5-6 digits); longest first.
        let mut keys: Vec<&String> = self.e214_to_e164.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
        for mccmnc in keys {
            if let Some(msin) = digits.strip_prefix(mccmnc.as_str()) {
                let prefix = &self.e214_to_e164[mccmnc];
                return Some(format!("{prefix}{msin}"));
            }
        }
        None
    }

    /// **Outbound** E.164 → E.214: replace the leading E.164 prefix with the
    /// PLMN's MCC+MNC, preserving the MSIN tail. Longest E.164 prefix wins.
    pub fn e164_to_e214(&self, digits: &str) -> Option<String> {
        for (e164, mccmnc) in &self.e164_to_e214 {
            if let Some(msin) = digits.strip_prefix(e164.as_str()) {
                return Some(format!("{mccmnc}{msin}"));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn tenant_sccp() -> Sccp {
        let cfg = Config::parse(crate::config::tests::SAMPLE).unwrap();
        cfg.default_tenant().unwrap().sccp.clone()
    }

    #[test]
    fn prefix_match_precedence() {
        let sccp = tenant_sccp();
        let r = GttResolver::compile(&sccp);
        // "155501…" with the full gti/tt/np/nai matches the first rule → group.
        let sel = GttSelector {
            digits: "15550142".into(),
            gti: Some(4),
            tt: Some(0),
            np: Some(1),
            nai: Some(4),
        };
        // ag-hlr is cost mode → primary member (dpc 2000, ssn 6).
        assert_eq!(
            r.translate(&sel),
            Some(GttResult::Dpc { dpc: 2000, ssn: 6 })
        );

        // "1555…" but WITHOUT the gti/tt/np/nai falls through to the 2nd rule.
        let sel2 = GttSelector::from_digits("15559999");
        assert_eq!(
            r.translate(&sel2),
            Some(GttResult::Dpc { dpc: 2000, ssn: 6 })
        );

        // A GT that matches neither prefix → no translation.
        let sel3 = GttSelector::from_digits("44770000");
        assert_eq!(r.translate(&sel3), None);
    }

    #[test]
    fn group_cost_selects_primary() {
        let sccp = tenant_sccp();
        let r = GttResolver::compile(&sccp);
        // ag-hlr order: cost 1 (dpc 2000) primary, cost 2 (dpc 2001) alternate.
        let order = r.group_cost_order("ag-hlr").unwrap();
        assert_eq!(order, &[(2000, 6), (2001, 6)]);
    }

    #[test]
    fn group_share_round_robins() {
        let sccp = tenant_sccp();
        let r = GttResolver::compile(&sccp);
        // ag-router is share mode, weights 1/1 → alternates 2003, 2004, 2003…
        // Match a GT to a rule that targets ag-router, the sample doesn't have
        // one in gtt, so exercise the group directly via a synthetic rule.
        let g = r.groups.get("ag-router").unwrap();
        let a = g.select().unwrap();
        let b = g.select().unwrap();
        let c = g.select().unwrap();
        assert_ne!(a, b); // two distinct members
        assert_eq!(a, c); // wraps around
    }

    #[test]
    fn e214_to_e164_via_plmn_map() {
        let sccp = tenant_sccp();
        let conv = GtConverter::from(&sccp.gt_conversion);
        // MCC 001 + MNC 01 → e164 prefix 15551; MSIN 23456 preserved.
        assert_eq!(
            conv.e214_to_e164("0010123456").as_deref(),
            Some("1555123456")
        );
        // MCC 001 + MNC 02 → 15552.
        assert_eq!(
            conv.e214_to_e164("0010299887").as_deref(),
            Some("1555299887")
        );
        // Unknown PLMN → None.
        assert_eq!(conv.e214_to_e164("9999912345"), None);
    }

    #[test]
    fn e164_to_e214_reverse() {
        let sccp = tenant_sccp();
        let conv = GtConverter::from(&sccp.gt_conversion);
        // E.164 15551 + MSIN 23456 → MCC+MNC 00101 + 23456.
        assert_eq!(
            conv.e164_to_e214("1555123456").as_deref(),
            Some("0010123456")
        );
    }
}
