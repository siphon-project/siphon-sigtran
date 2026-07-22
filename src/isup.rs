//! Optional **ISUP-aware screening** on the SI=5 transit path (ITU-T Q.763).
//!
//! An STP transits ISUP (Service Indicator 5) by destination point code without
//! looking inside it. When a tenant configures an [`IsupScreening`] block the
//! transit path decodes each SI=5 message with the `itu_isup` codec and evaluates
//! it against the tenant's ordered rules (first match wins). A `block` result
//! drops the message; everything else transits exactly as before.
//!
//! A rule matches on the ISUP message type (`iam`, `rel`, …) and/or a leading
//! prefix of the called- or calling-party number. A message that no rule matches
//! takes the configured `default` action. A message that will not decode as ISUP
//! also takes the default action (a malformed frame is never silently mis-routed:
//! the transport logs it either way).
//!
//! The engine is compiled once from config into [`IsupScreen`] and evaluated
//! synchronously; a tenant with no screening block holds `None`, so the transit
//! path pays only an `Option::is_none` beyond the Service-Indicator compare.

use itu_isup::{Message, MessageType, ParameterType};

use crate::config::{IsupScreening, ScreenAction, ScreenMatch};
use crate::metrics::ScreenReason;

/// Map a lower-case Q.763 message-type acronym (`"iam"`, `"rel"`, `"acm"`, …) to
/// its [`MessageType`], or `None` if the name is not a known ISUP message type.
///
/// Comparison is ASCII-case-insensitive. Only the named Q.763 types resolve; an
/// unnamed code (which the codec would decode as `MessageType::Other`) never does.
pub fn message_type_from_name(name: &str) -> Option<MessageType> {
    (0u8..=0xFF)
        .map(MessageType::from_u8)
        .find(|mt| !matches!(mt, MessageType::Other(_)) && mt.acronym().eq_ignore_ascii_case(name))
}

/// A compiled screening rule: the resolved match criteria plus an action.
#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    message_type: Option<MessageType>,
    called_prefix: Option<String>,
    calling_prefix: Option<String>,
    action: ScreenAction,
}

impl CompiledRule {
    fn compile(name: String, m: &ScreenMatch, action: ScreenAction) -> Self {
        Self {
            name,
            message_type: m.message_type.as_deref().and_then(message_type_from_name),
            called_prefix: m.called_prefix.clone(),
            calling_prefix: m.calling_prefix.clone(),
            action,
        }
    }

    /// Whether this rule's (AND-ed) criteria all hold for a decoded message. An
    /// absent criterion is a wildcard; a number-prefix criterion fails when the
    /// message carries no such number.
    fn matches(&self, msg: &Message) -> bool {
        if let Some(mt) = self.message_type {
            if msg.message_type != mt {
                return false;
            }
        }
        if let Some(prefix) = &self.called_prefix {
            match number_digits(msg, ParameterType::CalledPartyNumber) {
                Some(d) if d.starts_with(prefix.as_str()) => {}
                _ => return false,
            }
        }
        if let Some(prefix) = &self.calling_prefix {
            match number_digits(msg, ParameterType::CallingPartyNumber) {
                Some(d) if d.starts_with(prefix.as_str()) => {}
                _ => return false,
            }
        }
        true
    }
}

/// The digit string of a number-valued parameter (called / calling party), or
/// `None` if the parameter is absent or does not parse as a number.
fn number_digits(msg: &Message, code: ParameterType) -> Option<String> {
    msg.find(code)?.as_number().ok().map(|n| n.digits)
}

/// The verdict of screening one transiting ISUP MSU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screened {
    /// Transit the MSU unchanged.
    Pass,
    /// The MSU would not decode as ISUP and the screening default is `allow`, so
    /// it transits; `error` is why it would not decode, so the transport can log
    /// the malformed frame (it is never passed silently).
    PassUndecoded {
        /// The decode-error text.
        error: String,
    },
    /// Drop the MSU: it matched an explicit `block` rule (`rule` is its name).
    BlockRule {
        /// The matched rule's name.
        rule: String,
    },
    /// Drop the MSU: no rule matched and the screening default is `block`.
    BlockDefault,
    /// Drop the MSU: it would not decode as ISUP and the screening default is
    /// `block` (`error` is why it would not decode).
    BlockUndecoded {
        /// The decode-error text.
        error: String,
    },
}

impl Screened {
    /// The metric reason class for a drop verdict, or `None` for a pass.
    pub fn reason(&self) -> Option<ScreenReason> {
        match self {
            Screened::Pass | Screened::PassUndecoded { .. } => None,
            Screened::BlockRule { .. } => Some(ScreenReason::Rule),
            Screened::BlockDefault => Some(ScreenReason::Default),
            Screened::BlockUndecoded { .. } => Some(ScreenReason::DecodeError),
        }
    }
}

/// A tenant's compiled ISUP screening engine. Built from an [`IsupScreening`]
/// config block; a tenant with no such block holds `None` instead.
#[derive(Debug, Clone)]
pub struct IsupScreen {
    default: ScreenAction,
    rules: Vec<CompiledRule>,
}

impl IsupScreen {
    /// Compile a screening config into its runtime engine.
    pub fn compile(cfg: &IsupScreening) -> Self {
        let rules = cfg
            .rules
            .iter()
            .map(|r| CompiledRule::compile(r.name.clone(), &r.match_, r.action))
            .collect();
        Self {
            default: cfg.default,
            rules,
        }
    }

    /// Evaluate a decoded message against the ordered rules (first match wins),
    /// falling back to the default action.
    fn evaluate(&self, msg: &Message) -> Screened {
        for rule in &self.rules {
            if rule.matches(msg) {
                return match rule.action {
                    ScreenAction::Block => Screened::BlockRule {
                        rule: rule.name.clone(),
                    },
                    ScreenAction::Allow => Screened::Pass,
                };
            }
        }
        match self.default {
            ScreenAction::Block => Screened::BlockDefault,
            ScreenAction::Allow => Screened::Pass,
        }
    }

    /// Decode `payload` as an ISUP message and screen it. On a decode failure the
    /// configured default action applies (never a silent mis-route).
    pub fn screen(&self, payload: &[u8]) -> Screened {
        match Message::decode(payload) {
            Ok(msg) => self.evaluate(&msg),
            Err(e) => match self.default {
                ScreenAction::Block => Screened::BlockUndecoded {
                    error: e.to_string(),
                },
                ScreenAction::Allow => Screened::PassUndecoded {
                    error: e.to_string(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IsupScreening, ScreenAction, ScreenMatch, ScreenRule};
    use itu_isup::{
        calling_party_category, transmission_medium_requirement, CauseIndicators, Message, Number,
        Parameter,
    };

    fn rule(name: &str, m: ScreenMatch, action: ScreenAction) -> ScreenRule {
        ScreenRule {
            name: name.to_string(),
            match_: m,
            action,
        }
    }

    fn iam(called: &str, calling: &str) -> Vec<u8> {
        Message::iam(
            1,
            0x00,
            0x2000,
            calling_party_category::ORDINARY,
            transmission_medium_requirement::SPEECH,
            &Number::called(3, 1, false, called),
        )
        .unwrap()
        .with_optional(
            Parameter::calling_party_number(&Number::calling(3, 1, false, 0, 3, calling)).unwrap(),
        )
        .encode()
        .unwrap()
    }

    #[test]
    fn message_type_from_name_maps_named_types() {
        assert_eq!(message_type_from_name("iam"), Some(MessageType::Iam));
        assert_eq!(message_type_from_name("REL"), Some(MessageType::Rel));
        assert_eq!(message_type_from_name("cgba"), Some(MessageType::Cgba));
        assert_eq!(message_type_from_name("not-a-type"), None);
        // "unknown" is the acronym of Other(_); it must not resolve.
        assert_eq!(message_type_from_name("unknown"), None);
    }

    #[test]
    fn blocks_matching_called_prefix() {
        let scr = IsupScreen::compile(&IsupScreening {
            default: ScreenAction::Allow,
            rules: vec![rule(
                "premium",
                ScreenMatch {
                    message_type: Some("iam".into()),
                    called_prefix: Some("1999".into()),
                    calling_prefix: None,
                },
                ScreenAction::Block,
            )],
        });
        assert_eq!(
            scr.screen(&iam("1999555", "1555000")),
            Screened::BlockRule {
                rule: "premium".into()
            }
        );
        // A different called prefix does not match → default allow → pass.
        assert_eq!(scr.screen(&iam("1555555", "1555000")), Screened::Pass);
    }

    #[test]
    fn message_type_gate_narrows_the_rule() {
        let scr = IsupScreen::compile(&IsupScreening {
            default: ScreenAction::Allow,
            rules: vec![rule(
                "rel-only",
                ScreenMatch {
                    message_type: Some("rel".into()),
                    called_prefix: None,
                    calling_prefix: None,
                },
                ScreenAction::Block,
            )],
        });
        // An IAM is not a REL → default allow.
        assert_eq!(scr.screen(&iam("1555555", "1555000")), Screened::Pass);
        // A REL matches and is blocked.
        let rel = Message::release(1, &CauseIndicators::new(1, 16))
            .encode()
            .unwrap();
        assert_eq!(
            scr.screen(&rel),
            Screened::BlockRule {
                rule: "rel-only".into()
            }
        );
    }

    #[test]
    fn calling_prefix_matches_optional_parameter() {
        let scr = IsupScreen::compile(&IsupScreening {
            default: ScreenAction::Allow,
            rules: vec![rule(
                "cli",
                ScreenMatch {
                    message_type: None,
                    called_prefix: None,
                    calling_prefix: Some("1555".into()),
                },
                ScreenAction::Block,
            )],
        });
        assert_eq!(
            scr.screen(&iam("1999555", "1555000")),
            Screened::BlockRule { rule: "cli".into() }
        );
        assert_eq!(scr.screen(&iam("1999555", "1999000")), Screened::Pass);
    }

    #[test]
    fn default_block_drops_unmatched() {
        let scr = IsupScreen::compile(&IsupScreening {
            default: ScreenAction::Block,
            rules: vec![rule(
                "allow-national",
                ScreenMatch {
                    message_type: None,
                    called_prefix: Some("1555".into()),
                    calling_prefix: None,
                },
                ScreenAction::Allow,
            )],
        });
        // Explicit allow rule passes national calls.
        assert_eq!(scr.screen(&iam("1555555", "1555000")), Screened::Pass);
        // Everything else falls through to the block default.
        assert_eq!(
            scr.screen(&iam("1999555", "1555000")),
            Screened::BlockDefault
        );
    }

    #[test]
    fn decode_failure_takes_the_default_action() {
        let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let block = IsupScreen::compile(&IsupScreening {
            default: ScreenAction::Block,
            rules: vec![],
        });
        assert!(matches!(
            block.screen(&garbage),
            Screened::BlockUndecoded { .. }
        ));
        let allow = IsupScreen::compile(&IsupScreening {
            default: ScreenAction::Allow,
            rules: vec![],
        });
        assert!(matches!(
            allow.screen(&garbage),
            Screened::PassUndecoded { .. }
        ));
    }

    #[test]
    fn reason_classes_map_to_metric() {
        assert_eq!(
            Screened::BlockRule { rule: "x".into() }.reason(),
            Some(ScreenReason::Rule)
        );
        assert_eq!(Screened::BlockDefault.reason(), Some(ScreenReason::Default));
        assert_eq!(
            Screened::BlockUndecoded { error: "e".into() }.reason(),
            Some(ScreenReason::DecodeError)
        );
        assert_eq!(Screened::Pass.reason(), None);
        assert_eq!(Screened::PassUndecoded { error: "e".into() }.reason(), None);
    }
}
