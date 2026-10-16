//! Admission of new TCAP dialogues: a policy the embedding binary sets on the
//! [`Router`](crate::routing::Router) that decides, per dialogue-starting
//! message, whether the node lets a new dialogue through or start here.
//!
//! The policy is plain Rust, evaluated on the transport's per-message path with
//! no Python call. With no policy set, every message is admitted and the node
//! behaves exactly as it does without this module.
//!
//! # What is evaluated
//!
//! Only a message that **starts** a dialogue is put to the policy: a TCAP
//! `Begin` (TC-BEGIN), and a `Unidirectional` (TC-UNI), which is a one-shot
//! exchange with no transaction to continue. A `Continue`, `End` or `Abort`
//! belongs to a dialogue that was already admitted and always passes, so the
//! node needs no dialogue state to apply a policy as a relay. Non-SCCP traffic,
//! an SCCP service message (UDTS / XUDTS / LUDTS), and SCCP traffic that does
//! not carry one of those two TCAP messages (SCCP management among it) always
//! pass. A segmented message is judged by its first segment, which carries the
//! TCAP message type; later segments pass.
//!
//! # What a refusal does
//!
//! * **At a node that relays the message** (MTP3 transfer of an SCCP message, or
//!   a global-title translation to another point code), the SCCP message return
//!   procedure applies (ITU-T Q.714 4.2): when the UDT / XUDT / LUDT has the
//!   "return message on error" option set, the node answers the calling party
//!   with a UDTS / XUDTS / LUDTS carrying the [`RefuseCause`]'s return cause
//!   (Q.713 3.12, "unqualified" by default); without the option, the message is
//!   discarded. The return goes back over the association the message arrived
//!   on.
//! * **At a node that terminates the dialogue** (the message is for one of its
//!   own subsystems), a `Begin` is answered with an `Abort` carrying the P-Abort
//!   cause "resource limitation" (Q.773; Q.772 2.3.5: "sufficient resources are
//!   not available to start a transaction"), the same answer the dialogue
//!   engine gives a `Begin` over its `max_dialogues` ceiling. The dialogue
//!   engine never sees it. A refused `Unidirectional` has no transaction to
//!   abort and is discarded.
//!
//! Each refusal is counted in
//! `sigtran_admission_refused_total{reason,action}` (`action` is `returned`,
//! `discarded` or `aborted`) and logged on stderr.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicBool, Ordering};
//! use siphon_sigtran::admission::{Admission, DialogueStart, RefuseCause};
//! use siphon_sigtran::{Config, Router};
//!
//! let config = Config::parse(
//!     "node: { point_code: 1000, variant: ITU }\nassociations: []",
//! )?;
//! let open = Arc::new(AtomicBool::new(true));
//! let gate = open.clone();
//! let router = Router::new(&config).with_admission_policy(Arc::new(
//!     move |_start: &DialogueStart<'_>| {
//!         if gate.load(Ordering::Relaxed) {
//!             Admission::Admit
//!         } else {
//!             Admission::Refuse(RefuseCause::new("closed"))
//!         }
//!     },
//! ));
//! assert!(router.admission_policy().is_some());
//! # Ok::<(), siphon_sigtran::Error>(())
//! ```

use sccp::{SccpAddress, SccpMessage};
use tcap::dialogue::DialoguePdu;
use tcap::{Decoded, TcapMessage};

pub use sccp::ReturnCause;

use crate::transport::framing::SI_SCCP;
use crate::transport::Msu;

/// The TCAP message that starts the dialogue being admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogueKind {
    /// A `Begin` (TC-BEGIN): opens a transaction.
    Begin,
    /// A `Unidirectional` (TC-UNI): a one-shot message with no transaction.
    Unidirectional,
}

impl DialogueKind {
    /// A short label for logs.
    pub fn label(self) -> &'static str {
        match self {
            DialogueKind::Begin => "begin",
            DialogueKind::Unidirectional => "unidirectional",
        }
    }
}

/// One SCCP party address, as the message carries it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Party<'a> {
    /// Global title digits, when the address has a global title.
    pub global_title: Option<&'a str>,
    /// Subsystem number, when present.
    pub ssn: Option<u8>,
    /// Signalling point code in the address, when present.
    pub point_code: Option<u32>,
}

impl<'a> Party<'a> {
    fn of(address: &'a SccpAddress) -> Self {
        Self {
            global_title: address.global_title.digits(),
            ssn: address.ssn.map(|s| s.value()),
            point_code: address.point_code.map(u32::from),
        }
    }
}

/// What is known about a dialogue-starting message when the policy is asked.
/// Read-only; borrowed from the decoded message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialogueStart<'a> {
    /// `Begin` or `Unidirectional`.
    pub kind: DialogueKind,
    /// The SCCP calling party.
    pub calling: Party<'a>,
    /// The SCCP called party.
    pub called: Party<'a>,
    /// The MTP3 originating point code of the message.
    pub opc: u32,
    /// The MTP3 destination point code of the message.
    pub dpc: u32,
    /// The application context name (OID arcs) from the AARQ or AUDT, when the
    /// message carries a readable dialogue portion.
    pub application_context: Option<&'a [u32]>,
    /// The routing domain the message is routed in (`default` for a node with
    /// a single domain).
    pub domain: &'a str,
    /// Whether the dialogue terminates at this node (one of its own
    /// subsystems) rather than being relayed through it.
    pub terminates_here: bool,
}

/// Why a dialogue was refused, and the SCCP return cause a relaying node
/// answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefuseCause {
    reason: &'static str,
    return_cause: ReturnCause,
}

impl RefuseCause {
    /// The return cause a refusal carries unless another is chosen: "unqualified"
    /// (Q.713 3.12, `0000 0111`). It says nothing about the state of the
    /// destination, which a policy refusal is not about.
    pub const DEFAULT_RETURN_CAUSE: ReturnCause = ReturnCause::Unqualified;

    /// A refusal with this `reason` and the default return cause. `reason` is
    /// the `reason` label of `sigtran_admission_refused_total`; keep the set of
    /// values small.
    pub const fn new(reason: &'static str) -> Self {
        Self {
            reason,
            return_cause: Self::DEFAULT_RETURN_CAUSE,
        }
    }

    /// The same refusal with another SCCP return cause.
    pub const fn with_return_cause(mut self, return_cause: ReturnCause) -> Self {
        self.return_cause = return_cause;
        self
    }

    /// The `reason` label.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// The SCCP return cause a relaying node answers with.
    pub const fn return_cause(&self) -> ReturnCause {
        self.return_cause
    }
}

impl Default for RefuseCause {
    /// Reason `policy`, return cause "unqualified".
    fn default() -> Self {
        Self::new("policy")
    }
}

/// The policy's answer for one dialogue-starting message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Let the dialogue through (or start it here).
    Admit,
    /// Refuse it.
    Refuse(RefuseCause),
}

/// An admission policy for new dialogues. Called on the transport's
/// per-message path, so it must be cheap and must not block. Any
/// `Fn(&DialogueStart<'_>) -> Admission + Send + Sync` is one.
pub trait AdmissionPolicy: Send + Sync {
    /// Decide on one dialogue-starting message.
    fn admit(&self, start: &DialogueStart<'_>) -> Admission;
}

impl<F> AdmissionPolicy for F
where
    F: Fn(&DialogueStart<'_>) -> Admission + Send + Sync,
{
    fn admit(&self, start: &DialogueStart<'_>) -> Admission {
        self(start)
    }
}

/// The outcome of putting one MSU to a policy.
#[derive(Debug)]
pub(crate) enum Gate {
    /// Not a dialogue start, or admitted: carry on.
    Pass,
    /// Refused.
    Refused(Refusal),
}

/// A refused dialogue start, with what the transport needs to answer it.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub cause: RefuseCause,
    pub kind: DialogueKind,
    /// The originating transaction id of a `Begin`, when it can be read.
    pub otid: Option<Vec<u8>>,
    /// The decoded SCCP message (for the return).
    pub sccp: SccpMessage,
}

/// TCAP message type tags (Q.773 4.1): `[APPLICATION 1]` Unidirectional and
/// `[APPLICATION 2]` Begin, both constructed.
const TAG_UNIDIRECTIONAL: u8 = 0x61;
const TAG_BEGIN: u8 = 0x62;

/// Put one inbound MSU to `policy`. Only an SCCP UDT / XUDT / LUDT whose data
/// starts with a TCAP `Begin` or `Unidirectional` tag is evaluated; everything
/// else passes without being decoded past the SCCP header.
pub(crate) fn check(
    policy: &dyn AdmissionPolicy,
    msu: &Msu,
    domain: &str,
    terminates_here: bool,
) -> Gate {
    if msu.si != SI_SCCP {
        return Gate::Pass;
    }
    let Ok(sccp) = SccpMessage::decode(&msu.payload) else {
        return Gate::Pass;
    };
    if matches!(
        sccp,
        SccpMessage::Udts(_) | SccpMessage::Xudts(_) | SccpMessage::Ludts(_)
    ) {
        return Gate::Pass;
    }
    let data = sccp.data();
    let kind = match data.first() {
        Some(&TAG_BEGIN) => DialogueKind::Begin,
        Some(&TAG_UNIDIRECTIONAL) => DialogueKind::Unidirectional,
        _ => return Gate::Pass,
    };

    // A damaged message is still a dialogue start: what can be read of it
    // (the transaction id, perhaps the dialogue portion) is used.
    let (otid, dialogue) = match tcap::decode_detailed(data) {
        Decoded::Complete(TcapMessage::Begin(b)) => (
            Some(b.otid.to_vec()),
            b.dialogue_portion
                .and_then(|p| p.dialogue_pdu().ok().flatten()),
        ),
        Decoded::Complete(TcapMessage::Unidirectional(u)) => (
            None,
            u.dialogue_portion
                .and_then(|p| p.dialogue_pdu().ok().flatten()),
        ),
        Decoded::Complete(_) => (None, None),
        Decoded::Problem(problem) => (problem.otid.map(|t| t.to_vec()), None),
    };
    let application_context = match &dialogue {
        Some(DialoguePdu::Aarq {
            application_context_name,
            ..
        })
        | Some(DialoguePdu::Audt {
            application_context_name,
            ..
        }) => Some(application_context_name.as_ref()),
        _ => None,
    };

    let start = DialogueStart {
        kind,
        calling: Party::of(sccp.calling_party()),
        called: Party::of(sccp.called_party()),
        opc: msu.opc,
        dpc: msu.dpc,
        application_context,
        domain,
        terminates_here,
    };
    let cause = match policy.admit(&start) {
        Admission::Admit => return Gate::Pass,
        Admission::Refuse(cause) => cause,
    };
    let otid = match kind {
        DialogueKind::Begin => otid,
        DialogueKind::Unidirectional => None,
    };
    Gate::Refused(Refusal {
        cause,
        kind,
        otid,
        sccp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::{Any, Oid};
    use sccp::{ExtendedUnitData, GlobalTitle, SubsystemNumber, UnitData, UnitDataService};
    use std::sync::Mutex;
    use tcap::dialogue::DialoguePortion;
    use tcap::{Begin, Component, Continue, End, Invoke, OperationCode, Unidirectional};

    const AC: [u32; 8] = [0, 4, 0, 0, 1, 0, 20, 3];

    fn gt(digits: &str) -> GlobalTitle {
        GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: digits.to_string(),
        }
    }

    fn invoke() -> Component {
        Component::Invoke(Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(45),
            parameter: Some(Any::new(vec![0x04, 0x01, 0x00])),
        })
    }

    fn begin() -> Vec<u8> {
        tcap::encode(&TcapMessage::Begin(Begin {
            otid: vec![0x11, 0x22, 0x33, 0x44].into(),
            dialogue_portion: Some(DialoguePortion::aarq(Oid::new(&AC).unwrap())),
            components: Some(vec![invoke()]),
        }))
        .unwrap()
    }

    fn unidirectional() -> Vec<u8> {
        tcap::encode(&TcapMessage::Unidirectional(Unidirectional {
            dialogue_portion: None,
            components: vec![invoke()],
        }))
        .unwrap()
    }

    fn continue_() -> Vec<u8> {
        tcap::encode(&TcapMessage::Continue(Continue {
            otid: vec![0x11, 0x22, 0x33, 0x44].into(),
            dtid: vec![0x80, 0x00, 0x00, 0x01].into(),
            dialogue_portion: None,
            components: Some(vec![invoke()]),
        }))
        .unwrap()
    }

    fn end() -> Vec<u8> {
        tcap::encode(&TcapMessage::End(End {
            dtid: vec![0x80, 0x00, 0x00, 0x01].into(),
            dialogue_portion: None,
            components: None,
        }))
        .unwrap()
    }

    fn calling() -> SccpAddress {
        SccpAddress::with_gt(gt("15550170"), Some(SubsystemNumber::Msc))
    }

    fn called() -> SccpAddress {
        let mut a = SccpAddress::with_gt(gt("15550142"), Some(SubsystemNumber::Hlr));
        a.point_code = Some(2000);
        a
    }

    fn msu(payload: Vec<u8>) -> Msu {
        Msu {
            opc: 4000,
            dpc: 1000,
            si: SI_SCCP,
            ni: 0,
            mp: 0,
            sls: 0,
            payload,
        }
    }

    fn udt(tcap: Vec<u8>) -> Msu {
        msu(UnitData::new(called(), calling(), tcap).encode().unwrap())
    }

    /// A policy that refuses everything and records what it was shown.
    struct Recorder(Mutex<Vec<String>>);
    impl AdmissionPolicy for Recorder {
        fn admit(&self, start: &DialogueStart<'_>) -> Admission {
            self.0.lock().unwrap().push(format!("{start:?}"));
            Admission::Refuse(RefuseCause::default())
        }
    }

    fn refuse_all(_: &DialogueStart<'_>) -> Admission {
        Admission::Refuse(RefuseCause::new("test"))
    }

    #[test]
    fn a_begin_is_put_to_the_policy_with_what_the_message_carries() {
        let seen = Mutex::new(None);
        let policy = |start: &DialogueStart<'_>| {
            *seen.lock().unwrap() = Some((
                start.kind,
                start.calling.global_title.map(str::to_string),
                start.calling.ssn,
                start.called.global_title.map(str::to_string),
                start.called.ssn,
                start.called.point_code,
                start.opc,
                start.dpc,
                start.application_context.map(<[u32]>::to_vec),
                start.domain.to_string(),
                start.terminates_here,
            ));
            Admission::Refuse(RefuseCause::new("test"))
        };
        match check(&policy, &udt(begin()), "default", false) {
            Gate::Refused(r) => {
                assert_eq!(r.kind, DialogueKind::Begin);
                assert_eq!(r.otid, Some(vec![0x11, 0x22, 0x33, 0x44]));
                assert_eq!(r.cause.reason(), "test");
                assert_eq!(r.cause.return_cause(), ReturnCause::Unqualified);
            }
            Gate::Pass => panic!("a refused Begin passed"),
        }
        let seen = seen.into_inner().unwrap().expect("the policy was asked");
        assert_eq!(
            seen,
            (
                DialogueKind::Begin,
                Some("15550170".into()),
                Some(8),
                Some("15550142".into()),
                Some(6),
                Some(2000),
                4000,
                1000,
                Some(AC.to_vec()),
                "default".into(),
                false,
            )
        );
    }

    #[test]
    fn a_unidirectional_is_a_dialogue_start() {
        match check(&refuse_all, &udt(unidirectional()), "default", true) {
            Gate::Refused(r) => {
                assert_eq!(r.kind, DialogueKind::Unidirectional);
                assert_eq!(r.otid, None, "a TC-UNI has no transaction to abort");
            }
            Gate::Pass => panic!("a refused Unidirectional passed"),
        }
    }

    #[test]
    fn continue_and_end_always_pass_and_the_policy_is_not_asked() {
        let policy = Recorder(Mutex::new(Vec::new()));
        for tcap in [continue_(), end()] {
            assert!(matches!(
                check(&policy, &udt(tcap), "default", false),
                Gate::Pass
            ));
        }
        assert!(policy.0.lock().unwrap().is_empty());
    }

    #[test]
    fn non_tcap_and_non_sccp_traffic_passes() {
        let policy = Recorder(Mutex::new(Vec::new()));
        // SCCP management (SSN 1) data: an SSA, not TCAP.
        let scmg = msu(
            UnitData::new(called(), calling(), vec![0x01, 0x06, 0xE8, 0x03, 0x00])
                .encode()
                .unwrap(),
        );
        assert!(matches!(
            check(&policy, &scmg, "default", false),
            Gate::Pass
        ));
        // An ISUP MSU.
        let mut isup = msu(vec![0x01, 0x00, 0x01]);
        isup.si = 5;
        assert!(matches!(
            check(&policy, &isup, "default", false),
            Gate::Pass
        ));
        // A service message carrying a Begin is a return, not a new dialogue.
        let udts = msu(SccpMessage::Udts(UnitDataService::new(
            ReturnCause::Unqualified,
            calling(),
            called(),
            begin(),
        ))
        .encode()
        .unwrap());
        assert!(matches!(
            check(&policy, &udts, "default", false),
            Gate::Pass
        ));
        assert!(policy.0.lock().unwrap().is_empty());
    }

    #[test]
    fn an_xudt_begin_is_evaluated() {
        let xudt = msu(ExtendedUnitData::new(called(), calling(), begin())
            .encode()
            .unwrap());
        assert!(matches!(
            check(&refuse_all, &xudt, "default", false),
            Gate::Refused(_)
        ));
    }

    #[test]
    fn a_damaged_begin_is_still_a_dialogue_start() {
        // A Begin whose component portion is cut short: the transaction id
        // can still be read, so a terminating node can abort it.
        let mut damaged = begin();
        damaged.truncate(damaged.len() - 3);
        match check(&refuse_all, &udt(damaged), "default", true) {
            Gate::Refused(r) => assert_eq!(r.otid, Some(vec![0x11, 0x22, 0x33, 0x44])),
            Gate::Pass => panic!("a refused damaged Begin passed"),
        }
    }

    #[test]
    fn an_admitted_begin_passes() {
        let admit = |_: &DialogueStart<'_>| Admission::Admit;
        assert!(matches!(
            check(&admit, &udt(begin()), "default", false),
            Gate::Pass
        ));
    }

    #[test]
    fn the_return_cause_is_selectable() {
        let cause = RefuseCause::new("busy").with_return_cause(ReturnCause::SubsystemCongestion);
        assert_eq!(cause.reason(), "busy");
        assert_eq!(cause.return_cause(), ReturnCause::SubsystemCongestion);
        assert_eq!(RefuseCause::default().reason(), "policy");
        assert_eq!(
            RefuseCause::default().return_cause().value(),
            0x07,
            "unqualified, Q.713 3.12"
        );
    }
}
