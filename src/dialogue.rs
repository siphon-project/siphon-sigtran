//! The MAP/CAP **dialogue-termination SAP**: a TCAP transaction engine that
//! terminates the messages the [router](crate::routing) hands up as
//! [`RouteDecision::Local`](crate::routing::RouteDecision::Local).
//!
//! When a message terminates here it is an SCCP UDT carrying a TCAP transaction
//! (Q.771-775). This engine decodes it, drives the transaction, and dispatches
//! the decoded MAP (TS 29.002) / CAP (TS 29.078) operation to a registered
//! [`TerminationHandler`]. The handler answers through a [`Dialogue`] handle:
//! `reply` (a ReturnResultLast in a closing End), `invoke` + `send` (a Continue
//! that holds the dialogue open), `end`, or `abort`.
//!
//! The whole engine is **synchronous**: [`DialogueEngine::deliver`] takes one
//! inbound MSU and returns the MSUs to send back, so it composes with the async
//! transport (which owns the SCTP I/O) exactly the way the routing brain does.
//! The TCAP + SCCP bytes it produces are wire-real (built with the published
//! `tcap` / `sccp` / `gsm_map` / `gsm_cap` codecs), not a re-encoding of the
//! request.
//!
//! # The three shapes
//!
//! * **Single request/response** (SRI-SM, initialDP): a `Begin(AARQ, Invoke)`
//!   arrives, the handler replies, the reply is an `End(AARE, ReturnResultLast)`
//!   echoing the peer's transaction id.
//! * **Held-open, multi-leg** (updateLocation with an insertSubscriberData leg):
//!   the handler answers a `Begin` with a `Continue(AARE, Invoke)` and keeps the
//!   dialogue open; the peer's follow-up `Continue`/`End` re-enters the handler
//!   via [`TerminationHandler::on_continue`], which finishes with an `End`.
//! * **Originating** (an SMSC doing SRI-SM then a multi-segment MT-ForwardSM):
//!   [`DialogueEngine::begin`] opens a dialogue we initiate, the handler stages
//!   the opening `Invoke` in [`TerminationHandler::on_start`], and each peer
//!   `Continue`/`End` re-enters `on_continue` for the next leg.
//!
//! # Damaged and unexpected messages
//!
//! A message that cannot be fully decoded is never dropped where ITU-T Q.774
//! calls for an answer, and never processed as if it were complete:
//!
//! * a fault in the **transaction portion** of a Begin, a Continue or a message
//!   of unknown type whose originating transaction id can be read is answered
//!   with an Abort carrying the P-Abort cause (Q.774 3.3.4, Table 7); the local
//!   dialogue it named, if any, is released and its handler told
//!   ([`CloseReason::ProviderAbort`]);
//! * a fault in the **dialogue portion** is answered with an Abort carrying an
//!   ABRT APDU, abort-source dialogue-service-provider, and is an "abnormal
//!   dialogue" locally (Q.774 3.2.2.1, [`CloseReason::AbnormalDialogue`]);
//! * a fault in a **component** is answered with a Reject component: the
//!   components before the faulty one are delivered as a normal turn followed
//!   by a [`PeerComponent::LocalReject`], the ones after it are discarded, and
//!   the Reject leaves with the next Continue or End of the dialogue (Q.774
//!   3.2.2.2);
//! * a Continue for a transaction id this engine does not know is answered with
//!   a P-Abort "unrecognized transaction ID"; an End or an Abort for one is
//!   discarded (Table 7).
//!
//! # Operation classes and timers
//!
//! Every invoke has an [`OperationClass`] (Q.774 Table 2) and an invocation
//! timer. [`DialogueEngine::sweep`] expires the timers. The expiry is a
//! TC-L-CANCEL to the handler ([`TerminationHandler::on_invoke_timeout`]), never
//! an abort by the engine: for a class 1 operation it is an abnormal situation
//! the handler decides on (the default aborts the dialogue), for a class 2 or 3
//! operation it is the normal outcome, and a class 4 operation just returns to
//! idle. A dialogue with no traffic for its idle timeout (the `dialogue_timer_ms`
//! default, or [`Dialogue::set_idle_timeout`]) is aborted and its handler told.
//! A Begin over the `max_dialogues` ceiling is refused with a P-Abort "resource
//! limitation".
//!
//! # The end of a dialogue
//!
//! However a dialogue ends, its handler hears of it exactly once, through
//! [`TerminationHandler::on_closed`], with the [`CloseReason`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rasn::types::{Any, Oid};
use sccp::{ExtendedUnitData, ReturnCause, SccpAddress, SccpMessage, UnitData};
use tcap::dialogue::{
    AbortSource as TcapAbortSource, AssociateSourceDiagnostic, DialoguePdu, DialoguePortion,
    ProtocolVersion,
};
use tcap::{
    Abort, AbortReason, Begin, Component, Continue as TcapContinue, DecodeProblem, Decoded, End,
    ErrorCode, Fault, Invoke, OperationCode, Reject, ReturnError, ReturnResult, ReturnResultValue,
    TcapMessage,
};

pub use tcap::{
    GeneralProblem, InvokeId, InvokeProblem, PAbortCause, Problem, ReturnErrorProblem,
    ReturnResultProblem,
};

use crate::config::Tcap;
use crate::metrics::{
    self, AbortCause, AbortSource, Dir, LoopKind, RejectClass, RxDiscard, TcapDiscard,
};
use crate::transport::framing::SI_SCCP;
use crate::transport::Msu;

/// A transaction id (OTID / DTID), 1-4 octets.
pub type Tid = Vec<u8>;

/// Whether we opened the dialogue (initiator, a TCAP Begin we sent) or a peer
/// opened it against us (responder, a Begin we received).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A peer opened the dialogue; we terminate its operation and answer.
    Responder,
    /// We opened the dialogue (originating side, e.g. an SMSC's SRI-SM / MT).
    Initiator,
}

/// The class of an operation (Q.774 Table 2): which outcomes the performer
/// reports. "The two peer applications must have a priori knowledge of the
/// classes and timers associated with each operation" (Q.774 3.2.1.1.2), so the
/// class is given by whoever stages the invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationClass {
    /// Class 1: reporting success or failure.
    One,
    /// Class 2: reporting failure only. Silence until the timer expires is
    /// success.
    Two,
    /// Class 3: reporting success only. Silence until the timer expires is
    /// failure.
    Three,
    /// Class 4: outcome not reported.
    Four,
}

impl OperationClass {
    /// The class for its number, 1 to 4.
    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            4 => Some(Self::Four),
            _ => None,
        }
    }

    /// The class number, 1 to 4.
    pub fn number(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    /// Whether the performer reports success (a ReturnResult is a valid reply).
    pub fn reports_success(self) -> bool {
        matches!(self, Self::One | Self::Three)
    }

    /// Whether the performer reports failure (a ReturnError is a valid reply).
    pub fn reports_failure(self) -> bool {
        matches!(self, Self::One | Self::Two)
    }
}

/// What can go wrong when a handler drives a [`Dialogue`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DialogueError {
    /// The dialogue is closed: it was ended or aborted, or the peer ended it.
    #[error("the dialogue is closed")]
    Closed,
    /// Every invoke id of the dialogue is assigned to an operation in progress.
    #[error("every invoke id of the dialogue is in use")]
    NoInvokeId,
    /// A Continue or an End was asked for before the peer answered the Begin,
    /// so there is no destination transaction id to send it to.
    #[error("the peer has not answered the Begin yet: no destination transaction id")]
    NoPeerTransaction,
    /// The handler opened a dialogue without sending its Begin.
    #[error("the dialogue was opened without sending a Begin")]
    NothingSent,
    /// The TCAP message could not be encoded: Q.773 does not allow what was
    /// staged (a parameter that is not one BER element, for instance).
    #[error("the TCAP message could not be encoded: {0}")]
    Encode(String),
    /// The SCCP message could not be encoded (the TCAP message does not fit a
    /// UDT, for instance).
    #[error("the SCCP message could not be encoded: {0}")]
    Sccp(String),
    /// The argument of an invoke could not be built for this dialogue (it
    /// depends on the application context, and the dialogue has none it can be
    /// built for).
    #[error("the invoke argument could not be built: {0}")]
    Argument(String),
}

/// The decoded opening operation handed to [`TerminationHandler::on_begin`].
#[derive(Debug, Clone)]
pub struct IncomingOp {
    /// The local operation code (MAP TS 29.002 / CAP TS 29.078).
    pub operation_code: i64,
    /// The invoke id the peer used (echoed on the reply).
    pub invoke_id: InvokeId,
    /// The raw BER argument bytes, if the Invoke carried a parameter.
    pub argument: Option<Vec<u8>>,
    /// The application context OID arcs from the AARQ, if present.
    pub application_context: Option<Vec<u32>>,
    /// The called-party SSN the message was addressed to (which subsystem we own).
    pub called_ssn: u8,
    /// The calling-party global-title digits (the peer), if present.
    pub calling_gt: Option<String>,
    /// The called-party global-title digits (us), if present.
    pub called_gt: Option<String>,
    /// Every other component of the Begin, in the order received: the dialogue
    /// belongs to the handler of its first Invoke, and the remaining components
    /// (further Invokes, or a [`PeerComponent::LocalReject`] for one that could
    /// not be read) are its to act on in the same turn.
    pub further: Vec<PeerComponent>,
}

/// One TCAP component the peer sent, decoded for
/// [`TerminationHandler::on_continue`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerComponent {
    /// An `Invoke` (the peer asked us to do something in an open dialogue).
    Invoke {
        /// The invoke id.
        invoke_id: InvokeId,
        /// The operation code.
        operation_code: i64,
        /// The raw BER argument, if present.
        argument: Option<Vec<u8>>,
    },
    /// A `ReturnResultLast` (the peer answered one of our invokes).
    Result {
        /// The invoke id being answered.
        invoke_id: InvokeId,
        /// The operation code echoed in the result, if present.
        operation_code: Option<i64>,
        /// The raw BER result parameter, if present.
        parameter: Option<Vec<u8>>,
    },
    /// A `ReturnError` (the peer rejected one of our invokes).
    Error {
        /// The invoke id being answered.
        invoke_id: InvokeId,
        /// The MAP/CAP error code.
        error_code: i64,
    },
    /// A `Reject` the peer sent: its TCAP or its TC-user refused one of our
    /// components as a protocol error (TC-R-REJECT / TC-U-REJECT indication).
    /// The operation it names, if it names one, is no longer in progress.
    Reject {
        /// The invoke id of the rejected component, or `None` when the peer
        /// could not derive it.
        invoke_id: Option<InvokeId>,
        /// What was wrong with it.
        problem: Problem,
    },
    /// A component of this message was rejected **here**, by the component
    /// sub-layer (TC-L-REJECT indication): it could not be decoded, or it does
    /// not fit the state of the operation it names. The Reject is built and
    /// leaves with the next Continue or End of the dialogue (Q.774 3.2.2.2); the
    /// handler is told "so that it can issue a dialogue control primitive".
    /// Components after an undecodable one were discarded.
    LocalReject {
        /// The invoke id of the rejected component, when it could be read.
        invoke_id: Option<InvokeId>,
        /// The problem the Reject carries.
        problem: Problem,
    },
}

impl PeerComponent {
    /// What a handler rejects this component with when its parameter does not
    /// decode as the type the operation defines: the invoke id to name and the
    /// "mistyped parameter" problem of the component's class, for
    /// [`Dialogue::reject`]. Q.772 3.7.2.3: "mistyped parameter: Signifies that
    /// the type of parameter in an invoke component is not that agreed by the
    /// two TC-Users"; 3.7.3.3 and 3.7.4.5 say the same of a return result and a
    /// return error. `None` for a Reject, which has no parameter and is never
    /// answered with one.
    pub fn mistyped_parameter(&self) -> Option<(Option<InvokeId>, Problem)> {
        match self {
            Self::Invoke { invoke_id, .. } => Some((
                Some(*invoke_id),
                Problem::Invoke(InvokeProblem::MISTYPED_PARAMETER),
            )),
            Self::Result { invoke_id, .. } => Some((
                Some(*invoke_id),
                Problem::ReturnResult(ReturnResultProblem::MISTYPED_PARAMETER),
            )),
            Self::Error { invoke_id, .. } => Some((
                Some(*invoke_id),
                Problem::ReturnError(ReturnErrorProblem::MISTYPED_PARAMETER),
            )),
            Self::Reject { .. } | Self::LocalReject { .. } => None,
        }
    }
}

impl IncomingOp {
    /// What a handler rejects the opening Invoke with when its argument does
    /// not decode: see [`PeerComponent::mistyped_parameter`].
    pub fn mistyped_parameter(&self) -> (Option<InvokeId>, Problem) {
        (
            Some(self.invoke_id),
            Problem::Invoke(InvokeProblem::MISTYPED_PARAMETER),
        )
    }
}

/// One follow-up turn from the peer on an open dialogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTurn {
    /// Whether this turn arrived in a TCAP `End` (the peer closed the dialogue).
    pub is_end: bool,
    /// The decoded components.
    pub components: Vec<PeerComponent>,
}

/// An invocation timer expired (TC-L-CANCEL indication, Q.774 3.2.1.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeTimeout {
    /// The invoke id, now released.
    pub invoke_id: InvokeId,
    /// The operation that was invoked.
    pub operation_code: i64,
    /// Its class. For class 1 the expiry is an abnormal situation; for class 2
    /// it is the definite success of the operation and for class 3 its failure.
    pub class: OperationClass,
}

/// What an Abort from the peer carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAbort {
    /// A P-Abort: the peer's transaction sub-layer aborted, with this cause.
    Provider(PAbortCause),
    /// An ABRT APDU with abort-source dialogue-service-provider: the peer's
    /// component sub-layer found our dialogue portion incorrect (Q.774
    /// 3.2.2.1, "abnormal dialogue").
    AbnormalDialogue,
    /// A refusing AARE from the peer's component sub-layer: it does not support
    /// version 1 of the dialogue portion (Q.774 3.2.3).
    NoCommonDialoguePortion,
    /// A U-Abort: the peer's TC-user aborted.
    User(UserAbort),
}

impl PeerAbort {
    /// Whether the peer's TCAP aborted (TC-P-ABORT indication), as opposed to
    /// its TC-user (TC-U-ABORT indication).
    pub fn is_provider(self) -> bool {
        !matches!(self, Self::User(_))
    }
}

/// What the peer's TC-user sent with its abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserAbort {
    /// Nothing.
    NoInformation,
    /// An ABRT APDU, abort-source dialogue-service-user.
    DialogueServiceUser,
    /// A refusing AARE: the application context is not supported.
    ApplicationContextNotSupported,
    /// A refusing AARE for another reason.
    DialogueRefused,
    /// Information in a user-defined abstract syntax.
    UserDefined,
}

/// Why a dialogue ended, for [`TerminationHandler::on_closed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// The handler ended it ([`Dialogue::end`]).
    Ended,
    /// The peer ended it (the End was delivered through `on_continue`).
    PeerEnded,
    /// The handler aborted it ([`Dialogue::abort`]).
    Aborted,
    /// The peer aborted it.
    PeerAbort(PeerAbort),
    /// A message for this dialogue arrived with a damaged transaction portion,
    /// and the transaction sub-layer released the transaction (Q.774 3.3.4,
    /// Table 7). `sent` says whether an Abort went back to the peer: it does for
    /// a Continue or a message of unknown type, not for an End or an Abort.
    ProviderAbort {
        /// The P-Abort cause that describes the damage.
        cause: PAbortCause,
        /// Whether an Abort was sent.
        sent: bool,
    },
    /// A message for this dialogue arrived with an incorrect dialogue portion
    /// (Q.774 3.2.2.1, TC-P-ABORT "abnormal dialogue"). `sent` as above.
    AbnormalDialogue {
        /// Whether an Abort was sent.
        sent: bool,
    },
    /// An invocation timer expired and the handler's
    /// [`on_invoke_timeout`](TerminationHandler::on_invoke_timeout) aborted the
    /// dialogue.
    InvokeTimeout {
        /// The invoke id that timed out.
        invoke_id: InvokeId,
        /// Its operation code.
        operation_code: i64,
    },
    /// Nothing was exchanged for the dialogue's idle timeout; the engine
    /// aborted it.
    IdleTimeout,
    /// The handler gave no answer to a Begin; the engine aborted the dialogue so
    /// the peer is not left waiting.
    NoAnswer,
    /// The handler opened a dialogue and its Begin could not be sent.
    NotSent,
}

/// The end of a dialogue, for [`TerminationHandler::on_closed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogueClosed {
    /// Our transaction id.
    pub otid: Tid,
    /// The peer's transaction id (empty if the peer never answered our Begin).
    pub dtid: Tid,
    /// Whether we opened the dialogue.
    pub role: Role,
    /// Why it ended.
    pub reason: CloseReason,
}

/// A termination host: registered per (SSN, operation), it drives a dialogue.
///
/// The Python addon layer implements this over the `gsm_map` / `gsm_cap`
/// decorators; the crate's tests exercise it with small in-Rust handlers.
pub trait TerminationHandler: Send + Sync {
    /// A `Begin` opened a responder dialogue with this first operation. Drive the
    /// answer: `reply` + `end` for a single response, or `invoke` + `send` to
    /// hold it open for a follow-up leg. A responder must override this; the
    /// default answers nothing (which the engine turns into an abort so the peer
    /// is never left hanging). An originating-only handler leaves it defaulted.
    fn on_begin(&self, _dialogue: &mut Dialogue, _op: &IncomingOp) {}

    /// Called by [`DialogueEngine::begin`] on the initiator side to stage the
    /// opening `Invoke`(s) before the `Begin` goes out. Unused by responders.
    fn on_start(&self, _dialogue: &mut Dialogue) {}

    /// The peer continued an open dialogue (a `Continue` or `End`) with these
    /// components. Drive the next leg (`reply`/`invoke`/`send`/`end`), or do
    /// nothing: the dialogue then stays open and waits (for the next event of a
    /// call, say) until the peer or its idle timeout ends it. After a peer
    /// `End` the dialogue is closed and nothing more can be sent on it.
    fn on_continue(&self, _dialogue: &mut Dialogue, _peer: &PeerTurn) {}

    /// The invocation timer of one of our invokes expired (TC-L-CANCEL). The
    /// invoke id is already released.
    ///
    /// Q.774 3.2.1.1.3: "This notification indicates an abnormal situation for a
    /// class 1 operation, or gives the definite outcome of a class 2 or 3
    /// operation for which no result has been received (normal situation)", and
    /// for class 1, "It is now up to the application to decide whether to abort
    /// the transaction or to report an error to the peer application." The
    /// default takes the first option for class 1 and does nothing otherwise.
    fn on_invoke_timeout(&self, dialogue: &mut Dialogue, timeout: &InvokeTimeout) {
        if timeout.class == OperationClass::One {
            let _ = dialogue.abort();
        }
    }

    /// The dialogue ended. Called exactly once for every dialogue this handler
    /// was given (through `on_begin` or `on_start`), whatever ended it: release
    /// here whatever was tied to the dialogue.
    fn on_closed(&self, _closed: &DialogueClosed) {}
}

/// The reversible addressing for a dialogue's outbound messages: the SCCP party
/// addresses to stamp and the MTP3 routing label to send under.
#[derive(Debug, Clone)]
struct Addressing {
    /// The called party of our outbound messages (the peer).
    out_called: SccpAddress,
    /// The calling party of our outbound messages (us).
    out_calling: SccpAddress,
    /// Our point code (outbound OPC).
    opc: u32,
    /// The peer's point code (outbound DPC).
    dpc: u32,
    /// Network indicator.
    ni: u8,
    /// Signalling link selection.
    sls: u8,
    /// The SCCP message our outbound messages go in.
    form: UnitdataForm,
}

/// Which SCCP connectionless message carries a TCAP message. Q.714 4.1 leaves
/// the choice to the sending SCCP ("the user data is then transferred in XUDT
/// or LUDT or UDT message(s)"), and 4.1.1.1.1 says of user data that needs no
/// segmentation that "an XUDT or LUDT or UDT message is passed to SCRC". A
/// dialogue the peer opened is answered in the form the peer chose, since that
/// is a form the path between the two is known to carry; one this node opens
/// goes in a UDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitdataForm {
    /// Unitdata (Q.713 4.10).
    Udt,
    /// Extended unitdata (Q.713 4.18), unsegmented: no optional part.
    Xudt,
}

impl Addressing {
    /// Reverse an inbound unitdata + routing label into the addressing for the
    /// reply, which goes in the form the request came in.
    fn reverse(udt: &UnitData, inbound: &Msu, form: UnitdataForm) -> Self {
        Self {
            out_called: udt.calling_party.clone(),
            out_calling: udt.called_party.clone(),
            opc: inbound.dpc,
            dpc: inbound.opc,
            ni: inbound.ni,
            sls: inbound.sls,
            form,
        }
    }
}

/// One of our invokes in the "operation sent" state (Q.774 3.2.1.1.3).
#[derive(Debug, Clone)]
struct Outstanding {
    id: InvokeId,
    op: i64,
    class: OperationClass,
    timeout: Duration,
    /// When the invocation timer expires. `None` until the Invoke is passed to
    /// the transaction sub-layer (flushed).
    deadline: Option<Instant>,
}

/// A live dialogue handle. Handlers stage components (`invoke`, `reply`,
/// `error`, `reject`) and flush them as a TCAP leg (`send` = Continue, `end` =
/// End).
pub struct Dialogue {
    role: Role,
    our_tid: Tid,
    peer_tid: Tid,
    ac: Vec<u32>,
    /// The invoke id to reply to by default (the opening operation's).
    reply_invoke_id: InvokeId,
    /// Where the search for the next free invoke id starts.
    next_invoke_id: InvokeId,
    first_flush_done: bool,
    aare_pending: bool,
    closed: Option<CloseReason>,
    addressing: Addressing,
    /// Components the handler staged since the last flush.
    pending: Vec<Component>,
    /// The invokes among `pending`: they enter the "operation sent" state when
    /// the message carrying them is flushed.
    staged: Vec<Outstanding>,
    /// Our invokes in progress.
    outstanding: Vec<Outstanding>,
    /// Reject components the component sub-layer built for this dialogue, sent
    /// with the next Continue or End.
    rejects: Vec<Reject>,
    out: Vec<Msu>,
    /// The first error of a flush in the current turn.
    send_error: Option<DialogueError>,
    default_invoke_timeout: Duration,
    idle_timeout: Option<Duration>,
}

impl Dialogue {
    fn new(
        role: Role,
        our_tid: Tid,
        peer_tid: Tid,
        ac: Vec<u32>,
        reply_invoke_id: InvokeId,
        addressing: Addressing,
        config: &Tcap,
    ) -> Self {
        Self {
            role,
            our_tid,
            peer_tid,
            // An AARE answers an AARQ: only a responder that was offered an
            // application context sends one, on its first backward message.
            aare_pending: role == Role::Responder && !ac.is_empty(),
            ac,
            reply_invoke_id,
            next_invoke_id: 1,
            first_flush_done: false,
            closed: None,
            addressing,
            pending: Vec::new(),
            staged: Vec::new(),
            outstanding: Vec::new(),
            rejects: Vec::new(),
            out: Vec::new(),
            send_error: None,
            default_invoke_timeout: Duration::from_millis(config.invoke_timer_ms),
            idle_timeout: (config.dialogue_timer_ms > 0)
                .then(|| Duration::from_millis(config.dialogue_timer_ms)),
        }
    }

    /// Our originating transaction id.
    pub fn otid(&self) -> &[u8] {
        &self.our_tid
    }

    /// The peer's transaction id (the destination id we send toward).
    pub fn dtid(&self) -> &[u8] {
        &self.peer_tid
    }

    /// The negotiated application-context OID arcs.
    pub fn application_context(&self) -> &[u32] {
        &self.ac
    }

    /// Whether the dialogue has been closed (an `End` or `abort` flushed, or the
    /// peer ended it).
    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Whether we opened this dialogue (the initiator/originating side).
    pub fn is_initiator(&self) -> bool {
        self.role == Role::Initiator
    }

    /// The invoke ids of our operations in progress, with their operation codes.
    pub fn outstanding_invokes(&self) -> Vec<(InvokeId, i64)> {
        self.outstanding.iter().map(|o| (o.id, o.op)).collect()
    }

    /// The idle timeout of this dialogue: how long it may go without a message
    /// in either direction before the engine aborts it. `None` waits forever.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Set the idle timeout of this dialogue, overriding the configured
    /// `dialogue_timer_ms`. A dialogue that legitimately waits a long time (a
    /// call-control dialogue whose next event is the end of the call) sets what
    /// the call can last, or `None` to wait until the peer ends it.
    pub fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.idle_timeout = timeout;
    }

    /// Stage a class 1 `Invoke` of `operation_code` carrying `argument`, with
    /// the configured `invoke_timer_ms`; returns the allocated invoke id. The
    /// dialogue must still be flushed with `send`/`end`.
    pub fn invoke(
        &mut self,
        operation_code: i64,
        argument: Option<Vec<u8>>,
    ) -> Result<InvokeId, DialogueError> {
        self.invoke_with(operation_code, argument, OperationClass::One, None)
    }

    /// Stage an `Invoke` of the given operation class. `timeout` is the
    /// invocation timer ("The TC-INVOKE request primitive indicates a timer
    /// value", Q.774 3.2.1.1.3); `None` takes the configured `invoke_timer_ms`.
    pub fn invoke_with(
        &mut self,
        operation_code: i64,
        argument: Option<Vec<u8>>,
        class: OperationClass,
        timeout: Option<Duration>,
    ) -> Result<InvokeId, DialogueError> {
        if self.closed.is_some() {
            return Err(DialogueError::Closed);
        }
        let id = self.allocate_invoke_id().ok_or(DialogueError::NoInvokeId)?;
        self.pending.push(Component::Invoke(Invoke {
            invoke_id: id,
            linked_id: None,
            operation_code: OperationCode::Local(operation_code),
            parameter: argument.map(Any::new),
        }));
        self.staged.push(Outstanding {
            id,
            op: operation_code,
            class,
            timeout: timeout.unwrap_or(self.default_invoke_timeout),
            deadline: None,
        });
        Ok(id)
    }

    /// The next invoke id that is not assigned to an operation in progress.
    ///
    /// `InvokeIdType ::= INTEGER (-128..127)` (Q.773 3.1). Ids are handed out
    /// in a ring over 0..=127, starting at 1 and resuming after the last one
    /// handed out, so a released id is not reused at once (Q.774 3.2.1.1.2: "A
    /// released ID value ... should therefore not be reallocated immediately").
    /// Only when all 128 of those are in progress are the negative ids used,
    /// from -1 down. `None` when all 256 are in progress.
    fn allocate_invoke_id(&mut self) -> Option<InvokeId> {
        let in_use = |id: InvokeId| {
            self.outstanding.iter().any(|o| o.id == id) || self.staged.iter().any(|o| o.id == id)
        };
        let start = i16::from(self.next_invoke_id.max(0));
        let ring = (0..128i16).map(|k| ((start + k) % 128) as InvokeId);
        let negative = (1..=128i16).map(|k| (-k) as InvokeId);
        let id = ring.chain(negative).find(|id| !in_use(*id))?;
        if id >= 0 {
            self.next_invoke_id = ((i16::from(id) + 1) % 128) as InvokeId;
        }
        Some(id)
    }

    /// Stage a `ReturnResultLast` answering the opening invoke.
    pub fn reply(&mut self, operation_code: i64, result: Option<Vec<u8>>) {
        let invoke_id = self.reply_invoke_id;
        self.reply_to(invoke_id, operation_code, result);
    }

    /// Stage a `ReturnResultLast` answering a specific invoke id.
    ///
    /// Q.773 3.1 has `result SEQUENCE { operationCode OPERATION, parameter ANY
    /// DEFINED BY operationCode } OPTIONAL`: the sequence is there with both
    /// members or not at all. An operation that returns nothing (`result:
    /// None`) is answered with the invoke id alone.
    pub fn reply_to(&mut self, invoke_id: InvokeId, operation_code: i64, result: Option<Vec<u8>>) {
        self.pending.push(Component::ReturnResultLast(ReturnResult {
            invoke_id,
            result: result.map(|parameter| ReturnResultValue {
                operation_code: OperationCode::Local(operation_code),
                parameter: Some(Any::new(parameter)),
            }),
        }));
    }

    /// Stage a `ReturnError` answering a specific invoke id.
    pub fn error(&mut self, invoke_id: InvokeId, error_code: i64) {
        self.pending.push(Component::ReturnError(ReturnError {
            invoke_id,
            error_code: ErrorCode::Local(error_code),
            parameter: None,
        }));
    }

    /// Stage a `Reject` of a component the peer sent (TC-U-REJECT): the handler
    /// found a protocol error in it, a mistyped parameter for instance.
    /// `invoke_id` is the id of the rejected component.
    pub fn reject(&mut self, invoke_id: Option<InvokeId>, problem: Problem) {
        self.pending
            .push(Component::Reject(Reject { invoke_id, problem }));
    }

    /// Drop the components staged since the last flush, without sending them.
    /// For a caller that stages several components as one answer and finds it
    /// cannot stage them all: the part it did stage must not go out alone.
    /// Rejects the component sub-layer built are kept.
    pub fn discard_staged(&mut self) {
        self.pending.clear();
        self.staged.clear();
    }

    /// Flush the staged components as a `Continue` (or, on the initiator's first
    /// flush, the opening `Begin`). The dialogue stays open.
    ///
    /// An error means nothing was sent: it is logged with the dialogue's
    /// transaction ids, and the components staged for this flush are dropped.
    pub fn send(&mut self) -> Result<(), DialogueError> {
        self.flush(false)
    }

    /// Flush the staged components as an `End`, closing the dialogue. Errors as
    /// for [`send`](Self::send); the dialogue then stays open.
    pub fn end(&mut self) -> Result<(), DialogueError> {
        self.flush(true)
    }

    /// Abort the dialogue as its TC-user (TC-U-ABORT). Components staged and
    /// not flushed are discarded, and every operation returns to idle.
    ///
    /// What goes on the wire follows Q.774 3.2.2.1: an Abort with an ABRT APDU,
    /// abort-source dialogue-service-user, when the dialogue was established
    /// with an application context ("a Dialogue Abort (ABRT) APDU is formatted
    /// only for the case when the AARQ/AARE APDUs were used during the dialogue
    /// establishment state"), and an Abort with no reason otherwise. Before the
    /// peer answered our Begin nothing is sent: "the result of the
    /// TC/TR-U-ABORT request primitive is purely local".
    pub fn abort(&mut self) -> Result<(), DialogueError> {
        self.abort_as(CloseReason::Aborted)
    }

    fn abort_as(&mut self, reason: CloseReason) -> Result<(), DialogueError> {
        if self.closed.is_some() {
            return Err(DialogueError::Closed);
        }
        self.pending.clear();
        self.staged.clear();
        self.outstanding.clear();
        self.rejects.clear();
        self.closed = Some(reason);
        if self.peer_tid.is_empty() {
            return Ok(());
        }
        let information = (!self.ac.is_empty())
            .then(|| DialoguePortion::abrt(TcapAbortSource::DialogueServiceUser));
        let abort = Abort::u_abort(self.peer_tid.clone().into(), information);
        self.emit(&TcapMessage::Abort(abort))
    }

    fn flush(&mut self, closing: bool) -> Result<(), DialogueError> {
        if self.closed.is_some() {
            return Err(DialogueError::Closed);
        }
        let opening = self.role == Role::Initiator && !self.first_flush_done;
        if !opening && self.peer_tid.is_empty() {
            return Err(self.fail(DialogueError::NoPeerTransaction));
        }

        // Q.774 3.2.1.2: "any components passed on the interface plus any reject
        // components built by the component sub-layer for this dialogue are
        // passed for transmission".
        let rejects = self.rejects.clone();
        let mut comps: Vec<Component> = rejects.iter().copied().map(Component::Reject).collect();
        comps.append(&mut self.pending);
        let staged = std::mem::take(&mut self.staged);
        let reject_classes: Vec<RejectClass> = comps
            .iter()
            .filter_map(|c| match c {
                Component::Reject(r) => Some(reject_class(&r.problem)),
                _ => None,
            })
            .collect();
        let comps = if comps.is_empty() { None } else { Some(comps) };

        // Dialogue portion: AARQ opens an initiator Begin; AARE rides the
        // responder's first outbound leg (End or Continue). Nothing otherwise.
        let dp = if opening {
            Oid::new(&self.ac).map(DialoguePortion::aarq)
        } else if self.aare_pending {
            Oid::new(&self.ac).map(DialoguePortion::aare_accept)
        } else {
            None
        };

        let msg = if opening {
            TcapMessage::Begin(Begin {
                otid: self.our_tid.clone().into(),
                dialogue_portion: dp,
                components: comps,
            })
        } else if closing {
            TcapMessage::End(End {
                dtid: self.peer_tid.clone().into(),
                dialogue_portion: dp,
                components: comps,
            })
        } else {
            TcapMessage::Continue(TcapContinue {
                otid: self.our_tid.clone().into(),
                dtid: self.peer_tid.clone().into(),
                dialogue_portion: dp,
                components: comps,
            })
        };

        // Nothing changes state until the message is known to be sendable: on
        // an error the dialogue is as it was, minus the components that could
        // not be encoded. The Rejects the component sub-layer built stay.
        self.emit(&msg)?;

        self.rejects.clear();
        for class in reject_classes {
            metrics::tcap_reject(Dir::Tx, class);
        }
        self.aare_pending = false;
        self.first_flush_done = true;
        if closing {
            // Q.774 3.2.1.2: "In an end situation, any non-idle-state machine is
            // returned to Idle when the TR-END request primitive is passed to
            // the transaction sub-layer".
            self.outstanding.clear();
            self.closed = Some(CloseReason::Ended);
        } else {
            // "This invocation timer is started when the invoke component is
            // passed to the transaction sub-layer" (Q.774 3.2.1.1.3).
            let now = Instant::now();
            self.outstanding.extend(staged.into_iter().map(|mut o| {
                o.deadline = Some(now + o.timeout);
                o
            }));
        }
        Ok(())
    }

    /// Encode `msg` and queue it for sending. An encode failure is logged at
    /// error level with the dialogue's identifiers, counted, kept for the
    /// engine, and returned.
    fn emit(&mut self, msg: &TcapMessage) -> Result<(), DialogueError> {
        match wrap_msu(msg, &self.addressing) {
            Ok(msu) => {
                if let TcapMessage::Abort(abort) = msg {
                    count_abort_sent(abort);
                }
                self.out.push(msu);
                Ok(())
            }
            Err(e) => {
                log_error(format_args!(
                    "{} not sent on dialogue otid={} dtid={} (dpc {}): {e}",
                    msg.message_type(),
                    hex(&self.our_tid),
                    hex(&self.peer_tid),
                    self.addressing.dpc,
                ));
                Err(self.fail(e))
            }
        }
    }

    fn fail(&mut self, e: DialogueError) -> DialogueError {
        metrics::tcap_send_error();
        if self.send_error.is_none() {
            self.send_error = Some(e.clone());
        }
        e
    }

    fn closed_event(&self, reason: CloseReason) -> DialogueClosed {
        DialogueClosed {
            otid: self.our_tid.clone(),
            dtid: self.peer_tid.clone(),
            role: self.role,
            reason,
        }
    }
}

/// A parameterised opening request for [`DialogueEngine::begin`] (originating).
pub struct OutgoingBegin {
    /// The application-context OID arcs carried in the AARQ.
    pub application_context: Vec<u32>,
    /// The called party (the peer we address: HLR, MSC, ...).
    pub called: SccpAddress,
    /// The calling party (us).
    pub calling: SccpAddress,
    /// Our point code (outbound OPC).
    pub opc: u32,
    /// The peer's point code (outbound DPC).
    pub dpc: u32,
    /// Network indicator.
    pub ni: u8,
    /// Signalling link selection.
    pub sls: u8,
    /// The association responses come back on / that outbound goes out over.
    pub ingress_assoc: String,
}

/// The stored per-dialogue state between legs.
struct Record {
    handler: Arc<dyn TerminationHandler>,
    dialogue: Dialogue,
    ingress_assoc: String,
    last_activity: Instant,
}

#[derive(Default)]
struct Inner {
    dialogues: HashMap<Tid, Record>,
    tid_counter: u32,
}

/// The dialogue-termination engine: a handler registry keyed by (SSN, op) plus
/// the live transaction store.
pub struct DialogueEngine {
    config: Tcap,
    handlers: HashMap<(u8, i64), Arc<dyn TerminationHandler>>,
    /// Lower-priority handlers consulted only when no specific `handlers` entry
    /// matches (a catch-all registered across a whole namespace). A specific
    /// handler always wins over one of these, whichever registered first.
    fallback_handlers: HashMap<(u8, i64), Arc<dyn TerminationHandler>>,
    inner: Mutex<Inner>,
}

/// Which callback a turn of the handler came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    /// `on_begin`: the peer is waiting for the dialogue to be answered.
    Begin,
    /// `on_continue` on a Continue.
    Continue,
    /// `on_invoke_timeout`.
    Timer,
}

impl DialogueEngine {
    /// A fresh engine with the given TCAP settings and no handlers.
    pub fn new(config: Tcap) -> Self {
        Self {
            config,
            handlers: HashMap::new(),
            fallback_handlers: HashMap::new(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Register a handler for one (SSN, operation) pair. Later registrations for
    /// the same key win, and a specific handler always takes precedence over a
    /// [`register_fallback`](Self::register_fallback) catch-all for the same key.
    pub fn register(&mut self, ssn: u8, operation_code: i64, handler: Arc<dyn TerminationHandler>) {
        self.handlers.insert((ssn, operation_code), handler);
    }

    /// Register a lower-priority catch-all handler for one (SSN, operation) pair.
    /// It fires only when no specific [`register`](Self::register) handler matches
    /// that key, so a bare `@ns.on_operation` never shadows an explicit
    /// `on_operation("<name>")`, regardless of the order they registered in.
    pub fn register_fallback(
        &mut self,
        ssn: u8,
        operation_code: i64,
        handler: Arc<dyn TerminationHandler>,
    ) {
        self.fallback_handlers
            .insert((ssn, operation_code), handler);
    }

    /// The number of currently-open dialogues (deterministic per engine; the
    /// `sigtran_active_dialogues` gauge is the process-wide sum).
    pub fn open_dialogues(&self) -> usize {
        self.lock().dialogues.len()
    }

    /// The configured TCAP settings.
    pub fn config(&self) -> &Tcap {
        &self.config
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn alloc_tid(&self) -> Tid {
        let mut inner = self.lock();
        inner.tid_counter = inner.tid_counter.wrapping_add(1);
        // A non-zero, 4-octet id. The high bit marks it as ours so it never
        // collides with a small peer OTID we might store under the same map.
        (inner.tid_counter | 0x8000_0000).to_be_bytes().to_vec()
    }

    fn take(&self, tid: &[u8]) -> Option<Record> {
        let rec = self.lock().dialogues.remove(tid)?;
        metrics::dialogue_closed();
        Some(rec)
    }

    /// Terminate one inbound MSU: an SCCP UDT, or an XUDT that is not a segment
    /// of a segmented message, carrying TCAP. Returns the MSUs to send back to
    /// the peer, if any.
    ///
    /// Q.714 4.1: "When a UDT or XUDT or LUDT message is received at the
    /// destination node, an N-UNITDATA indication primitive is invoked, after
    /// possible reassembly of all segments". Reassembly is not implemented, so
    /// a segment is counted and dropped, as is an LUDT.
    pub fn deliver(&self, inbound: &Msu, ingress_assoc: &str) -> Vec<Msu> {
        if inbound.si != SI_SCCP {
            not_unitdata(inbound, ingress_assoc, "not an SCCP message");
            return Vec::new();
        }
        let message = match SccpMessage::decode(&inbound.payload) {
            Ok(message) => message,
            Err(error) => {
                not_unitdata(inbound, ingress_assoc, error);
                return Vec::new();
            }
        };
        let is_segment = crate::content::is_segment(&message);
        let (udt, form) = match message {
            SccpMessage::Udt(udt) => (udt, UnitdataForm::Udt),
            SccpMessage::Xudt(_) if is_segment => {
                let what = "a segment of a segmented XUDT, which is not reassembled";
                not_unitdata(inbound, ingress_assoc, what);
                return Vec::new();
            }
            SccpMessage::Xudt(xudt) => {
                if hop_counter_violated(&xudt) {
                    return hop_counter_violation(inbound, ingress_assoc, xudt);
                }
                (xudt_as_unitdata(xudt), UnitdataForm::Xudt)
            }
            other => {
                not_unitdata(inbound, ingress_assoc, sccp_type(&other));
                return Vec::new();
            }
        };
        // Whatever the answer is (a reply, an Abort for a message that belongs
        // to no dialogue), it goes back where the message came from.
        let reply_to = Addressing::reverse(&udt, inbound, form);
        match tcap::decode_detailed(&udt.data) {
            Decoded::Complete(msg) => self.on_message(msg, None, &reply_to, &udt, ingress_assoc),
            Decoded::Problem(problem) => self.on_problem(*problem, &reply_to, &udt, ingress_assoc),
        }
    }

    /// A message that was understood, or the understood part of one whose
    /// component `rejected` could not be read.
    fn on_message(
        &self,
        msg: TcapMessage,
        rejected: Option<Rejected>,
        reply_to: &Addressing,
        udt: &UnitData,
        ingress_assoc: &str,
    ) -> Vec<Msu> {
        match msg {
            TcapMessage::Begin(b) => self.on_begin(b, rejected, reply_to, udt, ingress_assoc),
            TcapMessage::Continue(c) => {
                let components = c.components.unwrap_or_default();
                self.on_turn(
                    &c.dtid,
                    Some(c.otid.to_vec()),
                    components,
                    rejected,
                    false,
                    reply_to,
                )
            }
            TcapMessage::End(e) => {
                let components = e.components.unwrap_or_default();
                self.on_turn(&e.dtid, None, components, rejected, true, reply_to)
            }
            TcapMessage::Abort(a) => {
                self.on_abort(&a);
                Vec::new()
            }
            TcapMessage::Unidirectional(_) => Vec::new(),
        }
    }

    /// A message that was not fully understood: answer it as Q.774 requires.
    fn on_problem(
        &self,
        problem: DecodeProblem,
        reply_to: &Addressing,
        udt: &UnitData,
        ingress_assoc: &str,
    ) -> Vec<Msu> {
        // A fault in a component: the message stands up to that component.
        if let Fault::Component {
            invoke_id,
            problem: general,
            ..
        } = problem.fault
        {
            // `reject()` is `None` when the faulty component is itself a
            // Reject: "the component is discarded and the local TC-user is
            // advised of the syntax error in the received Reject component"
            // (Q.774 3.2.2.2).
            let rejected = Rejected {
                invoke_id,
                problem: Problem::General(general),
                reject: problem.reject(),
            };
            return match problem.partial {
                Some(partial) => {
                    self.on_message(partial, Some(rejected), reply_to, udt, ingress_assoc)
                }
                None => {
                    metrics::tcap_discard(TcapDiscard::Undecodable);
                    Vec::new()
                }
            };
        }

        // A fault in the transaction portion or the dialogue portion: the whole
        // message is discarded (Q.774 3.3.4: "regardless of the disposition of
        // the transaction IDs, the entire erroneous TCAP message should be
        // discarded"; 3.2.2.1: "If any components are received in the message
        // with an incorrect dialogue portion, these are discarded").
        let abort = problem.abort();
        let frames: Vec<Msu> = match &abort {
            Some(abort) => send_abort(abort, reply_to),
            None => {
                metrics::tcap_discard(TcapDiscard::Undecodable);
                Vec::new()
            }
        };
        // Table 7/Q.774: when the destination transaction ID is derivable and
        // assigned, the transaction returns to idle and the local user is
        // advised. That holds for a damaged Continue (answered with the Abort
        // above) and for a damaged End or Abort (discarded, nothing sent).
        if let Some(rec) = problem.dtid.as_ref().and_then(|dtid| self.take(dtid)) {
            let sent = !frames.is_empty();
            let reason = match problem.fault {
                Fault::TransactionPortion { cause } => CloseReason::ProviderAbort { cause, sent },
                _ => CloseReason::AbnormalDialogue { sent },
            };
            metrics::abort(AbortSource::Local);
            self.closed(&rec.handler, &rec.dialogue, reason);
        }
        frames
    }

    fn on_begin(
        &self,
        b: Begin,
        rejected: Option<Rejected>,
        reply_to: &Addressing,
        udt: &UnitData,
        ingress_assoc: &str,
    ) -> Vec<Msu> {
        let peer_tid = b.otid.clone();

        // The transaction sub-layer first: is there room for a transaction?
        // Q.772 2.3.5: "resource limitation: Sufficient resources are not
        // available to start a transaction."
        if self.lock().dialogues.len() >= self.config.max_dialogues {
            metrics::abort(AbortSource::Local);
            return send_abort(
                &Abort::p_abort(peer_tid, PAbortCause::RESOURCE_LIMITATION),
                reply_to,
            );
        }

        // Then the dialogue portion (the component sub-layer, Q.774 3.2.2.1 and
        // 3.2.3). The decoder has parsed it already, so an error here is not
        // expected; it is handled the same way all the same.
        let ac = match b
            .dialogue_portion
            .as_ref()
            .map(DialoguePortion::dialogue_pdu)
        {
            None | Some(Ok(None)) => None,
            Some(Ok(Some(DialoguePdu::Aarq {
                protocol_version,
                application_context_name,
                ..
            }))) => {
                if protocol_version != ProtocolVersion::Version1 {
                    // Q.774 3.2.3: an AARQ "which indicates that version 1 is
                    // not in the list of supported versions" is answered with a
                    // refusing AARE "as user abort information. Informing its
                    // local TC-user is not required and any received components
                    // are discarded."
                    metrics::abort(AbortSource::Local);
                    let information =
                        DialoguePortion::no_common_dialogue_portion(&application_context_name);
                    return send_abort(&Abort::u_abort(peer_tid, Some(information)), reply_to);
                }
                Some(application_context_name.as_ref().to_vec())
            }
            // A dialogue portion that cannot be read, or an APDU that has no
            // place in a Begin ("inconsistent with the state of the underlying
            // transaction"): an abnormal dialogue.
            Some(Err(_)) | Some(Ok(Some(_))) => {
                metrics::abort(AbortSource::Local);
                let information = DialoguePortion::abnormal_dialogue();
                return send_abort(&Abort::u_abort(peer_tid, Some(information)), reply_to);
            }
        };

        let called_ssn = udt.called_party.ssn.map(|s| s.value()).unwrap_or(0);
        let our_tid = self.alloc_tid();
        let mut dlg = Dialogue::new(
            Role::Responder,
            our_tid,
            peer_tid.to_vec(),
            ac.clone().unwrap_or_default(),
            0,
            reply_to.clone(),
            &self.config,
        );

        // The components, each checked against the state of the dialogue (which
        // has no operation of ours in progress yet).
        let wire = b.components.unwrap_or_default();
        let mut components = receive_components(&wire, &mut dlg, false);
        if let Some(rejected) = rejected {
            components.push(rejected.stage(&mut dlg, false));
        }

        // The dialogue belongs to the handler of its first Invoke.
        let first = components.iter().position(
            |c| matches!(c, PeerComponent::Invoke { operation_code, .. } if *operation_code >= 0),
        );
        let Some(first) = first else {
            if !dlg.rejects.is_empty() {
                // Nothing in the Begin could be dispatched, and the component
                // sub-layer has a Reject to send. With no TC-user to hand the
                // dialogue to, the engine ends it (Q.774 3.2.2.2, b): "to end
                // the dialogue using the basic scenario", which "triggers
                // transmission of the stored Reject component(s)").
                let _ = dlg.end();
                return std::mem::take(&mut dlg.out);
            }
            // A Begin without an Invoke opens nothing a MAP/CAP user serves:
            // the TC-user side of this engine aborts it.
            metrics::abort(AbortSource::Local);
            let _ = dlg.abort();
            return std::mem::take(&mut dlg.out);
        };
        let PeerComponent::Invoke {
            invoke_id,
            operation_code: op,
            argument,
        } = components.remove(first)
        else {
            return Vec::new();
        };
        dlg.reply_invoke_id = invoke_id;

        let handler = self
            .handlers
            .get(&(called_ssn, op))
            .or_else(|| self.fallback_handlers.get(&(called_ssn, op)))
            .cloned();
        let Some(handler) = handler else {
            // No termination host for this subsystem/operation: the TC-user
            // refuses the dialogue (TC-U-ABORT, Q.774 3.2.2.1).
            metrics::abort(AbortSource::Local);
            let _ = dlg.abort();
            return std::mem::take(&mut dlg.out);
        };

        let incoming = IncomingOp {
            operation_code: op,
            invoke_id,
            argument,
            application_context: ac,
            called_ssn,
            calling_gt: gt_digits(&udt.calling_party),
            called_gt: gt_digits(&udt.called_party),
            further: components,
        };
        handler.on_begin(&mut dlg, &incoming);

        self.finish_turn(dlg, handler, ingress_assoc, Turn::Begin, Instant::now())
    }

    fn on_turn(
        &self,
        our_tid: &[u8],
        peer_otid: Option<Tid>,
        components: Vec<Component>,
        rejected: Option<Rejected>,
        is_end: bool,
        reply_to: &Addressing,
    ) -> Vec<Msu> {
        // Pop the record so the handler runs without the lock held.
        let Some(rec) = self.take(our_tid) else {
            return match peer_otid {
                // Table 7/Q.774, CONTINUE with a derivable originating
                // transaction ID and an unassigned destination transaction ID:
                // Abort. Q.772 2.3.2: "unrecognized transaction ID: A
                // transaction ID has been received for which a transaction does
                // not exist at the receiving node."
                Some(otid) => send_abort(
                    &Abort::p_abort(otid.into(), PAbortCause::UNRECOGNIZED_TRANSACTION_ID),
                    reply_to,
                ),
                // END with an unassigned destination transaction ID: Discard.
                // An answer that comes after the dialogue timed out ends here,
                // so say which one it was.
                None => {
                    metrics::tcap_discard(TcapDiscard::UnknownTransaction);
                    eprintln!(
                        "siphon-sigtran: discarded an End for transaction {}, which is not open here (never was, or already ended or timed out)",
                        hex(our_tid)
                    );
                    Vec::new()
                }
            };
        };
        let Record {
            handler,
            dialogue: mut dlg,
            ingress_assoc,
            ..
        } = rec;

        // Learn the peer's transaction id from a Continue (an initiator's first
        // response carries it).
        if let Some(otid) = peer_otid {
            if dlg.peer_tid.is_empty() {
                dlg.peer_tid = otid;
            }
        }

        let mut components = receive_components(&components, &mut dlg, is_end);
        if let Some(rejected) = rejected {
            components.push(rejected.stage(&mut dlg, is_end));
        }
        let peer = PeerTurn { is_end, components };

        if is_end {
            // The peer ended the transaction: every operation returns to idle
            // (Q.774 3.2.1.1.3, "End situation") and nothing more can be sent,
            // so the handler sees a closed dialogue.
            dlg.outstanding.clear();
            dlg.rejects.clear();
            dlg.closed = Some(CloseReason::PeerEnded);
            handler.on_continue(&mut dlg, &peer);
            self.closed(&handler, &dlg, CloseReason::PeerEnded);
            return Vec::new();
        }
        handler.on_continue(&mut dlg, &peer);
        self.finish_turn(dlg, handler, &ingress_assoc, Turn::Continue, Instant::now())
    }

    /// An Abort from the peer: release the dialogue and tell its handler what
    /// kind of abort it was.
    fn on_abort(&self, abort: &Abort) {
        let Some(rec) = self.take(&abort.dtid) else {
            // Table 7/Q.774, ABORT with an unassigned destination transaction
            // ID: Discard.
            metrics::tcap_discard(TcapDiscard::UnknownTransaction);
            eprintln!(
                "siphon-sigtran: discarded an Abort for transaction {}, which is not open here",
                hex(&abort.dtid)
            );
            return;
        };
        let (kind, cause) = classify_abort(abort);
        metrics::tcap_abort(Dir::Rx, cause);
        metrics::abort(if kind.is_provider() {
            AbortSource::Provider
        } else {
            AbortSource::User
        });
        self.closed(&rec.handler, &rec.dialogue, CloseReason::PeerAbort(kind));
    }

    /// Start an **originating** dialogue: the handler stages the opening invoke
    /// in [`TerminationHandler::on_start`]. Returns our transaction id and the
    /// MSUs to send (the `Begin`).
    ///
    /// An error means no dialogue was opened: the handler sent no Begin, or the
    /// Begin could not be encoded. The handler's `on_closed` has been called.
    pub fn begin(
        &self,
        req: OutgoingBegin,
        handler: Arc<dyn TerminationHandler>,
    ) -> Result<(Tid, Vec<Msu>), DialogueError> {
        let our_tid = self.alloc_tid();
        let addressing = Addressing {
            out_called: req.called,
            out_calling: req.calling,
            opc: req.opc,
            dpc: req.dpc,
            ni: req.ni,
            sls: req.sls,
            form: UnitdataForm::Udt,
        };
        let mut dlg = Dialogue::new(
            Role::Initiator,
            our_tid.clone(),
            Vec::new(),
            req.application_context,
            0,
            addressing,
            &self.config,
        );
        handler.on_start(&mut dlg);

        let frames = std::mem::take(&mut dlg.out);
        if let Some(reason) = dlg.closed {
            // The handler ended or aborted before anything went out.
            self.closed(&handler, &dlg, reason);
            return Err(dlg.send_error.take().unwrap_or(DialogueError::NothingSent));
        }
        if frames.is_empty() {
            let error = dlg.send_error.take().unwrap_or(DialogueError::NothingSent);
            self.closed(&handler, &dlg, CloseReason::NotSent);
            return Err(error);
        }
        self.store(dlg, handler, &req.ingress_assoc, Instant::now());
        Ok((our_tid, frames))
    }

    /// Common tail after a handler callback: take the frames, then store the
    /// dialogue if it is still open, or tell the handler it closed.
    fn finish_turn(
        &self,
        mut dlg: Dialogue,
        handler: Arc<dyn TerminationHandler>,
        ingress_assoc: &str,
        turn: Turn,
        last_activity: Instant,
    ) -> Vec<Msu> {
        // A handler that answers nothing to a Begin would leave the peer with a
        // transaction nobody confirms. That is the TC-user failing to serve the
        // dialogue, so the abort is a TC-user abort. (Saying nothing to a
        // Continue is legitimate: the dialogue waits.)
        if turn == Turn::Begin && dlg.closed.is_none() && dlg.out.is_empty() {
            metrics::abort(AbortSource::Local);
            let _ = dlg.abort_as(CloseReason::NoAnswer);
        }
        dlg.send_error = None;
        let frames = std::mem::take(&mut dlg.out);
        match dlg.closed {
            Some(reason) => {
                if reason == CloseReason::Aborted {
                    metrics::abort(AbortSource::Local);
                }
                self.closed(&handler, &dlg, reason);
            }
            None => {
                // A timer callback that sent nothing is not activity.
                let at = if turn == Turn::Timer && frames.is_empty() {
                    last_activity
                } else {
                    Instant::now()
                };
                self.store(dlg, handler, ingress_assoc, at);
            }
        }
        frames
    }

    fn store(
        &self,
        dialogue: Dialogue,
        handler: Arc<dyn TerminationHandler>,
        ingress_assoc: &str,
        last_activity: Instant,
    ) {
        let tid = dialogue.our_tid.clone();
        let rec = Record {
            handler,
            dialogue,
            ingress_assoc: ingress_assoc.to_string(),
            last_activity,
        };
        self.lock().dialogues.insert(tid, rec);
        metrics::dialogue_opened();
    }

    /// Tell a handler its dialogue ended. Every path that drops a dialogue the
    /// handler was given goes through here, once.
    fn closed(&self, handler: &Arc<dyn TerminationHandler>, dlg: &Dialogue, reason: CloseReason) {
        handler.on_closed(&dlg.closed_event(reason));
    }

    /// Run the timers. For every dialogue with an expired invocation timer the
    /// handler gets [`TerminationHandler::on_invoke_timeout`] (a class 4
    /// operation just returns to idle), and a dialogue idle past its idle
    /// timeout is aborted. Returns `(ingress, MSU)` pairs to send: whatever the
    /// handlers flushed, and the aborts. Call it periodically (the transport
    /// does) or with an explicit `now` in a test.
    pub fn sweep(&self, now: Instant) -> Vec<(String, Msu)> {
        let due: Vec<Record> = {
            let mut inner = self.lock();
            let tids: Vec<Tid> = inner
                .dialogues
                .iter()
                .filter(|(_, rec)| {
                    let invoke_expired = rec
                        .dialogue
                        .outstanding
                        .iter()
                        .any(|o| o.deadline.is_some_and(|d| now >= d));
                    invoke_expired || idle_expired(rec, now)
                })
                .map(|(tid, _)| tid.clone())
                .collect();
            tids.iter()
                .filter_map(|tid| inner.dialogues.remove(tid))
                .collect()
        };

        let mut out = Vec::new();
        for rec in due {
            metrics::dialogue_closed();
            let idle = idle_expired(&rec, now);
            let Record {
                handler,
                dialogue: mut dlg,
                ingress_assoc,
                last_activity,
            } = rec;

            // Q.774 3.2.1.1.3, "Invocation timeout": "the state machine returns
            // to Idle, with notification to the TC-user by means of a
            // TC-L-CANCEL indication (in the case of a class 1, 2 or 3
            // operation)".
            let (expired, running): (Vec<Outstanding>, Vec<Outstanding>) = dlg
                .outstanding
                .drain(..)
                .partition(|o| o.deadline.is_some_and(|d| now >= d));
            dlg.outstanding = running;
            for invoke in expired {
                if dlg.closed.is_some() {
                    break;
                }
                if invoke.class == OperationClass::Four {
                    continue;
                }
                if invoke.class == OperationClass::One {
                    // The one class for which silence is an abnormal situation.
                    metrics::invoke_timeout(invoke.op);
                }
                let timeout = InvokeTimeout {
                    invoke_id: invoke.id,
                    operation_code: invoke.op,
                    class: invoke.class,
                };
                handler.on_invoke_timeout(&mut dlg, &timeout);
                if dlg.closed == Some(CloseReason::Aborted) {
                    dlg.closed = Some(CloseReason::InvokeTimeout {
                        invoke_id: invoke.id,
                        operation_code: invoke.op,
                    });
                    metrics::abort(AbortSource::Local);
                }
            }

            // Q.774 3.3.4, case 1 ("No reaction to transaction"): "covered by a
            // local, implementation-dependent, mechanism which results in
            // aborting the transaction locally". The idle timeout is that
            // mechanism. The transaction sub-layer has no P-Abort cause for it
            // (Q.772 2.3 lists five, none of them a timeout), so what the peer
            // is sent, in case it is still there, is a TC-user abort.
            if dlg.closed.is_none() && idle {
                metrics::dialogue_timeout();
                metrics::abort(AbortSource::Local);
                let _ = dlg.abort_as(CloseReason::IdleTimeout);
            }

            let frames = self.finish_turn(dlg, handler, &ingress_assoc, Turn::Timer, last_activity);
            out.extend(frames.into_iter().map(|m| (ingress_assoc.clone(), m)));
        }
        out
    }
}

fn idle_expired(rec: &Record, now: Instant) -> bool {
    rec.dialogue
        .idle_timeout
        .is_some_and(|idle| now.saturating_duration_since(rec.last_activity) >= idle)
}

/// A component the decoder could not read, on its way to the handler.
struct Rejected {
    invoke_id: Option<InvokeId>,
    problem: Problem,
    /// The Reject to send; `None` when the unreadable component was itself a
    /// Reject, which is never answered.
    reject: Option<Reject>,
}

impl Rejected {
    /// Store the Reject for the next Continue or End (unless the message was an
    /// End, which leaves no transaction to send it in) and build the indication
    /// for the handler.
    fn stage(self, dlg: &mut Dialogue, is_end: bool) -> PeerComponent {
        if let (Some(reject), false) = (self.reject, is_end) {
            dlg.rejects.push(reject);
        }
        PeerComponent::LocalReject {
            invoke_id: self.invoke_id,
            problem: self.problem,
        }
    }
}

/// Turn the components of a received message into the handler's view, applying
/// the checks of the component sub-layer (Q.774 3.2.2.2, Table 5): a component
/// that does not fit the state of the operation it names is rejected, which
/// builds a Reject for the next Continue or End and puts a
/// [`PeerComponent::LocalReject`] in its place.
fn receive_components(
    components: &[Component],
    dlg: &mut Dialogue,
    is_end: bool,
) -> Vec<PeerComponent> {
    let mut out = Vec::with_capacity(components.len());
    for component in components {
        let verdict = match component {
            Component::Invoke(inv) => match inv.linked_id {
                // Q.772 3.7.2.6: "unrecognized linked ID: The linked ID does not
                // correspond to an active invoke operation. This code is
                // generated only by the component sublayer."
                Some(linked) if !dlg.outstanding.iter().any(|o| o.id == linked) => Err(
                    Reject::invoke(inv.invoke_id, InvokeProblem::UNRECOGNIZED_LINKED_ID),
                ),
                _ => Ok(PeerComponent::Invoke {
                    invoke_id: inv.invoke_id,
                    operation_code: local_op(&inv.operation_code),
                    argument: inv.parameter.as_ref().map(|p| p.as_bytes().to_vec()),
                }),
            },
            Component::ReturnResultLast(rr) | Component::ReturnResultNotLast(rr) => {
                let last = matches!(component, Component::ReturnResultLast(_));
                match dlg.outstanding.iter().position(|o| o.id == rr.invoke_id) {
                    None => Err(Reject::return_result(
                        rr.invoke_id,
                        ReturnResultProblem::UNRECOGNIZED_INVOKE_ID,
                    )),
                    // Table 5/Q.774: Return result, Operation Class 2/4:
                    // Initiate Reject, Return to Idle.
                    Some(i) if !dlg.outstanding[i].class.reports_success() => {
                        dlg.outstanding.remove(i);
                        Err(Reject::return_result(
                            rr.invoke_id,
                            ReturnResultProblem::RETURN_RESULT_UNEXPECTED,
                        ))
                    }
                    Some(i) => {
                        if last {
                            dlg.outstanding.remove(i);
                        }
                        Ok(PeerComponent::Result {
                            invoke_id: rr.invoke_id,
                            operation_code: rr.result.as_ref().map(|r| local_op(&r.operation_code)),
                            parameter: rr
                                .result
                                .as_ref()
                                .and_then(|r| r.parameter.as_ref())
                                .map(|p| p.as_bytes().to_vec()),
                        })
                    }
                }
            }
            Component::ReturnError(re) => {
                match dlg.outstanding.iter().position(|o| o.id == re.invoke_id) {
                    None => Err(Reject::return_error(
                        re.invoke_id,
                        ReturnErrorProblem::UNRECOGNIZED_INVOKE_ID,
                    )),
                    // Table 5/Q.774: Return error, Operation Class 3/4:
                    // Initiate Reject, Return to Idle.
                    Some(i) if !dlg.outstanding[i].class.reports_failure() => {
                        dlg.outstanding.remove(i);
                        Err(Reject::return_error(
                            re.invoke_id,
                            ReturnErrorProblem::RETURN_ERROR_UNEXPECTED,
                        ))
                    }
                    Some(i) => {
                        dlg.outstanding.remove(i);
                        Ok(PeerComponent::Error {
                            invoke_id: re.invoke_id,
                            error_code: match &re.error_code {
                                ErrorCode::Local(v) => *v,
                                ErrorCode::Global(_) => -1,
                            },
                        })
                    }
                }
            }
            Component::Reject(rj) => {
                metrics::tcap_reject(Dir::Rx, reject_class(&rj.problem));
                // A Reject of one of our invokes ends that operation ("When a
                // component is rejected, the associated state machine returns
                // to Idle", Q.774 3.2.2.2). A Reject of a result or an error we
                // sent names the peer's invoke, which has no state here.
                if matches!(rj.problem, Problem::General(_) | Problem::Invoke(_)) {
                    if let Some(id) = rj.invoke_id {
                        dlg.outstanding.retain(|o| o.id != id);
                    }
                }
                Ok(PeerComponent::Reject {
                    invoke_id: rj.invoke_id,
                    problem: rj.problem,
                })
            }
        };
        out.push(match verdict {
            Ok(component) => component,
            Err(reject) => {
                if !is_end {
                    dlg.rejects.push(reject);
                }
                PeerComponent::LocalReject {
                    invoke_id: reject.invoke_id,
                    problem: reject.problem,
                }
            }
        });
    }
    out
}

/// What an Abort from the peer carried, for the handler and for the metrics.
fn classify_abort(abort: &Abort) -> (PeerAbort, AbortCause) {
    match &abort.reason {
        None => (
            PeerAbort::User(UserAbort::NoInformation),
            AbortCause::NoInformation,
        ),
        Some(AbortReason::PAbort(cause)) => (
            PeerAbort::Provider(*cause),
            AbortCause::from_p_abort(cause.value()),
        ),
        Some(AbortReason::UAbort(portion)) => match portion.dialogue_pdu() {
            Ok(Some(DialoguePdu::Abrt { abort_source, .. })) => match abort_source {
                TcapAbortSource::DialogueServiceUser => (
                    PeerAbort::User(UserAbort::DialogueServiceUser),
                    AbortCause::AbrtUser,
                ),
                // Q.774 3.2.2.1: "a TC-P-ABORT indication is issued by the
                // component sub-layer on the receipt of an ABRT APDU ... with
                // the abort-source field of the ABRT APDU set to
                // "dialogue-service-provider"".
                TcapAbortSource::DialogueServiceProvider => {
                    (PeerAbort::AbnormalDialogue, AbortCause::AbrtProvider)
                }
            },
            Ok(Some(DialoguePdu::Aare {
                result_source_diagnostic,
                ..
            })) => {
                let kind = match result_source_diagnostic {
                    AssociateSourceDiagnostic::PROVIDER_NO_COMMON_DIALOGUE_PORTION => {
                        PeerAbort::NoCommonDialoguePortion
                    }
                    AssociateSourceDiagnostic::DialogueServiceProvider(_) => {
                        PeerAbort::AbnormalDialogue
                    }
                    AssociateSourceDiagnostic::USER_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED => {
                        PeerAbort::User(UserAbort::ApplicationContextNotSupported)
                    }
                    AssociateSourceDiagnostic::DialogueServiceUser(_) => {
                        PeerAbort::User(UserAbort::DialogueRefused)
                    }
                };
                (kind, AbortCause::AareReject)
            }
            Ok(_) => (
                PeerAbort::User(UserAbort::UserDefined),
                AbortCause::UserDefined,
            ),
            // The decoder refuses an Abort whose user abort information is
            // malformed, so this is not reached; it is an abnormal dialogue.
            Err(_) => (PeerAbort::AbnormalDialogue, AbortCause::AbrtProvider),
        },
    }
}

fn count_abort_sent(abort: &Abort) {
    let (_, cause) = classify_abort(abort);
    metrics::tcap_abort(Dir::Tx, cause);
}

fn reject_class(problem: &Problem) -> RejectClass {
    match problem {
        Problem::General(_) => RejectClass::General,
        Problem::Invoke(_) => RejectClass::Invoke,
        Problem::ReturnResult(_) => RejectClass::ReturnResult,
        Problem::ReturnError(_) => RejectClass::ReturnError,
    }
}

/// Wrap one TCAP message in an SCCP UDT or XUDT + MTP3 routing label, ready for
/// the transport to frame onto M3UA / M2PA. An XUDT goes out whole (no
/// segmentation parameter, Table 19/Q.713 Note 2), protocol class 0, with the
/// hop counter a message starts with.
fn wrap_msu(msg: &TcapMessage, a: &Addressing) -> Result<Msu, DialogueError> {
    let tcap_bytes = tcap::encode(msg).map_err(|e| DialogueError::Encode(e.to_string()))?;
    let (called, calling) = (a.out_called.clone(), a.out_calling.clone());
    let sccp = match a.form {
        UnitdataForm::Udt => UnitData::new(called, calling, tcap_bytes).encode(),
        UnitdataForm::Xudt => ExtendedUnitData::new(called, calling, tcap_bytes).encode(),
    }
    .map_err(|e| DialogueError::Sccp(e.to_string()))?;
    Ok(Msu {
        opc: a.opc,
        dpc: a.dpc,
        si: SI_SCCP,
        ni: a.ni,
        mp: 0,
        sls: a.sls,
        payload: sccp,
    })
}

/// Build a standalone TCAP Abort MSU toward the peer, for a message that
/// belongs to no dialogue of ours (or whose dialogue is being released).
fn send_abort(abort: &Abort, a: &Addressing) -> Vec<Msu> {
    match wrap_msu(&TcapMessage::Abort(abort.clone()), a) {
        Ok(msu) => {
            count_abort_sent(abort);
            vec![msu]
        }
        Err(e) => {
            metrics::tcap_send_error();
            log_error(format_args!(
                "Abort not sent for dtid={} (dpc {}): {e}",
                hex(&abort.dtid),
                a.dpc
            ));
            Vec::new()
        }
    }
}

/// Answer a `Begin` the [admission policy](crate::admission) refused at this
/// node with an Abort carrying the P-Abort cause "resource limitation" (Q.772
/// 2.3.5), addressed back to the originator: the answer [`DialogueEngine`] gives
/// a `Begin` over its `max_dialogues` ceiling, in the form the `Begin` came in.
/// `None` when the inbound message is not one the engine terminates (a UDT, or
/// a whole XUDT whose hop counter allows delivery) or the Abort cannot be built.
pub(crate) fn refuse_begin(inbound: &Msu, otid: &[u8]) -> Option<Msu> {
    let message = SccpMessage::decode(&inbound.payload).ok()?;
    if crate::content::is_segment(&message) {
        return None;
    }
    let (udt, form) = match message {
        SccpMessage::Udt(udt) => (udt, UnitdataForm::Udt),
        SccpMessage::Xudt(xudt) if !hop_counter_violated(&xudt) => {
            (xudt_as_unitdata(xudt), UnitdataForm::Xudt)
        }
        _ => return None,
    };
    let reply_to = Addressing::reverse(&udt, inbound, form);
    let abort = Abort::p_abort(otid.to_vec().into(), PAbortCause::RESOURCE_LIMITATION);
    let frame = send_abort(&abort, &reply_to).pop()?;
    metrics::abort(AbortSource::Local);
    Some(frame)
}

/// A whole XUDT as the unitdata the dialogue engine reads (Q.714 4.1): the
/// parties, the data, the protocol class and the message handling.
fn xudt_as_unitdata(xudt: ExtendedUnitData) -> UnitData {
    let mut udt = UnitData::new(xudt.called_party, xudt.calling_party, xudt.data);
    udt.protocol_class = xudt.protocol_class;
    udt.message_handling = xudt.message_handling;
    udt
}

/// The crate has no logging framework: the operator-facing log is stderr, and
/// an error is marked as one.
fn log_error(message: std::fmt::Arguments<'_>) {
    eprintln!("siphon-sigtran: ERROR: {message}");
}

/// Whether delivering this XUDT here uses up its hop counter. Q.714 2.3.1: a
/// called party address that routes on its subsystem number is handed to the
/// subsystem as it is; one that routes on a global title is translated first,
/// and "the SCCP Hop Counter (if present) is decremented and if a Hop Counter
/// violation is encountered (i.e. the value zero is reached), then ... the
/// message return procedure is initiated", before the translation is found to
/// lead to this node.
fn hop_counter_violated(xudt: &ExtendedUnitData) -> bool {
    !xudt.called_party.route_on_ssn && xudt.hop_counter <= 1
}

/// Drop an XUDT whose hop counter ran out at the translation to this node:
/// count it with the loops, log it, and return it in an XUDTS with the cause
/// "hop counter violation" (Q.714 2.8.6) when it asked to be returned.
fn hop_counter_violation(inbound: &Msu, ingress_assoc: &str, xudt: ExtendedUnitData) -> Vec<Msu> {
    metrics::record_loop(LoopKind::HopCounter);
    eprintln!(
        "siphon-sigtran: loop dropped (hop-counter): OPC {} DPC {} received on `{ingress_assoc}`, exhausted at the translation to a local subsystem",
        inbound.opc, inbound.dpc
    );
    let cause = ReturnCause::HopCounterViolation;
    crate::transport::sccp_return(inbound, &SccpMessage::Xudt(xudt), cause, None)
        .into_iter()
        .collect()
}

/// Count and log an MSU that was routed to a subsystem of this node and is not
/// a unitdata message the engine reads: a segment of a segmented XUDT (there is
/// no reassembly), an LUDT, a service message.
fn not_unitdata(inbound: &Msu, ingress_assoc: &str, what: impl std::fmt::Display) {
    metrics::rx_discard(RxDiscard::NotUnitdata);
    eprintln!(
        "siphon-sigtran: dropped a message received on `{ingress_assoc}` ({}): OPC {} DPC {} SI {}, {what}",
        RxDiscard::NotUnitdata.label(),
        inbound.opc,
        inbound.dpc,
        inbound.si
    );
}

/// The name of an SCCP message type, for a log line.
fn sccp_type(message: &SccpMessage) -> &'static str {
    match message {
        SccpMessage::Udt(_) => "UDT",
        SccpMessage::Udts(_) => "UDTS",
        SccpMessage::Xudt(_) => "XUDT",
        SccpMessage::Xudts(_) => "XUDTS",
        SccpMessage::Ludt(_) => "LUDT",
        SccpMessage::Ludts(_) => "LUDTS",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn local_op(op: &OperationCode) -> i64 {
    match op {
        OperationCode::Local(v) => *v,
        OperationCode::Global(_) => -1,
    }
}

/// The global-title digits of an SCCP address, if it carries a GT.
fn gt_digits(addr: &SccpAddress) -> Option<String> {
    addr.global_title.digits().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccp::SubsystemNumber;

    fn dialogue() -> Dialogue {
        let party = SccpAddress::with_ssn(SubsystemNumber::Hlr, None);
        Dialogue::new(
            Role::Initiator,
            vec![0x80, 0, 0, 1],
            Vec::new(),
            Vec::new(),
            0,
            Addressing {
                out_called: party.clone(),
                out_calling: party,
                opc: 1000,
                dpc: 2000,
                ni: 0,
                sls: 0,
                form: UnitdataForm::Udt,
            },
            &Tcap::default(),
        )
    }

    /// An inbound MSU from point code 4000 to 1000 carrying `sccp`.
    fn inbound(sccp: Vec<u8>) -> Msu {
        Msu {
            opc: 4000,
            dpc: 1000,
            si: SI_SCCP,
            ni: 0,
            mp: 0,
            sls: 3,
            payload: sccp,
        }
    }

    fn hlr() -> SccpAddress {
        SccpAddress::with_ssn(SubsystemNumber::Hlr, Some(1000))
    }

    fn msc() -> SccpAddress {
        SccpAddress::with_ssn(SubsystemNumber::Msc, Some(4000))
    }

    /// The P-Abort an admission refusal sends, decoded: its SCCP form, the dtid
    /// and the cause.
    fn refusal(frame: &Msu) -> (&'static str, Vec<u8>, Option<PAbortCause>) {
        assert_eq!((frame.opc, frame.dpc, frame.sls), (1000, 4000, 3));
        let (form, data) = match SccpMessage::decode(&frame.payload).unwrap() {
            SccpMessage::Udt(m) => ("udt", m.data),
            SccpMessage::Xudt(m) => {
                assert!(m.optional_part.is_empty(), "an answer is never segmented");
                ("xudt", m.data)
            }
            other => panic!("not unitdata: {other:?}"),
        };
        let TcapMessage::Abort(abort) = tcap::decode(&data).unwrap() else {
            panic!("not an Abort");
        };
        (form, abort.dtid.to_vec(), abort.p_abort_cause())
    }

    const OTID: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    #[test]
    fn a_refused_udt_begin_is_aborted_in_a_udt() {
        let msu = inbound(
            UnitData::new(hlr(), msc(), vec![0x62, 0x00])
                .encode()
                .unwrap(),
        );
        let frame = refuse_begin(&msu, &OTID).expect("an Abort");
        assert_eq!(
            refusal(&frame),
            ("udt", OTID.to_vec(), Some(PAbortCause::RESOURCE_LIMITATION))
        );
    }

    #[test]
    fn a_refused_whole_xudt_begin_is_aborted_in_an_xudt() {
        let msu = inbound(
            ExtendedUnitData::new(hlr(), msc(), vec![0x62, 0x00])
                .encode()
                .unwrap(),
        );
        let frame = refuse_begin(&msu, &OTID).expect("an Abort, as for a UDT");
        assert_eq!(
            refusal(&frame),
            (
                "xudt",
                OTID.to_vec(),
                Some(PAbortCause::RESOURCE_LIMITATION)
            )
        );
    }

    #[test]
    fn a_refused_segment_of_an_xudt_is_not_answered() {
        let mut xudt = ExtendedUnitData::new(hlr(), msc(), vec![0x62, 0x00]);
        // Segmentation (Q.713 3.17): first segment, one remaining.
        xudt.optional_part = vec![0x10, 0x04, 0x81, 0x00, 0x00, 0x01, 0x00];
        let msu = inbound(xudt.encode().unwrap());
        assert!(refuse_begin(&msu, &OTID).is_none());
    }

    /// Make every staged invoke an operation in progress, as a flush does.
    fn flush_staged(d: &mut Dialogue) {
        d.pending.clear();
        let staged = std::mem::take(&mut d.staged);
        d.outstanding.extend(staged);
    }

    #[test]
    fn invoke_ids_start_at_one_and_wrap_from_127_to_0() {
        let mut d = dialogue();
        let mut ids = Vec::new();
        for _ in 0..130 {
            ids.push(d.invoke(1, None).expect("an id"));
            // Complete each operation at once: its id is released.
            flush_staged(&mut d);
            d.outstanding.clear();
        }
        assert_eq!(ids[0], 1);
        assert_eq!(ids[126], 127);
        assert_eq!(ids[127], 0, "after 127 the ring wraps to 0, not to -128");
        assert_eq!(ids[128], 1);
        assert_eq!(ids[129], 2);
    }

    #[test]
    fn a_released_invoke_id_is_not_reused_at_once() {
        let mut d = dialogue();
        let first = d.invoke(1, None).unwrap();
        flush_staged(&mut d);
        d.outstanding.clear();
        assert_ne!(d.invoke(1, None).unwrap(), first);
    }

    #[test]
    fn an_invoke_id_still_in_progress_is_skipped_at_the_wrap() {
        let mut d = dialogue();
        // Ids 1 and 2 stay in progress; everything after completes at once.
        assert_eq!(d.invoke(1, None).unwrap(), 1);
        assert_eq!(d.invoke(1, None).unwrap(), 2);
        flush_staged(&mut d);
        for _ in 3..=127 {
            d.invoke(1, None).unwrap();
            flush_staged(&mut d);
            d.outstanding.retain(|o| o.id <= 2);
        }
        assert_eq!(d.invoke(1, None).unwrap(), 0);
        flush_staged(&mut d);
        d.outstanding.retain(|o| o.id == 1 || o.id == 2);
        assert_eq!(
            d.invoke(1, None).unwrap(),
            3,
            "1 and 2 are still in progress and are not handed out again"
        );
    }

    #[test]
    fn negative_invoke_ids_are_used_only_when_0_to_127_are_all_in_progress() {
        let mut d = dialogue();
        for _ in 0..128 {
            assert!(d.invoke(1, None).unwrap() >= 0);
        }
        flush_staged(&mut d);
        assert_eq!(d.invoke(1, None).unwrap(), -1);
        assert_eq!(d.invoke(1, None).unwrap(), -2);
        for _ in 0..126 {
            d.invoke(1, None).unwrap();
        }
        assert_eq!(d.outstanding.len() + d.staged.len(), 256);
        assert_eq!(d.invoke(1, None), Err(DialogueError::NoInvokeId));
    }

    #[test]
    fn operation_classes_say_which_reply_is_valid() {
        assert!(OperationClass::One.reports_success() && OperationClass::One.reports_failure());
        assert!(!OperationClass::Two.reports_success() && OperationClass::Two.reports_failure());
        assert!(
            OperationClass::Three.reports_success() && !OperationClass::Three.reports_failure()
        );
        assert!(!OperationClass::Four.reports_success() && !OperationClass::Four.reports_failure());
        for n in 1..=4 {
            assert_eq!(OperationClass::from_number(n).map(|c| c.number()), Some(n));
        }
        assert_eq!(OperationClass::from_number(0), None);
        assert_eq!(OperationClass::from_number(5), None);
    }
}
