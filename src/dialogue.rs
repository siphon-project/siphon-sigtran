//! Dialogue termination SAP, **phase-2 stub**.
//!
//! When the [router](crate::routing) decides a message terminates locally
//! ([`RouteDecision::Local`](crate::routing::RouteDecision::Local)), it is
//! handed to a **dialogue SAP** built on `tcap::dialogue`: an incoming TCAP
//! `Begin` opens a dialogue, the decoded MAP/CAP operation is dispatched to a
//! handler, and the handler replies / continues / ends.
//!
//! This is where the SMSC (`onMoForwardSm`) and SCP (`onInitialDp`) example
//! flows from the spec live. Phase-1 ships the trait shape only; the TCAP
//! transaction coordinator (matching OTID/DTID, invoke-id bookkeeping, timers)
//! is the phase-2 build.

/// A local dialogue handed up from the transport when a message terminates
/// here. **Phase-2 stub**, the concrete type wraps a `tcap` transaction.
pub trait IncomingDialogue: Send {
    /// The originating transaction id (OTID) of the dialogue.
    fn otid(&self) -> &[u8];

    /// The local operation code of the invoke that opened the dialogue.
    fn operation_code(&self) -> i64;

    // TODO(phase-2): reply(result_bytes), continue_(invoke), end(), abort(reason)
    // built on tcap::{Begin, Continue, End, Abort} with TID threading + the
    // AARQ/AARE dialogue portion (tcap::dialogue).
}

/// The service-access point a termination host implements: incoming dialogues
/// are dispatched to it. **Phase-2 stub.**
pub trait DialogueSap: Send + Sync {
    /// Handle a freshly-opened incoming dialogue (the `Begin` leg). The impl
    /// inspects the operation, does its work, and replies / continues / ends.
    ///
    /// Phase-1 defines the seam only.
    fn on_dialogue(&self, dialogue: Box<dyn IncomingDialogue>);

    // TODO(phase-2): the SMSC/SCP handler registry keyed by op code + AC,
    // the multi-segment MT-ForwardSM held-open dialogue, invoke timers, and the
    // Python-facing @gmap.on_* / @cap.on_* decorators (phase-3).
}
