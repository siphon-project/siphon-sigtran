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
//! # Timers
//!
//! Each open dialogue carries the config [`Tcap`] timers. [`DialogueEngine::sweep`]
//! ages out a dialogue whose outstanding invoke passed `invoke_timer_ms`
//! (`sigtran_invoke_timeouts_total`) or that sat idle past `dialogue_timer_ms`
//! (`sigtran_dialogue_timeouts_total`), returning a TCAP Abort to send. A Begin
//! over the `max_dialogues` ceiling is refused with an Abort.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rasn::types::{Any, Oid};
use sccp::{SccpAddress, SccpMessage, UnitData};
use tcap::dialogue::{AbortSource as TcapAbortSource, DialoguePdu, DialoguePortion};
use tcap::{
    Abort, Begin, Component, Continue as TcapContinue, End, ErrorCode, Invoke, OperationCode,
    ReturnError, ReturnResult, ReturnResultValue, TcapMessage,
};

use crate::config::Tcap;
use crate::metrics::{self, AbortSource};
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

/// The decoded opening operation handed to [`TerminationHandler::on_begin`].
#[derive(Debug, Clone)]
pub struct IncomingOp {
    /// The local operation code (MAP TS 29.002 / CAP TS 29.078).
    pub operation_code: i64,
    /// The invoke id the peer used (echoed on the reply).
    pub invoke_id: i64,
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
}

/// One TCAP component the peer sent on a follow-up leg, decoded for
/// [`TerminationHandler::on_continue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerComponent {
    /// An `Invoke` (the peer asked us to do something in an open dialogue).
    Invoke {
        /// The invoke id.
        invoke_id: i64,
        /// The operation code.
        operation_code: i64,
        /// The raw BER argument, if present.
        argument: Option<Vec<u8>>,
    },
    /// A `ReturnResultLast` (the peer answered one of our invokes).
    Result {
        /// The invoke id being answered.
        invoke_id: i64,
        /// The operation code echoed in the result, if present.
        operation_code: Option<i64>,
        /// The raw BER result parameter, if present.
        parameter: Option<Vec<u8>>,
    },
    /// A `ReturnError` (the peer rejected one of our invokes).
    Error {
        /// The invoke id being answered.
        invoke_id: i64,
        /// The MAP/CAP error code.
        error_code: i64,
    },
}

/// One follow-up turn from the peer on an open dialogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTurn {
    /// Whether this turn arrived in a TCAP `End` (the peer closed the dialogue).
    pub is_end: bool,
    /// The decoded components.
    pub components: Vec<PeerComponent>,
}

/// A termination host: registered per (SSN, operation), it drives a dialogue.
///
/// The phase-4 Python layer implements this over the `gsm_map` / `gsm_cap`
/// decorators; phase-3 exercises it with small in-Rust handlers.
pub trait TerminationHandler: Send + Sync {
    /// A `Begin` opened a responder dialogue with this first operation. Drive the
    /// answer: `reply` + `end` for a single response, or `invoke` + `send` to
    /// hold it open for a follow-up leg. A responder must override this; the
    /// default answers nothing (which the engine turns into a P-Abort so the peer
    /// is never left hanging). An originating-only handler leaves it defaulted.
    fn on_begin(&self, _dialogue: &mut Dialogue, _op: &IncomingOp) {}

    /// Called by [`DialogueEngine::begin`] on the initiator side to stage the
    /// opening `Invoke`(s) before the `Begin` goes out. Unused by responders.
    fn on_start(&self, _dialogue: &mut Dialogue) {}

    /// The peer continued an open dialogue (a `Continue` or `End`) with these
    /// components. Drive the next leg (`reply`/`invoke`/`send`/`end`) or let it
    /// close. The default lets the dialogue close.
    fn on_continue(&self, _dialogue: &mut Dialogue, _peer: &PeerTurn) {}
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
}

impl Addressing {
    /// Reverse an inbound UDT + routing label into the addressing for the reply.
    fn reverse(udt: &UnitData, inbound: &Msu) -> Self {
        Self {
            out_called: udt.calling_party.clone(),
            out_calling: udt.called_party.clone(),
            opc: inbound.dpc,
            dpc: inbound.opc,
            ni: inbound.ni,
            sls: inbound.sls,
        }
    }
}

/// A live dialogue handle. Handlers stage components (`invoke`, `reply`,
/// `error`) and flush them as a TCAP leg (`send` = Continue, `end` = End).
pub struct Dialogue {
    role: Role,
    our_tid: Tid,
    peer_tid: Tid,
    ac: Vec<u32>,
    /// The invoke id to reply to by default (the opening operation's).
    reply_invoke_id: i64,
    next_invoke_id: i64,
    first_flush_done: bool,
    aare_pending: bool,
    closed: bool,
    /// The op code of the last invoke we staged that expects a result, if any.
    awaiting_op: Option<i64>,
    addressing: Addressing,
    pending: Vec<Component>,
    out: Vec<TcapMessage>,
}

impl Dialogue {
    fn responder(
        our_tid: Tid,
        peer_tid: Tid,
        ac: Vec<u32>,
        reply_invoke_id: i64,
        a: Addressing,
    ) -> Self {
        Self {
            role: Role::Responder,
            our_tid,
            peer_tid,
            ac,
            reply_invoke_id,
            next_invoke_id: 1,
            first_flush_done: false,
            aare_pending: true,
            closed: false,
            awaiting_op: None,
            addressing: a,
            pending: Vec::new(),
            out: Vec::new(),
        }
    }

    fn initiator(our_tid: Tid, ac: Vec<u32>, a: Addressing) -> Self {
        Self {
            role: Role::Initiator,
            our_tid,
            peer_tid: Vec::new(),
            ac,
            reply_invoke_id: 0,
            next_invoke_id: 1,
            first_flush_done: false,
            aare_pending: false,
            closed: false,
            awaiting_op: None,
            addressing: a,
            pending: Vec::new(),
            out: Vec::new(),
        }
    }

    /// Rebuild a handle for a follow-up leg from a stored [`Record`].
    fn from_record(rec: &Record) -> Self {
        Self {
            role: rec.role,
            our_tid: rec.our_tid.clone(),
            peer_tid: rec.peer_tid.clone(),
            ac: rec.ac.clone(),
            reply_invoke_id: rec.reply_invoke_id,
            next_invoke_id: rec.next_invoke_id,
            first_flush_done: true,
            aare_pending: false,
            closed: false,
            awaiting_op: None,
            addressing: rec.addressing.clone(),
            pending: Vec::new(),
            out: Vec::new(),
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

    /// Whether the dialogue has been closed (an `End` or `abort` flushed).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Stage an `Invoke` of `operation_code` carrying `argument`; returns the
    /// allocated invoke id. The dialogue must still be flushed with `send`/`end`.
    pub fn invoke(&mut self, operation_code: i64, argument: Option<Vec<u8>>) -> i64 {
        let id = self.next_invoke_id;
        self.next_invoke_id += 1;
        self.pending.push(Component::Invoke(Invoke {
            invoke_id: id,
            linked_id: None,
            operation_code: OperationCode::Local(operation_code),
            parameter: argument.map(Any::new),
        }));
        self.awaiting_op = Some(operation_code);
        id
    }

    /// Stage a `ReturnResultLast` answering the opening invoke.
    pub fn reply(&mut self, operation_code: i64, result: Option<Vec<u8>>) {
        let invoke_id = self.reply_invoke_id;
        self.reply_to(invoke_id, operation_code, result);
    }

    /// Stage a `ReturnResultLast` answering a specific invoke id.
    pub fn reply_to(&mut self, invoke_id: i64, operation_code: i64, result: Option<Vec<u8>>) {
        self.pending.push(Component::ReturnResultLast(ReturnResult {
            invoke_id,
            result: Some(ReturnResultValue {
                operation_code: OperationCode::Local(operation_code),
                parameter: result.map(Any::new),
            }),
        }));
    }

    /// Stage a `ReturnError` answering a specific invoke id.
    pub fn error(&mut self, invoke_id: i64, error_code: i64) {
        self.pending.push(Component::ReturnError(ReturnError {
            invoke_id,
            error_code: ErrorCode::Local(error_code),
            parameter: None,
        }));
    }

    /// Flush the staged components as a `Continue` (or, on the initiator's first
    /// flush, the opening `Begin`). The dialogue stays open.
    pub fn send(&mut self) {
        self.flush(false);
    }

    /// Flush the staged components as an `End`, closing the dialogue.
    pub fn end(&mut self) {
        self.flush(true);
    }

    /// Abort the dialogue with the given source, flushing a TCAP `Abort`.
    pub fn abort(&mut self, source: TcapAbortSource) {
        self.pending.clear();
        let dp = DialoguePortion::abrt(source);
        self.out.push(TcapMessage::Abort(Abort {
            dtid: self.peer_tid.clone().into(),
            reason: Some(dp.external),
        }));
        self.closed = true;
    }

    fn flush(&mut self, closing: bool) {
        let comps = std::mem::take(&mut self.pending);
        let comps = if comps.is_empty() { None } else { Some(comps) };
        let opening = self.role == Role::Initiator && !self.first_flush_done;

        // Dialogue portion: AARQ opens an initiator Begin; AARE rides the
        // responder's first outbound leg (End or Continue). Nothing otherwise.
        let dp = if opening {
            Oid::new(&self.ac).map(DialoguePortion::aarq)
        } else if self.aare_pending {
            self.aare_pending = false;
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

        self.first_flush_done = true;
        if closing {
            self.closed = true;
        }
        self.out.push(msg);
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
    role: Role,
    our_tid: Tid,
    peer_tid: Tid,
    ac: Vec<u32>,
    addressing: Addressing,
    reply_invoke_id: i64,
    next_invoke_id: i64,
    ingress_assoc: String,
    last_activity: Instant,
    /// When the outstanding invoke expires (if we are awaiting a result).
    invoke_deadline: Option<Instant>,
    /// The op code of the outstanding invoke (for the timeout metric label).
    pending_op: i64,
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
    inner: Mutex<Inner>,
}

impl DialogueEngine {
    /// A fresh engine with the given TCAP settings and no handlers.
    pub fn new(config: Tcap) -> Self {
        Self {
            config,
            handlers: HashMap::new(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Register a handler for one (SSN, operation) pair. Later registrations for
    /// the same key win.
    pub fn register(&mut self, ssn: u8, operation_code: i64, handler: Arc<dyn TerminationHandler>) {
        self.handlers.insert((ssn, operation_code), handler);
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

    fn alloc_tid(&self, inner: &mut Inner) -> Tid {
        inner.tid_counter = inner.tid_counter.wrapping_add(1);
        // A non-zero, 4-octet id. The high bit marks it as ours so it never
        // collides with a small peer OTID we might store under the same map.
        (inner.tid_counter | 0x8000_0000).to_be_bytes().to_vec()
    }

    /// Terminate one inbound MSU (an SCCP UDT carrying TCAP). Returns the MSUs to
    /// send back to the peer, if any.
    pub fn deliver(&self, inbound: &Msu, ingress_assoc: &str) -> Vec<Msu> {
        if inbound.si != SI_SCCP {
            return Vec::new();
        }
        let udt = match SccpMessage::decode(&inbound.payload) {
            Ok(SccpMessage::Udt(u)) => u,
            _ => return Vec::new(),
        };
        let tcap = match tcap::decode(&udt.data) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        match tcap {
            TcapMessage::Begin(b) => self.on_begin(b, &udt, inbound, ingress_assoc),
            TcapMessage::Continue(c) => {
                let components = c.components.unwrap_or_default();
                self.on_turn(c.dtid.to_vec(), Some(c.otid.to_vec()), components, false)
            }
            TcapMessage::End(e) => {
                let components = e.components.unwrap_or_default();
                self.on_turn(e.dtid.to_vec(), None, components, true)
            }
            TcapMessage::Abort(a) => {
                self.close(&a.dtid.to_vec());
                metrics::abort(AbortSource::Provider);
                Vec::new()
            }
            TcapMessage::Unidirectional(_) => Vec::new(),
        }
    }

    fn on_begin(&self, b: Begin, udt: &UnitData, inbound: &Msu, ingress_assoc: &str) -> Vec<Msu> {
        let peer_tid = b.otid.to_vec();
        let ac = b
            .dialogue_portion
            .as_ref()
            .and_then(DialoguePortion::dialogue_pdu)
            .and_then(|pdu| match pdu {
                DialoguePdu::Aarq {
                    application_context_name,
                    ..
                } => Some(application_context_name.as_ref().to_vec()),
                _ => None,
            });

        let addressing = Addressing::reverse(udt, inbound);
        let called_ssn = udt.called_party.ssn.map(|s| s.value()).unwrap_or(0);

        let first = b
            .components
            .as_ref()
            .and_then(|cs| cs.iter().find_map(as_invoke));
        let Some((invoke_id, op, arg)) = first else {
            // A Begin with no Invoke is malformed for a MAP/CAP dialogue: abort.
            metrics::abort(AbortSource::Local);
            return abort_now(
                &addressing,
                &peer_tid,
                TcapAbortSource::DialogueServiceProvider,
            );
        };

        let Some(handler) = self.handlers.get(&(called_ssn, op)).cloned() else {
            // No termination host for this subsystem/operation: refuse cleanly.
            metrics::abort(AbortSource::Local);
            return abort_now(
                &addressing,
                &peer_tid,
                TcapAbortSource::DialogueServiceProvider,
            );
        };

        // Ceiling.
        {
            let inner = self.lock();
            if inner.dialogues.len() >= self.config.max_dialogues {
                drop(inner);
                metrics::abort(AbortSource::Local);
                return abort_now(
                    &addressing,
                    &peer_tid,
                    TcapAbortSource::DialogueServiceProvider,
                );
            }
        }

        let our_tid = {
            let mut inner = self.lock();
            self.alloc_tid(&mut inner)
        };

        let mut dlg = Dialogue::responder(
            our_tid.clone(),
            peer_tid,
            ac.clone().unwrap_or_default(),
            invoke_id,
            addressing.clone(),
        );

        let incoming = IncomingOp {
            operation_code: op,
            invoke_id,
            argument: arg,
            application_context: ac,
            called_ssn,
            calling_gt: gt_digits(&udt.calling_party),
            called_gt: gt_digits(&udt.called_party),
        };
        handler.on_begin(&mut dlg, &incoming);

        self.finish_turn(dlg, handler, ingress_assoc)
    }

    fn on_turn(
        &self,
        our_tid: Tid,
        peer_otid: Option<Tid>,
        components: Vec<Component>,
        is_end: bool,
    ) -> Vec<Msu> {
        // Pop the record so the handler runs without the lock held.
        let mut rec = match self.lock().dialogues.remove(&our_tid) {
            Some(r) => r,
            None => return Vec::new(), // unknown / already-closed dialogue
        };
        metrics::dialogue_closed();

        // Learn the peer's transaction id from a Continue (an initiator's first
        // response carries it).
        if let Some(otid) = peer_otid {
            if rec.peer_tid.is_empty() {
                rec.peer_tid = otid;
            }
        }

        let peer = PeerTurn {
            is_end,
            components: components.iter().map(peer_component).collect(),
        };
        // A result for our outstanding invoke arrived in time: clear the timer.
        if peer.components.iter().any(is_result_or_error) {
            rec.invoke_deadline = None;
        }

        let mut dlg = Dialogue::from_record(&rec);
        // A peer End closes the transaction; the handler may still act, but we do
        // not reopen it.
        rec.handler.on_continue(&mut dlg, &peer);

        if is_end {
            // The peer ended: nothing more to store, no further response.
            return self.frames(&dlg, &rec.addressing);
        }
        self.finish_turn(dlg, rec.handler.clone(), &rec.ingress_assoc)
    }

    /// Start an **originating** dialogue: the handler stages the opening invoke
    /// in [`TerminationHandler::on_start`]. Returns our transaction id and the
    /// MSUs to send (the `Begin`).
    pub fn begin(
        &self,
        req: OutgoingBegin,
        handler: Arc<dyn TerminationHandler>,
    ) -> (Tid, Vec<Msu>) {
        let our_tid = {
            let mut inner = self.lock();
            self.alloc_tid(&mut inner)
        };
        let addressing = Addressing {
            out_called: req.called,
            out_calling: req.calling,
            opc: req.opc,
            dpc: req.dpc,
            ni: req.ni,
            sls: req.sls,
        };
        let mut dlg =
            Dialogue::initiator(our_tid.clone(), req.application_context, addressing.clone());
        handler.on_start(&mut dlg);
        let frames = self.frames(&dlg, &addressing);
        self.store_if_open(dlg, handler, &req.ingress_assoc);
        (our_tid, frames)
    }

    /// Common tail after a responder turn: emit the frames, then store the
    /// dialogue if it is still open (else it closed with the flushed End).
    fn finish_turn(
        &self,
        dlg: Dialogue,
        handler: Arc<dyn TerminationHandler>,
        ingress_assoc: &str,
    ) -> Vec<Msu> {
        let addressing = dlg.addressing.clone();
        // A handler that produced no output on an open dialogue would leave the
        // peer hanging; that is a bug, so refuse the dialogue rather than drop it.
        if dlg.out.is_empty() && !dlg.closed {
            metrics::abort(AbortSource::Local);
            return abort_now(
                &addressing,
                &dlg.peer_tid,
                TcapAbortSource::DialogueServiceProvider,
            );
        }
        let frames = self.frames(&dlg, &addressing);
        self.store_if_open(dlg, handler, ingress_assoc);
        frames
    }

    fn store_if_open(
        &self,
        dlg: Dialogue,
        handler: Arc<dyn TerminationHandler>,
        ingress_assoc: &str,
    ) {
        if dlg.closed {
            return;
        }
        let now = Instant::now();
        let invoke_deadline = dlg
            .awaiting_op
            .map(|_| now + Duration::from_millis(self.config.invoke_timer_ms));
        let rec = Record {
            handler,
            role: dlg.role,
            our_tid: dlg.our_tid.clone(),
            peer_tid: dlg.peer_tid.clone(),
            ac: dlg.ac.clone(),
            addressing: dlg.addressing.clone(),
            reply_invoke_id: dlg.reply_invoke_id,
            next_invoke_id: dlg.next_invoke_id,
            ingress_assoc: ingress_assoc.to_string(),
            last_activity: now,
            invoke_deadline,
            pending_op: dlg.awaiting_op.unwrap_or(0),
        };
        self.lock().dialogues.insert(dlg.our_tid, rec);
        metrics::dialogue_opened();
    }

    fn close(&self, our_tid: &Tid) {
        if self.lock().dialogues.remove(our_tid).is_some() {
            metrics::dialogue_closed();
        }
    }

    /// Age out expired dialogues. A dialogue whose outstanding invoke passed the
    /// invoke timer counts an invoke timeout; one idle past the dialogue timer
    /// counts a dialogue timeout. Both are aborted. Returns `(ingress, abort MSU)`
    /// pairs to send. Call it periodically (the transport does) or with an
    /// explicit `now` in a test.
    pub fn sweep(&self, now: Instant) -> Vec<(String, Msu)> {
        let dialogue_timer = Duration::from_millis(self.config.dialogue_timer_ms);
        let mut aborts = Vec::new();
        let mut inner = self.lock();
        let expired: Vec<Tid> = inner
            .dialogues
            .iter()
            .filter_map(|(tid, rec)| {
                let invoke_expired = rec.invoke_deadline.is_some_and(|d| now >= d);
                let idle_expired = now.duration_since(rec.last_activity) >= dialogue_timer;
                (invoke_expired || idle_expired).then(|| tid.clone())
            })
            .collect();

        for tid in expired {
            if let Some(rec) = inner.dialogues.remove(&tid) {
                if rec.invoke_deadline.is_some_and(|d| now >= d) {
                    metrics::invoke_timeout(rec.pending_op);
                } else {
                    metrics::dialogue_timeout();
                }
                metrics::dialogue_closed();
                metrics::abort(AbortSource::Local);
                let msu = abort_now(
                    &rec.addressing,
                    &rec.peer_tid,
                    TcapAbortSource::DialogueServiceProvider,
                );
                aborts.extend(msu.into_iter().map(|m| (rec.ingress_assoc.clone(), m)));
            }
        }
        aborts
    }

    /// Build the outbound MSUs from a dialogue's queued TCAP messages.
    fn frames(&self, dlg: &Dialogue, addressing: &Addressing) -> Vec<Msu> {
        dlg.out
            .iter()
            .filter_map(|msg| wrap_msu(msg, addressing))
            .collect()
    }
}

/// Wrap one TCAP message in an SCCP UDT + MTP3 routing label, ready for the
/// transport to frame onto M3UA / M2PA.
fn wrap_msu(msg: &TcapMessage, a: &Addressing) -> Option<Msu> {
    let tcap_bytes = tcap::encode(msg).ok()?;
    let udt = UnitData::new(a.out_called.clone(), a.out_calling.clone(), tcap_bytes);
    let sccp = udt.encode().ok()?;
    Some(Msu {
        opc: a.opc,
        dpc: a.dpc,
        si: SI_SCCP,
        ni: a.ni,
        mp: 0,
        sls: a.sls,
        payload: sccp,
    })
}

/// Build a standalone TCAP Abort MSU toward the peer.
fn abort_now(a: &Addressing, peer_tid: &[u8], source: TcapAbortSource) -> Vec<Msu> {
    let dp = DialoguePortion::abrt(source);
    let msg = TcapMessage::Abort(Abort {
        dtid: peer_tid.to_vec().into(),
        reason: Some(dp.external),
    });
    wrap_msu(&msg, a).into_iter().collect()
}

/// Extract `(invoke_id, op, arg)` if a component is an `Invoke` with a local op.
fn as_invoke(c: &Component) -> Option<(i64, i64, Option<Vec<u8>>)> {
    match c {
        Component::Invoke(inv) => match &inv.operation_code {
            OperationCode::Local(op) => Some((
                inv.invoke_id,
                *op,
                inv.parameter.as_ref().map(|p| p.as_bytes().to_vec()),
            )),
            OperationCode::Global(_) => None,
        },
        _ => None,
    }
}

/// Decode one TCAP component into the peer-turn view.
fn peer_component(c: &Component) -> PeerComponent {
    match c {
        Component::Invoke(inv) => PeerComponent::Invoke {
            invoke_id: inv.invoke_id,
            operation_code: local_op(&inv.operation_code),
            argument: inv.parameter.as_ref().map(|p| p.as_bytes().to_vec()),
        },
        Component::ReturnResultLast(rr) | Component::ReturnResultNotLast(rr) => {
            PeerComponent::Result {
                invoke_id: rr.invoke_id,
                operation_code: rr.result.as_ref().map(|r| local_op(&r.operation_code)),
                parameter: rr
                    .result
                    .as_ref()
                    .and_then(|r| r.parameter.as_ref())
                    .map(|p| p.as_bytes().to_vec()),
            }
        }
        Component::ReturnError(re) => PeerComponent::Error {
            invoke_id: re.invoke_id,
            error_code: match &re.error_code {
                ErrorCode::Local(v) => *v,
                ErrorCode::Global(_) => -1,
            },
        },
        Component::Reject(rj) => PeerComponent::Error {
            invoke_id: rj.invoke_id,
            error_code: -1,
        },
    }
}

fn is_result_or_error(c: &PeerComponent) -> bool {
    matches!(
        c,
        PeerComponent::Result { .. } | PeerComponent::Error { .. }
    )
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
