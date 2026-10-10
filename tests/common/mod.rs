//! Shared harness for the abnormal-procedure tests: BER assembly by hand, the
//! SCCP wrapping, reply decoding, and the Wireshark dissection gate.
#![allow(dead_code)]

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use sccp::{GlobalTitle, SccpAddress, SccpMessage, SubsystemNumber, UnitData};
use tcap::{Abort, AbortReason, TcapMessage};

use siphon_sigtran::config::Tcap;
use siphon_sigtran::dialogue::{
    CloseReason, Dialogue, DialogueClosed, DialogueEngine, IncomingOp, InvokeTimeout,
    OperationClass, OutgoingBegin, PeerTurn, TerminationHandler,
};
use siphon_sigtran::transport::framing::wrap_m3ua;
use siphon_sigtran::transport::Msu;

// ── Synthetic fixed parameters ───────────────────────────────────────────────

pub const OUR_PC: u32 = 1000;
pub const PEER_PC: u32 = 4000;
pub const OUR_GT: &str = "15550100";
pub const PEER_GT: &str = "15550170";
/// The subsystem the test handlers are registered on (HLR).
pub const HLR: u8 = 6;
/// MAP sendIMSI (TS 29.002): the argument is an ISDN-AddressString and the
/// result an IMSI, both plain OCTET STRINGs, so Wireshark's MAP dissector reads
/// the whole component without a larger argument to assemble.
pub const OP: i64 = 58;
/// `04 05 91 51 55 10 00`: OCTET STRING, international E.164 15550100.
pub const ARG: [u8; 7] = [0x04, 0x05, 0x91, 0x51, 0x55, 0x10, 0x00];
/// `04 08 ..`: OCTET STRING, IMSI 001010000000042 in TBCD.
pub const RES: [u8; 10] = [0x04, 0x08, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x40, 0xF2];
/// A MAP application context (interVlrInfoRetrieval v2), content octets of the
/// OBJECT IDENTIFIER 0.4.0.0.1.0.15.2.
pub const AC: [u8; 7] = [0x04, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x02];
/// The same application context as arcs.
pub const AC_ARCS: [u32; 8] = [0, 4, 0, 0, 1, 0, 15, 2];

// ── BER by hand (Q.773 clause 3 / 4.1) ───────────────────────────────────────

/// One element: the identifier octet, the length in the short or long definite
/// form, and the content.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 128 => out.push(n as u8),
        n if n < 256 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// A context-class element whose tag number is 31 or more: the high tag number
/// form (X.690 8.1.2.4), `9F nn` primitive or `BF nn` constructed, for numbers
/// up to 127.
pub fn tlv_high(constructed: bool, number: u8, content: &[u8]) -> Vec<u8> {
    assert!((31..128).contains(&number));
    let mut out = vec![if constructed { 0xBF } else { 0x9F }, number];
    assert!(content.len() < 128);
    out.push(content.len() as u8);
    out.extend_from_slice(content);
    out
}

/// `Invoke ::= [1] SEQUENCE { invokeID INTEGER, operationCode INTEGER,
/// parameter ANY OPTIONAL }` with a local operation code.
pub fn invoke(invoke_id: i8, op: i64, parameter: Option<&[u8]>) -> Vec<u8> {
    let mut body = tlv(0x02, &[invoke_id as u8]);
    body.extend(tlv(0x02, &[op as u8]));
    if let Some(p) = parameter {
        body.extend_from_slice(p);
    }
    tlv(0xA1, &body)
}

/// An Invoke with `linkedID [0] IMPLICIT INTEGER`.
pub fn linked_invoke(invoke_id: i8, linked_id: i8, op: i64) -> Vec<u8> {
    let mut body = tlv(0x02, &[invoke_id as u8]);
    body.extend(tlv(0x80, &[linked_id as u8]));
    body.extend(tlv(0x02, &[op as u8]));
    tlv(0xA1, &body)
}

/// `ReturnResult ::= [2] SEQUENCE { invokeID, result SEQUENCE { operationCode,
/// parameter } OPTIONAL }`.
pub fn return_result_last(invoke_id: i8, result: Option<(i64, &[u8])>) -> Vec<u8> {
    let mut body = tlv(0x02, &[invoke_id as u8]);
    if let Some((op, parameter)) = result {
        let mut seq = tlv(0x02, &[op as u8]);
        seq.extend_from_slice(parameter);
        body.extend(tlv(0x30, &seq));
    }
    tlv(0xA2, &body)
}

/// `ReturnError ::= [3] SEQUENCE { invokeID, errorCode INTEGER }`.
pub fn return_error(invoke_id: i8, error: i64) -> Vec<u8> {
    let mut body = tlv(0x02, &[invoke_id as u8]);
    body.extend(tlv(0x02, &[error as u8]));
    tlv(0xA3, &body)
}

/// `Reject ::= [4] SEQUENCE { invokeID CHOICE { INTEGER, NULL }, problem [n]
/// IMPLICIT INTEGER }`; `class` is the problem tag number 0 to 3.
pub fn reject(invoke_id: Option<i8>, class: u8, code: u8) -> Vec<u8> {
    let mut body = match invoke_id {
        Some(id) => tlv(0x02, &[id as u8]),
        None => vec![0x05, 0x00],
    };
    body.extend(tlv(0x80 | class, &[code]));
    tlv(0xA4, &body)
}

/// The dialogue portion content (an `EXTERNAL`) holding an AARQ for the
/// application context whose OID content octets are `ac`:
/// `28 { 06 dialogue-as-id, [0] { 60 { [1] { 06 ac } } } }`. The protocol
/// version is left to its DEFAULT.
pub fn aarq(ac: &[u8]) -> Vec<u8> {
    let apdu = tlv(0x60, &tlv(0xA1, &tlv(0x06, ac)));
    dialogue_external(&apdu)
}

/// An accepting AARE: `61 { [1] { 06 ac }, [2] { INTEGER 0 }, [3] { [1] {
/// INTEGER 0 } } }` (result accepted, dialogue-service-user null).
pub fn aare(ac: &[u8]) -> Vec<u8> {
    let mut body = tlv(0xA1, &tlv(0x06, ac));
    body.extend(tlv(0xA2, &[0x02, 0x01, 0x00]));
    body.extend(tlv(0xA3, &tlv(0xA1, &[0x02, 0x01, 0x00])));
    dialogue_external(&tlv(0x61, &body))
}

/// An ABRT: `64 { [0] IMPLICIT INTEGER source }`.
pub fn abrt(source: u8) -> Vec<u8> {
    dialogue_external(&tlv(0x64, &[0x80, 0x01, source]))
}

/// `EXTERNAL { direct-reference dialogue-as-id (0.0.17.773.1.1.1),
/// single-ASN1-type [0] apdu }`.
pub fn dialogue_external(apdu: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x06, &[0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01]);
    body.extend(tlv(0xA0, apdu));
    tlv(0x28, &body)
}

fn portions(dialogue: Option<&[u8]>, components: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(external) = dialogue {
        out.extend(tlv(0x6B, external));
    }
    if !components.is_empty() {
        out.extend(tlv(0x6C, &components.concat()));
    }
    out
}

/// `Begin ::= [APPLICATION 2] { otid [APPLICATION 8], dialoguePortion
/// [APPLICATION 11] OPTIONAL, components [APPLICATION 12] OPTIONAL }`.
pub fn begin(otid: &[u8], dialogue: Option<&[u8]>, components: &[Vec<u8>]) -> Vec<u8> {
    let mut body = tlv(0x48, otid);
    body.extend(portions(dialogue, components));
    tlv(0x62, &body)
}

/// `Continue ::= [APPLICATION 5] { otid, dtid [APPLICATION 9], .. }`.
pub fn cont(otid: &[u8], dtid: &[u8], components: &[Vec<u8>]) -> Vec<u8> {
    cont_with(otid, dtid, None, components)
}

/// A Continue with a dialogue portion.
pub fn cont_with(
    otid: &[u8],
    dtid: &[u8],
    dialogue: Option<&[u8]>,
    components: &[Vec<u8>],
) -> Vec<u8> {
    let mut body = tlv(0x48, otid);
    body.extend(tlv(0x49, dtid));
    body.extend(portions(dialogue, components));
    tlv(0x65, &body)
}

/// `End ::= [APPLICATION 4] { dtid, .. }`.
pub fn end(dtid: &[u8], components: &[Vec<u8>]) -> Vec<u8> {
    let mut body = tlv(0x49, dtid);
    body.extend(portions(None, components));
    tlv(0x64, &body)
}

/// `Abort ::= [APPLICATION 7] { dtid, reason }` with a P-Abort cause
/// (`[APPLICATION 10] IMPLICIT INTEGER`).
pub fn p_abort(dtid: &[u8], cause: u8) -> Vec<u8> {
    let mut body = tlv(0x49, dtid);
    body.extend(tlv(0x4A, &[cause]));
    tlv(0x67, &body)
}

/// An Abort with user abort information (a dialogue portion), or none.
pub fn u_abort(dtid: &[u8], information: Option<&[u8]>) -> Vec<u8> {
    let mut body = tlv(0x49, dtid);
    if let Some(external) = information {
        body.extend(tlv(0x6B, external));
    }
    tlv(0x67, &body)
}

// ── SCCP / MTP3 wrapping ─────────────────────────────────────────────────────

fn gt(digits: &str) -> GlobalTitle {
    GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    }
}

/// TCAP octets from the peer (GT 15550170, SSN MSC, PC 4000) to us (GT
/// 15550100, SSN HLR, PC 1000) as an inbound MSU.
pub fn inbound(tcap_bytes: &[u8]) -> Msu {
    inbound_to(SubsystemNumber::Hlr, tcap_bytes)
}

/// The same, addressed to another of our subsystems.
pub fn inbound_to(called_ssn: SubsystemNumber, tcap_bytes: &[u8]) -> Msu {
    let called = SccpAddress::with_gt(gt(OUR_GT), Some(called_ssn));
    let calling = SccpAddress::with_gt(gt(PEER_GT), Some(SubsystemNumber::Msc));
    Msu {
        opc: PEER_PC,
        dpc: OUR_PC,
        si: 3,
        ni: 0,
        mp: 0,
        sls: 0,
        payload: UnitData::new(called, calling, tcap_bytes.to_vec())
            .encode()
            .expect("encode sccp udt"),
    }
}

/// The same between two subsystems given by number, for the protocols whose
/// dissector Wireshark picks by subsystem (the peer's becomes the called
/// subsystem of our replies).
pub fn inbound_between(called_ssn: u8, calling_ssn: u8, tcap_bytes: &[u8]) -> Msu {
    let called = SccpAddress::with_gt(gt(OUR_GT), Some(SubsystemNumber::from_u8(called_ssn)));
    let calling = SccpAddress::with_gt(gt(PEER_GT), Some(SubsystemNumber::from_u8(calling_ssn)));
    Msu {
        opc: PEER_PC,
        dpc: OUR_PC,
        si: 3,
        ni: 0,
        mp: 0,
        sls: 0,
        payload: UnitData::new(called, calling, tcap_bytes.to_vec())
            .encode()
            .expect("encode sccp udt"),
    }
}

fn udt_of(m: &Msu) -> UnitData {
    match SccpMessage::decode(&m.payload).expect("decode sccp") {
        SccpMessage::Udt(u) => u,
        _ => panic!("reply is not a UDT"),
    }
}

/// The TCAP octets an outbound MSU carries.
pub fn tcap_bytes(m: &Msu) -> Vec<u8> {
    udt_of(m).data
}

/// Decode an outbound MSU with the strict decoder.
pub fn decode(m: &Msu) -> TcapMessage {
    tcap::decode(&tcap_bytes(m)).expect("the engine emits a valid TCAP message")
}

/// The Abort an outbound MSU carries.
pub fn abort_of(m: &Msu) -> Abort {
    match decode(m) {
        TcapMessage::Abort(a) => a,
        other => panic!("expected an Abort, got {other}"),
    }
}

/// The abort-source of the ABRT APDU an Abort carries as user abort
/// information, if it carries one.
pub fn abrt_source(abort: &Abort) -> Option<i64> {
    match &abort.reason {
        Some(AbortReason::UAbort(portion)) => match portion.dialogue_pdu() {
            Ok(Some(tcap::DialoguePdu::Abrt { abort_source, .. })) => Some(abort_source.value()),
            _ => None,
        },
        _ => None,
    }
}

/// The reply goes back where the request came from: point codes and SCCP
/// party addresses swapped.
pub fn assert_reversed(m: &Msu) {
    assert_eq!((m.opc, m.dpc), (OUR_PC, PEER_PC), "point codes reversed");
    let udt = udt_of(m);
    assert_eq!(udt.called_party.global_title.digits(), Some(PEER_GT));
    assert_eq!(udt.calling_party.global_title.digits(), Some(OUR_GT));
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// An engine with `handler` registered for [`OP`] on the HLR subsystem.
pub fn engine(handler: Arc<dyn TerminationHandler>) -> DialogueEngine {
    engine_with(Tcap::default(), handler)
}

/// The same with explicit TCAP settings.
pub fn engine_with(config: Tcap, handler: Arc<dyn TerminationHandler>) -> DialogueEngine {
    let mut e = DialogueEngine::new(config);
    e.register(HLR, OP, handler);
    e
}

type BeginFn = Box<dyn Fn(&mut Dialogue, &IncomingOp) + Send + Sync>;
type TurnFn = Box<dyn Fn(&mut Dialogue, &PeerTurn) + Send + Sync>;
type TimeoutFn = Box<dyn Fn(&mut Dialogue, &InvokeTimeout) + Send + Sync>;
type StartFn = Box<dyn Fn(&mut Dialogue) + Send + Sync>;

/// A handler that records everything the engine tells it and acts as scripted.
/// With no script it answers nothing.
#[derive(Default)]
pub struct Probe {
    begins: Mutex<Vec<IncomingOp>>,
    turns: Mutex<Vec<PeerTurn>>,
    timeouts: Mutex<Vec<InvokeTimeout>>,
    closed: Mutex<Vec<DialogueClosed>>,
    begin: Option<BeginFn>,
    turn: Option<TurnFn>,
    timeout: Option<TimeoutFn>,
    start: Option<StartFn>,
}

impl Probe {
    pub fn new() -> Self {
        Self::default()
    }

    /// What to do on the opening operation.
    pub fn on_begin(
        mut self,
        f: impl Fn(&mut Dialogue, &IncomingOp) + Send + Sync + 'static,
    ) -> Self {
        self.begin = Some(Box::new(f));
        self
    }

    /// What to do on a follow-up turn.
    pub fn on_turn(mut self, f: impl Fn(&mut Dialogue, &PeerTurn) + Send + Sync + 'static) -> Self {
        self.turn = Some(Box::new(f));
        self
    }

    /// What to do when an invocation timer expires (instead of the default).
    pub fn on_timeout(
        mut self,
        f: impl Fn(&mut Dialogue, &InvokeTimeout) + Send + Sync + 'static,
    ) -> Self {
        self.timeout = Some(Box::new(f));
        self
    }

    /// What to stage when the engine opens a dialogue for us.
    pub fn on_start(mut self, f: impl Fn(&mut Dialogue) + Send + Sync + 'static) -> Self {
        self.start = Some(Box::new(f));
        self
    }

    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    pub fn begins(&self) -> Vec<IncomingOp> {
        self.begins.lock().unwrap().clone()
    }
    pub fn turns(&self) -> Vec<PeerTurn> {
        self.turns.lock().unwrap().clone()
    }
    pub fn timeouts(&self) -> Vec<InvokeTimeout> {
        self.timeouts.lock().unwrap().clone()
    }
    pub fn closed(&self) -> Vec<DialogueClosed> {
        self.closed.lock().unwrap().clone()
    }
    /// The reasons of every `on_closed` call, in order.
    pub fn reasons(&self) -> Vec<CloseReason> {
        self.closed().into_iter().map(|c| c.reason).collect()
    }
}

impl TerminationHandler for Probe {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        self.begins.lock().unwrap().push(op.clone());
        if let Some(f) = &self.begin {
            f(dlg, op);
        }
    }
    fn on_start(&self, dlg: &mut Dialogue) {
        if let Some(f) = &self.start {
            f(dlg);
        }
    }
    fn on_continue(&self, dlg: &mut Dialogue, peer: &PeerTurn) {
        self.turns.lock().unwrap().push(peer.clone());
        if let Some(f) = &self.turn {
            f(dlg, peer);
        }
    }
    fn on_invoke_timeout(&self, dlg: &mut Dialogue, timeout: &InvokeTimeout) {
        self.timeouts.lock().unwrap().push(*timeout);
        match &self.timeout {
            Some(f) => f(dlg, timeout),
            // The trait's default: abort on a class 1 expiry.
            None if timeout.class == OperationClass::One => {
                let _ = dlg.abort();
            }
            None => {}
        }
    }
    fn on_closed(&self, closed: &DialogueClosed) {
        self.closed.lock().unwrap().push(closed.clone());
    }
}

/// Answer the opening operation with [`RES`] in an End.
pub fn reply_and_end(dlg: &mut Dialogue, op: &IncomingOp) {
    dlg.reply(op.operation_code, Some(RES.to_vec()));
    dlg.end().expect("end");
}

/// Answer the opening operation with [`RES`] in a Continue: the dialogue stays
/// open with no operation of ours in progress.
pub fn reply_and_hold(dlg: &mut Dialogue, op: &IncomingOp) {
    dlg.reply(op.operation_code, Some(RES.to_vec()));
    dlg.send().expect("send");
}

/// Invoke [`OP`] back at the peer (class 1) in a Continue and keep the dialogue
/// open.
pub fn invoke_and_hold(dlg: &mut Dialogue, _op: &IncomingOp) {
    dlg.invoke(OP, Some(ARG.to_vec())).expect("invoke");
    dlg.send().expect("send");
}

/// Open a dialogue on `engine` with a Begin from the peer and return our
/// transaction id, read off the Continue the handler answered with.
pub fn open(engine: &DialogueEngine, peer_otid: &[u8]) -> Vec<u8> {
    let out = engine.deliver(
        &inbound(&begin(
            peer_otid,
            Some(&aarq(&AC)),
            &[invoke(1, OP, Some(&ARG))],
        )),
        "ingress",
    );
    assert_eq!(out.len(), 1, "the Begin is answered");
    match decode(&out[0]) {
        TcapMessage::Continue(c) => c.otid.to_vec(),
        other => panic!("expected a Continue, got {other}"),
    }
}

/// The components of an outbound Continue or End.
pub fn components_of(m: &Msu) -> Vec<tcap::Component> {
    decode(m).components().to_vec()
}

/// The Reject components of an outbound message.
pub fn rejects_of(m: &Msu) -> Vec<tcap::Reject> {
    components_of(m)
        .into_iter()
        .filter_map(|c| match c {
            tcap::Component::Reject(r) => Some(r),
            _ => None,
        })
        .collect()
}

/// The addressing of a dialogue this node opens toward the peer's HLR.
pub fn outgoing() -> OutgoingBegin {
    let party = |digits: &str, ssn| SccpAddress::with_gt(gt(digits), Some(ssn));
    OutgoingBegin {
        application_context: AC_ARCS.to_vec(),
        called: party(PEER_GT, SubsystemNumber::Hlr),
        calling: party(OUR_GT, SubsystemNumber::Msc),
        opc: OUR_PC,
        dpc: PEER_PC,
        ni: 0,
        sls: 0,
        ingress_assoc: String::new(),
    }
}

// ── The Wireshark dissection gate ────────────────────────────────────────────

fn tool(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether `tshark` is installed. When it is not, the dissection half of a
/// test is skipped with a message; `SIGTRAN_REQUIRE_TSHARK` turns that into a
/// failure so a CI job that is meant to dissect cannot pass by skipping.
pub fn tshark_available() -> bool {
    if tool("tshark") {
        return true;
    }
    let message = "tshark not found: the independent Wireshark dissection is skipped, \
                   only the codec-level assertions run";
    assert!(
        std::env::var_os("SIGTRAN_REQUIRE_TSHARK").is_none(),
        "SIGTRAN_REQUIRE_TSHARK is set but {message}"
    );
    eprintln!("SKIP: {message}");
    false
}

/// One field of a PDML dissection.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub show: String,
    pub showname: String,
    pub value: String,
}

/// What Wireshark read from one or more frames.
pub struct Dissection {
    pub fields: Vec<Field>,
    pub pdml: String,
}

impl Dissection {
    /// Every occurrence of `name`. A few fields were renamed between Wireshark
    /// 4.2 and 4.6; when the newer name is not in the dissection, the name the
    /// older release gives the same field is looked up instead.
    fn all(&self, name: &str) -> Vec<&Field> {
        let named = |wanted: &str| -> Vec<&Field> {
            self.fields.iter().filter(|f| f.name == wanted).collect()
        };
        let found = named(name);
        if !found.is_empty() {
            return found;
        }
        match Self::name_before_4_6(name) {
            Some(older) => named(older),
            None => found,
        }
    }

    fn name_before_4_6(name: &str) -> Option<&'static str> {
        match name {
            "tcap.aarq_application_context_name" | "tcap.aare_application_context_name" => {
                Some("tcap.application_context_name")
            }
            "camel.invokeProblem" => Some("camel.invoke"),
            "inap.invokeProblem" => Some("inap.invoke"),
            _ => None,
        }
    }

    /// The field is present at least once.
    #[track_caller]
    pub fn present(&self, name: &str) -> &Self {
        assert!(
            !self.all(name).is_empty(),
            "Wireshark did not read {name}; it read: {}",
            self.summary()
        );
        self
    }

    /// The field is not present.
    #[track_caller]
    pub fn absent(&self, name: &str) -> &Self {
        assert!(
            self.all(name).is_empty(),
            "Wireshark read {name}, which should be absent: {}",
            self.summary()
        );
        self
    }

    /// The raw octets of the first occurrence, as lower-case hex.
    #[track_caller]
    pub fn hex(&self, name: &str, expected: &str) -> &Self {
        let got: Vec<&str> = self.all(name).iter().map(|f| f.value.as_str()).collect();
        assert_eq!(
            got.first().copied(),
            Some(expected),
            "{name}: {}",
            self.summary()
        );
        self
    }

    /// The displayed value of the first occurrence.
    #[track_caller]
    pub fn show(&self, name: &str, expected: &str) -> &Self {
        let got: Vec<&str> = self.all(name).iter().map(|f| f.show.as_str()).collect();
        assert_eq!(
            got.first().copied(),
            Some(expected),
            "{name}: {}",
            self.summary()
        );
        self
    }

    /// The displayed values of every occurrence, in order.
    #[track_caller]
    pub fn show_all(&self, name: &str, expected: &[&str]) -> &Self {
        let got: Vec<&str> = self.all(name).iter().map(|f| f.show.as_str()).collect();
        assert_eq!(got, expected, "{name}: {}", self.summary());
        self
    }

    /// The label Wireshark prints for the first occurrence contains `text`.
    #[track_caller]
    pub fn label(&self, name: &str, text: &str) -> &Self {
        let label = self
            .all(name)
            .first()
            .map(|f| f.showname.clone())
            .unwrap_or_default();
        assert!(label.contains(text), "{name} is labelled `{label}`");
        self
    }

    /// The fields of the application layers, for failure messages.
    pub fn summary(&self) -> String {
        self.fields
            .iter()
            .filter(|f| {
                ["tcap.", "gsm_old.", "gsm_map.", "camel.", "inap."]
                    .iter()
                    .any(|p| f.name.starts_with(p))
            })
            .map(|f| format!("{}={}", f.name, f.show))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Nothing Wireshark flags as an error: no malformed frame, no BER error,
    /// no expert information of severity warning or error, no undissected
    /// octets.
    #[track_caller]
    pub fn clean(&self) -> &Self {
        let bad: Vec<String> = self
            .fields
            .iter()
            .filter(|f| {
                let name = f.name.to_ascii_lowercase();
                let text = f.showname.to_ascii_lowercase();
                name == "_ws.malformed"
                    || name == "_ws.unreassembled"
                    || name.ends_with(".error")
                    || name == "ber.unknown"
                    || text.contains("malformed")
                    || text.contains("ber error")
                    || text.contains("dissector bug")
                    || text.contains("beyond the end")
                    || (name == "_ws.expert.severity"
                        && (f.show.contains("Warn") || f.show.contains("Error")))
            })
            .map(|f| format!("{}: {}", f.name, f.showname))
            .collect();
        assert!(
            bad.is_empty(),
            "Wireshark flagged the frame:\n{}\n{}",
            bad.join("\n"),
            self.summary()
        );
        self
    }
}

fn attribute(line: &str, key: &str) -> Option<String> {
    let needle = format!(" {key}=\"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find('"')? + start;
    Some(
        line[start..end]
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

fn parse_pdml(pdml: &str) -> Vec<Field> {
    pdml.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            if !(line.starts_with("<field ") || line.starts_with("<proto ")) {
                return None;
            }
            Some(Field {
                name: attribute(line, "name")?,
                show: attribute(line, "show").unwrap_or_default(),
                showname: attribute(line, "showname").unwrap_or_default(),
                value: attribute(line, "value").unwrap_or_default(),
            })
        })
        .collect()
}

/// One SCTP packet (common header and a single DATA chunk, payload protocol
/// identifier 3 = M3UA) in IPv4 in Ethernet.
fn ethernet_frame(m3ua: &[u8], tsn: u32) -> Vec<u8> {
    let mut chunk = vec![0x00, 0x03];
    chunk.extend_from_slice(&((16 + m3ua.len()) as u16).to_be_bytes());
    chunk.extend_from_slice(&tsn.to_be_bytes());
    chunk.extend_from_slice(&1u16.to_be_bytes());
    chunk.extend_from_slice(&0u16.to_be_bytes());
    chunk.extend_from_slice(&3u32.to_be_bytes());
    chunk.extend_from_slice(m3ua);
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    let mut sctp = Vec::new();
    sctp.extend_from_slice(&2905u16.to_be_bytes());
    sctp.extend_from_slice(&2905u16.to_be_bytes());
    sctp.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    sctp.extend_from_slice(&0u32.to_be_bytes());
    sctp.extend_from_slice(&chunk);

    let mut frame = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&((20 + sctp.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 132, 0, 0]);
    frame.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
    frame.extend_from_slice(&sctp);
    frame
}

fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&262_144u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, frame) in frames.iter().enumerate() {
        out.extend_from_slice(&(i as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Dissect MSUs (framed as M3UA DATA over SCTP, as the transport sends them)
/// with `tshark`, without judging the result. `None` when `tshark` is missing.
pub fn dissect_unchecked(msus: &[&Msu]) -> Option<Dissection> {
    if !tshark_available() {
        return None;
    }
    let frames: Vec<Vec<u8>> = msus
        .iter()
        .enumerate()
        .map(|(i, m)| ethernet_frame(&wrap_m3ua(m, None), i as u32 + 1))
        .collect();
    let directory = std::env::temp_dir().join(format!(
        "sigtran-tshark-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("temporary directory");
    let capture = directory.join("frames.pcap");
    std::fs::write(&capture, pcap(&frames)).expect("write pcap");

    // An empty configuration directory keeps the run independent of whatever
    // protocol preferences the local Wireshark profile carries.
    let dissected = Command::new("tshark")
        .env("WIRESHARK_CONFIG_DIR", &directory)
        .env("XDG_CONFIG_HOME", &directory)
        .arg("-r")
        .arg(&capture)
        .args(["-T", "pdml"])
        .output()
        .expect("run tshark");
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        dissected.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&dissected.stderr)
    );
    let pdml = String::from_utf8_lossy(&dissected.stdout).into_owned();
    Some(Dissection {
        fields: parse_pdml(&pdml),
        pdml,
    })
}

/// Dissect one MSU and require a clean dissection that reaches TCAP.
#[track_caller]
pub fn dissect(msu: &Msu) -> Option<Dissection> {
    dissect_all(&[msu])
}

/// Dissect several MSUs as one capture and require a clean dissection.
#[track_caller]
pub fn dissect_all(msus: &[&Msu]) -> Option<Dissection> {
    let dissection = dissect_unchecked(msus)?;
    dissection.clean();
    dissection.present("tcap");
    Some(dissection)
}
