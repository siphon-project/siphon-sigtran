//! In-process dialogue-termination tests: assemble genuine TCAP (Begin + AARQ +
//! Invoke over an SCCP UDT, the ss7-stack way) and drive the [`DialogueEngine`]
//! end to end, asserting the emitted responses decode back to the right
//! operation, echo the transaction id, and carry an AARE.
//!
//! These run without SCTP (the engine is synchronous); the on-the-wire
//! termination path is proven separately in `tests/wire.rs`. Every value is
//! synthetic: test PLMN MCC 001 / MNC 01, `+1-555-01xx` global titles, decimal
//! point codes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rasn::types::{Any, Oid};

use gsm_cap::operations::{ConnectArg, ReleaseCallArg, RequestReportBcsmEventArg};
use gsm_cap::types::{BcsmEvent, EventTypeBcsm, MonitorMode};
use gsm_map::operations::auth::{
    AuthenticationQuintuplet, AuthenticationSetList, SendAuthenticationInfoArg,
    SendAuthenticationInfoRes,
};
use gsm_map::operations::location::UpdateLocationRes;
use gsm_map::operations::mo_forward_sm::MoForwardSmRes;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::sri_sm::RoutingInfoForSmRes;
use gsm_map::operations::subscriber_data::InsertSubscriberDataArg;
use gsm_map::types::{LocationInfoWithLmsi, SmRpDa, SmRpOa};

use sccp::{GlobalTitle, SccpAddress, SccpMessage, SubsystemNumber, UnitData};
use tcap::dialogue::{DialoguePdu, DialoguePortion};
use tcap::{
    Begin, Component, Continue as TcapContinue, End, Invoke, OperationCode, ReturnResult,
    ReturnResultValue, TcapMessage,
};

use siphon_sigtran::config::Tcap;
use siphon_sigtran::dialogue::{
    Dialogue, DialogueEngine, IncomingOp, OutgoingBegin, PeerComponent, PeerTurn,
    TerminationHandler,
};
use siphon_sigtran::metrics;
use siphon_sigtran::transport::Msu;

// ── Synthetic fixed parameters ───────────────────────────────────────────────

const OUR_PC: u32 = 1000;
const PEER_PC: u32 = 4000;
const OUR_GT: &str = "15550100";
const PEER_GT: &str = "15550170";
const IMSI: &str = "001010000000042";
const MSC_NUM: &str = "15550180";
const HLR_NUM: &str = "15550190";
const SI_SCCP: u8 = 3;
const PEER_TID: [u8; 4] = [0x22, 0x22, 0x22, 0x22];

// MAP/CAP application contexts.
const AC_SRI_SM: [u32; 8] = [0, 4, 0, 0, 1, 0, 20, 3]; // shortMsgGateway v3
const AC_NET_LOC_UP: [u32; 8] = [0, 4, 0, 0, 1, 0, 1, 3]; // networkLocUp v3
const AC_INFO_RETRIEVAL: [u32; 8] = [0, 4, 0, 0, 1, 0, 5, 3]; // infoRetrieval v3
const AC_MO_RELAY: [u32; 8] = [0, 4, 0, 0, 1, 0, 21, 3]; // shortMsgMO-Relay v3
const AC_MT_RELAY: [u32; 8] = [0, 4, 0, 0, 1, 0, 25, 3]; // shortMsgMT-Relay v3
const AC_CAP: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 4]; // gsmSSF-scfGeneric v3
const AC_INAP: [u32; 8] = [0, 4, 0, 1, 1, 0, 3, 0]; // cs1-ssp-to-scp (Core INAP CS-1)

// The IN SCP subsystem (route-on-SSN, dispatched to the INAP dissector in
// Wireshark by default).
const SCP_SSN: u8 = 106;

// ── TBCD helpers (same shape as ss7-stack) ───────────────────────────────────

fn tbcd(digits: &str) -> Vec<u8> {
    let ds: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
    let mut out = Vec::with_capacity(ds.len().div_ceil(2));
    for pair in ds.chunks(2) {
        let lo = pair[0];
        let hi = if pair.len() == 2 { pair[1] } else { 0x0F };
        out.push((hi << 4) | lo);
    }
    out
}

fn isdn(digits: &str) -> Vec<u8> {
    let mut v = vec![0x91];
    v.extend(tbcd(digits));
    v
}

// ── SCCP + TCAP assembly ─────────────────────────────────────────────────────

fn gt(digits: &str) -> GlobalTitle {
    GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    }
}

/// Wrap TCAP bytes in an SCCP UDT addressed to `called_ssn` at our GT.
fn udt(called_ssn: SubsystemNumber, tcap_bytes: &[u8]) -> Vec<u8> {
    let called = SccpAddress::with_gt(gt(OUR_GT), Some(called_ssn));
    let calling = SccpAddress::with_gt(gt(PEER_GT), Some(SubsystemNumber::Msc));
    UnitData::new(called, calling, tcap_bytes.to_vec())
        .encode()
        .expect("encode sccp udt")
}

fn aarq(ac: &[u32]) -> DialoguePortion {
    DialoguePortion::aarq(Oid::new(ac).expect("valid ac oid"))
}

fn invoke(op: i64, arg: Vec<u8>, id: i64) -> Component {
    Component::Invoke(Invoke {
        invoke_id: id,
        linked_id: None,
        operation_code: OperationCode::Local(op),
        parameter: Some(Any::new(arg)),
    })
}

fn return_result(op: i64, param: Vec<u8>, id: i64) -> Component {
    Component::ReturnResultLast(ReturnResult {
        invoke_id: id,
        result: Some(ReturnResultValue {
            operation_code: OperationCode::Local(op),
            parameter: Some(Any::new(param)),
        }),
    })
}

/// A Begin (AARQ + one Invoke) as an inbound MSU addressed to `called_ssn`.
fn begin_msu(op: i64, arg: Vec<u8>, ac: &[u32], called_ssn: SubsystemNumber, otid: &[u8]) -> Msu {
    let begin = Begin {
        otid: otid.to_vec().into(),
        dialogue_portion: Some(aarq(ac)),
        components: Some(vec![invoke(op, arg, 1)]),
    };
    let bytes = tcap::encode(&TcapMessage::Begin(begin)).expect("encode begin");
    msu(udt(called_ssn, &bytes))
}

/// A Continue carrying `components` as an inbound MSU for the dialogue whose
/// destination id is `dtid` (our OTID). Carries an AARE if `with_aare`.
fn continue_msu(dtid: &[u8], components: Vec<Component>, with_aare: bool, ac: &[u32]) -> Msu {
    let dp = with_aare.then(|| DialoguePortion::aare_accept(Oid::new(ac).unwrap()));
    let cont = TcapContinue {
        otid: PEER_TID.to_vec().into(),
        dtid: dtid.to_vec().into(),
        dialogue_portion: dp,
        components: Some(components),
    };
    let bytes = tcap::encode(&TcapMessage::Continue(cont)).expect("encode continue");
    msu(udt(SubsystemNumber::Hlr, &bytes))
}

/// An End carrying `components` as an inbound MSU closing the dialogue `dtid`.
fn end_msu(dtid: &[u8], components: Vec<Component>) -> Msu {
    let end = End {
        dtid: dtid.to_vec().into(),
        dialogue_portion: None,
        components: Some(components),
    };
    let bytes = tcap::encode(&TcapMessage::End(end)).expect("encode end");
    msu(udt(SubsystemNumber::Hlr, &bytes))
}

fn msu(payload: Vec<u8>) -> Msu {
    Msu {
        opc: PEER_PC,
        dpc: OUR_PC,
        si: SI_SCCP,
        ni: 0,
        mp: 0,
        sls: 0,
        payload,
    }
}

// ── Reply decoding ───────────────────────────────────────────────────────────

fn decode_reply(m: &Msu) -> TcapMessage {
    let udt = match SccpMessage::decode(&m.payload).expect("decode sccp") {
        SccpMessage::Udt(u) => u,
        _ => panic!("reply is not a UDT"),
    };
    tcap::decode(&udt.data).expect("decode tcap reply")
}

fn first_component(msg: &TcapMessage) -> Component {
    let comps = match msg {
        TcapMessage::End(e) => e.components.clone(),
        TcapMessage::Continue(c) => c.components.clone(),
        TcapMessage::Begin(b) => b.components.clone(),
        _ => None,
    };
    comps
        .and_then(|c| c.into_iter().next())
        .expect("a component")
}

fn invoke_of(msg: &TcapMessage) -> (i64, Vec<u8>) {
    match first_component(msg) {
        Component::Invoke(inv) => {
            let op = match inv.operation_code {
                OperationCode::Local(v) => v,
                _ => panic!("global op"),
            };
            (op, inv.parameter.expect("arg").as_bytes().to_vec())
        }
        other => panic!("expected Invoke, got {other:?}"),
    }
}

fn result_of(msg: &TcapMessage) -> (i64, Vec<u8>) {
    match first_component(msg) {
        Component::ReturnResultLast(rr) => {
            let val = rr.result.expect("result value");
            let op = match val.operation_code {
                OperationCode::Local(v) => v,
                _ => panic!("global op"),
            };
            (op, val.parameter.expect("param").as_bytes().to_vec())
        }
        other => panic!("expected ReturnResultLast, got {other:?}"),
    }
}

/// Every `Invoke` component the message carries as `(op, argument)`, in order.
fn invoke_all(msg: &TcapMessage) -> Vec<(i64, Vec<u8>)> {
    let comps = match msg {
        TcapMessage::End(e) => e.components.clone(),
        TcapMessage::Continue(c) => c.components.clone(),
        TcapMessage::Begin(b) => b.components.clone(),
        _ => None,
    };
    comps
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| match c {
            Component::Invoke(inv) => match inv.operation_code {
                OperationCode::Local(v) => Some((
                    v,
                    inv.parameter
                        .map(|p| p.as_bytes().to_vec())
                        .unwrap_or_default(),
                )),
                OperationCode::Global(_) => None,
            },
            _ => None,
        })
        .collect()
}

/// The operation codes of every `Invoke` component the message carries, in order.
fn invoke_ops(msg: &TcapMessage) -> Vec<i64> {
    invoke_all(msg).into_iter().map(|(op, _)| op).collect()
}

/// The AARE application-context arcs the reply carries (asserting an AARE is
/// present), or `None`.
fn aare_ac(msg: &TcapMessage) -> Option<Vec<u32>> {
    let dp = match msg {
        TcapMessage::End(e) => e.dialogue_portion.as_ref(),
        TcapMessage::Continue(c) => c.dialogue_portion.as_ref(),
        _ => None,
    }?;
    match dp.dialogue_pdu()? {
        DialoguePdu::Aare {
            application_context_name,
            ..
        } => Some(application_context_name.as_ref().to_vec()),
        _ => None,
    }
}

fn dtid_of(msg: &TcapMessage) -> Vec<u8> {
    match msg {
        TcapMessage::End(e) => e.dtid.to_vec(),
        TcapMessage::Continue(c) => c.dtid.to_vec(),
        _ => panic!("no dtid on {msg}"),
    }
}

fn otid_of(msg: &TcapMessage) -> Vec<u8> {
    match msg {
        TcapMessage::Begin(b) => b.otid.to_vec(),
        TcapMessage::Continue(c) => c.otid.to_vec(),
        _ => panic!("no otid on {msg}"),
    }
}

// ── MAP/CAP argument bytes ───────────────────────────────────────────────────

fn sri_sm_res() -> Vec<u8> {
    let res = RoutingInfoForSmRes {
        imsi: tbcd(IMSI).into(),
        location_info_with_lmsi: LocationInfoWithLmsi {
            network_node_number: isdn(MSC_NUM).into(),
            lmsi: None,
            gprs_node_indicator: None,
            additional_number: None,
        },
    };
    rasn::ber::encode(&res).expect("encode sri-sm res")
}

fn isd_arg() -> Vec<u8> {
    let arg = InsertSubscriberDataArg {
        imsi: Some(tbcd(IMSI).into()),
        msisdn: Some(isdn(PEER_GT).into()),
        category: None,
        subscriber_status: None,
        bearer_service_list: None,
        teleservice_list: None,
        odb_data: None,
        roaming_restricted_in_sgsn_due_to_unsupported_feature: None,
        network_access_mode: None,
    };
    rasn::ber::encode(&arg).expect("encode isd")
}

fn isd_res() -> Vec<u8> {
    use gsm_map::operations::subscriber_data::InsertSubscriberDataRes;
    let res = InsertSubscriberDataRes {
        teleservice_list: None,
        bearer_service_list: None,
        odb_general_data: None,
    };
    rasn::ber::encode(&res).expect("encode isd res")
}

fn update_location_res() -> Vec<u8> {
    let res = UpdateLocationRes {
        hlr_number: isdn(HLR_NUM).into(),
    };
    rasn::ber::encode(&res).expect("encode ul res")
}

fn mo_forward_sm_res() -> Vec<u8> {
    let res = MoForwardSmRes { sm_rp_ui: None };
    rasn::ber::encode(&res).expect("encode mo res")
}

fn mt_forward_sm_res() -> Vec<u8> {
    use gsm_map::operations::mt_forward_sm::MtForwardSmRes;
    let res = MtForwardSmRes { sm_rp_ui: None };
    rasn::ber::encode(&res).expect("encode mt res")
}

fn mt_forward_sm_arg(segment: u8, last: bool) -> Vec<u8> {
    let arg = MtForwardSmArg {
        sm_rp_da: SmRpDa::Imsi(tbcd(IMSI).into()),
        sm_rp_oa: SmRpOa::ServiceCentreAddressOa(isdn(OUR_GT).into()),
        sm_rp_ui: vec![0x04, 0x0B, segment].into(),
        more_messages_to_send: (!last).then_some(()),
    };
    rasn::ber::encode(&arg).expect("encode mt")
}

fn connect_arg() -> Vec<u8> {
    let arg = ConnectArg {
        destination_routing_address: vec![isdn("15550123").into()],
        original_called_party_id: None,
        calling_partys_category: None,
        redirecting_party_id: None,
        generic_numbers: None,
    };
    gsm_cap::encode(&arg).expect("encode connect")
}

fn send_auth_info_res() -> Vec<u8> {
    let res = SendAuthenticationInfoRes {
        authentication_set_list: Some(AuthenticationSetList::QuintupletList(vec![
            AuthenticationQuintuplet {
                rand: vec![0x11; 16].into(),
                xres: vec![0x22; 8].into(),
                ck: vec![0x33; 16].into(),
                ik: vec![0x44; 16].into(),
                autn: vec![0x55; 16].into(),
            },
        ])),
    };
    rasn::ber::encode(&res).expect("encode sai res")
}

fn rrbe_arg() -> Vec<u8> {
    let arg = RequestReportBcsmEventArg {
        bcsm_events: vec![
            BcsmEvent {
                event_type_bcsm: EventTypeBcsm::OAnswer,
                monitor_mode: MonitorMode::Interrupted,
                leg_id: None,
            },
            BcsmEvent {
                event_type_bcsm: EventTypeBcsm::ODisconnect,
                monitor_mode: MonitorMode::NotifyAndContinue,
                leg_id: None,
            },
        ],
    };
    gsm_cap::encode(&arg).expect("encode rrbe")
}

fn release_call_arg() -> Vec<u8> {
    let arg = ReleaseCallArg {
        cause: vec![0x90, 0x03].into(), // Q.850 normal, unspecified
    };
    gsm_cap::encode(&arg).expect("encode release")
}

// ── INAP CS-1 argument bytes (fixed-network IN, distinct from the CAMEL set) ──

fn inap_initial_dp_arg() -> Vec<u8> {
    let arg = inap::operations::InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(isdn("15550142").into()),
        calling_party_number: Some(isdn(PEER_GT).into()),
        calling_partys_category: None,
        ip_ssp_capabilities: None,
        ip_available: None,
        location_number: None,
        original_called_party_id: None,
        high_layer_compatibility: None,
        service_interaction_indicators: None,
        additional_calling_party_number: None,
        forward_call_indicators: None,
        event_type_bcsm: None,
        redirecting_party_id: None,
    };
    inap::encode(&arg).expect("encode inap idp")
}

fn inap_rrbe_arg() -> Vec<u8> {
    let arg = inap::operations::RequestReportBcsmEventArg {
        bcsm_events: vec![
            inap::types::BcsmEvent {
                event_type_bcsm: inap::types::EventTypeBcsm::OAnswer,
                monitor_mode: inap::types::MonitorMode::Interrupted,
                leg_id: None,
            },
            inap::types::BcsmEvent {
                event_type_bcsm: inap::types::EventTypeBcsm::ODisconnect,
                monitor_mode: inap::types::MonitorMode::NotifyAndContinue,
                leg_id: None,
            },
        ],
    };
    inap::encode(&arg).expect("encode inap rrbe")
}

fn inap_connect_arg() -> Vec<u8> {
    let arg = inap::operations::ConnectArg {
        destination_routing_address: vec![isdn("15550123").into()],
        correlation_id: None,
        original_called_party_id: None,
        scf_id: None,
    };
    inap::encode(&arg).expect("encode inap connect")
}

fn inap_release_call_arg() -> Vec<u8> {
    // INAP CS-1 releaseCall is a bare Q.850 Cause (not a SEQUENCE).
    let arg = inap::operations::ReleaseCallArg(vec![0x90, 0x03].into());
    inap::encode(&arg).expect("encode inap release")
}

fn inap_event_report_bcsm_arg() -> Vec<u8> {
    let arg = inap::operations::EventReportBcsmArg {
        event_type_bcsm: inap::types::EventTypeBcsm::OAnswer,
        leg_id: None,
        misc_call_info: None,
    };
    inap::encode(&arg).expect("encode inap erb")
}

// ── Test handlers (the phase-4 Python handlers, done in Rust here) ───────────

/// A fake HLR answering SRI-SM with an imsi + serving-MSC number, single shot.
struct FakeHlrSriSm;
impl TerminationHandler for FakeHlrSriSm {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        dlg.reply(op.operation_code, Some(sri_sm_res()));
        dlg.end();
    }
}

/// A fake HLR answering updateLocation with an insertSubscriberData leg held
/// open, then the updateLocation result on the peer's ISD ack.
struct FakeHlrUpdateLocation;
impl TerminationHandler for FakeHlrUpdateLocation {
    fn on_begin(&self, dlg: &mut Dialogue, _op: &IncomingOp) {
        dlg.invoke(
            gsm_map::operations::subscriber_data::op_codes::INSERT_SUBSCRIBER_DATA,
            Some(isd_arg()),
        );
        dlg.send(); // Continue: AARE + Invoke(ISD), dialogue held open
    }
    fn on_continue(&self, dlg: &mut Dialogue, peer: &PeerTurn) {
        // The VLR acked the ISD; close with the updateLocation result.
        if peer.components.iter().any(is_result) {
            dlg.reply(
                gsm_map::operations::location::op_codes::UPDATE_LOCATION,
                Some(update_location_res()),
            );
            dlg.end();
        }
    }
}

/// A fake SMSC terminating MO-ForwardSM: ack and close.
struct FakeSmscMoForward;
impl TerminationHandler for FakeSmscMoForward {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        dlg.reply(op.operation_code, Some(mo_forward_sm_res()));
        dlg.end();
    }
}

/// A fake SCP answering initialDP with a connect in the closing End.
struct FakeScp;
impl TerminationHandler for FakeScp {
    fn on_begin(&self, dlg: &mut Dialogue, _op: &IncomingOp) {
        dlg.invoke(gsm_cap::op_codes::CONNECT, Some(connect_arg()));
        dlg.end(); // connect Invoke in the closing dialogue
    }
}

/// A fake HLR answering sendAuthenticationInfo with a quintuplet vector, single
/// shot (the vectors ride the closing End).
struct FakeHlrSendAuthInfo;
impl TerminationHandler for FakeHlrSendAuthInfo {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        dlg.reply(op.operation_code, Some(send_auth_info_res()));
        dlg.end();
    }
}

/// A fuller SCP: arm two BCSM detection points (RequestReportBCSMEvent) and then
/// connect, both in the closing End.
struct FakeScpFull;
impl TerminationHandler for FakeScpFull {
    fn on_begin(&self, dlg: &mut Dialogue, _op: &IncomingOp) {
        dlg.invoke(
            gsm_cap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            Some(rrbe_arg()),
        );
        dlg.invoke(gsm_cap::op_codes::CONNECT, Some(connect_arg()));
        dlg.end();
    }
}

/// An SCP that releases the call instead of connecting (a barred number).
struct FakeScpRelease;
impl TerminationHandler for FakeScpRelease {
    fn on_begin(&self, dlg: &mut Dialogue, _op: &IncomingOp) {
        dlg.invoke(gsm_cap::op_codes::RELEASE_CALL, Some(release_call_arg()));
        dlg.end();
    }
}

/// A fake IN SCP terminating an INAP CS-1 initialDP: arm two BCSM detection
/// points (RequestReportBCSMEvent) and connect the call, both in the closing End.
struct FakeInapScp;
impl TerminationHandler for FakeInapScp {
    fn on_begin(&self, dlg: &mut Dialogue, _op: &IncomingOp) {
        dlg.invoke(
            inap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            Some(inap_rrbe_arg()),
        );
        dlg.invoke(inap::op_codes::CONNECT, Some(inap_connect_arg()));
        dlg.end();
    }
}

/// A fake IN SCP that arms detection points and holds the dialogue open (RRBE in
/// a Continue), then releases the call when the SSF reports the armed event
/// (eventReportBCSM).
struct FakeInapScpHeldOpen;
impl TerminationHandler for FakeInapScpHeldOpen {
    fn on_begin(&self, dlg: &mut Dialogue, _op: &IncomingOp) {
        dlg.invoke(
            inap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            Some(inap_rrbe_arg()),
        );
        dlg.send(); // Continue: AARE + RRBE, dialogue held open
    }
    fn on_continue(&self, dlg: &mut Dialogue, peer: &PeerTurn) {
        // The SSF reported an armed detection point; release the call and close.
        if peer
            .components
            .iter()
            .any(|c| matches!(c, PeerComponent::Invoke { .. }))
        {
            dlg.invoke(inap::op_codes::RELEASE_CALL, Some(inap_release_call_arg()));
            dlg.end();
        }
    }
}

/// A responder that holds the dialogue open with no outstanding invoke (a
/// ReturnResultLast in a Continue), used to exercise the dialogue timer.
struct KeepOpen;
impl TerminationHandler for KeepOpen {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        dlg.reply(op.operation_code, Some(mo_forward_sm_res()));
        dlg.send(); // Continue, no end: stays open, no outstanding invoke
    }
}

/// An originating SMSC delivering a (possibly concatenated) MT message: one
/// dialogue held open across segments, moreMessagesToSend on all but the last,
/// each segment acked, End on the last.
struct SmscMtOriginator {
    segments: usize,
    sent: Mutex<u8>,
}
impl SmscMtOriginator {
    fn emit(&self, dlg: &mut Dialogue) {
        let mut idx = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        if *idx as usize >= self.segments {
            return;
        }
        let last = *idx as usize == self.segments - 1;
        dlg.invoke(
            gsm_map::op_codes::MT_FORWARD_SM,
            Some(mt_forward_sm_arg(*idx, last)),
        );
        if last {
            dlg.end();
        } else {
            dlg.send();
        }
        *idx += 1;
    }
}
impl TerminationHandler for SmscMtOriginator {
    fn on_start(&self, dlg: &mut Dialogue) {
        self.emit(dlg);
    }
    fn on_continue(&self, dlg: &mut Dialogue, peer: &PeerTurn) {
        if peer.components.iter().any(is_result) {
            self.emit(dlg);
        }
    }
}

/// An originating SMSC doing SRI-SM: invoke, then capture the HLR's result.
struct SriSmOriginator {
    result: Mutex<Option<(Vec<u8>, Vec<u8>)>>,
}
impl TerminationHandler for SriSmOriginator {
    fn on_start(&self, dlg: &mut Dialogue) {
        // A minimal SRI-SM arg (msisdn + sc address); the fake HLR ignores it.
        let arg = gsm_map::operations::sri_sm::RoutingInfoForSmArg {
            msisdn: isdn(PEER_GT).into(),
            sm_rp_pri: true,
            service_centre_address: isdn(OUR_GT).into(),
            gprs_support_indicator: None,
            sm_rp_mti: None,
            sm_rp_smea: None,
        };
        dlg.invoke(
            gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM,
            Some(rasn::ber::encode(&arg).unwrap()),
        );
        dlg.send();
    }
    fn on_continue(&self, _dlg: &mut Dialogue, peer: &PeerTurn) {
        for c in &peer.components {
            if let PeerComponent::Result {
                parameter: Some(p), ..
            } = c
            {
                let res: RoutingInfoForSmRes = rasn::ber::decode(p).expect("decode sri-sm res");
                *self.result.lock().unwrap_or_else(|e| e.into_inner()) = Some((
                    res.imsi.to_vec(),
                    res.location_info_with_lmsi.network_node_number.to_vec(),
                ));
            }
        }
    }
}

fn is_result(c: &PeerComponent) -> bool {
    matches!(c, PeerComponent::Result { .. })
}

fn engine_with(ssn: u8, op: i64, handler: Arc<dyn TerminationHandler>) -> DialogueEngine {
    let mut e = DialogueEngine::new(Tcap::default());
    e.register(ssn, op, handler);
    e
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn sri_sm_request_gets_a_return_result_in_an_end() {
    let engine = engine_with(
        6,
        gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM,
        Arc::new(FakeHlrSriSm),
    );
    let otid = [0x11, 0x22, 0x33, 0x44];
    let arg = rasn::ber::encode(&gsm_map::operations::sri_sm::RoutingInfoForSmArg {
        msisdn: isdn(PEER_GT).into(),
        sm_rp_pri: true,
        service_centre_address: isdn(OUR_GT).into(),
        gprs_support_indicator: None,
        sm_rp_mti: None,
        sm_rp_smea: None,
    })
    .unwrap();

    let out = engine.deliver(
        &begin_msu(
            gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM,
            arg,
            &AC_SRI_SM,
            SubsystemNumber::Hlr,
            &otid,
        ),
        "ingress",
    );
    assert_eq!(out.len(), 1, "one reply frame");

    let reply = decode_reply(&out[0]);
    assert!(
        matches!(reply, TcapMessage::End(_)),
        "SRI-SM answered in a TCAP End"
    );
    assert_eq!(
        dtid_of(&reply),
        otid,
        "the End echoes the request OTID as its DTID"
    );
    assert_eq!(
        aare_ac(&reply).as_deref(),
        Some(&AC_SRI_SM[..]),
        "AARE present, same AC"
    );

    let (op, param) = result_of(&reply);
    assert_eq!(op, gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM);
    let res: RoutingInfoForSmRes = rasn::ber::decode(&param).expect("decode res");
    assert_eq!(res.imsi.to_vec(), tbcd(IMSI));
    assert_eq!(
        res.location_info_with_lmsi.network_node_number.to_vec(),
        isdn(MSC_NUM)
    );
    assert_eq!(engine.open_dialogues(), 0, "single-shot dialogue closed");
}

#[test]
fn update_location_holds_open_for_the_isd_leg_then_ends() {
    let engine = engine_with(
        6,
        gsm_map::op_codes::UPDATE_LOCATION,
        Arc::new(FakeHlrUpdateLocation),
    );
    let otid = [0xA1, 0xA2, 0xA3, 0xA4];
    let arg = rasn::ber::encode(&gsm_map::operations::location::UpdateLocationArg {
        imsi: tbcd(IMSI).into(),
        msc_number: isdn(MSC_NUM).into(),
        vlr_number: isdn(PEER_GT).into(),
        lmsi: None,
        vlr_capability: None,
    })
    .unwrap();

    // Begin(updateLocation) → Continue(AARE, Invoke ISD), dialogue held open.
    let out = engine.deliver(
        &begin_msu(
            gsm_map::op_codes::UPDATE_LOCATION,
            arg,
            &AC_NET_LOC_UP,
            SubsystemNumber::Hlr,
            &otid,
        ),
        "ingress",
    );
    assert_eq!(out.len(), 1);
    let leg1 = decode_reply(&out[0]);
    assert!(
        matches!(leg1, TcapMessage::Continue(_)),
        "ISD leg is a Continue"
    );
    assert_eq!(
        aare_ac(&leg1).as_deref(),
        Some(&AC_NET_LOC_UP[..]),
        "AARE on the first leg"
    );
    let (isd_op, _) = invoke_of(&leg1);
    assert_eq!(
        isd_op,
        gsm_map::operations::subscriber_data::op_codes::INSERT_SUBSCRIBER_DATA,
        "the held-open leg carries an insertSubscriberData invoke"
    );
    assert_eq!(
        engine.open_dialogues(),
        1,
        "dialogue is held open across the ISD leg"
    );
    let our_tid = otid_of(&leg1);

    // The VLR acks the ISD; the HLR closes with the updateLocation result.
    let ack = continue_msu(
        &our_tid,
        vec![return_result(
            gsm_map::operations::subscriber_data::op_codes::INSERT_SUBSCRIBER_DATA,
            isd_res(),
            1,
        )],
        false,
        &AC_NET_LOC_UP,
    );
    let out2 = engine.deliver(&ack, "ingress");
    assert_eq!(out2.len(), 1);
    let leg2 = decode_reply(&out2[0]);
    assert!(
        matches!(leg2, TcapMessage::End(_)),
        "the updateLocation result closes in an End"
    );
    // A responder's peer transaction id is fixed from the Begin, so the closing
    // End echoes the VLR's original OTID across both legs.
    assert_eq!(
        dtid_of(&leg2),
        otid,
        "the End echoes the VLR's original OTID"
    );
    let (ul_op, _) = result_of(&leg2);
    assert_eq!(ul_op, gsm_map::op_codes::UPDATE_LOCATION);
    assert_eq!(
        engine.open_dialogues(),
        0,
        "dialogue closed after the result"
    );
}

#[test]
fn mo_forward_sm_terminates_with_an_ack() {
    let engine = engine_with(
        8,
        gsm_map::op_codes::MO_FORWARD_SM,
        Arc::new(FakeSmscMoForward),
    );
    let otid = [0x01, 0x02, 0x03, 0x04];
    let arg = rasn::ber::encode(&gsm_map::operations::mo_forward_sm::MoForwardSmArg {
        sm_rp_da: SmRpDa::ServiceCentreAddressDa(isdn(OUR_GT).into()),
        sm_rp_oa: SmRpOa::MsIsdn(isdn(PEER_GT).into()),
        sm_rp_ui: vec![0x00, 0x01, 0x02].into(),
        imsi: None,
    })
    .unwrap();

    let out = engine.deliver(
        &begin_msu(
            gsm_map::op_codes::MO_FORWARD_SM,
            arg,
            &AC_MO_RELAY,
            SubsystemNumber::Msc,
            &otid,
        ),
        "ingress",
    );
    let reply = decode_reply(&out[0]);
    assert!(matches!(reply, TcapMessage::End(_)));
    assert_eq!(dtid_of(&reply), otid);
    assert_eq!(result_of(&reply).0, gsm_map::op_codes::MO_FORWARD_SM);
    assert_eq!(aare_ac(&reply).as_deref(), Some(&AC_MO_RELAY[..]));
}

#[test]
fn initial_dp_gets_connect_in_the_closing_end() {
    let engine = engine_with(146, gsm_cap::op_codes::INITIAL_DP, Arc::new(FakeScp));
    let otid = [0xDE, 0xAD, 0xBE, 0xEF];
    let arg = gsm_cap::encode(&gsm_cap::operations::InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(isdn("15550123").into()),
        calling_party_number: Some(isdn(PEER_GT).into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: None,
        redirecting_party_id: None,
        imsi: Some(tbcd(IMSI).into()),
        location_information: None,
        call_reference_number: None,
        msc_address: None,
        called_party_bcd_number: None,
        time_and_timezone: None,
    })
    .unwrap();

    let out = engine.deliver(
        &begin_msu(
            gsm_cap::op_codes::INITIAL_DP,
            arg,
            &AC_CAP,
            SubsystemNumber::Cap,
            &otid,
        ),
        "ingress",
    );
    let reply = decode_reply(&out[0]);
    assert!(
        matches!(reply, TcapMessage::End(_)),
        "connect rides the closing End"
    );
    assert_eq!(dtid_of(&reply), otid);
    assert_eq!(aare_ac(&reply).as_deref(), Some(&AC_CAP[..]));
    let (op, param) = invoke_of(&reply);
    assert_eq!(
        op,
        gsm_cap::op_codes::CONNECT,
        "the End carries a connect invoke"
    );
    let _: ConnectArg = gsm_cap::decode(&param).expect("connect decodes");
}

#[test]
fn send_auth_info_gets_auth_vectors_in_an_end() {
    let engine = engine_with(
        6,
        gsm_map::op_codes::SEND_AUTHENTICATION_INFO,
        Arc::new(FakeHlrSendAuthInfo),
    );
    let otid = [0x51, 0x52, 0x53, 0x54];
    let arg = rasn::ber::encode(&SendAuthenticationInfoArg {
        imsi: tbcd(IMSI).into(),
        number_of_requested_vectors: 5.into(),
        re_synchronisation_info: None,
        requesting_node_type: None,
    })
    .unwrap();

    let out = engine.deliver(
        &begin_msu(
            gsm_map::op_codes::SEND_AUTHENTICATION_INFO,
            arg,
            &AC_INFO_RETRIEVAL,
            SubsystemNumber::Hlr,
            &otid,
        ),
        "ingress",
    );
    assert_eq!(out.len(), 1);
    let reply = decode_reply(&out[0]);
    assert!(
        matches!(reply, TcapMessage::End(_)),
        "sendAuthenticationInfo answered in a TCAP End"
    );
    assert_eq!(dtid_of(&reply), otid, "the End echoes the request OTID");
    assert_eq!(aare_ac(&reply).as_deref(), Some(&AC_INFO_RETRIEVAL[..]));

    let (op, param) = result_of(&reply);
    assert_eq!(op, gsm_map::op_codes::SEND_AUTHENTICATION_INFO);
    let res: SendAuthenticationInfoRes = rasn::ber::decode(&param).expect("decode sai res");
    match res.authentication_set_list {
        Some(AuthenticationSetList::QuintupletList(q)) => {
            assert_eq!(q.len(), 1, "one quintuplet returned");
            assert_eq!(q[0].rand.len(), 16);
            assert_eq!(q[0].autn.len(), 16);
        }
        other => panic!("expected a quintuplet list, got {other:?}"),
    }
    assert_eq!(engine.open_dialogues(), 0, "single-shot dialogue closed");
}

#[test]
fn initial_dp_gets_rrbe_and_connect_in_the_closing_end() {
    let engine = engine_with(146, gsm_cap::op_codes::INITIAL_DP, Arc::new(FakeScpFull));
    let otid = [0xC0, 0xFF, 0xEE, 0x01];
    let arg = gsm_cap::encode(&gsm_cap::operations::InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(isdn("15550123").into()),
        calling_party_number: Some(isdn(PEER_GT).into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: None,
        redirecting_party_id: None,
        imsi: Some(tbcd(IMSI).into()),
        location_information: None,
        call_reference_number: None,
        msc_address: None,
        called_party_bcd_number: None,
        time_and_timezone: None,
    })
    .unwrap();

    let out = engine.deliver(
        &begin_msu(
            gsm_cap::op_codes::INITIAL_DP,
            arg,
            &AC_CAP,
            SubsystemNumber::Cap,
            &otid,
        ),
        "ingress",
    );
    let reply = decode_reply(&out[0]);
    assert!(matches!(reply, TcapMessage::End(_)));
    assert_eq!(dtid_of(&reply), otid, "the End echoes the request OTID");

    let ops = invoke_ops(&reply);
    assert_eq!(
        ops,
        vec![
            gsm_cap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            gsm_cap::op_codes::CONNECT
        ],
        "the End carries RequestReportBCSMEvent then Connect"
    );
    // Both components decode as their CAP operations.
    let rrbe = invoke_all(&reply)
        .into_iter()
        .find(|(op, _)| *op == gsm_cap::op_codes::REQUEST_REPORT_BCSM_EVENT)
        .expect("rrbe present")
        .1;
    let arg: RequestReportBcsmEventArg = gsm_cap::decode(&rrbe).expect("rrbe decodes");
    assert_eq!(arg.bcsm_events.len(), 2);
    assert_eq!(engine.open_dialogues(), 0);
}

#[test]
fn initial_dp_gets_release_call_for_a_barred_number() {
    let engine = engine_with(146, gsm_cap::op_codes::INITIAL_DP, Arc::new(FakeScpRelease));
    let otid = [0xBA, 0x88, 0xED, 0x00];
    let arg = gsm_cap::encode(&gsm_cap::operations::InitialDpArg {
        service_key: 7.into(),
        called_party_number: Some(isdn("15550666").into()),
        calling_party_number: Some(isdn(PEER_GT).into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: None,
        redirecting_party_id: None,
        imsi: Some(tbcd(IMSI).into()),
        location_information: None,
        call_reference_number: None,
        msc_address: None,
        called_party_bcd_number: None,
        time_and_timezone: None,
    })
    .unwrap();

    let out = engine.deliver(
        &begin_msu(
            gsm_cap::op_codes::INITIAL_DP,
            arg,
            &AC_CAP,
            SubsystemNumber::Cap,
            &otid,
        ),
        "ingress",
    );
    let reply = decode_reply(&out[0]);
    assert!(matches!(reply, TcapMessage::End(_)));
    assert_eq!(dtid_of(&reply), otid);
    let (op, param) = invoke_of(&reply);
    assert_eq!(
        op,
        gsm_cap::op_codes::RELEASE_CALL,
        "a barred call is released, not connected"
    );
    let _: ReleaseCallArg = gsm_cap::decode(&param).expect("releaseCall decodes");
    assert_eq!(engine.open_dialogues(), 0);
}

#[test]
fn inap_initial_dp_gets_rrbe_and_connect_at_the_scp() {
    // An IN SCP owns SSN 106; the SSF triggers an INAP CS-1 initialDP under the
    // cs1-ssp-to-scp application context. The SCP arms two BCSM detection points
    // and connects the call, both in the closing End; the AARE echoes the IN
    // application context (not a CAMEL one).
    let engine = engine_with(SCP_SSN, inap::op_codes::INITIAL_DP, Arc::new(FakeInapScp));
    let otid = [0x1A, 0x2B, 0x3C, 0x4D];

    let out = engine.deliver(
        &begin_msu(
            inap::op_codes::INITIAL_DP,
            inap_initial_dp_arg(),
            &AC_INAP,
            SubsystemNumber::from_u8(SCP_SSN),
            &otid,
        ),
        "ingress",
    );
    let reply = decode_reply(&out[0]);
    assert!(matches!(reply, TcapMessage::End(_)));
    assert_eq!(dtid_of(&reply), otid, "the End echoes the request OTID");
    assert_eq!(
        aare_ac(&reply).as_deref(),
        Some(&AC_INAP[..]),
        "the AARE carries the IN application context, not a CAMEL one"
    );

    let ops = invoke_ops(&reply);
    assert_eq!(
        ops,
        vec![
            inap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            inap::op_codes::CONNECT
        ],
        "the End carries RequestReportBCSMEvent then Connect"
    );
    // Both components decode as their INAP CS-1 operations.
    let rrbe = invoke_all(&reply)
        .into_iter()
        .find(|(op, _)| *op == inap::op_codes::REQUEST_REPORT_BCSM_EVENT)
        .expect("rrbe present")
        .1;
    let arg: inap::operations::RequestReportBcsmEventArg =
        inap::decode(&rrbe).expect("inap rrbe decodes");
    assert_eq!(arg.bcsm_events.len(), 2);
    let connect = invoke_all(&reply)
        .into_iter()
        .find(|(op, _)| *op == inap::op_codes::CONNECT)
        .expect("connect present")
        .1;
    let _: inap::operations::ConnectArg = inap::decode(&connect).expect("inap connect decodes");
    assert_eq!(engine.open_dialogues(), 0);
}

#[test]
fn inap_initial_dp_held_open_then_event_report_releases() {
    // The SCP arms detection points in a Continue (dialogue held open); the SSF
    // then reports the armed event (eventReportBCSM), and the SCP releases the
    // call in the closing End. One handler drives both legs.
    let engine = engine_with(
        SCP_SSN,
        inap::op_codes::INITIAL_DP,
        Arc::new(FakeInapScpHeldOpen),
    );
    let otid = [0x5E, 0x6F, 0x70, 0x81];

    // Opening leg: initialDP → RequestReportBCSMEvent in a Continue.
    let leg1 = engine.deliver(
        &begin_msu(
            inap::op_codes::INITIAL_DP,
            inap_initial_dp_arg(),
            &AC_INAP,
            SubsystemNumber::from_u8(SCP_SSN),
            &otid,
        ),
        "ingress",
    );
    let r1 = decode_reply(&leg1[0]);
    assert!(
        matches!(r1, TcapMessage::Continue(_)),
        "RRBE holds the dialogue open"
    );
    assert_eq!(aare_ac(&r1).as_deref(), Some(&AC_INAP[..]));
    assert_eq!(invoke_of(&r1).0, inap::op_codes::REQUEST_REPORT_BCSM_EVENT);
    assert_eq!(engine.open_dialogues(), 1);
    let our_tid = otid_of(&r1);

    // Follow-up leg: the SSF reports the armed event; the SCP releases + closes.
    let leg2 = engine.deliver(
        &continue_msu(
            &our_tid,
            vec![invoke(
                inap::op_codes::EVENT_REPORT_BCSM,
                inap_event_report_bcsm_arg(),
                1,
            )],
            false,
            &AC_INAP,
        ),
        "ingress",
    );
    let r2 = decode_reply(&leg2[0]);
    assert!(
        matches!(r2, TcapMessage::End(_)),
        "the SCP closes with a releaseCall"
    );
    assert_eq!(invoke_of(&r2).0, inap::op_codes::RELEASE_CALL);
    assert_eq!(engine.open_dialogues(), 0);
}

#[test]
fn mt_forward_sm_multi_segment_with_more_messages_to_send() {
    // Originating: one dialogue, three MT segments, moreMessagesToSend NULL on
    // all but the last, each acked, End on the last.
    let engine = DialogueEngine::new(Tcap::default());
    let originator = Arc::new(SmscMtOriginator {
        segments: 3,
        sent: Mutex::new(0),
    });
    let (our_tid, out) = engine.begin(
        OutgoingBegin {
            application_context: AC_MT_RELAY.to_vec(),
            called: SccpAddress::with_gt(gt(MSC_NUM), Some(SubsystemNumber::Msc)),
            calling: SccpAddress::with_gt(gt(OUR_GT), Some(SubsystemNumber::Msc)),
            opc: OUR_PC,
            dpc: PEER_PC,
            ni: 0,
            sls: 0,
            ingress_assoc: "msc".into(),
        },
        originator,
    );

    // Segment 0: a Begin carrying MT-ForwardSM with moreMessagesToSend set.
    let seg0 = decode_reply(&out[0]);
    assert!(matches!(seg0, TcapMessage::Begin(_)));
    assert_eq!(otid_of(&seg0), our_tid);
    let (op0, arg0) = invoke_of(&seg0);
    assert_eq!(op0, gsm_map::op_codes::MT_FORWARD_SM);
    let a0: MtForwardSmArg = rasn::ber::decode(&arg0).unwrap();
    assert!(
        a0.more_messages_to_send.is_some(),
        "segment 0 sets moreMessagesToSend"
    );
    assert_eq!(engine.open_dialogues(), 1, "the MT dialogue is held open");

    // Ack segment 0 → segment 1 (still not last, still more).
    let out1 = engine.deliver(
        &continue_msu(
            &our_tid,
            vec![return_result(
                gsm_map::op_codes::MT_FORWARD_SM,
                mt_forward_sm_res(),
                1,
            )],
            true,
            &AC_MT_RELAY,
        ),
        "msc",
    );
    let seg1 = decode_reply(&out1[0]);
    assert!(
        matches!(seg1, TcapMessage::Continue(_)),
        "middle segment is a Continue"
    );
    assert_eq!(
        dtid_of(&seg1),
        PEER_TID,
        "the Continue echoes the peer OTID"
    );
    let a1: MtForwardSmArg = rasn::ber::decode(&invoke_of(&seg1).1).unwrap();
    assert!(
        a1.more_messages_to_send.is_some(),
        "segment 1 still sets moreMessagesToSend"
    );

    // Ack segment 1 → the last segment: no more, in an End.
    let out2 = engine.deliver(
        &continue_msu(
            &our_tid,
            vec![return_result(
                gsm_map::op_codes::MT_FORWARD_SM,
                mt_forward_sm_res(),
                2,
            )],
            false,
            &AC_MT_RELAY,
        ),
        "msc",
    );
    let seg2 = decode_reply(&out2[0]);
    assert!(
        matches!(seg2, TcapMessage::End(_)),
        "the last segment closes in an End"
    );
    let a2: MtForwardSmArg = rasn::ber::decode(&invoke_of(&seg2).1).unwrap();
    assert!(
        a2.more_messages_to_send.is_none(),
        "the last segment clears moreMessagesToSend"
    );
    assert_eq!(
        engine.open_dialogues(),
        0,
        "the dialogue closed on the last segment"
    );
}

#[test]
fn originating_sri_sm_captures_the_hlr_result() {
    let engine = DialogueEngine::new(Tcap::default());
    let originator = Arc::new(SriSmOriginator {
        result: Mutex::new(None),
    });
    let (our_tid, out) = engine.begin(
        OutgoingBegin {
            application_context: AC_SRI_SM.to_vec(),
            called: SccpAddress::with_gt(gt("15550111"), Some(SubsystemNumber::Hlr)),
            calling: SccpAddress::with_gt(gt(OUR_GT), Some(SubsystemNumber::Msc)),
            opc: OUR_PC,
            dpc: PEER_PC,
            ni: 0,
            sls: 0,
            ingress_assoc: "hlr".into(),
        },
        originator.clone(),
    );
    let begin = decode_reply(&out[0]);
    assert!(matches!(begin, TcapMessage::Begin(_)));
    assert_eq!(
        invoke_of(&begin).0,
        gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM
    );

    // The HLR answers in an End; the originator captures imsi + serving node.
    let end = end_msu(
        &our_tid,
        vec![return_result(
            gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM,
            sri_sm_res(),
            1,
        )],
    );
    let follow = engine.deliver(&end, "hlr");
    assert!(follow.is_empty(), "an End needs no further response");
    let captured = originator.result.lock().unwrap().clone();
    assert_eq!(
        captured,
        Some((tbcd(IMSI), isdn(MSC_NUM))),
        "SRI-SM result captured"
    );
    assert_eq!(
        engine.open_dialogues(),
        0,
        "the originating dialogue closed on the End"
    );
}

#[test]
fn no_handler_for_the_operation_is_refused_with_an_abort() {
    let before = metrics::aborts(metrics::AbortSource::Local);
    // Engine with a handler for SRI-SM only; deliver an initialDP.
    let engine = engine_with(
        6,
        gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM,
        Arc::new(FakeHlrSriSm),
    );
    let out = engine.deliver(
        &begin_msu(
            gsm_cap::op_codes::INITIAL_DP,
            connect_arg(),
            &AC_CAP,
            SubsystemNumber::Cap,
            &[0x09],
        ),
        "ingress",
    );
    assert_eq!(out.len(), 1, "an unserved Begin is still answered");
    assert!(
        matches!(decode_reply(&out[0]), TcapMessage::Abort(_)),
        "with a TCAP Abort"
    );
    assert!(metrics::aborts(metrics::AbortSource::Local) > before);
    assert_eq!(engine.open_dialogues(), 0);
}

#[test]
fn dialogue_ceiling_refuses_over_the_limit() {
    let mut e = DialogueEngine::new(Tcap {
        invoke_timer_ms: 100_000,
        dialogue_timer_ms: 100_000,
        max_dialogues: 1,
    });
    e.register(
        6,
        gsm_map::op_codes::UPDATE_LOCATION,
        Arc::new(FakeHlrUpdateLocation),
    );
    let ul_arg = || {
        rasn::ber::encode(&gsm_map::operations::location::UpdateLocationArg {
            imsi: tbcd(IMSI).into(),
            msc_number: isdn(MSC_NUM).into(),
            vlr_number: isdn(PEER_GT).into(),
            lmsi: None,
            vlr_capability: None,
        })
        .unwrap()
    };

    // First updateLocation opens a held-open dialogue (fills the ceiling of 1).
    let _ = e.deliver(
        &begin_msu(
            gsm_map::op_codes::UPDATE_LOCATION,
            ul_arg(),
            &AC_NET_LOC_UP,
            SubsystemNumber::Hlr,
            &[0x01],
        ),
        "ingress",
    );
    assert_eq!(e.open_dialogues(), 1);

    // The second is over the ceiling: refused with an Abort, no new dialogue.
    let out = e.deliver(
        &begin_msu(
            gsm_map::op_codes::UPDATE_LOCATION,
            ul_arg(),
            &AC_NET_LOC_UP,
            SubsystemNumber::Hlr,
            &[0x02],
        ),
        "ingress",
    );
    assert!(matches!(decode_reply(&out[0]), TcapMessage::Abort(_)));
    assert_eq!(
        e.open_dialogues(),
        1,
        "the over-ceiling Begin did not open a dialogue"
    );
}

#[test]
fn invoke_timer_ages_out_an_outstanding_invoke() {
    let before = metrics::invoke_timeouts(
        gsm_map::operations::subscriber_data::op_codes::INSERT_SUBSCRIBER_DATA,
    );
    let mut e = DialogueEngine::new(Tcap {
        invoke_timer_ms: 50,
        dialogue_timer_ms: 100_000,
        max_dialogues: 100,
    });
    e.register(
        6,
        gsm_map::op_codes::UPDATE_LOCATION,
        Arc::new(FakeHlrUpdateLocation),
    );

    let arg = rasn::ber::encode(&gsm_map::operations::location::UpdateLocationArg {
        imsi: tbcd(IMSI).into(),
        msc_number: isdn(MSC_NUM).into(),
        vlr_number: isdn(PEER_GT).into(),
        lmsi: None,
        vlr_capability: None,
    })
    .unwrap();
    // Opens the ISD leg with an outstanding invoke, then never gets an ack.
    let _ = e.deliver(
        &begin_msu(
            gsm_map::op_codes::UPDATE_LOCATION,
            arg,
            &AC_NET_LOC_UP,
            SubsystemNumber::Hlr,
            &[0x01],
        ),
        "ingress",
    );
    assert_eq!(e.open_dialogues(), 1);

    // Sweep well past the invoke timer.
    let aborts = e.sweep(Instant::now() + Duration::from_secs(5));
    assert_eq!(aborts.len(), 1, "the aged dialogue is aborted to the peer");
    assert_eq!(aborts[0].0, "ingress");
    assert!(
        metrics::invoke_timeouts(
            gsm_map::operations::subscriber_data::op_codes::INSERT_SUBSCRIBER_DATA
        ) > before,
        "the invoke-timeout counter incremented"
    );
    assert_eq!(e.open_dialogues(), 0, "the timed-out dialogue was removed");
}

#[test]
fn dialogue_timer_ages_out_an_idle_dialogue() {
    let before = metrics::dialogue_timeouts();
    let mut e = DialogueEngine::new(Tcap {
        invoke_timer_ms: 100_000,
        dialogue_timer_ms: 50,
        max_dialogues: 100,
    });
    e.register(8, gsm_map::op_codes::MO_FORWARD_SM, Arc::new(KeepOpen));

    let arg = rasn::ber::encode(&gsm_map::operations::mo_forward_sm::MoForwardSmArg {
        sm_rp_da: SmRpDa::ServiceCentreAddressDa(isdn(OUR_GT).into()),
        sm_rp_oa: SmRpOa::MsIsdn(isdn(PEER_GT).into()),
        sm_rp_ui: vec![0x00].into(),
        imsi: None,
    })
    .unwrap();
    let _ = e.deliver(
        &begin_msu(
            gsm_map::op_codes::MO_FORWARD_SM,
            arg,
            &AC_MO_RELAY,
            SubsystemNumber::Msc,
            &[0x07],
        ),
        "ingress",
    );
    assert_eq!(
        e.open_dialogues(),
        1,
        "held open with no outstanding invoke"
    );

    let aborts = e.sweep(Instant::now() + Duration::from_secs(5));
    assert_eq!(aborts.len(), 1);
    assert!(
        metrics::dialogue_timeouts() > before,
        "the dialogue-timeout counter incremented"
    );
    assert_eq!(e.open_dialogues(), 0);
}
