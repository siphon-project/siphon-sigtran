//! On-the-wire SCTP loopback: drive genuinely-assembled SS7 MSUs **through** a
//! running `siphon-sigtran` node over real kernel SCTP and assert the node
//! routed / forwarded each one to the correct outbound association.
//!
//! Unlike `tests/routing.rs` (which feeds assembled bytes straight into the
//! `Router`), every byte here crosses a real `lksctp` association. The node is a
//! [`TransportHandle`]; the peers around it are raw `async-sctp` endpoints that
//! run the M3UA ASPSM/ASPTM handshake or the M2PA link alignment, send MSUs in,
//! and collect the MSUs the node forwards back out.
//!
//! Scenarios:
//! * transit MSU forwarded to an M3UA Application Server,
//! * load-share spread across an AS's two ASPs (SLS-keyed),
//! * failover to an M2PA linkset when the primary AS's ASP drops,
//! * SI-agnostic transfer (an ISUP `SI=5` MSU transits by DPC, undecoded),
//! * ISUP screening on the SI=5 transit path (a blocked IAM dropped + counted,
//!   an allowed IAM transited to the egress AS unchanged),
//! * the transfer-path loop guards (own-OPC, route-reflection) and the SCCP
//!   hop-counter guard on a GTT translation (decrement, then drop + XUDTS return),
//! * a `sua` association starting, and a SUA CLDT routed via GTT to an egress AS
//!   (the CLDT ⇄ SCCP-user bridge on both faces),
//! * a tshark dissection gate over the forwarded frames (M3UA + M2PA, and SUA).
//!
//! Real SCTP is required; if a bind/connect fails (module not loaded, no
//! privilege) the test prints a SKIP and passes. All data is synthetic: test
//! PLMN MCC 001 / MNC 01, `+1-555-01xx` global titles, decimal point codes.

use std::io::Write as _;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rasn::types::{Any, Oid};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use async_sctp::{SctpAssociation, SctpConfig, SctpListener};

use gsm_cap::operations::InitialDpArg;
use gsm_map::operations::location::UpdateLocationArg;
use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::types::{LocationInfoWithLmsi, SmRpDa, SmRpOa};

use m2pa::{LinkState, LinkStatusMessage, M2paMessage, M2paStateMachine};
use m3ua::{M3uaMessage, MessageType, ProtocolData};
use mtp3::NetworkIndicator;
use sccp::{
    ExtendedUnitData, GlobalTitle, ReturnCause, SccpAddress, SccpMessage, SubsystemNumber, UnitData,
};
use sua::{GlobalTitle as SuaGt, MessageType as SuaType, SuaAddress, SuaMessage};
use tcap::dialogue::{DialoguePdu, DialoguePortion};
use tcap::{Begin, Component, Invoke, OperationCode, ReturnResult, ReturnResultValue, TcapMessage};

use siphon_sigtran::config::{Config, Tcap};
use siphon_sigtran::dialogue::{Dialogue, DialogueEngine, IncomingOp, TerminationHandler};
use siphon_sigtran::metrics::{self, LoopKind, ScreenReason};
use siphon_sigtran::mtp3::route::Destination;
use siphon_sigtran::routing::{Inbound, RouteDecision, Router};
use siphon_sigtran::transport::next_status;
use siphon_sigtran::TransportHandle;

// ── Synthetic fixed parameters ───────────────────────────────────────────────

const NODE_PC: u32 = 1000;
const OPC_UPSTREAM: u32 = 4000; // some upstream MSC that originates the MSUs
const DPC_HLR: u32 = 2000; // routed to AS `hlr`
const DPC_ADJ: u32 = 3000; // m2pa adjacent → linkset `transit`
const OUR_GT: &str = "15550100";
const PPID_M3UA: u32 = 3;
const PPID_M2PA: u32 = 5;
const PPID_SUA: u32 = 4;
const SI_SCCP: u8 = 3;
const SI_ISUP: u8 = 5;

// ── MAP/CAP application contexts (bind Wireshark's operation dissector) ───────

/// shortMsgGatewayContext v3 (SRI-SM).
const AC_SRI_SM: [u32; 8] = [0, 4, 0, 0, 1, 0, 20, 3];
/// networkLocUpContext v3 (updateLocation).
const AC_NET_LOC_UP: [u32; 8] = [0, 4, 0, 0, 1, 0, 1, 3];
/// shortMsgMO-RelayContext v3 (MO-ForwardSM).
const AC_MO_RELAY: [u32; 8] = [0, 4, 0, 0, 1, 0, 21, 3];
/// gsmSSF-scfGenericAC v3 (CAMEL initialDP).
const AC_CAP: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 4];
/// cs1-ssp-to-scp (Core INAP CS-1 initialDP). Binds Wireshark's INAP dissector.
const AC_INAP: [u32; 8] = [0, 4, 0, 1, 1, 0, 3, 0];
/// The IN SCP subsystem number (Wireshark dispatches SSN 106 to INAP by default).
const SCP_SSN: u8 = 106;

// ── Synthetic value helpers (same shape as ss7-stack) ────────────────────────

/// TBCD-encode a decimal string (swap-nibble, F-pad odd length).
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

/// International ISDN-AddressString (0x91 + TBCD digits).
fn isdn(digits: &str) -> Vec<u8> {
    let mut v = vec![0x91];
    v.extend(tbcd(digits));
    v
}

fn imsi_bytes(digits: &str) -> Vec<u8> {
    tbcd(digits)
}

// ── MAP/CAP argument bytes (BER) ─────────────────────────────────────────────

fn sri_sm_arg(msisdn: &str) -> Vec<u8> {
    let arg = RoutingInfoForSmArg {
        msisdn: isdn(msisdn).into(),
        sm_rp_pri: true,
        service_centre_address: isdn(OUR_GT).into(),
        gprs_support_indicator: None,
        sm_rp_mti: None,
        sm_rp_smea: None,
    };
    rasn::ber::encode(&arg).expect("encode sri-sm")
}

fn update_location_arg(imsi: &str) -> Vec<u8> {
    let arg = UpdateLocationArg {
        imsi: imsi_bytes(imsi).into(),
        msc_number: isdn("15550170").into(),
        vlr_number: isdn("15550171").into(),
        lmsi: None,
        vlr_capability: None,
    };
    rasn::ber::encode(&arg).expect("encode ul")
}

fn mo_forward_sm_arg() -> Vec<u8> {
    let arg = MoForwardSmArg {
        sm_rp_da: SmRpDa::ServiceCentreAddressDa(isdn(OUR_GT).into()),
        sm_rp_oa: SmRpOa::MsIsdn(isdn("15550142").into()),
        sm_rp_ui: vec![0x00, 0x01, 0x02].into(),
        imsi: None,
    };
    rasn::ber::encode(&arg).expect("encode mo")
}

fn mt_forward_sm_arg() -> Vec<u8> {
    let arg = MtForwardSmArg {
        sm_rp_da: SmRpDa::Imsi(imsi_bytes("001010000000042").into()),
        sm_rp_oa: SmRpOa::ServiceCentreAddressOa(isdn(OUR_GT).into()),
        sm_rp_ui: vec![0x04, 0x0B, 0x91].into(),
        more_messages_to_send: None,
    };
    rasn::ber::encode(&arg).expect("encode mt")
}

fn initial_dp_arg(imsi: &str) -> Vec<u8> {
    let arg = InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(isdn("15550142").into()),
        calling_party_number: Some(isdn("15550101").into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: None,
        redirecting_party_id: None,
        imsi: Some(imsi_bytes(imsi).into()),
        location_information: None,
        call_reference_number: None,
        msc_address: None,
        called_party_bcd_number: None,
        time_and_timezone: None,
    };
    gsm_cap::encode(&arg).expect("encode idp")
}

/// An INAP CS-1 initialDP argument (fixed-network IEs, no mobile fields).
fn inap_initial_dp_arg() -> Vec<u8> {
    let arg = inap::operations::InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(isdn("15550142").into()),
        calling_party_number: Some(isdn("15550101").into()),
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

// ── TCAP + SCCP assembly (real dialogue portion for a clean dissection) ───────

fn aarq(ac: &[u32]) -> DialoguePortion {
    DialoguePortion::aarq(Oid::new(ac).expect("valid application-context OID"))
}

/// A TCAP `Begin` carrying an AARQ dialogue portion and one `Invoke(op, arg)`.
fn tcap_begin(op: i64, arg: Vec<u8>, ac: &[u32]) -> Vec<u8> {
    let begin = Begin {
        otid: vec![0x11, 0x22, 0x33, 0x44].into(),
        dialogue_portion: Some(aarq(ac)),
        components: Some(vec![Component::Invoke(Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(op),
            parameter: Some(Any::new(arg)),
        })]),
    };
    tcap::encode(&TcapMessage::Begin(begin)).expect("encode tcap")
}

/// Wrap TCAP bytes in an SCCP UDT with synthetic GT+SSN party addresses.
fn sccp_udt(called_ssn: SubsystemNumber, tcap_bytes: &[u8]) -> Vec<u8> {
    let gt = |digits: &str| GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    };
    let called = SccpAddress::with_gt(gt("15550142"), Some(called_ssn));
    let calling = SccpAddress::with_gt(gt(OUR_GT), Some(SubsystemNumber::Msc));
    UnitData::new(called, calling, tcap_bytes.to_vec())
        .encode()
        .expect("encode sccp")
}

/// Build the SCCP bytes for a named MAP operation.
fn map_sccp(op: i64, arg: Vec<u8>, ac: &[u32]) -> Vec<u8> {
    sccp_udt(SubsystemNumber::Hlr, &tcap_begin(op, arg, ac))
}

/// Wrap TCAP bytes in an SCCP **XUDT** carrying a hop counter, with a called-party
/// GT that a GTT rule will translate. `return_on_error` sets the message-handling
/// that asks for an XUDTS back when the message cannot be delivered.
fn sccp_xudt(tcap_bytes: &[u8], hop: u8, return_on_error: bool) -> Vec<u8> {
    let gt = |digits: &str| GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    };
    let called = SccpAddress::with_gt(gt("15550142"), Some(SubsystemNumber::Hlr));
    let calling = SccpAddress::with_gt(gt(OUR_GT), Some(SubsystemNumber::Msc));
    let mut xudt = ExtendedUnitData::new(called, calling, tcap_bytes.to_vec());
    xudt.hop_counter = hop;
    if return_on_error {
        xudt.message_handling = 0x8; // return message on error
    }
    xudt.encode().expect("encode xudt")
}

/// An SRI-SM XUDT (hop counter set) addressed by GT to the translating node.
fn map_xudt(hop: u8, return_on_error: bool) -> Vec<u8> {
    sccp_xudt(
        &tcap_begin(
            gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
            sri_sm_arg("15559999"),
            &AC_SRI_SM,
        ),
        hop,
        return_on_error,
    )
}

/// The (dpc, hop_counter) recovered from a forwarded M3UA DATA frame carrying an
/// SCCP XUDT.
fn xudt_of_m3ua(payload: &[u8]) -> Option<(u32, u8)> {
    let msg = M3uaMessage::decode(payload).ok()?;
    let pd = msg.protocol_data().ok()?;
    match SccpMessage::decode(&pd.user_data).ok()? {
        SccpMessage::Xudt(x) => Some((pd.dpc, x.hop_counter)),
        _ => None,
    }
}

/// The return cause of an XUDTS carried in a forwarded M3UA DATA frame.
fn xudts_cause_of_m3ua(payload: &[u8]) -> Option<u8> {
    let msg = M3uaMessage::decode(payload).ok()?;
    let pd = msg.protocol_data().ok()?;
    match SccpMessage::decode(&pd.user_data).ok()? {
        SccpMessage::Xudts(x) => Some(x.return_cause.value()),
        _ => None,
    }
}

/// Build the SCCP bytes for the CAMEL initialDP operation.
fn cap_sccp(imsi: &str) -> Vec<u8> {
    sccp_udt(
        SubsystemNumber::Cap,
        &tcap_begin(gsm_cap::op_codes::INITIAL_DP, initial_dp_arg(imsi), &AC_CAP),
    )
}

/// Build the SCCP bytes for the INAP CS-1 initialDP operation, addressed
/// route-on-SSN to the SCP (SSN 106) under the Core INAP CS-1 application context.
///
/// It carries a distinct OTID so a dissector keys it as its own TCAP transaction
/// (the shared `tcap_begin` OTID would otherwise group every Begin in the capture
/// into one transaction and dissect them all under the first frame's SSN).
fn inap_sccp() -> Vec<u8> {
    let begin = Begin {
        otid: vec![0x51, 0x52, 0x53, 0x54].into(),
        dialogue_portion: Some(aarq(&AC_INAP)),
        components: Some(vec![Component::Invoke(Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(inap::op_codes::INITIAL_DP),
            parameter: Some(Any::new(inap_initial_dp_arg())),
        })]),
    };
    let tcap = tcap::encode(&TcapMessage::Begin(begin)).expect("encode inap tcap");
    sccp_udt(SubsystemNumber::from_u8(SCP_SSN), &tcap)
}

// ── Transport framing (explicit OPC/DPC/SLS, any Service Indicator) ──────────

/// An M3UA DATA message with an explicit routing label and Service Indicator.
fn m3ua_data_si(payload: &[u8], si: u8, opc: u32, dpc: u32, sls: u8) -> Vec<u8> {
    let pd = ProtocolData::new(
        opc,
        dpc,
        si,
        NetworkIndicator::International.bits(),
        0,
        sls,
        payload.to_vec(),
    );
    M3uaMessage::data(None, Some(1), pd, None).encode()
}

/// An M3UA DATA message carrying SCCP (`SI=3`).
fn m3ua_sccp(sccp: &[u8], opc: u32, dpc: u32, sls: u8) -> Vec<u8> {
    m3ua_data_si(sccp, SI_SCCP, opc, dpc, sls)
}

// ── Decode the forwarded frames back out ─────────────────────────────────────

/// (dpc, si, invoke-operation-code) recovered from a forwarded M3UA DATA frame.
fn decode_m3ua(payload: &[u8]) -> (u32, u8, Option<i64>) {
    let msg = M3uaMessage::decode(payload).expect("decode m3ua");
    let pd = msg.protocol_data().expect("protocol data");
    (pd.dpc, pd.si, op_of_sccp(pd.si, &pd.user_data))
}

/// (dpc, si, invoke-operation-code) recovered from a forwarded M2PA User Data
/// frame (the hand-rolled ITU MTP3 MSU inside it).
fn decode_m2pa(payload: &[u8]) -> (u32, u8, Option<i64>) {
    let msg = M2paMessage::decode(payload).expect("decode m2pa");
    let raw = match msg {
        M2paMessage::UserData { message, .. } => message.msu,
        _ => panic!("expected M2PA User Data"),
    };
    let sio = raw[0];
    let si = sio & 0x0F;
    let label = u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]);
    let dpc = label & 0x3FFF;
    (dpc, si, op_of_sccp(si, &raw[5..]))
}

/// The Invoke operation code inside SCCP-carried TCAP, or `None` for non-SCCP.
fn op_of_sccp(si: u8, sccp_bytes: &[u8]) -> Option<i64> {
    if si != SI_SCCP {
        return None;
    }
    let udt = match SccpMessage::decode(sccp_bytes).ok()? {
        SccpMessage::Udt(u) => u,
        _ => return None,
    };
    match tcap::decode(&udt.data).ok()? {
        TcapMessage::Begin(b) => match b.components?.into_iter().next()? {
            Component::Invoke(inv) => match inv.operation_code {
                OperationCode::Local(op) => Some(op),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

// ── Synthetic M3UA ASP peer (connects to the node's SG association) ──────────

/// An ASP peer: it connects to one of the node's `server` M3UA associations,
/// runs the ASPSM/ASPTM handshake to Active, then sends MSUs in and collects the
/// DATA the node forwards back out to it.
struct AspPeer {
    assoc: Arc<SctpAssociation>,
    rx: mpsc::Receiver<Vec<u8>>,
    task: JoinHandle<()>,
}

impl AspPeer {
    /// Connect + handshake. `rc` is the AS routing context to activate.
    async fn connect(addr: SocketAddr, rc: u32) -> Option<Self> {
        let cfg = SctpConfig::new().nodelay(true);
        let assoc = Arc::new(SctpAssociation::connect_with(addr, &cfg).await.ok()?);
        assoc
            .send(&M3uaMessage::asp_up(Some(1), None).encode(), 0, PPID_M3UA)
            .await
            .ok()?;
        wait_m3ua(&assoc, MessageType::AspUpAck).await?;
        assoc
            .send(
                &M3uaMessage::asp_active(Some(2), Some(rc)).encode(),
                0,
                PPID_M3UA,
            )
            .await
            .ok()?;
        wait_m3ua(&assoc, MessageType::AspActiveAck).await?;

        let (tx, rx) = mpsc::channel(64);
        let a2 = assoc.clone();
        let task = tokio::spawn(async move {
            while let Ok((data, info)) = a2.recv().await {
                if info.ppid != PPID_M3UA {
                    continue;
                }
                match M3uaMessage::decode(&data) {
                    Ok(m) if m.message_type == MessageType::Data => {
                        if tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Ok(m) if m.message_type == MessageType::Heartbeat => {
                        let _ = a2
                            .send(&M3uaMessage::heartbeat_ack(None).encode(), 0, PPID_M3UA)
                            .await;
                    }
                    _ => {}
                }
            }
        });
        Some(Self { assoc, rx, task })
    }

    /// Send an already-framed M3UA DATA message in on stream 1.
    async fn send_in(&self, bytes: &[u8]) {
        let _ = self.assoc.send(bytes, 1, PPID_M3UA).await;
    }

    /// Await the next forwarded frame (up to 5 s).
    async fn recv_out(&mut self) -> Option<Vec<u8>> {
        timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// Drain every frame that arrives within `dur`.
    async fn drain(&mut self, dur: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Ok(Some(frame)) = timeout(dur, self.rx.recv()).await {
            out.push(frame);
        }
        out
    }

    /// Tear the association down (fd close) so the node observes the ASP drop.
    fn close(self) {
        self.task.abort();
        // Dropping `self.assoc` here releases the last handle → SCTP shutdown.
    }
}

/// Receive on an association until an M3UA message of the wanted type arrives.
async fn wait_m3ua(assoc: &SctpAssociation, want: MessageType) -> Option<()> {
    loop {
        let (data, info) = timeout(Duration::from_secs(5), assoc.recv())
            .await
            .ok()?
            .ok()?;
        if info.ppid != PPID_M3UA {
            continue;
        }
        if let Ok(m) = M3uaMessage::decode(&data) {
            if m.message_type == want {
                return Some(());
            }
        }
    }
}

// ── Synthetic M2PA peer (the node connects to it as an m2pa client) ──────────

/// An M2PA peer: it listens, and on the node's connect it runs link alignment
/// to In-Service (mirroring the node's own reactive alignment) and collects the
/// User Data the node forwards out over the linkset.
struct M2paPeer {
    port: u16,
    rx: mpsc::Receiver<Vec<u8>>,
    task: JoinHandle<()>,
}

impl M2paPeer {
    async fn spawn() -> Option<Self> {
        let cfg = SctpConfig::new().nodelay(true);
        let listener = SctpListener::bind_config("127.0.0.1:0".parse().ok()?, &cfg).ok()?;
        let port = listener.local_addr().ok()?.port();
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let assoc = match listener.accept().await {
                Ok((a, _)) => Arc::new(a),
                Err(_) => return,
            };
            let mut sm = M2paStateMachine::new();
            sm.start();
            send_link_status(&assoc, LinkState::Alignment).await;
            while let Ok((data, info)) = assoc.recv().await {
                if info.ppid != PPID_M2PA {
                    continue;
                }
                match M2paMessage::decode(&data) {
                    Ok(M2paMessage::LinkStatus { message, .. }) => {
                        let new = sm.on_link_status(message.state);
                        if let Some(next) = next_status(new) {
                            send_link_status(&assoc, next).await;
                        }
                    }
                    Ok(M2paMessage::UserData { .. }) => {
                        if tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        });
        Some(Self { port, rx, task })
    }

    async fn recv_out(&mut self) -> Option<Vec<u8>> {
        timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .ok()
            .flatten()
    }
}

impl Drop for M2paPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn send_link_status(assoc: &SctpAssociation, state: LinkState) {
    let msg = M2paMessage::LinkStatus {
        bsn: 0xFF_FFFF,
        fsn: 0xFF_FFFF,
        message: LinkStatusMessage::new(state),
    };
    if let Ok(bytes) = msg.encode() {
        let _ = assoc.send(&bytes, 0, PPID_M2PA).await;
    }
}

// ── Synthetic SUA ASP peer (connects to the node's SG association) ────────────

/// A SUA ASP peer: it connects to one of the node's `server` SUA associations,
/// runs the ASPSM/ASPTM handshake to Active on PPID 4, then sends CLDT in and
/// collects the CLDT/CLDR the node forwards back out to it.
struct SuaPeer {
    assoc: Arc<SctpAssociation>,
    rx: mpsc::Receiver<Vec<u8>>,
    task: JoinHandle<()>,
}

impl SuaPeer {
    /// Connect + handshake. `rc` is the AS routing context to activate.
    async fn connect(addr: SocketAddr, rc: u32) -> Option<Self> {
        let cfg = SctpConfig::new().nodelay(true);
        let assoc = Arc::new(SctpAssociation::connect_with(addr, &cfg).await.ok()?);
        assoc
            .send(&SuaMessage::asp_up(Some(1), None).encode(), 0, PPID_SUA)
            .await
            .ok()?;
        wait_sua(&assoc, SuaType::AspUpAck).await?;
        assoc
            .send(
                &SuaMessage::asp_active(Some(1), Some(rc)).encode(),
                0,
                PPID_SUA,
            )
            .await
            .ok()?;
        wait_sua(&assoc, SuaType::AspActiveAck).await?;

        let (tx, rx) = mpsc::channel(64);
        let a2 = assoc.clone();
        let task = tokio::spawn(async move {
            while let Ok((data, info)) = a2.recv().await {
                if info.ppid != PPID_SUA {
                    continue;
                }
                match SuaMessage::decode(&data) {
                    Ok(m) if matches!(m.message_type, SuaType::Cldt | SuaType::Cldr) => {
                        if tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Ok(m) if m.message_type == SuaType::Heartbeat => {
                        let _ = a2
                            .send(&SuaMessage::heartbeat_ack(None).encode(), 0, PPID_SUA)
                            .await;
                    }
                    _ => {}
                }
            }
        });
        Some(Self { assoc, rx, task })
    }

    /// Send an already-encoded SUA message in on stream 1.
    async fn send_in(&self, bytes: &[u8]) {
        let _ = self.assoc.send(bytes, 1, PPID_SUA).await;
    }

    /// Await the next forwarded CLDT/CLDR frame (up to 5 s).
    async fn recv_out(&mut self) -> Option<Vec<u8>> {
        timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .ok()
            .flatten()
    }

    fn close(self) {
        self.task.abort();
    }
}

/// Receive on an association until a SUA message of the wanted type arrives.
async fn wait_sua(assoc: &SctpAssociation, want: SuaType) -> Option<()> {
    loop {
        let (data, info) = timeout(Duration::from_secs(5), assoc.recv())
            .await
            .ok()?
            .ok()?;
        if info.ppid != PPID_SUA {
            continue;
        }
        if let Ok(m) = SuaMessage::decode(&data) {
            if m.message_type == want {
                return Some(());
            }
        }
    }
}

/// A SUA CLDT carrying a MAP operation, addressed by GT so a GTT rule translates
/// it. Calling party is us (MSC, `OUR_GT`); called party carries `called_gt` and
/// SSN 6 (HLR). `hop` seeds the SS7 hop counter.
fn sua_cldt_map(op: i64, arg: Vec<u8>, ac: &[u32], called_gt: &str, hop: u8) -> Vec<u8> {
    let source = SuaAddress::with_gt(SuaGt::e164(OUR_GT), Some(SubsystemNumber::Msc.value()));
    let dest = SuaAddress::with_gt(SuaGt::e164(called_gt), Some(SubsystemNumber::Hlr.value()));
    let data = tcap_begin(op, arg, ac);
    SuaMessage::cldt(0, 0, &source, &dest, 0, Some(hop), data)
        .expect("build cldt")
        .encode()
}

/// (destination GT digits, SS7 hop count, invoke operation code) recovered from a
/// forwarded SUA CLDT.
fn decode_cldt(payload: &[u8]) -> (Option<String>, Option<u8>, Option<i64>) {
    let msg = SuaMessage::decode(payload).expect("decode cldt");
    let dst = msg
        .destination_address()
        .ok()
        .and_then(|a| a.gt_digits().map(|s| s.to_string()));
    let hop = msg.ss7_hop_count();
    let op = msg.data().and_then(op_of_tcap);
    (dst, hop, op)
}

/// The first Invoke operation code inside a TCAP Begin, or `None`.
fn op_of_tcap(tcap_bytes: &[u8]) -> Option<i64> {
    match tcap::decode(tcap_bytes).ok()? {
        TcapMessage::Begin(b) => match b.components?.into_iter().next()? {
            Component::Invoke(inv) => match inv.operation_code {
                OperationCode::Local(op) => Some(op),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

// ── Route-state polling ──────────────────────────────────────────────────────

/// Poll the node until DPC `dpc` transit-resolves to `want`, up to ~10 s.
async fn wait_route(router: &Router, dpc: u32, want: &Destination) -> bool {
    for _ in 0..200 {
        if let RouteDecision::Route { via } = router.route_in(
            "default",
            &Inbound {
                dpc,
                ..Default::default()
            },
        ) {
            if &via == want {
                return true;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

// ── Node configs ─────────────────────────────────────────────────────────────

/// Ingress SG + an AS `hlr` load-shared over two ASPs. Route 2000 → hlr.
const LOADSHARE_NODE: &str = r#"
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: ingress, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
  - { id: hlr-a,   adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
  - { id: hlr-b,   adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
application_servers:
  - { name: hlr, traffic_mode: loadshare, routing_context: 100, asps: [hlr-a, hlr-b] }
mtp3_routes:
  - { dpc: 2000, as: hlr, priority: 1 }
sccp:
  local_ssns: [8]
"#;

/// Ingress SG + a primary AS `hlr` (one ASP) + an M2PA linkset `transit`
/// alternate. Route 2000 → hlr (pri 1) then transit (pri 2); 3000 is adjacent
/// via transit. `port` is the synthetic M2PA peer's listen port.
fn dual_node(m2pa_port: u16) -> String {
    format!(
        r#"
node: {{ point_code: 1000, variant: ITU, network_indicator: international }}
associations:
  - {{ id: ingress, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }}
  - {{ id: hlr-a,   adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }}
  - {{ id: xit-1,   adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {m2pa_port}, adjacent_pc: 3000 }}
application_servers:
  - {{ name: hlr, traffic_mode: override, routing_context: 100, asps: [hlr-a] }}
linksets:
  - {{ name: transit, links: [{{assoc: xit-1, slc: 0}}] }}
mtp3_routes:
  - {{ dpc: 2000, as: hlr,          priority: 1 }}
  - {{ dpc: 2000, linkset: transit, priority: 2 }}
sccp:
  local_ssns: [8]
"#
    )
}

/// A SUA-only node: an ingress SUA SG association `sua-in`, an egress SUA AS
/// `sccp-as` (one ASP `sua-out`), and a GTT rule translating GT prefix `1555`
/// to dpc 2000 (which routes to that AS). A CLDT arriving on `sua-in` is bridged
/// to the SCCP path, translated by GTT, and re-wrapped as a CLDT toward the AS.
const SUA_NODE: &str = r#"
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: sua-in,  adaptation: sua, role: server, addrs: [127.0.0.1], port: 0 }
  - { id: sua-out, adaptation: sua, role: server, addrs: [127.0.0.1], port: 0 }
application_servers:
  - { name: sccp-as, traffic_mode: override, routing_context: 200, asps: [sua-out] }
mtp3_routes:
  - { dpc: 2000, as: sccp-as, priority: 1 }
sccp:
  local_ssns: [8]
  gtt:
    - { match: {gt_prefix: "1555"}, to: {dpc: 2000, ssn: 6} }
"#;

/// Start a node, or print a SKIP and return `None` if SCTP is unavailable.
async fn start_node(yaml: &str, what: &str) -> Option<TransportHandle> {
    let cfg = Config::parse(yaml).expect("config parses");
    let router = Arc::new(Router::new(&cfg));
    match TransportHandle::start(&cfg, router).await {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("SKIP {what}: transport did not start ({e}); load `modprobe sctp`");
            None
        }
    }
}

// ── Scenario 1: transit MSU forwarded to an M3UA Application Server ───────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_transit_forwards_map_over_m3ua() {
    let Some(handle) = start_node(LOADSHARE_NODE, "wire_transit").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress bound");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a bound");

    let Some(src) = AspPeer::connect(ingress, 0).await else {
        eprintln!("SKIP wire_transit: ingress connect failed");
        return;
    };
    let Some(mut peer_a) = AspPeer::connect(hlr_a, 100).await else {
        eprintln!("SKIP wire_transit: hlr-a connect failed");
        return;
    };
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await,
        "AS hlr never came up"
    );

    // A genuine SRI-SM Begin, SCCP UDT, over M3UA to a transit DPC. SLS 0 → the
    // first active ASP (hlr-a) under load-share.
    let sccp = map_sccp(
        gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
        sri_sm_arg("15559999"),
        &AC_SRI_SM,
    );
    src.send_in(&m3ua_sccp(&sccp, OPC_UPSTREAM, DPC_HLR, 0))
        .await;

    let fwd = peer_a.recv_out().await.expect("forwarded to hlr-a");
    let (dpc, si, op) = decode_m3ua(&fwd);
    assert_eq!(dpc, DPC_HLR, "forwarded DPC preserved");
    assert_eq!(si, SI_SCCP);
    assert_eq!(
        op,
        Some(gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM),
        "SRI-SM operation intact on the forwarded frame"
    );

    src.close();
    peer_a.close();
    handle.shutdown();
}

// ── Scenario 2: load-share across an AS's two ASPs ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_loadshare_spreads_over_asps() {
    let Some(handle) = start_node(LOADSHARE_NODE, "wire_loadshare").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");
    let hlr_b = handle.bound_addr("hlr-b").expect("hlr-b");

    let (src, peer_a, peer_b) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
        AspPeer::connect(hlr_b, 100).await,
    ) {
        (Some(s), Some(a), Some(b)) => (s, a, b),
        _ => {
            eprintln!("SKIP wire_loadshare: a peer connect failed");
            return;
        }
    };
    let mut peer_a = peer_a;
    let mut peer_b = peer_b;

    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await,
        "AS hlr never came up"
    );
    // Let the second ASP's activation land before load-sharing.
    sleep(Duration::from_millis(150)).await;

    // Six MSUs across SLS 0..=5. Load-share keys on SLS: even → ASP index 0
    // (hlr-a), odd → index 1 (hlr-b).
    for sls in 0u8..6 {
        let sccp = map_sccp(
            gsm_map::types::op_codes::UPDATE_LOCATION,
            update_location_arg("001010000000042"),
            &AC_NET_LOC_UP,
        );
        src.send_in(&m3ua_sccp(&sccp, OPC_UPSTREAM, DPC_HLR, sls))
            .await;
    }

    let got_a = peer_a.drain(Duration::from_millis(800)).await;
    let got_b = peer_b.drain(Duration::from_millis(800)).await;

    assert!(!got_a.is_empty(), "hlr-a received no share of the traffic");
    assert!(!got_b.is_empty(), "hlr-b received no share of the traffic");
    assert_eq!(
        got_a.len() + got_b.len(),
        6,
        "every MSU forwarded exactly once (a={}, b={})",
        got_a.len(),
        got_b.len()
    );
    for frame in got_a.iter().chain(got_b.iter()) {
        let (dpc, _, op) = decode_m3ua(frame);
        assert_eq!(dpc, DPC_HLR);
        assert_eq!(op, Some(gsm_map::types::op_codes::UPDATE_LOCATION));
    }

    src.close();
    peer_a.close();
    peer_b.close();
    handle.shutdown();
}

// ── Scenario 3: failover to the M2PA linkset when the ASP drops ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_failover_moves_to_m2pa_linkset_on_asp_drop() {
    let Some(mut m2pa) = M2paPeer::spawn().await else {
        eprintln!("SKIP wire_failover: m2pa peer bind failed");
        return;
    };
    let Some(handle) = start_node(&dual_node(m2pa.port), "wire_failover").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    let (src, peer_a) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
    ) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            eprintln!("SKIP wire_failover: a peer connect failed");
            return;
        }
    };
    let mut peer_a = peer_a;

    // Both the primary AS and the M2PA alternate must be up first.
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await,
        "primary AS hlr never came up"
    );
    assert!(
        wait_route(
            handle.router(),
            DPC_ADJ,
            &Destination::Linkset("transit".into())
        )
        .await,
        "M2PA linkset transit never aligned"
    );

    // Primary path: MT-ForwardSM to 2000 lands on the AS.
    let sccp = map_sccp(
        gsm_map::types::op_codes::MT_FORWARD_SM,
        mt_forward_sm_arg(),
        &AC_NET_LOC_UP,
    );
    src.send_in(&m3ua_sccp(&sccp, OPC_UPSTREAM, DPC_HLR, 3))
        .await;
    let primary = peer_a.recv_out().await.expect("primary forward to hlr-a");
    assert_eq!(decode_m3ua(&primary).0, DPC_HLR);

    // Drop the only ASP of the primary AS. The node observes the SCTP shutdown,
    // marks hlr down, and 2000 fails over to the priority-2 M2PA linkset.
    peer_a.close();
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::Linkset("transit".into())
        )
        .await,
        "2000 did not fail over to the M2PA linkset after the ASP drop"
    );

    // Same MSU now transits over M2PA to the linkset peer.
    src.send_in(&m3ua_sccp(&sccp, OPC_UPSTREAM, DPC_HLR, 3))
        .await;
    let alt = m2pa.recv_out().await.expect("failover forward over m2pa");
    let (dpc, si, op) = decode_m2pa(&alt);
    assert_eq!(dpc, DPC_HLR);
    assert_eq!(si, SI_SCCP);
    assert_eq!(op, Some(gsm_map::types::op_codes::MT_FORWARD_SM));

    src.close();
    handle.shutdown();
}

// ── Scenario 4: SI-agnostic transfer (ISUP SI=5 transits by DPC) ─────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_transfers_non_sccp_by_dpc() {
    let Some(handle) = start_node(LOADSHARE_NODE, "wire_si_agnostic").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    let (src, peer_a) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
    ) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            eprintln!("SKIP wire_si_agnostic: a peer connect failed");
            return;
        }
    };
    let mut peer_a = peer_a;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await
    );

    // A non-SCCP user part (ISUP, SI=5) with an opaque payload. It must transit
    // by DPC alone, undecoded, SI intact.
    let isup = vec![0x01, 0x10, 0x00, 0x05, 0x0a, 0x08, 0x83];
    src.send_in(&m3ua_data_si(&isup, SI_ISUP, OPC_UPSTREAM, DPC_HLR, 0))
        .await;

    let fwd = peer_a
        .recv_out()
        .await
        .expect("ISUP MSU transited to hlr-a");
    let msg = M3uaMessage::decode(&fwd).expect("decode m3ua");
    let pd = msg.protocol_data().expect("protocol data");
    assert_eq!(pd.dpc, DPC_HLR, "transferred by DPC");
    assert_eq!(
        pd.si, SI_ISUP,
        "Service Indicator preserved (not decapsulated)"
    );
    assert_eq!(pd.user_data, isup, "ISUP payload passed through untouched");

    src.close();
    peer_a.close();
    handle.shutdown();
}

// ── Scenario 4b: ISUP screening on the SI=5 transit path ─────────────────────

/// Ingress SG + AS `hlr`, with ISUP screening: block an IAM whose called-party
/// number begins `1900`, allow everything else. Route 2000 → hlr.
const SCREEN_NODE: &str = r#"
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: ingress, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
  - { id: hlr-a,   adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
application_servers:
  - { name: hlr, traffic_mode: override, routing_context: 100, asps: [hlr-a] }
mtp3_routes:
  - { dpc: 2000, as: hlr, priority: 1 }
sccp:
  local_ssns: [8]
isup_screening:
  default: allow
  rules:
    - name: block-premium
      match: { message_type: iam, called_prefix: "1900" }
      action: block
"#;

/// A genuine ISUP Initial Address Message to `called` (national number), encoded
/// as the MTP3-user payload an M3UA DATA carries for `SI=5`. Synthetic +1-555/1900
/// digits.
fn isup_iam(called: &str) -> Vec<u8> {
    itu_isup::Message::iam(
        1,    // CIC
        0x00, // nature of connection indicators
        0x2000,
        itu_isup::calling_party_category::ORDINARY,
        0x00, // transmission medium requirement (speech)
        &itu_isup::Number::called(3, 1, false, called),
    )
    .expect("build isup iam")
    .encode()
    .expect("encode isup iam")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_isup_screening_drops_blocked_passes_allowed() {
    let before = metrics::isup_screened(ScreenReason::Rule);

    let Some(handle) = start_node(SCREEN_NODE, "wire_isup_screen").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    let (src, peer_a) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
    ) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            eprintln!("SKIP wire_isup_screen: a peer connect failed");
            return;
        }
    };
    let mut peer_a = peer_a;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await,
        "AS hlr never came up"
    );

    // 1. An ISUP IAM to a called number the block rule matches (prefix 1900) is
    //    screened: dropped before the transit, never forwarded, and counted.
    let blocked = isup_iam("1900123");
    src.send_in(&m3ua_data_si(&blocked, SI_ISUP, OPC_UPSTREAM, DPC_HLR, 0))
        .await;
    assert!(
        peer_a.drain(Duration::from_millis(500)).await.is_empty(),
        "screened ISUP IAM was forwarded instead of dropped"
    );
    assert!(
        metrics::isup_screened(ScreenReason::Rule) > before,
        "isup screening rule counter did not increment"
    );

    // 2. An ISUP IAM to a called number no rule matches transits by DPC to the
    //    egress AS under the default `allow`, SI=5 intact, payload untouched.
    let allowed = isup_iam("1555123");
    src.send_in(&m3ua_data_si(&allowed, SI_ISUP, OPC_UPSTREAM, DPC_HLR, 0))
        .await;
    let fwd = peer_a
        .recv_out()
        .await
        .expect("allowed ISUP IAM transited to hlr-a");
    let msg = M3uaMessage::decode(&fwd).expect("decode m3ua");
    let pd = msg.protocol_data().expect("protocol data");
    assert_eq!(pd.dpc, DPC_HLR, "transited by DPC");
    assert_eq!(pd.si, SI_ISUP, "Service Indicator preserved");
    assert_eq!(
        pd.user_data, allowed,
        "allowed ISUP payload passed through untouched"
    );

    src.close();
    peer_a.close();
    handle.shutdown();
}

// ── Scenario 5: own-OPC loop guard ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_loop_guard_drops_own_opc() {
    let before = metrics::loops_detected(LoopKind::OwnOpc);

    let Some(handle) = start_node(LOADSHARE_NODE, "wire_own_opc").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    let (src, peer_a) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
    ) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            eprintln!("SKIP wire_own_opc: a peer connect failed");
            return;
        }
    };
    let mut peer_a = peer_a;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await
    );

    // An MSU whose OPC is our own point code: a message we originated coming
    // back. It must be dropped, never forwarded.
    let sccp = map_sccp(
        gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
        sri_sm_arg("15559999"),
        &AC_SRI_SM,
    );
    src.send_in(&m3ua_sccp(&sccp, NODE_PC, DPC_HLR, 0)).await;

    assert!(
        peer_a.drain(Duration::from_millis(500)).await.is_empty(),
        "own-OPC MSU was forwarded instead of dropped"
    );
    assert!(
        metrics::loops_detected(LoopKind::OwnOpc) > before,
        "own-OPC loop counter did not increment"
    );

    src.close();
    peer_a.close();
    handle.shutdown();
}

// ── Scenario 6: route-reflection loop guard ──────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_loop_guard_drops_route_reflection() {
    let before = metrics::loops_detected(LoopKind::RouteReflect);

    let Some(m2pa) = M2paPeer::spawn().await else {
        eprintln!("SKIP wire_route_reflect: m2pa peer bind failed");
        return;
    };
    let mut m2pa = m2pa;
    let Some(handle) = start_node(&dual_node(m2pa.port), "wire_route_reflect").await else {
        return;
    };
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    // The peer connects on hlr-a, which is itself an ASP of AS `hlr`.
    let Some(peer_a) = AspPeer::connect(hlr_a, 100).await else {
        eprintln!("SKIP wire_route_reflect: hlr-a connect failed");
        return;
    };
    let mut peer_a = peer_a;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await
    );

    // An MSU arriving on hlr-a addressed to 2000 resolves back to AS hlr, the
    // very association it came in on. The guard drops it; it is NOT silently
    // rerouted to the priority-2 linkset.
    let sccp = map_sccp(
        gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
        sri_sm_arg("15559999"),
        &AC_SRI_SM,
    );
    peer_a
        .send_in(&m3ua_sccp(&sccp, OPC_UPSTREAM, DPC_HLR, 0))
        .await;

    assert!(
        peer_a.drain(Duration::from_millis(500)).await.is_empty(),
        "route-reflected MSU was echoed back to hlr-a"
    );
    assert!(
        timeout(Duration::from_millis(500), m2pa.recv_out())
            .await
            .unwrap_or(None)
            .is_none(),
        "route-reflected MSU leaked to the alternate linkset"
    );
    assert!(
        metrics::loops_detected(LoopKind::RouteReflect) > before,
        "route-reflect loop counter did not increment"
    );

    peer_a.close();
    handle.shutdown();
}

// ── Scenario 6b: SCCP hop-counter loop guard (GTT translation) ───────────────

/// A GTT-translating node. `ingress` is an ASP of AS `caller` (so a violation
/// return has a path back to the originator); `hlr-a` is an ASP of AS `hlr`. A
/// called-party GT prefixed `1555` translates to DPC 2000 → AS hlr, which is the
/// `RouteTo` path the SCCP hop counter guards. We own SSN 8 only, so an SRI-SM to
/// SSN 6 does not terminate locally.
const GTT_NODE: &str = r#"
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: ingress, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
  - { id: hlr-a,   adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
application_servers:
  - { name: caller, traffic_mode: override, routing_context: 0,   asps: [ingress] }
  - { name: hlr,    traffic_mode: override, routing_context: 100, asps: [hlr-a] }
mtp3_routes:
  - { dpc: 2000, as: hlr, priority: 1 }
sccp:
  local_ssns: [8]
  gtt:
    - { match: {gt_prefix: "1555"}, to: {dpc: 2000, ssn: 6} }
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_hop_counter_guards_the_gtt_loop() {
    let before = metrics::loops_detected(LoopKind::HopCounter);

    let Some(handle) = start_node(GTT_NODE, "wire_hop_counter").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    let (src, peer_a) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
    ) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            eprintln!("SKIP wire_hop_counter: a peer connect failed");
            return;
        }
    };
    let mut src = src;
    let mut peer_a = peer_a;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await,
        "AS hlr never came up"
    );

    // 1. An XUDT with room to spare (hop 3) is translated by GTT and relayed to
    //    the AS with the hop counter decremented by one (3 → 2).
    src.send_in(&m3ua_sccp(&map_xudt(3, false), OPC_UPSTREAM, NODE_PC, 0))
        .await;
    let fwd = peer_a.recv_out().await.expect("XUDT translated to hlr-a");
    let (dpc, hop) = xudt_of_m3ua(&fwd).expect("forwarded frame is an XUDT");
    assert_eq!(dpc, DPC_HLR, "translated to the GTT result DPC");
    assert_eq!(hop, 2, "hop counter decremented by one at the translation");

    // 2. An XUDT that would exhaust its hop counter at this translation (hop 1 →
    //    0) is a loop: it is dropped (never forwarded to the AS), counted, and,
    //    because it asked to be returned on error, an XUDTS "hop counter
    //    violation" comes back to the originator.
    src.send_in(&m3ua_sccp(&map_xudt(1, true), OPC_UPSTREAM, NODE_PC, 0))
        .await;

    let ret = src
        .recv_out()
        .await
        .expect("XUDTS violation returned to caller");
    assert_eq!(
        xudts_cause_of_m3ua(&ret),
        Some(ReturnCause::HopCounterViolation.value()),
        "return is an XUDTS with cause hop counter violation (0x0C)"
    );
    assert!(
        peer_a.drain(Duration::from_millis(400)).await.is_empty(),
        "the exhausted XUDT leaked to the AS instead of being dropped"
    );
    assert!(
        metrics::loops_detected(LoopKind::HopCounter) > before,
        "hop-counter loop counter did not increment"
    );

    src.close();
    peer_a.close();
    handle.shutdown();
}

// ── Scenario 7: a sua association starts ──────────────────────────────────────

#[tokio::test]
async fn wire_sua_association_starts() {
    // A `sua` association is a working transport now: a node with a sua `server`
    // association binds and comes up (no longer refused at start). Real SCTP is
    // required; a bind failure prints a SKIP and passes.
    let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: s1, adaptation: sua, role: server, addrs: [127.0.0.1], port: 0 }
"#;
    let Some(handle) = start_node(yaml, "wire_sua_starts").await else {
        return;
    };
    assert!(
        handle.bound_addr("s1").is_some(),
        "sua association did not bind"
    );
    handle.shutdown();
}

// ── Scenario 8: MAP/CAP dialogue termination over the wire ───────────────────

/// A node that owns HLR (SSN 6) locally: an SRI-SM addressed to it terminates in
/// the dialogue engine rather than being forwarded.
const TERMINATION_NODE: &str = r#"
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: ingress, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }
sccp:
  local_ssns: [6]
"#;

const HLR_IMSI: &str = "001010000000042";
const SERVING_MSC: &str = "15550180";

/// A fake HLR answering SRI-SM with an imsi + serving-MSC number in a TCAP End.
struct WireHlr;
impl TerminationHandler for WireHlr {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        let res = RoutingInfoForSmRes {
            imsi: imsi_bytes(HLR_IMSI).into(),
            location_info_with_lmsi: LocationInfoWithLmsi {
                network_node_number: isdn(SERVING_MSC).into(),
                lmsi: None,
                gprs_node_indicator: None,
                additional_number: None,
            },
        };
        dlg.reply(op.operation_code, Some(rasn::ber::encode(&res).unwrap()));
        dlg.end();
    }
}

/// An SCCP UDT addressed route-on-SSN to a subsystem we own (no called-party GT,
/// so the router terminates it locally by SSN).
fn sccp_udt_to_ssn(called_ssn: SubsystemNumber, tcap_bytes: &[u8]) -> Vec<u8> {
    let called = SccpAddress::with_ssn(called_ssn, Some(NODE_PC as u16));
    let calling = SccpAddress::with_gt(
        GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: OUR_GT.to_string(),
        },
        Some(SubsystemNumber::Msc),
    );
    UnitData::new(called, calling, tcap_bytes.to_vec())
        .encode()
        .expect("encode sccp udt")
}

/// The (operation, imsi, node) recovered from a forwarded/terminated M3UA DATA
/// frame carrying a TCAP End with a ReturnResultLast.
fn decode_sri_sm_reply(payload: &[u8]) -> Option<(i64, Vec<u8>, Vec<u8>)> {
    let msg = M3uaMessage::decode(payload).ok()?;
    let pd = msg.protocol_data().ok()?;
    let udt = match SccpMessage::decode(&pd.user_data).ok()? {
        SccpMessage::Udt(u) => u,
        _ => return None,
    };
    let end = match tcap::decode(&udt.data).ok()? {
        TcapMessage::End(e) => e,
        _ => return None,
    };
    // An AARE must be present on the terminating End.
    let has_aare = matches!(
        end.dialogue_portion
            .as_ref()
            .and_then(|dp| dp.dialogue_pdu()),
        Some(DialoguePdu::Aare { .. })
    );
    assert!(has_aare, "the terminating End carries an AARE");
    match end.components?.into_iter().next()? {
        Component::ReturnResultLast(ReturnResult {
            result:
                Some(ReturnResultValue {
                    operation_code: OperationCode::Local(op),
                    parameter: Some(param),
                }),
            ..
        }) => {
            let res: RoutingInfoForSmRes = rasn::ber::decode(param.as_bytes()).ok()?;
            Some((
                op,
                res.imsi.to_vec(),
                res.location_info_with_lmsi.network_node_number.to_vec(),
            ))
        }
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_terminates_sri_sm_in_the_dialogue_engine() {
    let rx_before = metrics::msu_total(metrics::Dir::Rx, SI_SCCP);

    let Some(mut handle) = start_node(TERMINATION_NODE, "wire_terminate").await else {
        return;
    };

    // Register the fake HLR and attach the engine to the running node.
    let mut engine = DialogueEngine::new(Tcap::default());
    engine.register(
        6,
        gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
        Arc::new(WireHlr),
    );
    let engine = Arc::new(engine);
    handle.serve_dialogues(engine.clone());

    let ingress = handle.bound_addr("ingress").expect("ingress bound");
    let Some(mut peer) = AspPeer::connect(ingress, 0).await else {
        eprintln!("SKIP wire_terminate: ingress connect failed");
        return;
    };
    // Let the ASP reach Active so the SG delivers our DATA up the stack.
    sleep(Duration::from_millis(150)).await;

    // A genuine SRI-SM Begin (AARQ + Invoke), addressed to us route-on-SSN 6.
    let sccp = sccp_udt_to_ssn(
        SubsystemNumber::Hlr,
        &tcap_begin(
            gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
            sri_sm_arg("15559999"),
            &AC_SRI_SM,
        ),
    );
    peer.send_in(&m3ua_sccp(&sccp, OPC_UPSTREAM, NODE_PC, 0))
        .await;

    // The node terminates it and sends the ReturnResultLast back to us.
    let reply = peer.recv_out().await.expect("terminated reply frame");
    let (op, imsi, node) = decode_sri_sm_reply(&reply).expect("reply decodes to an SRI-SM result");
    assert_eq!(op, gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM);
    assert_eq!(imsi, imsi_bytes(HLR_IMSI), "the HLR IMSI came back");
    assert_eq!(node, isdn(SERVING_MSC), "the serving MSC number came back");

    // The single-shot dialogue is closed, and the inbound MSU was counted.
    assert_eq!(engine.open_dialogues(), 0, "the terminated dialogue closed");
    assert!(
        metrics::msu_total(metrics::Dir::Rx, SI_SCCP) > rx_before,
        "the terminated MSU was counted on the rx path"
    );

    peer.close();
    handle.shutdown();
}

// ── Scenario 9: SUA CLDT routed via GTT to an egress SUA AS ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_sua_cldt_routes_via_gtt_to_egress_as() {
    let Some(handle) = start_node(SUA_NODE, "wire_sua_cldt").await else {
        return;
    };
    let sua_in = handle.bound_addr("sua-in").expect("sua-in bound");
    let sua_out = handle.bound_addr("sua-out").expect("sua-out bound");

    let (src, egress) = match (
        SuaPeer::connect(sua_in, 0).await,
        SuaPeer::connect(sua_out, 200).await,
    ) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            eprintln!("SKIP wire_sua_cldt: a peer connect failed");
            return;
        }
    };
    let mut egress = egress;

    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("sccp-as".into())
        )
        .await,
        "sua AS sccp-as never came up"
    );

    // A SUA CLDT carrying a genuine SRI-SM Begin, called-party GT `15559999` that
    // the GTT rule (`1555` prefix) translates to dpc 2000 → AS sccp-as. The node
    // bridges CLDT → SCCP (an XUDT, since the CLDT carries an SS7 hop counter),
    // runs GTT, decrements the hop counter on the relay, and re-wraps the routed
    // SCCP-user as a CLDT toward the egress AS.
    let cldt = sua_cldt_map(
        gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
        sri_sm_arg("15559999"),
        &AC_SRI_SM,
        "15559999",
        15,
    );
    src.send_in(&cldt).await;

    let fwd = egress
        .recv_out()
        .await
        .expect("forwarded CLDT to egress AS");
    let (dst_gt, hop, op) = decode_cldt(&fwd);
    assert_eq!(
        dst_gt.as_deref(),
        Some("15559999"),
        "called-party GT preserved on the forwarded CLDT"
    );
    assert_eq!(
        op,
        Some(gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM),
        "SRI-SM operation intact on the forwarded CLDT"
    );
    assert_eq!(
        hop,
        Some(14),
        "SS7 hop counter decremented at the GTT relay"
    );

    src.close();
    egress.close();
    handle.shutdown();
}

// ── tshark gate: the forwarded frames dissect clean ──────────────────────────

fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build one SCTP packet (common header + a single DATA chunk) around `payload`.
fn sctp_packet(payload: &[u8], ppid: u32, stream: u16, tsn: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&2905u16.to_be_bytes());
    p.extend_from_slice(&2905u16.to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());

    let mut chunk = Vec::new();
    chunk.push(0x00); // DATA
    chunk.push(0x03); // B|E
    let data_len = 16 + payload.len();
    chunk.extend_from_slice(&(data_len as u16).to_be_bytes());
    chunk.extend_from_slice(&tsn.to_be_bytes());
    chunk.extend_from_slice(&stream.to_be_bytes());
    chunk.extend_from_slice(&0u16.to_be_bytes());
    chunk.extend_from_slice(&ppid.to_be_bytes());
    chunk.extend_from_slice(payload);
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    p.extend_from_slice(&chunk);
    p
}

fn eth_ipv4_sctp(sctp: &[u8]) -> Vec<u8> {
    let total_len = 20 + sctp.len();
    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0x00);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.push(64);
    ip.push(132); // SCTP
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(sctp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    eth
}

fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(&0xa1b2c3d4u32.to_ne_bytes())?;
    f.write_all(&2u16.to_ne_bytes())?;
    f.write_all(&4u16.to_ne_bytes())?;
    f.write_all(&0i32.to_ne_bytes())?;
    f.write_all(&0u32.to_ne_bytes())?;
    f.write_all(&262144u32.to_ne_bytes())?;
    f.write_all(&1u32.to_ne_bytes())?;
    for (i, frame) in frames.iter().enumerate() {
        f.write_all(&(i as u32).to_ne_bytes())?;
        f.write_all(&0u32.to_ne_bytes())?;
        f.write_all(&(frame.len() as u32).to_ne_bytes())?;
        f.write_all(&(frame.len() as u32).to_ne_bytes())?;
        f.write_all(frame)?;
    }
    Ok(())
}

/// Drive several MSUs through a live node, capture what it forwards, and dissect
/// the captured frames with tshark. The bytes under test are the node's real
/// egress, not a re-assembly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_forwarded_frames_dissect_clean_in_tshark() {
    let Some(mut m2pa) = M2paPeer::spawn().await else {
        eprintln!("SKIP wire_tshark: m2pa peer bind failed");
        return;
    };
    let Some(handle) = start_node(&dual_node(m2pa.port), "wire_tshark").await else {
        return;
    };
    let ingress = handle.bound_addr("ingress").expect("ingress");
    let hlr_a = handle.bound_addr("hlr-a").expect("hlr-a");

    let (src, peer_a) = match (
        AspPeer::connect(ingress, 0).await,
        AspPeer::connect(hlr_a, 100).await,
    ) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            eprintln!("SKIP wire_tshark: a peer connect failed");
            return;
        }
    };
    let mut peer_a = peer_a;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("hlr".into())
        )
        .await
    );
    assert!(
        wait_route(
            handle.router(),
            DPC_ADJ,
            &Destination::Linkset("transit".into())
        )
        .await
    );

    // Three MAP operations to the AS (M3UA egress) and one CAMEL initialDP to the
    // adjacent point code (M2PA egress).
    let map_msus = [
        map_sccp(
            gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
            sri_sm_arg("15559999"),
            &AC_SRI_SM,
        ),
        map_sccp(
            gsm_map::types::op_codes::UPDATE_LOCATION,
            update_location_arg("001010000000042"),
            &AC_NET_LOC_UP,
        ),
        map_sccp(
            gsm_map::types::op_codes::MO_FORWARD_SM,
            mo_forward_sm_arg(),
            &AC_MO_RELAY,
        ),
    ];
    for sccp in &map_msus {
        src.send_in(&m3ua_sccp(sccp, OPC_UPSTREAM, DPC_HLR, 0))
            .await;
    }
    let cap = cap_sccp("001010000000042");
    src.send_in(&m3ua_sccp(&cap, OPC_UPSTREAM, DPC_ADJ, 0))
        .await;
    // One INAP CS-1 initialDP (SSN 106) routed to the M3UA AS, so it transits
    // undecoded and forwards over M3UA alongside the MAP frames.
    let inap = inap_sccp();
    src.send_in(&m3ua_sccp(&inap, OPC_UPSTREAM, DPC_HLR, 0))
        .await;

    // Collect the forwarded frames: three MAP + one INAP over M3UA (PPID 3), one
    // CAMEL over M2PA (PPID 5). The M2PA frame is pulled between the MAP and INAP
    // M3UA frames so the reverse-path indices below stay stable.
    let mut frames: Vec<(Vec<u8>, u32, u16)> = Vec::new();
    for _ in 0..map_msus.len() {
        let f = peer_a.recv_out().await.expect("m3ua forward");
        frames.push((f, PPID_M3UA, 1));
    }
    let mf = m2pa.recv_out().await.expect("m2pa forward");
    frames.push((mf, PPID_M2PA, 1));
    let inf = peer_a.recv_out().await.expect("m3ua inap forward");
    frames.push((inf, PPID_M3UA, 1));

    src.close();
    peer_a.close();
    handle.shutdown();

    // Sanity on our own reverse path first (independent of tshark).
    assert_eq!(
        decode_m3ua(&frames[0].0).2,
        Some(gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM)
    );
    assert_eq!(
        decode_m2pa(&frames[3].0).2,
        Some(gsm_cap::op_codes::INITIAL_DP)
    );
    assert_eq!(
        decode_m3ua(&frames[4].0).2,
        Some(inap::op_codes::INITIAL_DP)
    );

    if !tshark_available() {
        eprintln!(
            "SKIP wire_tshark dissection: tshark not installed (transport path still proven)"
        );
        return;
    }

    let eth: Vec<Vec<u8>> = frames
        .iter()
        .enumerate()
        .map(|(i, (payload, ppid, stream))| {
            eth_ipv4_sctp(&sctp_packet(payload, *ppid, *stream, i as u32 + 1))
        })
        .collect();
    let path = std::env::temp_dir().join(format!("sigtran_wire_{}.pcap", std::process::id()));
    write_pcap(&path, &eth).expect("write pcap");

    // Full dissection: any BER error / malformed / expert error|warn fails.
    let out = Command::new("tshark")
        .args(["-r", path.to_str().unwrap(), "-d", "sctp.ppi==5,m2pa", "-V"])
        .output()
        .expect("run tshark -V");
    let text = String::from_utf8_lossy(&out.stdout);
    let bad: Vec<String> = text
        .lines()
        .filter(|l| {
            let ll = l.to_ascii_lowercase();
            ll.contains("ber error")
                || ll.contains("malformed")
                || (ll.contains("expert info") && (ll.contains("error") || ll.contains("warn")))
                || ll.contains("beyond the end")
                || ll.contains("dissector bug")
        })
        .map(|l| l.trim().to_string())
        .collect();

    // The protocol chain must actually reach the application layer, otherwise a
    // "clean" result would just mean tshark stopped at SCTP.
    let proto = Command::new("tshark")
        .args([
            "-r",
            path.to_str().unwrap(),
            "-d",
            "sctp.ppi==5,m2pa",
            "-T",
            "fields",
            "-e",
            "frame.protocols",
        ])
        .output()
        .expect("run tshark -T fields");
    let proto_text = String::from_utf8_lossy(&proto.stdout);
    let tcap_frames = proto_text.lines().filter(|l| l.contains("tcap")).count();
    let map_frames = proto_text.lines().filter(|l| l.contains("gsm_map")).count();
    let inap_frames = proto_text.lines().filter(|l| l.contains("inap")).count();

    let _ = std::fs::remove_file(&path);

    assert!(
        bad.is_empty(),
        "tshark flagged the forwarded frames:\n{}",
        bad.join("\n")
    );
    // All five frames (4 over M3UA, 1 over M2PA) must dissect down to TCAP, the
    // three MAP operations down to gsm_map, and the INAP initialDP down to the
    // INAP dissector. This proves the framing on both egress transports is
    // genuinely valid, not merely non-erroring at SCTP.
    assert!(
        tcap_frames >= 5,
        "tshark did not dissect every forwarded frame through TCAP (got {tcap_frames})"
    );
    assert!(
        map_frames >= 3,
        "tshark did not dissect the M3UA-forwarded MAP frames through gsm_map (got {map_frames})"
    );
    assert!(
        inap_frames >= 1,
        "tshark did not dissect the INAP initialDP through the INAP dissector (got {inap_frames})"
    );
}

/// The node-emitted SUA CLDT (PPID 4) dissects clean through Wireshark's SUA
/// dissector: no Malformed / expert error, and the chain reaches the SUA
/// adaptation layer with the SCCP-user address parameters read back.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn wire_sua_cldt_dissects_clean_in_tshark() {
    let Some(handle) = start_node(SUA_NODE, "wire_sua_tshark").await else {
        return;
    };
    let sua_in = handle.bound_addr("sua-in").expect("sua-in bound");
    let sua_out = handle.bound_addr("sua-out").expect("sua-out bound");

    let (src, egress) = match (
        SuaPeer::connect(sua_in, 0).await,
        SuaPeer::connect(sua_out, 200).await,
    ) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            eprintln!("SKIP wire_sua_tshark: a peer connect failed");
            return;
        }
    };
    let mut egress = egress;
    assert!(
        wait_route(
            handle.router(),
            DPC_HLR,
            &Destination::ApplicationServer("sccp-as".into())
        )
        .await
    );

    let cldt = sua_cldt_map(
        gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM,
        sri_sm_arg("15559999"),
        &AC_SRI_SM,
        "15559999",
        15,
    );
    src.send_in(&cldt).await;
    let fwd = egress.recv_out().await.expect("forwarded CLDT");

    src.close();
    egress.close();
    handle.shutdown();

    // Reverse-path sanity first (independent of tshark).
    let (dst_gt, _hop, op) = decode_cldt(&fwd);
    assert_eq!(dst_gt.as_deref(), Some("15559999"));
    assert_eq!(op, Some(gsm_map::types::op_codes::SEND_ROUTING_INFO_FOR_SM));

    if !tshark_available() {
        eprintln!(
            "SKIP wire_sua_tshark dissection: tshark not installed (transport path still proven)"
        );
        return;
    }

    // PPID 4 auto-maps to SUA in Wireshark, so no `-d` override is needed.
    let frame = eth_ipv4_sctp(&sctp_packet(&fwd, PPID_SUA, 1, 1));
    let path = std::env::temp_dir().join(format!("sigtran_sua_{}.pcap", std::process::id()));
    write_pcap(&path, &[frame]).expect("write pcap");

    let out = Command::new("tshark")
        .args(["-r", path.to_str().unwrap(), "-V"])
        .output()
        .expect("run tshark -V");
    let text = String::from_utf8_lossy(&out.stdout);
    let bad: Vec<String> = text
        .lines()
        .filter(|l| {
            let ll = l.to_ascii_lowercase();
            ll.contains("malformed")
                || (ll.contains("[expert info") && (ll.contains("error") || ll.contains("warn")))
                || ll.contains("beyond the end")
                || ll.contains("dissector bug")
        })
        .map(|l| l.trim().to_string())
        .collect();

    let proto = Command::new("tshark")
        .args([
            "-r",
            path.to_str().unwrap(),
            "-T",
            "fields",
            "-e",
            "frame.protocols",
        ])
        .output()
        .expect("run tshark -T fields");
    let proto_text = String::from_utf8_lossy(&proto.stdout);

    let _ = std::fs::remove_file(&path);

    assert!(
        bad.is_empty(),
        "tshark flagged the SUA CLDT:\n{}\n--- dissection ---\n{}",
        bad.join("\n"),
        text
    );
    let low = text.to_ascii_lowercase();
    // The chain must reach the SUA adaptation layer, with the CLDT type and the
    // SCCP-user address parameter (the called-party global title) read back, not
    // merely stop at SCTP.
    assert!(low.contains("adaptation layer"), "no SUA layer:\n{text}");
    assert!(
        low.contains("connectionless data transfer") || low.contains("cldt"),
        "message type not CLDT:\n{text}"
    );
    assert!(
        text.contains("15559999"),
        "called-party GT digits absent from the SUA dissection:\n{text}"
    );
    assert!(
        proto_text.lines().any(|l| l.contains("sua")),
        "frame.protocols never reached sua: {proto_text}"
    );
}
