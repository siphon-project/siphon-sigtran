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
//! * the two transfer-path loop guards (own-OPC, route-reflection),
//! * the `sua` adaptation reserved-but-refused,
//! * a tshark dissection gate over the forwarded frames.
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
use gsm_map::operations::sri_sm::RoutingInfoForSmArg;
use gsm_map::types::{SmRpDa, SmRpOa};

use m2pa::{LinkState, LinkStatusMessage, M2paMessage, M2paStateMachine};
use m3ua::{M3uaMessage, MessageType, ProtocolData};
use mtp3::NetworkIndicator;
use sccp::{GlobalTitle, SccpAddress, SccpMessage, SubsystemNumber, UnitData};
use tcap::dialogue::DialoguePortion;
use tcap::{Begin, Component, Invoke, OperationCode, TcapMessage};

use siphon_sigtran::config::Config;
use siphon_sigtran::metrics::{self, LoopKind};
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

/// Build the SCCP bytes for the CAMEL initialDP operation.
fn cap_sccp(imsi: &str) -> Vec<u8> {
    sccp_udt(
        SubsystemNumber::Cap,
        &tcap_begin(gsm_cap::op_codes::INITIAL_DP, initial_dp_arg(imsi), &AC_CAP),
    )
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

// ── Scenario 7: sua reserved but refused ─────────────────────────────────────

#[tokio::test]
async fn wire_sua_adaptation_is_reserved_and_refused() {
    // Parsing accepts a `sua` association; starting the transport must refuse it
    // with a clear "not implemented", no SCTP required.
    let yaml = r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: s1, adaptation: sua, role: client, addrs: [127.0.0.1], port: 14001 }
"#;
    let cfg = Config::parse(yaml).expect("sua config parses");
    let router = Arc::new(Router::new(&cfg));
    let msg = match TransportHandle::start(&cfg, router).await {
        Ok(_) => panic!("sua must be refused at start, but the transport came up"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("sua") && msg.contains("not implemented"),
        "unexpected error for reserved sua: {msg}"
    );
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

    // Collect the forwarded frames: three M3UA (PPID 3), one M2PA (PPID 5).
    let mut frames: Vec<(Vec<u8>, u32, u16)> = Vec::new();
    for _ in 0..map_msus.len() {
        let f = peer_a.recv_out().await.expect("m3ua forward");
        frames.push((f, PPID_M3UA, 1));
    }
    let mf = m2pa.recv_out().await.expect("m2pa forward");
    frames.push((mf, PPID_M2PA, 1));

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

    let _ = std::fs::remove_file(&path);

    assert!(
        bad.is_empty(),
        "tshark flagged the forwarded frames:\n{}",
        bad.join("\n")
    );
    // All four frames (3 over M3UA, 1 over M2PA) must dissect down to TCAP, and
    // the three MAP operations down to gsm_map. This proves the framing on both
    // egress transports is genuinely valid, not merely non-erroring at SCTP.
    assert!(
        tcap_frames >= 4,
        "tshark did not dissect every forwarded frame through TCAP (got {tcap_frames})"
    );
    assert!(
        map_frames >= 3,
        "tshark did not dissect the M3UA-forwarded MAP frames through gsm_map (got {map_frames})"
    );
}
