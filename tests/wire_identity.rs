//! Who a listening association accepts, on the wire.
//!
//! The node is started on kernel SCTP loopback. Its peers are the hand-written
//! ones of `tests/m3ua_peer` and `tests/m2pa_peer`, bound to a loopback
//! address of their own before they connect: 127.0.0.x are distinct source
//! addresses, so "the configured peer" and "someone else" differ the way two
//! hosts do, and a peer bound to two of them is multihomed. What the node
//! sends to the peer it accepted is read back by Wireshark;
//! `SIGTRAN_REQUIRE_TSHARK=1` makes a missing `tshark` a failure. Without
//! kernel SCTP every test prints SKIP.
//!
//! A refused peer is refused after the SCTP handshake: the kernel answers an
//! INIT by itself and hands over an association that is established already.
//! The node reads the peer's addresses from it and aborts it, so the peer
//! sees the association come up and then an ABORT.

#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_sctp::{
    AssocChangeState, Notification, RecvResult, SctpAssociation, SctpConfig, SctpListener,
};
use tokio::time::{sleep, timeout, Instant};

use siphon_sigtran::config::Config;
use siphon_sigtran::metrics::{self, Refusal};
use siphon_sigtran::routing::Router;
use siphon_sigtran::transport::AsState;
use siphon_sigtran::TransportHandle;

mod m2pa_peer;
mod m3ua_peer;
use m2pa_peer::{FAST_LINK_TEST, FAST_M2PA, FAST_MTP3};
use m3ua_peer::*;

const NODE: u32 = 1000;
const HLR: u32 = 6000;
const MSC: u32 = 6100;
const ADJACENT: u32 = 3000;
const RC_HLR: u32 = 100;
const RC_MSC: u32 = 200;
/// National network.
const NI: u8 = 2;
/// The MTP testing user part: Wireshark does not look inside.
const SI_USER: u8 = 8;

const FIELDS: [&str; 5] = [
    "m3ua.message_class",
    "m3ua.message_type",
    "m3ua.routing_context",
    "m3ua.protocol_data_opc",
    "m3ua.protocol_data_dpc",
];

// ── Addresses ────────────────────────────────────────────────────────────────

static NEXT: AtomicU8 = AtomicU8::new(1);

/// A loopback address no other test of this suite uses: tests run in
/// parallel, and what one of them binds must not be what another expects to
/// be free.
fn fresh() -> String {
    format!("127.0.7.{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A port that is free on `ip`: bound once to learn it, then released.
fn free_port(ip: &str) -> Option<u16> {
    let probe = SctpListener::bind(format!("{ip}:0").parse().ok()?).ok()?;
    Some(probe.local_addr().ok()?.port())
}

/// An association to the node from chosen local addresses. Port 0 is any.
async fn dial(from: &[&str], port: u16, to: SocketAddr) -> Option<Arc<SctpAssociation>> {
    let local: Vec<SocketAddr> = from
        .iter()
        .filter_map(|ip| format!("{ip}:{port}").parse().ok())
        .collect();
    let cfg = SctpConfig::new().nodelay(true);
    let assoc = timeout(
        Duration::from_secs(5),
        SctpAssociation::connect_from(&local, &[to], &cfg),
    )
    .await
    .ok()?
    .ok()?;
    Some(Arc::new(assoc))
}

/// A second association for one that is established is aborted after the
/// node has waited two seconds for the first to end (it may be the same peer
/// that closed and dialled again).
const WITHIN: Duration = Duration::from_secs(4);

/// How an association the node did not want ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// The node aborted it (SCTP ABORT: communication lost).
    Aborted,
    /// The node sent something on it.
    Served(Vec<u8>),
    /// Nothing happened to it.
    Kept,
}

/// What becomes of an association within `wait`.
async fn fate(assoc: &SctpAssociation, wait: Duration) -> Ended {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, assoc.recv_msg()).await {
            Err(_) => return Ended::Kept,
            Ok(Err(_)) => return Ended::Aborted,
            Ok(Ok(RecvResult::Data(data, _))) => return Ended::Served(data),
            Ok(Ok(RecvResult::Notification(Notification::AssocChange(change))))
                if change.state == AssocChangeState::CommLost =>
            {
                return Ended::Aborted
            }
            Ok(Ok(RecvResult::Notification(_))) => {}
        }
    }
}

/// Wait until a refusal counter has moved past `before`.
async fn refused(reason: Refusal, before: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if metrics::association_refusals(reason) > before {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

// ── The node ─────────────────────────────────────────────────────────────────

struct Node {
    handle: TransportHandle,
}

impl Node {
    async fn start(what: &str, yaml: &str) -> Option<Self> {
        let cfg = Config::parse(yaml).expect("config parses");
        let router = Arc::new(Router::new(&cfg));
        match TransportHandle::start(&cfg, router).await {
            Ok(handle) => Some(Self { handle }),
            Err(error) => {
                eprintln!("SKIP {what}: transport did not start ({error})");
                None
            }
        }
    }

    fn addr(&self, association: &str) -> SocketAddr {
        self.handle.bound_addr(association).expect("bound")
    }

    async fn server(&self, name: &str, wanted: AsState) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if self.handle.registry().server_state(name) == Some(wanted) {
                return true;
            }
            sleep(Duration::from_millis(5)).await;
        }
        false
    }

    async fn carrying(&self, association: &str, wanted: bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let slot = self.handle.registry().slot(association).expect("slot");
            if slot.is_carrying() == wanted {
                return true;
            }
            sleep(Duration::from_millis(5)).await;
        }
        false
    }
}

/// A signalling gateway with two application servers of one ASP each. Each
/// association is written by the test: where it listens and whom it accepts.
fn gateway(hlr_a: &str, msc_a: &str) -> String {
    format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
application_servers:
  - {{ name: hlr, traffic_mode: override, routing_context: {RC_HLR}, asps: [hlr-a], recovery_ms: 200 }}
  - {{ name: msc, traffic_mode: override, routing_context: {RC_MSC}, asps: [msc-a], recovery_ms: 200 }}
associations:
  - {{ id: hlr-a, adaptation: m3ua, role: server, {hlr_a} }}
  - {{ id: msc-a, adaptation: m3ua, role: server, {msc_a} }}
mtp3_routes:
  - {{ dpc: {HLR}, as: hlr, priority: 1 }}
  - {{ dpc: {MSC}, as: msc, priority: 1 }}
"#
    )
}

fn asp(assoc: Arc<SctpAssociation>) -> Peer {
    Peer {
        assoc,
        log: Vec::new(),
    }
}

/// Bring an ASP up and make it active in the server of `context`; what the
/// node says on the way is returned (ASP Up Ack, Notify, ASP Active Ack) and
/// what follows it is read and forgotten.
async fn activate(peer: &mut Peer, context: u32) -> Vec<Received> {
    let mut said = Vec::new();
    peer.send(&asp_up(None)).await;
    said.push(peer.expect(ASPUP_ACK).await);
    said.push(peer.expect(NTFY).await);
    said.push(peer.activate(context).await);
    peer.drain(Duration::from_millis(150)).await;
    peer.log.clear();
    said
}

fn user(context: u32, opc: u32, dpc: u32, tag: u8) -> Vec<u8> {
    data(Some(context), opc, dpc, SI_USER, NI, 0, &[tag, 0x55])
}

/// The next DATA the node sends to a peer, whatever management it sends first.
async fn next_data(peer: &mut Peer) -> Option<Received> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let got = peer.within(Duration::from_millis(500)).await?;
        if got.is(DATA) {
            return Some(got);
        }
    }
    None
}

fn read(what: &str, received: &[&Received]) -> Option<m2pa_peer::Read> {
    let read = m2pa_peer::wireshark_every(&frames(received), &FIELDS)?;
    read.clean();
    eprintln!("{what}: as Wireshark reads it:\n{}", read.lines());
    Some(read)
}

// ── The reported fault ───────────────────────────────────────────────────────

/// "With an active ASP on the association, a second SCTP connection to the
/// port that sends nothing at all receives the next DATA for that application
/// server, and the real ASP receives nothing."
///
/// The association has no `peer_addrs`, as every file written before the key
/// existed: it takes whoever connects first, and nobody after that. An ASP is
/// one SCTP endpoint (RFC 4666 1.2, "An ASP contains an SCTP endpoint"), so
/// the second, from another address, is not the ASP.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_second_connection_does_not_get_the_traffic_of_an_active_asp() {
    let what = "a_second_connection_does_not_get_the_traffic";
    let any = "addrs: [127.0.0.1], port: 0";
    let Some(node) = Node::start(what, &gateway(any, any)).await else {
        return;
    };
    let mut hlr = asp(dial(&["127.0.0.2"], 0, node.addr("hlr-a"))
        .await
        .expect("hlr"));
    activate(&mut hlr, RC_HLR).await;
    let mut msc = asp(dial(&["127.0.0.3"], 0, node.addr("msc-a"))
        .await
        .expect("msc"));
    activate(&mut msc, RC_MSC).await;
    hlr.drain(Duration::from_millis(150)).await;
    assert!(node.server("hlr", AsState::Active).await);

    // Someone else connects to the port of `hlr-a` and says nothing.
    let before = metrics::association_refusals(Refusal::Duplicate);
    let second = dial(&["127.0.0.4"], 0, node.addr("hlr-a"))
        .await
        .expect("the kernel completes the handshake by itself");
    let ended = fate(&second, WITHIN).await;

    // Traffic for the server still reaches the ASP that is active in it.
    msc.transfer(&user(RC_MSC, MSC, HLR, 0x41)).await;
    let delivered = next_data(&mut hlr).await;
    let stolen = fate(&second, Duration::from_millis(300)).await;
    assert!(
        !matches!(stolen, Ended::Served(_)),
        "the second connection received what was for the ASP: {stolen:02x?}"
    );
    let delivered = delivered.expect("the DATA reaches the active ASP");
    let (opc, dpc, si, ..) = delivered.protocol_data().expect("protocol data");
    assert_eq!((opc, dpc, si), (MSC, HLR, SI_USER));
    assert_eq!(ended, Ended::Aborted, "the second connection is aborted");
    assert!(refused(Refusal::Duplicate, before).await, "and counted");
    assert_eq!(
        node.handle.registry().server_state("hlr"),
        Some(AsState::Active),
        "the server never left ASP-ACTIVE"
    );

    if let Some(read) = read(what, &[&delivered]) {
        assert_eq!(read.column("m3ua.message_class"), ["1"]);
        assert_eq!(read.column("m3ua.message_type"), ["1"]);
        assert_eq!(read.column("m3ua.routing_context"), ["100"]);
        assert_eq!(read.column("m3ua.protocol_data_opc"), ["6100"]);
        assert_eq!(read.column("m3ua.protocol_data_dpc"), ["6000"]);
    }
    node.handle.shutdown();
}

// ── The configured peer ──────────────────────────────────────────────────────

/// An association that lists its peer accepts that peer and aborts anyone
/// else, whatever they send.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_peer_no_association_lists_is_aborted() {
    let what = "a_peer_no_association_lists";
    let hlr_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.2]";
    let msc_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.3]";
    let Some(node) = Node::start(what, &gateway(hlr_a, msc_a)).await else {
        return;
    };

    // A stranger, before the peer and while nothing is established: it is
    // not "first come".
    let before = metrics::association_refusals(Refusal::UnknownPeer);
    let stranger = dial(&["127.0.0.9"], 0, node.addr("hlr-a"))
        .await
        .expect("the kernel completes the handshake by itself");
    // What it sends is never read.
    let _ = stranger.send(&asp_up(None), 0, PPID_M3UA).await;
    assert_eq!(
        fate(&stranger, Duration::from_secs(2)).await,
        Ended::Aborted
    );
    assert!(refused(Refusal::UnknownPeer, before).await);
    assert_eq!(
        node.handle.registry().server_state("hlr"),
        Some(AsState::Down)
    );

    // The peer the association lists.
    let mut hlr = asp(dial(&["127.0.0.2"], 0, node.addr("hlr-a"))
        .await
        .expect("hlr"));
    let said = activate(&mut hlr, RC_HLR).await;
    assert!(node.server("hlr", AsState::Active).await);

    // The stranger again, now that the association is established.
    let before = metrics::association_refusals(Refusal::UnknownPeer);
    let stranger = dial(&["127.0.0.9"], 0, node.addr("hlr-a"))
        .await
        .expect("handshake");
    assert_eq!(
        fate(&stranger, Duration::from_secs(2)).await,
        Ended::Aborted
    );
    assert!(refused(Refusal::UnknownPeer, before).await);
    assert_eq!(
        node.handle.registry().server_state("hlr"),
        Some(AsState::Active)
    );

    let said: Vec<&Received> = said.iter().collect();
    if let Some(read) = read(what, &said) {
        // ASP Up Ack, Notify, ASP Active Ack.
        assert_eq!(read.column("m3ua.message_class"), ["3", "0", "4"]);
        assert_eq!(read.column("m3ua.message_type"), ["4", "1", "3"]);
        assert_eq!(read.get(2, "m3ua.routing_context"), "100");
    }
    node.handle.shutdown();
}

/// "A signalling gateway normally listens on one port and tells its ASPs
/// apart by their address": two associations on one local address and port.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn associations_on_one_port_are_told_apart_by_the_address_of_the_peer() {
    let what = "associations_on_one_port";
    let ip = fresh();
    let Some(port) = free_port(&ip) else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let hlr_a = format!("addrs: [{ip}], port: {port}, peer_addrs: [127.0.0.2]");
    let msc_a = format!("addrs: [{ip}], port: {port}, peer_addrs: [127.0.0.3]");
    // Kernel SCTP is there (a port was found): a node that does not start
    // is the fault this test is about, not a reason to skip.
    let cfg = Config::parse(&gateway(&hlr_a, &msc_a)).expect("config parses");
    let handle = TransportHandle::start(&cfg, Arc::new(Router::new(&cfg)))
        .await
        .expect("two associations listen on one address and port");
    let node = Node { handle };
    assert_eq!(node.addr("hlr-a"), node.addr("msc-a"), "one endpoint");
    let endpoint = node.addr("hlr-a");
    assert_eq!(endpoint.port(), port);

    // The later association of the file first: the order of arrival says
    // nothing.
    let mut msc = asp(dial(&["127.0.0.3"], 0, endpoint).await.expect("msc"));
    activate(&mut msc, RC_MSC).await;
    let mut hlr = asp(dial(&["127.0.0.2"], 0, endpoint).await.expect("hlr"));
    activate(&mut hlr, RC_HLR).await;
    msc.drain(Duration::from_millis(150)).await;
    assert!(node.server("hlr", AsState::Active).await);
    assert!(node.server("msc", AsState::Active).await);

    // The peer at 127.0.0.3 is `msc-a`: the context of server `hlr` is not
    // one of its own.
    msc.send(&asp_active(None, &[RC_HLR])).await;
    let foreign = msc.expect(ERR).await;
    assert_eq!(foreign.error_code(), Some(INVALID_ROUTING_CONTEXT));

    // Traffic crosses from each to the other and to no one else.
    msc.transfer(&user(RC_MSC, MSC, HLR, 0x51)).await;
    let north = next_data(&mut hlr).await.expect("for the server of hlr-a");
    hlr.transfer(&user(RC_HLR, HLR, MSC, 0x52)).await;
    let south = next_data(&mut msc).await.expect("for the server of msc-a");
    assert_eq!(north.protocol_data().map(|p| (p.0, p.1)), Some((MSC, HLR)));
    assert_eq!(south.protocol_data().map(|p| (p.0, p.1)), Some((HLR, MSC)));

    // An address neither lists is nobody's on this endpoint.
    let before = metrics::association_refusals(Refusal::UnknownPeer);
    let stranger = dial(&["127.0.0.9"], 0, endpoint).await.expect("handshake");
    assert_eq!(
        fate(&stranger, Duration::from_secs(2)).await,
        Ended::Aborted
    );
    assert!(refused(Refusal::UnknownPeer, before).await);

    if let Some(read) = read(what, &[&north, &south]) {
        assert_eq!(read.column("m3ua.routing_context"), ["100", "200"]);
        assert_eq!(read.column("m3ua.protocol_data_opc"), ["6100", "6000"]);
        assert_eq!(read.column("m3ua.protocol_data_dpc"), ["6000", "6100"]);
    }
    node.handle.shutdown();
}

/// A multihomed peer is known by all of its addresses: RFC 4165 4.1.2 has
/// each endpoint know "the IP address (or IP addresses, if multi-homing is
/// used) and port number of both endpoints", and RFC 9260 5.1.2 C has the
/// receiver of an INIT "derive and record all the transport addresses from
/// the received chunk". A peer that brings an address the association does
/// not list is not that peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_multihomed_peer_is_known_by_all_of_its_addresses() {
    let what = "a_multihomed_peer";
    let hlr_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.2, 127.0.0.5]";
    let msc_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.3]";
    let Some(node) = Node::start(what, &gateway(hlr_a, msc_a)).await else {
        return;
    };

    // One listed address and one that is not.
    let before = metrics::association_refusals(Refusal::UnlistedAddress);
    let half = dial(&["127.0.0.2", "127.0.0.9"], 0, node.addr("hlr-a"))
        .await
        .expect("handshake");
    assert_eq!(fate(&half, Duration::from_secs(2)).await, Ended::Aborted);
    assert!(refused(Refusal::UnlistedAddress, before).await);

    // Both of its addresses.
    let both = dial(&["127.0.0.2", "127.0.0.5"], 0, node.addr("hlr-a"))
        .await
        .expect("hlr");
    let mut presented = both.local_addrs().expect("local addresses");
    presented.sort();
    assert_eq!(presented.len(), 2, "the peer is multihomed: {presented:?}");
    let mut hlr = asp(both);
    activate(&mut hlr, RC_HLR).await;
    assert!(node.server("hlr", AsState::Active).await);
    drop(hlr);
    assert!(node.server("hlr", AsState::Down).await || node.server("hlr", AsState::Pending).await);

    // One of them alone is that peer too.
    let mut hlr = asp(dial(&["127.0.0.5"], 0, node.addr("hlr-a"))
        .await
        .expect("hlr"));
    activate(&mut hlr, RC_HLR).await;
    assert!(node.server("hlr", AsState::Active).await);
    node.handle.shutdown();
}

/// `peer_port`: the remote port is part of who the peer is.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn the_port_of_the_peer_is_checked_when_one_is_configured() {
    let what = "the_port_of_the_peer";
    let Some(port) = free_port("127.0.0.2") else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let hlr_a = format!("addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.2], peer_port: {port}");
    let msc_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.3]";
    let Some(node) = Node::start(what, &gateway(&hlr_a, msc_a)).await else {
        return;
    };

    // The right address from another port.
    let before = metrics::association_refusals(Refusal::PeerPort);
    let other = dial(&["127.0.0.2"], 0, node.addr("hlr-a"))
        .await
        .expect("handshake");
    assert_ne!(other.local_addrs().expect("local")[0].port(), port);
    assert_eq!(fate(&other, Duration::from_secs(2)).await, Ended::Aborted);
    assert!(refused(Refusal::PeerPort, before).await);

    let mut hlr = asp(dial(&["127.0.0.2"], port, node.addr("hlr-a"))
        .await
        .expect("hlr"));
    activate(&mut hlr, RC_HLR).await;
    assert!(node.server("hlr", AsState::Active).await);
    node.handle.shutdown();
}

/// A second association from the address the association lists does not
/// displace the first. It is a new association and not a restart of the
/// first: RFC 9260 5.2 has an INIT from the same addresses and port processed
/// "as part of its current association", so what `accept` returns while one
/// is established came from another port.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_second_association_from_the_listed_address_does_not_displace_the_first() {
    let what = "a_second_association_from_the_listed_address";
    let hlr_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.2]";
    let msc_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.3]";
    let Some(node) = Node::start(what, &gateway(hlr_a, msc_a)).await else {
        return;
    };
    let mut hlr = asp(dial(&["127.0.0.2"], 0, node.addr("hlr-a"))
        .await
        .expect("hlr"));
    activate(&mut hlr, RC_HLR).await;
    let mut msc = asp(dial(&["127.0.0.3"], 0, node.addr("msc-a"))
        .await
        .expect("msc"));
    activate(&mut msc, RC_MSC).await;
    hlr.drain(Duration::from_millis(150)).await;

    let before = metrics::association_refusals(Refusal::Duplicate);
    let second = dial(&["127.0.0.2"], 0, node.addr("hlr-a"))
        .await
        .expect("handshake");
    // It even asks to come up.
    let _ = second.send(&asp_up(None), 0, PPID_M3UA).await;
    assert_eq!(fate(&second, WITHIN).await, Ended::Aborted);
    assert!(refused(Refusal::Duplicate, before).await);

    assert_eq!(
        node.handle.registry().server_state("hlr"),
        Some(AsState::Active)
    );
    msc.transfer(&user(RC_MSC, MSC, HLR, 0x61)).await;
    let delivered = next_data(&mut hlr).await.expect("to the first association");
    // Nothing told the first that anything happened.
    hlr.quiet(Duration::from_millis(200)).await;

    if let Some(read) = read(what, &[&delivered]) {
        assert_eq!(read.column("m3ua.protocol_data_dpc"), ["6000"]);
    }
    node.handle.shutdown();
}

/// Once the association of a peer has ended, the peer is accepted again: at
/// once, and every time.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_peer_is_accepted_again_once_its_association_has_ended() {
    let what = "a_peer_is_accepted_again";
    let hlr_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.2]";
    let msc_a = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.3]";
    let Some(node) = Node::start(what, &gateway(hlr_a, msc_a)).await else {
        return;
    };
    for round in 0..8 {
        let mut hlr = asp(dial(&["127.0.0.2"], 0, node.addr("hlr-a"))
            .await
            .expect("hlr"));
        peer_comes_up(&mut hlr, round).await;
        hlr.activate(RC_HLR).await;
        // Closed, and dialled again in the next round without waiting for
        // the node to have noticed.
        drop(hlr);
    }
    node.handle.shutdown();
}

async fn peer_comes_up(peer: &mut Peer, round: usize) {
    peer.send(&asp_up(None)).await;
    let ack = peer
        .within(Duration::from_secs(3))
        .await
        .unwrap_or_else(|| panic!("round {round}: the peer was not accepted"));
    assert!(ack.is(ASPUP_ACK), "round {round}: {:?}", ack.kind);
    peer.expect(NTFY).await;
}

// ── M2PA ─────────────────────────────────────────────────────────────────────

/// A node that listens for one M2PA link.
fn linked(link: &str) -> String {
    format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: a-0, adaptation: m2pa, role: server, {link}, adjacent_pc: {ADJACENT}, m2pa: {FAST_M2PA} }}
linksets:
  - {{ name: a, links: [{{assoc: a-0}}], link_test: {FAST_LINK_TEST} }}
mtp3_routes:
  - {{ dpc: 2000, linkset: a, priority: 1 }}
"#
    )
}

/// RFC 4165 4.1.2: "Each MTP link corresponds to an SCTP association." A
/// second association for a link that is in service is not the link; before,
/// it took the link over and the link failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_link_in_service_is_not_taken_by_a_second_association() {
    let what = "a_link_in_service_is_not_taken";
    let Some(node) = Node::start(what, &linked("addrs: [127.0.0.1], port: 0")).await else {
        return;
    };
    let assoc = dial(&["127.0.0.2"], 0, node.addr("a-0"))
        .await
        .expect("link");
    let mut link = m2pa_peer::Peer::new(assoc, ADJACENT, NODE, NI);
    link.bring_up().await;
    assert!(node.carrying("a-0", true).await, "the link is in service");
    link.quiet(Duration::from_millis(450)).await;

    let before = metrics::association_refusals(Refusal::Duplicate);
    let second = dial(&["127.0.0.4"], 0, node.addr("a-0"))
        .await
        .expect("handshake");
    assert_eq!(
        fate(&second, WITHIN).await,
        Ended::Aborted,
        "the second association is aborted, and is sent no Link Status"
    );
    assert!(refused(Refusal::Duplicate, before).await);

    // The link did not notice: nothing is sent on it, and it carries.
    link.quiet(Duration::from_millis(300)).await;
    assert!(node.carrying("a-0", true).await);
    assert!(
        node.handle.router().is_reachable("default", 2000),
        "the destination behind the link stayed accessible"
    );
    node.handle.shutdown();
}

/// A link that lists its adjacent point aligns with it and with no one else,
/// and again after the association has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_link_accepts_only_its_adjacent_point() {
    let what = "a_link_accepts_only_its_adjacent_point";
    let link = "addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.2]";
    let Some(node) = Node::start(what, &linked(link)).await else {
        return;
    };
    let before = metrics::association_refusals(Refusal::UnknownPeer);
    let stranger = dial(&["127.0.0.9"], 0, node.addr("a-0"))
        .await
        .expect("handshake");
    assert_eq!(
        fate(&stranger, Duration::from_secs(2)).await,
        Ended::Aborted
    );
    assert!(refused(Refusal::UnknownPeer, before).await);

    for _ in 0..2 {
        let assoc = dial(&["127.0.0.2"], 0, node.addr("a-0"))
            .await
            .expect("link");
        let mut link = m2pa_peer::Peer::new(assoc, ADJACENT, NODE, NI);
        link.bring_up().await;
        assert!(node.carrying("a-0", true).await);
        // What the node sent is M2PA, as Wireshark reads it.
        let statuses: Vec<m2pa_peer::Frame> =
            link.log.iter().filter(|f| f.is_status()).cloned().collect();
        if let Some(read) = m2pa_peer::wireshark(&statuses, &["m2pa.status"]) {
            read.clean();
            assert!(read.column("m2pa.status").contains(&"1"), "Alignment");
            assert!(read.column("m2pa.status").contains(&"4"), "Ready");
        }
        drop(link);
        assert!(node.carrying("a-0", false).await);
    }
    node.handle.shutdown();
}

// ── SUA ──────────────────────────────────────────────────────────────────────

const PPID_SUA: u32 = 4;
/// SUA connectionless data transfer (RFC 3868 3.1.2: class 7, type 1).
const CLDT: (u8, u8) = (7, 1);
const SUA_AS: u32 = 2000;
const RC_SUA: u32 = 300;

/// An M3UA server in front and a SUA server behind: an SCCP unitdata from the
/// M3UA ASP for the point code of the SUA server leaves as a CLDT.
fn bridged() -> String {
    format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
application_servers:
  - {{ name: msc, traffic_mode: override, routing_context: {RC_MSC}, asps: [msc-a], recovery_ms: 200 }}
  - {{ name: sccp-as, traffic_mode: override, routing_context: {RC_SUA}, asps: [sua-a] }}
associations:
  - {{ id: msc-a, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }}
  - {{ id: sua-a, adaptation: sua, role: server, addrs: [127.0.0.1], port: 0 }}
mtp3_routes:
  - {{ dpc: {MSC}, as: msc, priority: 1 }}
  - {{ dpc: {SUA_AS}, as: sccp-as, priority: 1 }}
"#
    )
}

/// An SCCP unitdata (ITU-T Q.713 4.10): message type, protocol class, three
/// pointers, called and calling party address (point code and subsystem
/// number, routed on the subsystem number), data.
fn unitdata(called_pc: u32, calling_pc: u32, user: &[u8]) -> Vec<u8> {
    let address = |pc: u32| vec![4, 0x43, pc as u8, (pc >> 8) as u8 & 0x3F, 6];
    let mut out = vec![0x09, 0x00, 3, 7, 11];
    out.extend(address(called_pc));
    out.extend(address(calling_pc));
    out.push(user.len() as u8);
    out.extend_from_slice(user);
    out
}

/// Come up as a SUA ASP and become active: the ASPSM and ASPTM messages of
/// RFC 3868 3.5 and 3.6 have the common header and the Routing Context
/// parameter of M3UA.
async fn sua_active(assoc: &SctpAssociation, context: u32) {
    let wait = |kind: (u8, u8)| async move {
        loop {
            let (bytes, info) = timeout(Duration::from_secs(3), assoc.recv())
                .await
                .expect("an answer from the node")
                .expect("the association");
            assert_eq!(info.ppid, PPID_SUA);
            if (bytes[2], bytes[3]) == kind {
                return;
            }
        }
    };
    assoc
        .send(&message(ASPUP, &[]), 0, PPID_SUA)
        .await
        .expect("ASP Up");
    wait(ASPUP_ACK).await;
    assoc
        .send(
            &message(ASPAC, &[integers(ROUTING_CONTEXT, &[context])]),
            0,
            PPID_SUA,
        )
        .await
        .expect("ASP Active");
    wait(ASPAC_ACK).await;
}

/// The same fault on a SUA association: the state of the ASP stayed with the
/// first association while the node sent to the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_second_connection_does_not_get_the_traffic_of_an_active_sua_asp() {
    let what = "a_second_connection_sua";
    let Some(node) = Node::start(what, &bridged()).await else {
        return;
    };
    let first = dial(&["127.0.0.2"], 0, node.addr("sua-a"))
        .await
        .expect("sua");
    sua_active(&first, RC_SUA).await;
    assert!(node.carrying("sua-a", true).await);
    let mut msc = asp(dial(&["127.0.0.3"], 0, node.addr("msc-a"))
        .await
        .expect("msc"));
    activate(&mut msc, RC_MSC).await;

    let before = metrics::association_refusals(Refusal::Duplicate);
    let second = dial(&["127.0.0.4"], 0, node.addr("sua-a"))
        .await
        .expect("handshake");
    let ended = fate(&second, WITHIN).await;

    let user = [0x62, 0x03, 0x48, 0x01, 0x07];
    msc.transfer(&data(
        Some(RC_MSC),
        MSC,
        SUA_AS,
        3,
        NI,
        0,
        &unitdata(SUA_AS, MSC, &user),
    ))
    .await;
    // What the node tells the ASP about destinations comes first and is
    // passed by.
    let mut delivered = fate(&first, Duration::from_secs(2)).await;
    while matches!(&delivered, Ended::Served(other) if (other[2], other[3]) != CLDT) {
        delivered = fate(&first, Duration::from_secs(2)).await;
    }
    let stolen = fate(&second, Duration::from_millis(300)).await;
    assert!(
        !matches!(stolen, Ended::Served(_)),
        "the second connection received what was for the ASP: {stolen:02x?}"
    );
    let Ended::Served(cldt) = delivered else {
        panic!("the CLDT did not reach the active ASP: {delivered:?}");
    };
    assert_eq!((cldt[2], cldt[3]), CLDT, "class and type: {cldt:02x?}");
    assert!(
        cldt.windows(user.len()).any(|w| w == user),
        "the data of the unitdata is in the CLDT"
    );
    assert_eq!(ended, Ended::Aborted);
    assert!(refused(Refusal::Duplicate, before).await);
    assert!(node.carrying("sua-a", true).await);
    node.handle.shutdown();
}
