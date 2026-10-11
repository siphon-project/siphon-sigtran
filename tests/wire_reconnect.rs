//! A `client` association is dialled until it is up, and again after it is
//! lost, on the wire.
//!
//! The node is started on kernel SCTP loopback. The far ends are the
//! hand-written peers of `tests/m2pa_peer` and `tests/m3ua_peer`: listeners
//! that are there or not, that accept, drop the association, and accept
//! again. What the node sends after it dialled again is read back by
//! Wireshark; `SIGTRAN_REQUIRE_TSHARK=1` makes a missing `tshark` a failure.
//! Without kernel SCTP every test prints SKIP.
//!
//! Every wait of the node is a configuration key in milliseconds (the `dial:`
//! block of an association), and the tests set them to tens of milliseconds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_sctp::{SctpConfig, SctpListener};
use tokio::time::{sleep, timeout, Instant};

use siphon_sigtran::config::Config;
use siphon_sigtran::metrics::{self, DialFailure};
use siphon_sigtran::routing::Router;
use siphon_sigtran::TransportHandle;

mod m2pa_peer;
mod m3ua_peer;
use m2pa_peer::{
    changeback, extended_changeover, itu_msu, wireshark, Adjacent, Frame, CBA, CBD, FAST_LINK_TEST,
    FAST_MTP3, XCA, XCO,
};
use m3ua_peer::{
    asp_up, integers, message, Peer, ASPAC, ASPAC_ACK, ASPUP, ASPUP_ACK, ASP_IDENTIFIER,
    ROUTING_CONTEXT,
};

const NODE: u32 = 1000;
const A: u32 = 3000;
const C: u32 = 3200;
const VIA_A: u32 = 2000;
const VIA_C: u32 = 2200;
const FAR: u32 = 7000;
const RC_FAR: u32 = 900;
/// National network.
const NI: u8 = 2;
/// The MTP testing user part: Wireshark does not look inside.
const SI_USER: u8 = 8;
/// An address of a documentation range (RFC 5737, TEST-NET-2): nothing
/// answers an INIT sent there.
const SILENT: &str = "198.51.100.1";

/// A link that is patient with acknowledgements and quick to align again.
const M2PA: &str = "{ t1_ms: 2000, t2_ms: 2000, t3_ms: 1000, t4n_ms: 60, t4e_ms: 20, \
                    t6_ms: 300, t7_ms: 3000, proving_interval_ms: 15, restart_ms: 100 }";
/// Dialled again after 40 ms, then 80, then every 160.
const DIAL: &str = "{ connect_timeout_ms: 1000, backoff_initial_ms: 40, backoff_max_ms: 160, \
                    backoff_jitter_percent: 0 }";

// ── Helpers ──────────────────────────────────────────────────────────────────

/// A loopback port nothing listens on: bound once to learn it, then released.
fn free_port() -> Option<u16> {
    let probe = SctpListener::bind("127.0.0.1:0".parse().ok()?).ok()?;
    Some(probe.local_addr().ok()?.port())
}

fn listen(port: u16) -> SctpListener {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("address");
    SctpListener::bind_config(addr, &SctpConfig::new().nodelay(true)).expect("the port is free")
}

async fn start(yaml: &str) -> TransportHandle {
    let cfg = Config::parse(yaml).expect("config parses");
    let router = Arc::new(Router::new(&cfg));
    // An absent peer is not a reason for the node not to start, and neither
    // is it one to wait: the start returns at once.
    timeout(Duration::from_secs(2), TransportHandle::start(&cfg, router))
        .await
        .expect("the start does not wait for a peer")
        .expect("the node starts whatever its peers do")
}

/// Wait until `read` is at least `wanted`.
async fn at_least(read: impl Fn() -> u64, wanted: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if read() >= wanted {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

async fn carrying(handle: &TransportHandle, association: &str, wanted: bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let slot = handle.registry().slot(association).expect("slot");
        if slot.is_carrying() == wanted {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

async fn reachable(handle: &TransportHandle, dpc: u32, wanted: bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if handle.router().is_reachable("default", dpc) == wanted {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

/// The gateway side of the node's M3UA association: acknowledge its ASP Up
/// and its ASP Active, and return both as the node sent them.
async fn bring_up(gateway: &mut Peer) -> (m3ua_peer::Received, m3ua_peer::Received) {
    let up = gateway.until(ASPUP).await;
    gateway.send(&message(ASPUP_ACK, &[])).await;
    let active = gateway.until(ASPAC).await;
    gateway
        .send(&message(
            ASPAC_ACK,
            &[integers(ROUTING_CONTEXT, &active.contexts())],
        ))
        .await;
    (up, active)
}

fn user(opc: u32, dpc: u32, tag: u8) -> Vec<u8> {
    itu_msu(SI_USER, NI, opc, dpc, 0, &[0xC0, 0xDE, tag])
}

fn tag(frame: &Frame) -> u8 {
    *frame
        .label()
        .expect("a label")
        .payload
        .last()
        .expect("a tag")
}

// ── The reported fault ───────────────────────────────────────────────────────

/// "With the far end of a client association not listening ... `start_tenant`
/// returns the error ... and no association is served", or "the connect never
/// returns ... that client association and every association after it in the
/// file never start". And "the link is not dialled when its far end appears".
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_peer_that_is_absent_at_start_stops_nothing_and_is_dialled_until_it_is_there() {
    let what = "a_peer_that_is_absent_at_start";
    let (Some(absent), Some(gateway)) = (free_port(), m3ua_peer::Listening::bind()) else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    // In the order of the file: a listening association, the link whose far
    // end is not there, and a client association after it.
    let yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: near, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0, peer_addrs: [127.0.0.1] }}
  - {{ id: absent-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {absent}, adjacent_pc: {A}, m2pa: {M2PA}, dial: {DIAL} }}
  - {{ id: to-gateway, adaptation: m3ua, role: client, addrs: [127.0.0.1], port: {}, m3ua: {{ ack_ms: 250 }}, dial: {DIAL} }}
application_servers:
  - {{ name: near, traffic_mode: override, routing_context: 100, asps: [near] }}
  - {{ name: far, traffic_mode: override, routing_context: {RC_FAR}, asps: [to-gateway] }}
linksets:
  - {{ name: a, links: [{{assoc: absent-0}}], link_test: {FAST_LINK_TEST} }}
mtp3_routes:
  - {{ dpc: 6000, as: near, priority: 1 }}
  - {{ dpc: {FAR}, as: far, priority: 1 }}
  - {{ dpc: {VIA_A}, linkset: a, priority: 1 }}
"#,
        gateway.port
    );
    let handle = start(&yaml).await;

    // The association after the absent one in the file is dialled and comes
    // up.
    let mut sg = gateway
        .accept()
        .await
        .expect("the later association is dialled");
    bring_up(&mut sg).await;
    assert!(carrying(&handle, "to-gateway", true).await);

    // The listening association before it serves its ASP.
    let near = handle.bound_addr("near").expect("bound");
    let local: SocketAddr = "127.0.0.1:0".parse().expect("address");
    let assoc = async_sctp::SctpAssociation::connect_from(&[local], &[near], &SctpConfig::new())
        .await
        .expect("the listening association accepts");
    let mut asp = Peer {
        assoc: Arc::new(assoc),
        log: Vec::new(),
    };
    asp.send(&asp_up(None)).await;
    asp.until(ASPUP_ACK).await;

    // The absent one is dialled again and again, each failure counted as
    // refused (the far end answers the INIT with an ABORT), and waits its
    // longest back-off between attempts.
    assert!(at_least(|| metrics::dial_attempts("absent-0"), 4).await);
    assert!(
        at_least(
            || metrics::dial_failures("absent-0", DialFailure::Refused),
            3
        )
        .await
    );
    assert!(
        at_least(|| metrics::dial_backoff("absent-0").as_millis() as u64, 160).await,
        "the back-off reaches its cap"
    );
    assert!(metrics::dial_backoff("absent-0") <= Duration::from_millis(160));
    assert!(!handle.router().is_reachable("default", VIA_A));
    let text = metrics::render();
    assert!(text.contains("sigtran_association_state{assoc=\"absent-0\",adaptation=\"m2pa\"} 0"));
    assert!(text.contains("sigtran_association_dial_backoff_seconds{assoc=\"absent-0\"} 0.160"));

    // Its far end appears: the next attempt finds it, the link is aligned and
    // tested, and the destination behind it is accessible.
    let listener = listen(absent);
    let (assoc, _) = timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("the link is dialled when its far end appears")
        .expect("accept");
    let mut link = m2pa_peer::Peer::new(Arc::new(assoc), A, NODE, NI);
    link.bring_up().await;
    assert!(carrying(&handle, "absent-0", true).await);
    assert_eq!(metrics::dial_backoff("absent-0"), Duration::ZERO);

    // What the node sent on the link it dialled at last is M2PA as Wireshark
    // reads it: Out of Service, Alignment, Proving, Ready.
    let statuses: Vec<Frame> = link.log.iter().filter(|f| f.is_status()).cloned().collect();
    if let Some(read) = wireshark(&statuses, &["m2pa.status"]) {
        read.clean();
        let seen = read.column("m2pa.status");
        eprintln!("{what}: link status as Wireshark reads it: {seen:?}");
        for status in ["9", "1", "4"] {
            assert!(seen.contains(&status), "status {status} in {seen:?}");
        }
    }
    handle.shutdown();
}

// ── M3UA ─────────────────────────────────────────────────────────────────────

fn as_an_asp(port: u16, extra: &str) -> String {
    format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
associations:
  - {{ id: to-gateway, adaptation: m3ua, role: client, addrs: [127.0.0.1], port: {port}, m3ua: {{ ack_ms: 250, asp_id: 77 }}, dial: {DIAL}{extra} }}
application_servers:
  - {{ name: far, traffic_mode: override, routing_context: {RC_FAR}, asps: [to-gateway] }}
mtp3_routes:
  - {{ dpc: {FAR}, as: far, priority: 1 }}
"#
    )
}

/// RFC 4666 4.3.4.6: "the signalling process SHOULD attempt to re-establish
/// communication if it is configured as the client for the disconnected M3UA
/// peer", and 4.3.3 on a restart: "The ASP, if it is to recover, must begin
/// any recovery with the ASP-Up procedure." Before, an association that was
/// lost was not dialled again.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn an_association_that_is_lost_is_dialled_again_and_the_asp_comes_up_as_at_first() {
    let what = "an_association_that_is_lost";
    let Some(gateway) = m3ua_peer::Listening::bind() else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let handle = start(&as_an_asp(gateway.port, "")).await;
    let mut said = Vec::new();
    // Three associations, one after the other: closed in good order, then
    // aborted (closed with what the node sent unread).
    for round in 0..3 {
        let mut sg = timeout(Duration::from_secs(3), gateway.accept())
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("round {round}: the association is not dialled"));
        let (up, active) = bring_up(&mut sg).await;
        assert_eq!(up.integers(ASP_IDENTIFIER), [77], "round {round}");
        assert_eq!(active.contexts(), [RC_FAR], "round {round}");
        assert!(carrying(&handle, "to-gateway", true).await);
        assert!(reachable(&handle, FAR, true).await);
        said.push(up);
        said.push(active);
        if round == 1 {
            // Left unread, so the close of the gateway is an ABORT.
            sg.send(&message(m3ua_peer::BEAT, &[])).await;
            sleep(Duration::from_millis(50)).await;
        } else {
            sg.drain(Duration::from_millis(50)).await;
        }
        drop(sg);
        assert!(
            carrying(&handle, "to-gateway", false).await,
            "round {round}: the ASP is down with its association"
        );
        assert!(reachable(&handle, FAR, false).await);
    }
    assert!(metrics::dial_attempts("to-gateway") >= 3);

    let said: Vec<&m3ua_peer::Received> = said.iter().collect();
    if let Some(read) = wireshark(
        &m3ua_peer::frames(&said),
        &[
            "m3ua.message_class",
            "m3ua.message_type",
            "m3ua.asp_identifier",
            "m3ua.routing_context",
        ],
    ) {
        read.clean();
        eprintln!("{what}: as Wireshark reads it:\n{}", read.lines());
        // ASP Up and ASP Active, three times over.
        assert_eq!(
            read.column("m3ua.message_class"),
            ["3", "4", "3", "4", "3", "4"]
        );
        assert_eq!(read.column("m3ua.message_type"), ["1"; 6]);
        assert_eq!(read.get(4, "m3ua.asp_identifier"), "77");
        assert_eq!(read.get(5, "m3ua.routing_context"), "900");
    }
    handle.shutdown();
}

/// The heartbeat that goes unanswered ends the association (RFC 4666
/// 4.3.4.6); the node then dials again.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_peer_that_stops_answering_the_heartbeat_is_dialled_again() {
    let what = "a_peer_that_stops_answering";
    let Some(gateway) = m3ua_peer::Listening::bind() else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let yaml = as_an_asp(gateway.port, "").replace("ack_ms: 250", "ack_ms: 250, beat_ms: 100");
    let handle = start(&yaml).await;
    let mut silent = gateway.accept().await.expect("dialled");
    bring_up(&mut silent).await;
    assert!(carrying(&handle, "to-gateway", true).await);
    // The gateway says nothing from here on, and keeps its association.
    let mut again = timeout(Duration::from_secs(3), gateway.accept())
        .await
        .ok()
        .flatten()
        .expect("dialled again after two heartbeat intervals of silence");
    bring_up(&mut again).await;
    assert!(carrying(&handle, "to-gateway", true).await);
    drop(silent);
    handle.shutdown();
}

/// `local_addrs` and `local_port`: the far end sees the association come
/// from exactly these, which is what lets it tell its peers apart by address.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_client_association_is_dialled_from_its_local_addresses_and_port() {
    let what = "a_client_association_is_dialled_from";
    let (Some(gateway), Some(local_port)) = (m3ua_peer::Listening::bind(), free_port()) else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let extra = format!(", local_addrs: [127.0.0.2, 127.0.0.3], local_port: {local_port}");
    let handle = start(&as_an_asp(gateway.port, &extra)).await;
    let mut sg = gateway.accept().await.expect("dialled");
    let mut from = sg.assoc.peer_addrs().expect("the addresses of the node");
    from.sort();
    let expected: Vec<SocketAddr> = ["127.0.0.2", "127.0.0.3"]
        .iter()
        .map(|ip| format!("{ip}:{local_port}").parse().expect("address"))
        .collect();
    assert_eq!(from, expected, "every local address, and no other");
    bring_up(&mut sg).await;
    assert!(carrying(&handle, "to-gateway", true).await);
    handle.shutdown();
}

/// An address that cannot be bound is a failure of the attempt like any
/// other: counted as `local`, and tried again.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn local_addresses_that_cannot_be_bound_do_not_stop_the_node() {
    let what = "local_addresses_that_cannot_be_bound";
    let Some(gateway) = m3ua_peer::Listening::bind() else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    // An address of a documentation range is not one this host can bind.
    let yaml = as_an_asp(gateway.port, ", local_addrs: [198.51.100.77]")
        .replace("to-gateway", "from-nowhere");
    let handle = start(&yaml).await;
    assert!(
        at_least(
            || metrics::dial_failures("from-nowhere", DialFailure::Local),
            3
        )
        .await
    );
    handle.shutdown();
}

// ── M2PA and level 3 ─────────────────────────────────────────────────────────

/// "client links never come back": a link whose association was lost is
/// dialled again, aligned and tested as at first, and level 3 changes back to
/// it (ITU-T Q.704 clause 6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_is_dialled_again_is_changed_back_to() {
    let what = "a_link_that_is_dialled_again";
    let spawn = |pc, slc| Adjacent::spawn(pc, NODE, NI, slc, true);
    let (Some(mut a0), Some(mut a1), Some(mut c)) =
        (spawn(A, 0).await, spawn(A, 1).await, spawn(C, 0).await)
    else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: a-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {A}, m2pa: {M2PA}, dial: {DIAL} }}
  - {{ id: a-1, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {A}, m2pa: {M2PA}, dial: {DIAL} }}
  - {{ id: c-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {C}, m2pa: {M2PA}, dial: {DIAL} }}
linksets:
  - {{ name: a, links: [{{assoc: a-0}}, {{assoc: a-1}}], link_test: {FAST_LINK_TEST} }}
  - {{ name: c, links: [{{assoc: c-0}}], link_test: {FAST_LINK_TEST} }}
mtp3_routes:
  - {{ dpc: {VIA_A}, linkset: a, priority: 1 }}
  - {{ dpc: {VIA_C}, linkset: c, priority: 1 }}
"#,
        a0.port, a1.port, c.port
    );
    let handle = start(&yaml).await;
    for dpc in [VIA_A, VIA_C, A, C] {
        assert!(reachable(&handle, dpc, true).await, "{dpc} is reachable");
    }
    for link in ["a-0", "a-1", "c-0"] {
        assert!(carrying(&handle, link, true).await, "{link} carries");
    }
    let wait = Duration::from_millis(450);
    tokio::join!(a0.drain(wait), a1.drain(wait), c.drain(wait));
    let dialled = metrics::dial_attempts("a-0");
    let statuses_before = a0.frames().len();

    // Selection code 0 goes by a-0.
    c.send(user(C, VIA_A, 1));
    let first = a0.traffic().await.expect("carried on a-0");
    assert_eq!(tag(&first), 1);

    // The association of a-0 goes (RFC 4165 4.1.7): the traffic changes over
    // to a-1.
    a0.drop_association();
    let order = a1.until(|f| f.is(XCO)).await.expect("a changeover order");
    assert_eq!(order.management().expect("management").slc, 0);
    a1.manage(0, extended_changeover(XCA, first.fsn()));
    c.send(user(C, VIA_A, 2));
    assert_eq!(tag(&a1.traffic().await.expect("diverted to a-1")), 2);

    // The node dials a-0 again. Its far end accepts, the link is aligned and
    // tested as at first, and then (Q.704 6.3.1): "a changeback declaration
    // is sent to the remote signalling point of the signalling link made
    // available via the concerned alternative signalling link".
    let declaration = a1
        .until(|f| f.is(CBD))
        .await
        .expect("a changeback declaration after the link was dialled again");
    let read = declaration.management().expect("management");
    assert_eq!((read.opc, read.dpc, read.slc), (NODE, A, 0));
    assert!(metrics::dial_attempts("a-0") > dialled, "dialled again");
    assert!(carrying(&handle, "a-0", true).await);
    // 6.3.2: "restart diverted traffic over the signalling link made
    // available when it receives a changeback acknowledgement".
    a1.manage(0, changeback(CBA, read.changeback_code().expect("code")));
    sleep(Duration::from_millis(50)).await;
    c.send(user(C, VIA_A, 3));
    assert_eq!(tag(&a0.traffic().await.expect("on a-0 again")), 3);

    if let Some(read) = wireshark(
        &[order, declaration],
        &["mtp3.dpc", "mtp3.sls", "mtp3mg.h0", "mtp3mg.h1"],
    ) {
        read.clean();
        eprintln!("{what}: as Wireshark reads it:\n{}", read.lines());
        assert_eq!(read.column("mtp3.dpc"), ["3000"; 2]);
        assert_eq!(read.column("mtp3.sls"), ["0"; 2], "the code of the link");
        assert_eq!(read.column("mtp3mg.h0"), ["0x01"; 2]);
        assert_eq!(
            read.get(0, "mtp3mg.h1"),
            "0x03",
            "extended changeover order"
        );
        assert_eq!(read.get(1, "mtp3mg.h1"), "0x05", "changeback declaration");
    }
    // The second association of the link started with the Link Status
    // exchange again.
    let again: Vec<Frame> = a0
        .frames()
        .into_iter()
        .skip(statuses_before)
        .filter(|f| f.is_status())
        .collect();
    if let Some(read) = wireshark(&again, &["m2pa.status"]) {
        read.clean();
        let seen = read.column("m2pa.status");
        eprintln!("{what}: link status after the redial: {seen:?}");
        for status in ["1", "4"] {
            assert!(seen.contains(&status), "status {status} in {seen:?}");
        }
    }
    handle.shutdown();
}

// ── SUA ──────────────────────────────────────────────────────────────────────

/// A `sua` client association is dialled again like any other, and asks to
/// come up again.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_sua_association_that_is_lost_is_dialled_again() {
    let what = "a_sua_association_that_is_lost";
    let Some(port) = free_port() else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let listener = listen(port);
    let yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
associations:
  - {{ id: to-sg, adaptation: sua, role: client, addrs: [127.0.0.1], port: {port}, dial: {DIAL} }}
application_servers:
  - {{ name: far, traffic_mode: override, routing_context: {RC_FAR}, asps: [to-sg] }}
mtp3_routes:
  - {{ dpc: {FAR}, as: far, priority: 1 }}
"#
    );
    let handle = start(&yaml).await;
    for round in 0..2 {
        let (assoc, _) = timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap_or_else(|_| panic!("round {round}: the association is not dialled"))
            .expect("accept");
        let (bytes, info) = timeout(Duration::from_secs(3), assoc.recv())
            .await
            .expect("the node asks to come up")
            .expect("the association");
        assert_eq!(info.ppid, 4, "the SUA payload protocol identifier");
        assert_eq!((bytes[2], bytes[3]), ASPUP, "round {round}: ASP Up");
        assoc
            .send(&message(ASPUP_ACK, &[]), 0, 4)
            .await
            .expect("ASP Up Ack");
    }
    handle.shutdown();
}

// ── Timeouts and shutdown ────────────────────────────────────────────────────

/// A far end that answers nothing at all: the attempt is given up after the
/// connect timeout of the association and counted, and the next one follows.
/// Nothing on loopback stays silent (the kernel answers every INIT, with an
/// ABORT if nobody listens), so the address is one of a documentation range
/// (RFC 5737): where the host has no route to it the failure is
/// `unreachable`, and where the host happens to have the address itself the
/// test says SKIP. The limit itself is tested without a network in
/// `src/transport/mod.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn an_attempt_that_gets_no_answer_is_given_up_after_the_connect_timeout() {
    let what = "an_attempt_that_gets_no_answer";
    if free_port().is_none() {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    }
    let yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
associations:
  - {{ id: silent, adaptation: m3ua, role: client, addrs: [{SILENT}], port: 2905, dial: {{ connect_timeout_ms: 80, backoff_initial_ms: 20, backoff_max_ms: 40, backoff_jitter_percent: 50 }} }}
"#
    );
    let handle = start(&yaml).await;
    assert!(at_least(|| metrics::dial_attempts("silent"), 1).await);
    let given_up = || {
        metrics::dial_failures("silent", DialFailure::Timeout)
            + metrics::dial_failures("silent", DialFailure::Unreachable)
    };
    if !at_least(given_up, 3).await {
        let refused = metrics::dial_failures("silent", DialFailure::Refused);
        assert!(refused > 0, "attempts that neither end nor are counted");
        eprintln!("SKIP {what}: {SILENT} is an address of this host");
        handle.shutdown();
        return;
    }
    assert!(metrics::dial_attempts("silent") >= 3);
    let waiting = metrics::dial_backoff("silent");
    assert!(waiting <= Duration::from_millis(40), "{waiting:?}");
    handle.shutdown();
}

/// `TransportHandle::shutdown` ends the dialling at once: the attempt that is
/// running, the wait between two attempts, and the task itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn shutdown_ends_every_attempt_and_every_wait() {
    let what = "shutdown_ends_every_attempt";
    let Some(absent) = free_port() else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return;
    };
    let tasks = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let before = tasks();
    // One association in a long wait between attempts, one in an attempt
    // that gets no answer for a long time.
    let yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: waiting, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {absent}, adjacent_pc: {A}, dial: {{ connect_timeout_ms: 60000, backoff_initial_ms: 60000, backoff_max_ms: 60000 }} }}
  - {{ id: asking, adaptation: m3ua, role: client, addrs: [{SILENT}], port: 2905, dial: {{ connect_timeout_ms: 60000, backoff_initial_ms: 60000, backoff_max_ms: 60000 }} }}
linksets:
  - {{ name: a, links: [{{assoc: waiting}}] }}
"#
    );
    let handle = start(&yaml).await;
    assert!(
        at_least(
            || metrics::dial_failures("waiting", DialFailure::Refused),
            1
        )
        .await
    );
    assert!(at_least(|| metrics::dial_attempts("asking"), 1).await);
    assert!(tasks() > before, "the node runs tasks");

    let stopped = Instant::now();
    handle.shutdown();
    let deadline = Instant::now() + Duration::from_secs(2);
    while tasks() > before && Instant::now() < deadline {
        sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(tasks(), before, "no task is left");
    assert!(
        stopped.elapsed() < Duration::from_secs(1),
        "and none took its wait to end: {:?}",
        stopped.elapsed()
    );

    // Nothing dials after the shutdown: the far end appears and hears
    // nothing.
    let attempts = metrics::dial_attempts("waiting");
    let listener = listen(absent);
    let heard = timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(
        heard.is_err(),
        "an association was dialled after the shutdown"
    );
    assert_eq!(metrics::dial_attempts("waiting"), attempts);
    assert_eq!(metrics::dial_backoff("waiting"), Duration::ZERO);
}
