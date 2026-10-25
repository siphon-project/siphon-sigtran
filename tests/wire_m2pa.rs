//! An M2PA link against a conformant peer, on the wire.
//!
//! The node is started on kernel SCTP loopback and its links are driven by the
//! hand-written peer of `tests/m2pa_peer` (octets from RFC 4165, ITU-T Q.704
//! 15.2 and Q.707 5.4, not from the codec the node uses). Everything the node
//! sends is then read by Wireshark, and the fields are asserted from what
//! Wireshark read. `SIGTRAN_REQUIRE_TSHARK=1` makes a missing `tshark` a
//! failure; without kernel SCTP every test here prints SKIP.
//!
//! The level-2 and link test timers are set to tens and hundreds of
//! milliseconds in the node's configuration, so nothing waits on a default.
//!
//! So are the level-3 timers. A node whose first link comes into service runs
//! the MTP restart procedure (ITU-T Q.704 9.2.1), during which "all messages to
//! another destination received at a signalling point whose MTP is restarting
//! are discarded" (9.6.6); a peer that restarts is waited for under T21 before
//! traffic is sent to it (9.3.2, 9.6.7). The peers of these tests are about
//! level 2 and send no traffic restart allowed, so the node is given a T18 and
//! a T21 that run out at once.

#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout, Instant};

use siphon_sigtran::config::Config;
use siphon_sigtran::metrics::{self, LinkTestResult, RxDiscard};
use siphon_sigtran::routing::Router;
use siphon_sigtran::transport::{M2paDiscard, M2paFailure};
use siphon_sigtran::TransportHandle;

mod m2pa_peer;
use m2pa_peer::*;

const NODE_PC: u32 = 1000;
const NORTH_PC: u32 = 3000;
const SOUTH_PC: u32 = 4000;
/// Reached over the south linkset.
const FAR_SOUTH: u32 = 2000;
/// Reached over the north linkset.
const FAR_NORTH: u32 = 2100;
/// National network.
const NI: u8 = 2;
/// The MTP testing user part (Q.704 14.2.1): a user part Wireshark does not
/// try to look inside, so transit traffic can carry any octets.
const SI_TEST_USER: u8 = 8;
const NORTH_SLC: u8 = 5;
const SOUTH_SLC: u8 = 0;

/// A node with two linksets of one link each, both dialled by the node.
fn node(north_port: u16, south_port: u16, link_test: &str) -> String {
    format!(
        r#"
node: {{ point_code: {NODE_PC}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: north-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {north_port}, adjacent_pc: {NORTH_PC}, m2pa: {FAST_M2PA} }}
  - {{ id: south-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {south_port}, adjacent_pc: {SOUTH_PC}, m2pa: {FAST_M2PA} }}
linksets:
  - {{ name: north, links: [{{assoc: north-0, slc: {NORTH_SLC}}}], link_test: {link_test} }}
  - {{ name: south, links: [{{assoc: south-0}}], link_test: {link_test} }}
mtp3_routes:
  - {{ dpc: {FAR_SOUTH}, linkset: south, priority: 1 }}
  - {{ dpc: {FAR_NORTH}, linkset: north, priority: 1 }}
"#
    )
}

/// A node, its two peers accepted (not yet aligned), or `None` with a SKIP
/// when kernel SCTP is not there.
async fn node_with_peers(what: &str, link_test: &str) -> Option<(TransportHandle, Peer, Peer)> {
    let (Some(north), Some(south)) = (Listening::bind(), Listening::bind()) else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return None;
    };
    let cfg = Config::parse(&node(north.port, south.port, link_test)).expect("config parses");
    let router = Arc::new(Router::new(&cfg));
    let handle = match TransportHandle::start(&cfg, router).await {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("SKIP {what}: transport did not start ({error})");
            return None;
        }
    };
    let mut north = north.accept(NORTH_PC, NODE_PC, NI).await.expect("north");
    let south = south.accept(SOUTH_PC, NODE_PC, NI).await.expect("south");
    north.slc = NORTH_SLC;
    Some((handle, north, south))
}

/// The same with both links aligned and tested.
async fn node_with_links_up(what: &str) -> Option<(TransportHandle, Peer, Peer)> {
    let (handle, mut north, mut south) = node_with_peers(what, FAST_LINK_TEST).await?;
    north.bring_up().await;
    south.bring_up().await;
    // A transfer point tells an adjacent point whose linkset became available
    // what it must not send here, and that traffic may restart (ITU-T Q.704
    // 9.3.2: "X sends any necessary TFP and TFR messages to Y; then X sends a
    // traffic restart allowed message to signalling point Y"). Those come
    // first on each link and are acknowledged here, for longer than the T21
    // the node waits for these peers; the tests below are about what follows.
    tokio::join!(
        north.quiet(Duration::from_millis(450)),
        south.quiet(Duration::from_millis(450))
    );
    assert!(reachable(&handle, FAR_SOUTH, true).await, "south is up");
    assert!(reachable(&handle, FAR_NORTH, true).await, "north is up");
    Some((handle, north, south))
}

/// Wait until the node's view of a destination is `wanted`.
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

/// Wait until a counter has moved past `before`.
async fn counted(read: impl Fn() -> u64, before: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if read() > before {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

/// A transit MSU from the north peer for a destination behind the south one.
fn transit(tag: u8) -> Vec<u8> {
    itu_msu(SI_TEST_USER, NI, NORTH_PC, FAR_SOUTH, 3, &[0xC0, 0xDE, tag])
}

const STATUS_FIELDS: [&str; 5] = [
    "sctp.data_sid",
    "m2pa.type",
    "m2pa.status",
    "m2pa.bsn",
    "m2pa.fsn",
];

// ── Alignment and the link test ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_link_aligns_by_the_status_exchange_and_opens_after_its_test() {
    let what = "a_link_aligns";
    let Some((handle, mut north, _south)) = node_with_peers(what, FAST_LINK_TEST).await else {
        return;
    };

    north.align().await;
    // Level 2 is in service; level 3 is not, until the test is acknowledged
    // (Q.707 2.2: "The signalling link becomes available only if the test is
    // successful").
    let sltm = north
        .until(false, |f| f.link_test().is_some())
        .await
        .expect("the node tests the link after alignment");
    assert!(
        !handle.router().is_reachable("default", FAR_NORTH),
        "no traffic before the link test is acknowledged"
    );
    north.accept_and_ack(&sltm).await;
    let label = sltm.label().unwrap();
    let slta = itu_msu(
        1,
        NI,
        NORTH_PC,
        NODE_PC,
        label.sls,
        &link_test(true, &NODE_PATTERN),
    );
    north.send_msu(&slta).await;
    assert!(
        reachable(&handle, FAR_NORTH, true).await,
        "available once tested"
    );
    // The node acknowledges the SLTA: an empty User Data message.
    let ack = north
        .until(false, Frame::is_ack)
        .await
        .expect("the SLTA is acknowledged");
    assert_eq!(
        (ack.bsn(), ack.fsn()),
        (0, 0),
        "BSN the SLTA's FSN, FSN our last"
    );

    // What the node sent, in order, by the peer's own reading.
    let statuses: Vec<u32> = north.log.iter().filter_map(Frame::status).collect();
    assert_eq!(
        statuses[..2],
        [OUT_OF_SERVICE, ALIGNMENT],
        "RFC 4165 4.1.3: Out of Service once the association is up, then Alignment"
    );
    assert_eq!(statuses.last(), Some(&READY));
    assert!(
        statuses[2..statuses.len() - 1]
            .iter()
            .all(|s| *s == PROVING_NORMAL),
        "proving between alignment and ready: {statuses:?}"
    );
    assert!(
        statuses.len() >= 5,
        "Proving is repeated while T4 runs: {statuses:?}"
    );

    // And by Wireshark's.
    let Some(read) = wireshark(&north.log, &STATUS_FIELDS) else {
        return;
    };
    read.clean();
    println!("{what}:\n{}", read.lines());
    let status_rows: Vec<usize> = (0..read.rows.len())
        .filter(|r| read.get(*r, "m2pa.type") == "2")
        .collect();
    assert_eq!(read.get(status_rows[0], "m2pa.status"), "9");
    assert_eq!(read.get(status_rows[1], "m2pa.status"), "1");
    assert_eq!(read.get(status_rows[2], "m2pa.status"), "2");
    assert_eq!(
        read.get(*status_rows.last().unwrap(), "m2pa.status"),
        "4",
        "Ready ends alignment"
    );
    for row in &status_rows {
        // RFC 4165 4.1.2: these statuses go on the Link Status stream; before
        // any User Data both sequence numbers are at their initial value.
        assert_eq!(read.get(*row, "sctp.data_sid"), "0x0000");
        assert_eq!(read.get(*row, "m2pa.bsn"), "16777215");
        assert_eq!(read.get(*row, "m2pa.fsn"), "16777215");
    }

    // The link test, read by Wireshark.
    let test = wireshark(
        std::slice::from_ref(&sltm),
        &[
            "sctp.data_sid",
            "m2pa.fsn",
            "m2pa.bsn",
            "mtp3.service_indicator",
            "mtp3.network_indicator",
            "mtp3.opc",
            "mtp3.dpc",
            "mtp3.sls",
            "mtp3mg.test.h0",
            "mtp3mg.test.h1",
            "mtp3mg.test.length",
            "mtp3mg.test.pattern",
        ],
    )
    .unwrap();
    test.clean();
    println!("{what} SLTM: {}", test.lines());
    assert_eq!(test.get(0, "sctp.data_sid"), "0x0001", "User Data stream");
    assert_eq!(test.get(0, "m2pa.fsn"), "0", "the first User Data is FSN 0");
    assert_eq!(test.get(0, "m2pa.bsn"), "16777215");
    assert_eq!(test.get(0, "mtp3.service_indicator"), "0x01");
    assert_eq!(test.get(0, "mtp3.opc"), NODE_PC.to_string());
    assert_eq!(test.get(0, "mtp3.dpc"), NORTH_PC.to_string());
    assert_eq!(
        test.get(0, "mtp3.sls"),
        NORTH_SLC.to_string(),
        "the link code"
    );
    assert_eq!(test.get(0, "mtp3mg.test.h0"), "0x01");
    assert_eq!(test.get(0, "mtp3mg.test.h1"), "0x01", "SLTM");
    assert_eq!(test.get(0, "mtp3mg.test.length"), "5");
    assert_eq!(test.get(0, "mtp3mg.test.pattern"), "0102030405");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_listening_link_aligns_and_answers_the_peers_link_test() {
    let what = "a_listening_link";
    let yaml = format!(
        r#"
node: {{ point_code: {NODE_PC}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: north-0, adaptation: m2pa, role: server, addrs: [127.0.0.1], port: 0, adjacent_pc: {NORTH_PC}, m2pa: {FAST_M2PA} }}
linksets:
  - {{ name: north, links: [{{assoc: north-0, slc: {NORTH_SLC}}}], link_test: {FAST_LINK_TEST} }}
"#
    );
    let cfg = Config::parse(&yaml).expect("config parses");
    let router = Arc::new(Router::new(&cfg));
    let Ok(handle) = TransportHandle::start(&cfg, router).await else {
        eprintln!("SKIP {what}: no kernel SCTP");
        return;
    };
    let addr = handle.bound_addr("north-0").expect("bound");
    let Some(mut north) = Peer::connect(addr, NORTH_PC, NODE_PC, NI).await else {
        eprintln!("SKIP {what}: connect failed");
        return;
    };
    north.bring_up().await;
    assert!(reachable(&handle, NORTH_PC, true).await);

    // The peer tests the link too: Q.707 2.2, the acknowledgement carries the
    // pattern received, on the link the test named.
    let mut answers = Vec::new();
    for pattern in [
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        (0x10..0x1F).collect::<Vec<u8>>(),
        vec![0x00],
    ] {
        let sltm = itu_msu(
            1,
            NI,
            NORTH_PC,
            NODE_PC,
            NORTH_SLC,
            &link_test(false, &pattern),
        );
        north.send_msu(&sltm).await;
        let slta = north
            .until(true, |f| matches!(f.link_test(), Some((true, _))))
            .await
            .expect("the SLTM is answered");
        assert_eq!(slta.link_test().unwrap().1, pattern);
        let label = slta.label().unwrap();
        assert_eq!(
            (label.opc, label.dpc, label.sls, label.ni),
            (NODE_PC, NORTH_PC, NORTH_SLC, NI)
        );
        answers.push(slta);
    }

    let Some(read) = wireshark(
        &answers,
        &[
            "m2pa.fsn",
            "m2pa.bsn",
            "mtp3.opc",
            "mtp3.dpc",
            "mtp3.sls",
            "mtp3mg.test.h1",
            "mtp3mg.test.length",
            "mtp3mg.test.pattern",
        ],
    ) else {
        return;
    };
    read.clean();
    println!("{what}:\n{}", read.lines());
    assert_eq!(read.column("mtp3mg.test.h1"), ["0x02"; 3], "SLTA");
    assert_eq!(read.column("mtp3mg.test.length"), ["4", "15", "1"]);
    assert_eq!(
        read.column("mtp3mg.test.pattern"),
        ["deadbeef", "101112131415161718191a1b1c1d1e", "00"]
    );
    assert_eq!(read.column("mtp3.opc"), ["1000"; 3]);
    assert_eq!(read.column("mtp3.dpc"), ["3000"; 3]);
    // The node's own SLTM was FSN 0, and FSN 1 the traffic restart allowed
    // that ends its restart (ITU-T Q.704 9.2.4: it "sends traffic restart
    // allowed messages to all adjacent signalling points"); its answers
    // follow on.
    assert_eq!(read.column("m2pa.fsn"), ["2", "3", "4"]);
    // Each acknowledges the SLTM it answers (the peer's SLTA was FSN 0).
    assert_eq!(read.column("m2pa.bsn"), ["1", "2", "3"]);
}

// ── Sequence numbers and acknowledgement ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn user_data_is_numbered_and_acknowledged() {
    let what = "user_data_is_numbered";
    let Some((handle, mut north, mut south)) = node_with_links_up(what).await else {
        return;
    };
    let north_seen = north.log.len();
    // The last FSN the node used on each link before the traffic: its link
    // test, and the management messages a transfer point sends an adjacent
    // point at the start (ITU-T Q.704 9.2.4, 9.3.2, 13.2.2).
    let (north_last, south_last) = (north.fsn_in, south.fsn_in);

    for tag in 0..4 {
        north.send_msu(&transit(tag)).await;
    }
    let mut forwarded = Vec::new();
    for tag in 0..4 {
        let frame = south
            .next_msu()
            .await
            .expect("forwarded over the south link");
        assert_eq!(frame.label().unwrap().payload, [0xC0, 0xDE, tag]);
        forwarded.push(frame);
    }
    // The node acknowledges each of the four with an empty User Data message.
    let mut acks = Vec::new();
    while acks.len() < 4 {
        let frame = north.recv().await.expect("acknowledgements");
        // BSN 0 acknowledged the SLTA, before the transit messages.
        if frame.is_ack() && frame.bsn() != 0 {
            acks.push(frame);
        }
    }
    assert!(north.log[north_seen..].iter().all(|f| f.status().is_none()));

    // Longer than T7: the peer acknowledged, so the link stays in service.
    sleep(Duration::from_millis(600)).await;
    assert!(handle.router().is_reachable("default", FAR_SOUTH));
    north.send_msu(&transit(9)).await;
    forwarded.push(south.next_msu().await.expect("still forwarding"));

    let Some(read) = wireshark(
        &forwarded,
        &[
            "sctp.data_sid",
            "m2pa.type",
            "m2pa.fsn",
            "m2pa.bsn",
            "m2pa.priority",
            "mtp3.service_indicator",
            "mtp3.opc",
            "mtp3.dpc",
        ],
    ) else {
        return;
    };
    println!("{what} forwarded:\n{}", read.lines());
    // The transit messages follow what the node sent before, one by one.
    let following: Vec<String> = (1..=5).map(|n| (south_last + n).to_string()).collect();
    assert_eq!(read.column("m2pa.fsn"), following);
    // The BSN is the last FSN the south peer sent: its SLTA, FSN 0.
    assert_eq!(read.column("m2pa.bsn"), ["0"; 5]);
    assert_eq!(read.column("sctp.data_sid"), ["0x0001"; 5]);
    assert_eq!(read.column("mtp3.opc"), ["3000"; 5]);
    assert_eq!(read.column("mtp3.dpc"), ["2000"; 5]);

    let acks = wireshark(&acks, &["m2pa.type", "m2pa.length", "m2pa.bsn", "m2pa.fsn"]).unwrap();
    acks.clean();
    println!("{what} acknowledgements:\n{}", acks.lines());
    assert_eq!(acks.column("m2pa.type"), ["1"; 4], "User Data");
    assert_eq!(acks.column("m2pa.length"), ["16"; 4], "with no Data field");
    // The north peer's SLTA was FSN 0, so its four MSUs are FSN 1 to 4.
    assert_eq!(acks.column("m2pa.bsn"), ["1", "2", "3", "4"]);
    // RFC 4165 4.2.1: the FSN of an empty message is not incremented: it is
    // that of the node's last message with data on this link.
    assert_eq!(
        acks.column("m2pa.fsn"),
        [north_last.to_string().as_str(); 4]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn user_data_out_of_sequence_is_discarded() {
    let Some((_handle, mut north, mut south)) = node_with_links_up("out_of_sequence").await else {
        return;
    };
    let before = metrics::m2pa_discards(M2paDiscard::RxOutOfSequence);
    // FSN 5 where FSN 1 is due.
    let stray = user_data(north.fsn_in, 5, &transit(0xEE));
    north.raw(&stray, 1).await;
    assert!(
        counted(
            || metrics::m2pa_discards(M2paDiscard::RxOutOfSequence),
            before
        )
        .await,
        "RFC 4165 4.2.1: out of order is discarded, and counted"
    );
    // The next one in sequence is carried, and is the only thing forwarded.
    north.send_msu(&transit(1)).await;
    let frame = south.next_msu().await.expect("forwarded");
    assert_eq!(frame.label().unwrap().payload, [0xC0, 0xDE, 1]);
    assert!(
        timeout(Duration::from_millis(200), south.next_msu())
            .await
            .is_err(),
        "the stray message was not forwarded"
    );
}

// ── Failure detection and return to alignment ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_message_that_is_not_acknowledged_fails_the_link_and_it_realigns() {
    let what = "t7";
    let Some((handle, mut north, mut south)) = node_with_links_up(what).await else {
        return;
    };
    let failures = metrics::m2pa_link_failures(M2paFailure::T7);
    let lost = metrics::m2pa_discards(M2paDiscard::TxLostOnFailure);
    let from = south.log.len();

    north.send_msu(&transit(1)).await;
    // The south peer takes the message and does not acknowledge it.
    let unacked = south
        .until(false, |f| f.msu().is_some())
        .await
        .expect("forwarded");
    // The next FSN after what the node sent this adjacent point at the start
    // (its link test, and the management messages of ITU-T Q.704 9.3.2).
    assert_eq!(unacked.fsn(), south.fsn_in + 1);

    // T7 (400 ms here) runs out: Out of Service, the destination is gone.
    let out = south
        .until(false, |f| f.status() == Some(OUT_OF_SERVICE))
        .await
        .expect("RFC 4165 4.1.6: Out of Service where MTP2 would send SIOS");
    assert_eq!(out.stream, 0);
    assert!(reachable(&handle, FAR_SOUTH, false).await);
    assert!(metrics::m2pa_link_failures(M2paFailure::T7) > failures);

    // After the restart delay the node starts alignment again by itself.
    let again = south
        .until(false, |f| f.status() == Some(ALIGNMENT))
        .await
        .expect("Q.704 12.2.2: alignment is tried again");
    assert_eq!(
        (again.bsn(), again.fsn()),
        (INITIAL, INITIAL),
        "sequence numbers start over"
    );
    assert!(
        counted(
            || metrics::m2pa_discards(M2paDiscard::TxLostOnFailure),
            lost
        )
        .await,
        "the unacknowledged message is counted as lost with the link"
    );

    // The peer aligns again: the link returns to service, numbering from 0.
    let sltm = south.realign().await;
    assert_eq!(sltm.fsn(), 0, "the first User Data after realignment");
    south.accept_and_ack(&sltm).await;
    let slta = itu_msu(
        1,
        NI,
        SOUTH_PC,
        NODE_PC,
        SOUTH_SLC,
        &link_test(true, &NODE_PATTERN),
    );
    south.send_msu(&slta).await;
    assert!(reachable(&handle, FAR_SOUTH, true).await, "back in service");

    let Some(read) = wireshark(&south.log[from..], &STATUS_FIELDS) else {
        return;
    };
    read.clean();
    println!("{what}:\n{}", read.lines());
    let statuses: Vec<&str> = read
        .column("m2pa.status")
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(statuses[..2], ["9", "1"], "out of service, then alignment");
    assert_eq!(statuses.last(), Some(&"4"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_status_of_alignment_on_a_link_in_service_is_a_link_failure() {
    let Some((handle, mut north, _south)) = node_with_links_up("status_in_service").await else {
        return;
    };
    let failures = metrics::m2pa_link_failures(M2paFailure::PeerStatus);
    // Q.703 Figure 8, in service: status indication O is a link failure.
    north.status(ALIGNMENT).await;
    let out = north
        .until(false, |f| f.status() == Some(OUT_OF_SERVICE))
        .await
        .expect("the node leaves service");
    assert_eq!(out.stream, 0);
    assert!(reachable(&handle, FAR_NORTH, false).await);
    assert!(metrics::m2pa_link_failures(M2paFailure::PeerStatus) > failures);
    north
        .until(false, |f| f.status() == Some(ALIGNMENT))
        .await
        .expect("and starts alignment again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_link_whose_test_is_not_acknowledged_is_taken_out() {
    let what = "link_test_fails";
    let Some((handle, mut north, _south)) = node_with_peers(what, FAST_LINK_TEST).await else {
        return;
    };
    let failed = metrics::link_tests(LinkTestResult::Failed);
    let failures = metrics::m2pa_link_failures(M2paFailure::LinkTest);
    north.align().await;

    // The peer acknowledges at level 2 and never answers the test: Q.707 2.2,
    // "the test is considered to have failed and is repeated once", then "the
    // link is put out of service".
    let started = Instant::now();
    let first = north
        .until(true, |f| f.link_test().is_some())
        .await
        .expect("first SLTM");
    let second = north
        .until(true, |f| f.link_test().is_some())
        .await
        .expect("the repeat");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "repeated after T1 (300 ms)"
    );
    north
        .until(true, |f| f.status() == Some(OUT_OF_SERVICE))
        .await
        .expect("out of service after the second failure");
    assert!(
        !handle.router().is_reachable("default", FAR_NORTH),
        "never available"
    );
    assert!(metrics::link_tests(LinkTestResult::Failed) >= failed + 2);
    assert!(metrics::m2pa_link_failures(M2paFailure::LinkTest) > failures);
    north
        .until(false, |f| f.status() == Some(ALIGNMENT))
        .await
        .expect("restoration is attempted");

    let Some(read) = wireshark(
        &[first, second],
        &["m2pa.fsn", "mtp3mg.test.h1", "mtp3mg.test.pattern"],
    ) else {
        return;
    };
    read.clean();
    println!("{what}:\n{}", read.lines());
    assert_eq!(read.column("mtp3mg.test.h1"), ["0x01", "0x01"]);
    assert_eq!(read.column("m2pa.fsn"), ["0", "1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_wrong_acknowledgement_fails_the_test_attempt() {
    let Some((handle, mut north, _south)) = node_with_peers("wrong_slta", FAST_LINK_TEST).await
    else {
        return;
    };
    north.align().await;
    // Each criterion of Q.707 2.2 in turn: the pattern, the originating point,
    // the link code. The first wrong one makes the node repeat the test at
    // once; the second takes the link out.
    let wrong = [
        itu_msu(
            1,
            NI,
            NORTH_PC,
            NODE_PC,
            NORTH_SLC,
            &link_test(true, &[9, 9, 9, 9, 9]),
        ),
        itu_msu(
            1,
            NI,
            SOUTH_PC,
            NODE_PC,
            NORTH_SLC,
            &link_test(true, &NODE_PATTERN),
        ),
    ];
    let started = Instant::now();
    for slta in &wrong {
        let sltm = north
            .until(false, |f| f.link_test().is_some())
            .await
            .expect("SLTM");
        north.accept_and_ack(&sltm).await;
        north.send_msu(slta).await;
    }
    north
        .until(true, |f| f.status() == Some(OUT_OF_SERVICE))
        .await
        .expect("out of service after two wrong acknowledgements");
    assert!(
        started.elapsed() < Duration::from_millis(280),
        "a wrong acknowledgement does not wait for T1"
    );
    assert!(!handle.router().is_reachable("default", FAR_NORTH));

    // And the link code: a second run on the realigned link.
    north
        .until(false, |f| f.status() == Some(ALIGNMENT))
        .await
        .expect("alignment again");
    let sltm = north.realign().await;
    north.accept_and_ack(&sltm).await;
    let other_link = itu_msu(1, NI, NORTH_PC, NODE_PC, 9, &link_test(true, &NODE_PATTERN));
    north.send_msu(&other_link).await;
    let repeat = north
        .until(true, |f| f.link_test().is_some())
        .await
        .expect("the test is repeated");
    assert_eq!(repeat.link_test().unwrap(), (false, NODE_PATTERN.to_vec()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn the_link_test_is_repeated_at_its_interval() {
    let Some((handle, mut north, _south)) = node_with_peers("periodic", PERIODIC_LINK_TEST).await
    else {
        return;
    };
    let sent = metrics::link_tests(LinkTestResult::Sent);
    north.bring_up().await;
    assert!(reachable(&handle, FAR_NORTH, true).await);
    // Q.707 2.2: "the signalling link test message is sent at regular
    // intervals T2" (400 ms here). Three more, each answered.
    let started = Instant::now();
    for _ in 0..3 {
        north.answer_link_test().await;
    }
    assert!(started.elapsed() >= Duration::from_millis(1000));
    assert!(
        handle.router().is_reachable("default", FAR_NORTH),
        "in service throughout"
    );
    assert!(metrics::link_tests(LinkTestResult::Sent) >= sent + 4);
}

// ── Remote congestion and remote processor outage ────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_busy_peer_is_sent_nothing_until_it_says_busy_ended() {
    let Some((_handle, mut north, mut south)) = node_with_links_up("busy").await else {
        return;
    };
    south.status(BUSY).await;
    sleep(Duration::from_millis(50)).await;
    north.send_msu(&transit(1)).await;
    north.send_msu(&transit(2)).await;
    // RFC 4165 4.1.5: "MUST NOT send User Data messages after receiving Link
    // Status Busy and before receiving Link Status Busy Ended".
    assert!(
        timeout(
            Duration::from_millis(200),
            south.until(false, |f| f.msu().is_some())
        )
        .await
        .is_err(),
        "nothing while the peer is busy"
    );
    south.status(BUSY_ENDED).await;
    for tag in [1, 2] {
        let frame = south.next_msu().await.expect("sent after Busy Ended");
        assert_eq!(frame.label().unwrap().payload, [0xC0, 0xDE, tag]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_peer_in_processor_outage_is_not_routed_to_until_it_recovers() {
    let what = "processor_outage";
    let Some((handle, _north, mut south)) = node_with_links_up(what).await else {
        return;
    };
    let from = south.log.len();
    // RFC 4165 4.1.2: Processor Outage and Recovered ride the User Data stream.
    south.status_on(PROCESSOR_OUTAGE, 1).await;
    assert!(
        reachable(&handle, FAR_SOUTH, false).await,
        "no egress while the peer's level 3 is out"
    );
    south.status_on(PROCESSOR_RECOVERED, 1).await;
    // RFC 4165 4.1.4: "the M2PA in RPO SHALL respond with a Link Status Ready
    // message on the User Data stream. The BSN in the Link Status Ready message
    // is set to the FSN of the last User Data message received".
    let ready = south
        .until(false, |f| f.status() == Some(READY))
        .await
        .expect("Ready in answer to Processor Recovered");
    assert_eq!(ready.stream, 1);
    assert_eq!(ready.bsn(), south.fsn_out);
    assert!(reachable(&handle, FAR_SOUTH, true).await);

    let Some(read) = wireshark(&south.log[from..], &STATUS_FIELDS) else {
        return;
    };
    read.clean();
    println!("{what}:\n{}", read.lines());
    let row = read
        .column("m2pa.status")
        .iter()
        .position(|s| *s == "4")
        .unwrap();
    assert_eq!(read.get(row, "sctp.data_sid"), "0x0001");
    assert_eq!(read.get(row, "m2pa.bsn"), "0");
}

// ── Malformed input ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn malformed_messages_are_counted_and_the_link_stays_up() {
    let Some((handle, mut north, mut south)) = node_with_links_up("malformed").await else {
        return;
    };
    let undecodable = metrics::rx_discards(RxDiscard::Undecodable);
    let link_tests = metrics::rx_discards(RxDiscard::LinkTest);

    let mut bad_class = link_status(READY, INITIAL, INITIAL);
    bad_class[2] = 3; // M3UA's class
    let mut bad_type = link_status(READY, INITIAL, INITIAL);
    bad_type[3] = 9;
    let mut bad_version = link_status(READY, INITIAL, INITIAL);
    bad_version[0] = 2;
    let malformed: Vec<Vec<u8>> = vec![
        vec![0x01],
        vec![0x01, 0x00, 0x0b, 0x02, 0, 0, 0, 20],
        link_status(READY, INITIAL, INITIAL)[..18].to_vec(),
        link_status(77, INITIAL, INITIAL),
        link_status(0, INITIAL, INITIAL),
        bad_class,
        bad_type,
        bad_version,
    ];
    for octets in &malformed {
        north.raw(octets, 0).await;
    }
    assert!(
        counted(
            || metrics::rx_discards(RxDiscard::Undecodable),
            undecodable + malformed.len() as u64 - 1
        )
        .await,
        "each one is counted"
    );

    // In sequence at level 2, damaged above it: an MSU too short for its
    // label, and link test messages that do not parse or are not for us.
    let undecodable = metrics::rx_discards(RxDiscard::Undecodable);
    north.send_msu(&[0x82, 0x01]).await;
    north
        .send_msu(&itu_msu(1, NI, NORTH_PC, NODE_PC, NORTH_SLC, &[0x11]))
        .await;
    north
        .send_msu(&itu_msu(
            1,
            NI,
            NORTH_PC,
            NODE_PC,
            NORTH_SLC,
            &[0x11, 0x40, 0xAA],
        ))
        .await;
    north
        .send_msu(&itu_msu(
            1,
            NI,
            NORTH_PC,
            NODE_PC,
            NORTH_SLC,
            &[0x91, 0x10, 0xAA],
        ))
        .await;
    assert!(
        counted(
            || metrics::rx_discards(RxDiscard::Undecodable),
            undecodable + 3
        )
        .await
    );
    // A test for another point code, a test naming a link code the linkset
    // does not have, and an acknowledgement nobody is waiting for.
    north
        .send_msu(&itu_msu(
            1,
            NI,
            NORTH_PC,
            777,
            NORTH_SLC,
            &link_test(false, &[1]),
        ))
        .await;
    north
        .send_msu(&itu_msu(
            1,
            NI,
            NORTH_PC,
            NODE_PC,
            12,
            &link_test(false, &[1]),
        ))
        .await;
    north
        .send_msu(&itu_msu(
            1,
            NI,
            NORTH_PC,
            NODE_PC,
            NORTH_SLC,
            &link_test(true, &[1]),
        ))
        .await;
    assert!(
        counted(|| metrics::rx_discards(RxDiscard::LinkTest), link_tests + 2).await,
        "each link test that cannot be acted on is counted"
    );

    // None of it took the link out or stopped it carrying traffic.
    assert!(handle.router().is_reachable("default", FAR_NORTH));
    north.send_msu(&transit(7)).await;
    let frame = south.next_msu().await.expect("still forwarding");
    assert_eq!(frame.label().unwrap().payload, [0xC0, 0xDE, 7]);
    // The first frame of the log is the Out of Service the node sent when the
    // association came up; there is no other.
    assert!(north
        .log
        .iter()
        .skip(1)
        .all(|f| f.status() != Some(OUT_OF_SERVICE)));
}

// ── The other configuration keys, on the wire ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn emergency_proving_and_a_link_without_a_test_follow_the_configuration() {
    let what = "emergency";
    let Some(listening) = Listening::bind() else {
        eprintln!("SKIP {what}: no kernel SCTP");
        return;
    };
    let fast = FAST_M2PA.replace("{ ", "{ proving: emergency, ");
    let yaml = format!(
        r#"
node: {{ point_code: {NODE_PC}, variant: ITU, network_indicator: national }}
mtp3: {FAST_MTP3}
associations:
  - {{ id: north-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {port}, adjacent_pc: {NORTH_PC}, m2pa: {fast} }}
linksets:
  - {{ name: north, links: [{{assoc: north-0}}], link_test: {{ enabled: false }} }}
"#,
        port = listening.port
    );
    let cfg = Config::parse(&yaml).expect("config parses");
    let router = Arc::new(Router::new(&cfg));
    let Ok(handle) = TransportHandle::start(&cfg, router).await else {
        eprintln!("SKIP {what}: transport did not start");
        return;
    };
    let mut north = listening
        .accept(NORTH_PC, NODE_PC, NI)
        .await
        .expect("north");
    north.align().await;
    // `link_test: {enabled: false}`: available on alignment, and no SLTM.
    assert!(reachable(&handle, NORTH_PC, true).await);
    assert!(
        timeout(
            Duration::from_millis(400),
            north.until(false, |f| f.link_test().is_some())
        )
        .await
        .is_err(),
        "no link test is sent"
    );

    let Some(read) = wireshark(&north.log, &STATUS_FIELDS) else {
        return;
    };
    read.clean();
    println!("{what}:\n{}", read.lines());
    let statuses = read.column("m2pa.status");
    assert_eq!(statuses[..3], ["9", "1", "3"], "Proving Emergency");
    assert!(!statuses.contains(&"2"), "never Proving Normal");
}
