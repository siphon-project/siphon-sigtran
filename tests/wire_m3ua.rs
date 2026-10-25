//! M3UA management of a signalling gateway (RFC 4666), on the wire.
//!
//! The node is started on kernel SCTP loopback and driven by the hand-written
//! peers of `tests/m3ua_peer` (ASPs that connect to it, a signalling gateway
//! it connects to) and, where an SS7 linkset is part of the picture, the
//! hand-written adjacent point of `tests/m2pa_peer`. Every octet they send
//! and read comes from the figures of RFC 4666 and ITU-T Q.704, not from the
//! codecs the node uses. What the node sends is read back by Wireshark and
//! asserted from what Wireshark read. `SIGTRAN_REQUIRE_TSHARK=1` makes a
//! missing `tshark` a failure; without kernel SCTP every test prints SKIP.
//!
//! ```text
//!   hlr-a   hlr-b        msc-a      spare            S (3000)
//!     \      /             |          |                | s-0
//!   server `hlr`      server `msc`  (in no           linkset `s`
//!   context 100       context 200    server)      (some tests only)
//!   6000, 6200           6100                         2000
//!                 node (1000), a signalling gateway
//! ```
//!
//! T(r), T(ack) and T(beat) are configuration keys in milliseconds; the tests
//! set them to a few hundred, so nothing waits on a default.

#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, Instant};

use siphon_sigtran::config::Config;
use siphon_sigtran::metrics::{self, Dir, RxDiscard};
use siphon_sigtran::routing::Router;
use siphon_sigtran::transport::{AsState, M3uaDiscard, M3uaEvent};
use siphon_sigtran::TransportHandle;

mod m2pa_peer;
mod m3ua_peer;
use m2pa_peer::{
    about, itu_msu, wireshark_every, Adjacent, Read, FAST_LINK_TEST, FAST_M2PA, SI_MANAGEMENT, TFA,
    TFC, TFP, TFR,
};
use m3ua_peer::*;

const NODE: u32 = 1000;
/// The point codes of the application servers.
const HLR: u32 = 6000;
const MSC: u32 = 6100;
/// A second point code behind server `hlr`.
const BEHIND_HLR: u32 = 6200;
/// The adjacent point of the linkset, and a destination behind it.
const ADJACENT: u32 = 3000;
const REMOTE: u32 = 2000;
/// Nothing routes there.
const NOWHERE: u32 = 2999;
const RC_HLR: u32 = 100;
const RC_MSC: u32 = 200;
/// National network.
const NI: u8 = 2;
/// The MTP testing user part (Q.704 14.2.1): Wireshark does not look inside.
const SI_USER: u8 = 8;

const FIELDS: [&str; 17] = [
    "m3ua.message_class",
    "m3ua.message_type",
    "m3ua.routing_context",
    "m3ua.error_code",
    "m3ua.status_type",
    "m3ua.status_info",
    "m3ua.asp_identifier",
    "m3ua.traffic_mode_type",
    "m3ua.affected_point_code_mask",
    "m3ua.affected_point_code_pc",
    "m3ua.congestion_level",
    "m3ua.concerned_dpc",
    "m3ua.unavailability_cause",
    "m3ua.user_identity",
    "m3ua.heartbeat_data",
    "m3ua.protocol_data_opc",
    "m3ua.protocol_data_dpc",
];

/// What a test asks of the node.
#[derive(Clone)]
struct Setup {
    /// The traffic mode of server `hlr`.
    mode: &'static str,
    /// T(r) of both servers.
    recovery_ms: u64,
    /// "n" of server `hlr`.
    required_asps: usize,
    /// The `m3ua:` block of every association.
    m3ua: &'static str,
    /// The port of the adjacent point, when the node has the linkset.
    linkset: Option<u16>,
    /// T18 of the node: how long its MTP restart lasts when the adjacent
    /// point sends no traffic restart allowed.
    t18_ms: u64,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            mode: "loadshare",
            recovery_ms: 300,
            required_asps: 1,
            m3ua: "{}",
            linkset: None,
            t18_ms: 60,
        }
    }
}

fn node(setup: &Setup) -> String {
    let Setup {
        mode,
        recovery_ms,
        required_asps,
        m3ua,
        t18_ms,
        ..
    } = setup;
    let mut yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {{ t1_ms: 150, t2_ms: 400, t3_ms: 150, t4_ms: 200, t5_ms: 200, t6_ms: 100, t8_ms: 300, t10_ms: 30000, t12_ms: 200, t13_ms: 200, t18_ms: {t18_ms}, t19_ms: 500, t20_ms: 4000, t21_ms: 300, t23_ms: 400 }}
application_servers:
  - {{ name: hlr, traffic_mode: {mode}, routing_context: {RC_HLR}, asps: [hlr-a, hlr-b], recovery_ms: {recovery_ms}, required_asps: {required_asps}, pending_queue: 4 }}
  - {{ name: msc, traffic_mode: override, routing_context: {RC_MSC}, asps: [msc-a], recovery_ms: {recovery_ms} }}
associations:
  - {{ id: hlr-a, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0, m3ua: {m3ua} }}
  - {{ id: hlr-b, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0, m3ua: {m3ua} }}
  - {{ id: msc-a, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0, m3ua: {m3ua} }}
  - {{ id: spare, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0, m3ua: {m3ua} }}
"#
    );
    let mut routes = format!(
        r#"mtp3_routes:
  - {{ dpc: {HLR}, as: hlr, priority: 1 }}
  - {{ dpc: {BEHIND_HLR}, as: hlr, priority: 1 }}
  - {{ dpc: {MSC}, as: msc, priority: 1 }}
"#
    );
    if let Some(port) = setup.linkset {
        yaml.push_str(&format!(
            "  - {{ id: s-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {port}, adjacent_pc: {ADJACENT}, m2pa: {FAST_M2PA} }}\n\
             linksets:\n  - {{ name: s, links: [{{assoc: s-0}}], link_test: {FAST_LINK_TEST} }}\n"
        ));
        routes.push_str(&format!(
            "  - {{ dpc: {REMOTE}, linkset: s, priority: 1 }}\n"
        ));
    }
    yaml + &routes
}

/// The running node.
struct Gateway {
    handle: TransportHandle,
}

impl Gateway {
    /// Start the node. `None` with a SKIP without kernel SCTP.
    async fn start(what: &str, setup: &Setup) -> Option<Self> {
        let cfg = Config::parse(&node(setup)).expect("config parses");
        let router = Arc::new(Router::new(&cfg));
        match TransportHandle::start(&cfg, router).await {
            Ok(handle) => Some(Self { handle }),
            Err(error) => {
                eprintln!("SKIP {what}: transport did not start ({error})");
                None
            }
        }
    }

    /// An ASP connected to one of the node's associations, not yet up.
    async fn asp(&self, association: &str) -> Peer {
        let addr = self.handle.bound_addr(association).expect("bound");
        Peer::connect(addr).await.expect("the node accepts")
    }

    /// An ASP that is active in the server of `context`, with everything the
    /// node said on the way (the Notify of the state of the server, what it
    /// is owed about the destinations) read and forgotten.
    async fn active(&self, association: &str, context: u32) -> Peer {
        let mut asp = self.asp(association).await;
        asp.up(None, 1).await;
        asp.activate(context).await;
        asp.drain(Duration::from_millis(150)).await;
        asp.log.clear();
        asp
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

    async fn reachable(&self, dpc: u32, wanted: bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.handle.router().is_reachable("default", dpc) == wanted {
                return true;
            }
            sleep(Duration::from_millis(5)).await;
        }
        false
    }
}

/// Wait until a counter is above what it was.
async fn counted(what: &str, before: u64, now: impl Fn() -> u64) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if now() > before {
            return;
        }
        sleep(Duration::from_millis(5)).await;
    }
    panic!("{what} was not counted");
}

/// Have Wireshark read what the node sent, print it, and require that it
/// found nothing malformed. `None` without `tshark`.
fn read(what: &str, received: &[&Received]) -> Option<Read> {
    let read = wireshark_every(&frames(received), &FIELDS)?;
    eprintln!("tshark, {what}:\n{}", read.lines());
    read.clean();
    Some(read)
}

/// A message of the test user part.
fn user(context: Option<u32>, opc: u32, dpc: u32, sls: u8, tag: u8) -> Vec<u8> {
    data(context, opc, dpc, SI_USER, NI, sls, &[tag, 0x55])
}

// ── The reported faults ──────────────────────────────────────────────────────

/// "A DAUD is answered but no unsolicited DUNA/DAVA is ever sent."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn an_asp_is_told_when_a_destination_becomes_available_and_unavailable() {
    let what = "an_asp_is_told";
    let Some(gw) = Gateway::start(what, &Setup::default()).await else {
        return;
    };
    let mut hlr = gw.asp("hlr-a").await;
    hlr.up(None, 1).await;
    hlr.send(&asp_active(None, &[RC_HLR])).await;
    hlr.expect(ASPAC_ACK).await;
    hlr.expect(NTFY).await;
    // RFC 4666 4.5.1: "the SG MAY send DUNA, DRST, or SCON messages for the
    // inaccessible, restricted, or congested destinations to the ASP newly
    // active for the AS". Server `msc` has no ASP yet.
    let owed = hlr.expect(DUNA).await;
    assert_eq!(owed.contexts(), [RC_HLR]);
    assert_eq!(owed.points(), [MSC], "its own point codes are not named");

    // 4.5.1: "the SGP M3UA layer will send a corresponding ... DUNA, DAVA,
    // SCON, or DUPU message ... to the M3UA peers at concerned ASPs".
    let msc = gw.active("msc-a", RC_MSC).await;
    let available = hlr.expect(DAVA).await;
    assert_eq!(available.points(), [MSC]);

    // The ASP of `msc` goes: when T(r) has run out the destination is gone.
    msc.close();
    let failed = Instant::now();
    let unavailable = hlr.expect(DUNA).await;
    assert_eq!(unavailable.points(), [MSC]);
    assert!(
        failed.elapsed() >= Duration::from_millis(250),
        "the server was pending for T(r) first"
    );
    hlr.quiet(Duration::from_millis(200)).await;

    if let Some(read) = read(what, &[&owed, &available, &unavailable]) {
        assert_eq!(read.column("m3ua.message_class"), ["2", "2", "2"]);
        assert_eq!(read.column("m3ua.message_type"), ["1", "2", "1"]);
        assert_eq!(read.column("m3ua.routing_context"), ["100", "100", "100"]);
        assert_eq!(
            read.column("m3ua.affected_point_code_pc"),
            ["6100", "6100", "6100"]
        );
        assert_eq!(
            read.column("m3ua.affected_point_code_mask"),
            ["0", "0", "0"]
        );
    }
    assert!(metrics::m3ua_management_total(Dir::Tx, "DUNA") >= 2);
    assert!(metrics::m3ua_management_total(Dir::Tx, "DAVA") >= 1);
    gw.handle.shutdown();
}

/// "An ASPAC with a routing context no application server has is
/// acknowledged."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_routing_context_no_server_has_is_refused() {
    let what = "a_routing_context_no_server_has";
    let Some(gw) = Gateway::start(what, &Setup::default()).await else {
        return;
    };
    let mut asp = gw.asp("hlr-a").await;
    asp.up(None, 1).await;

    // RFC 4666 3.8.1: "The "Invalid Routing Context" error is sent if a
    // message is received from a peer with an invalid (unconfigured) Routing
    // Context value. For this error, the invalid Routing Context(s) MUST be
    // included in the Error message."
    asp.send(&asp_active(None, &[777])).await;
    let unknown = asp.expect(ERR).await;
    assert_eq!(unknown.error_code(), Some(INVALID_ROUTING_CONTEXT));
    assert_eq!(unknown.contexts(), [777]);
    // The context of a server this ASP is not configured in is no better.
    asp.send(&asp_active(None, &[RC_MSC])).await;
    let foreign = asp.expect(ERR).await;
    assert_eq!(foreign.error_code(), Some(INVALID_ROUTING_CONTEXT));
    assert_eq!(foreign.contexts(), [RC_MSC]);
    assert_eq!(
        gw.handle.registry().server_state("hlr"),
        Some(AsState::Inactive),
        "the ASP is not active"
    );

    // One it has and two it has not: the one is acknowledged by itself.
    asp.send(&asp_active(None, &[777, RC_HLR, 778])).await;
    let two = asp.expect(ERR).await;
    assert_eq!(two.contexts(), [777, 778]);
    let ack = asp.expect(ASPAC_ACK).await;
    assert_eq!(ack.contexts(), [RC_HLR]);
    asp.drain(Duration::from_millis(150)).await;

    // DATA that names a context the ASP is not configured in is not routed.
    let dropped = metrics::rx_discards(RxDiscard::RoutingContext);
    asp.transfer(&user(Some(777), HLR, MSC, 0, 1)).await;
    let data = asp.expect(ERR).await;
    assert_eq!(data.error_code(), Some(INVALID_ROUTING_CONTEXT));
    assert_eq!(data.contexts(), [777]);
    counted("the DATA", dropped, || {
        metrics::rx_discards(RxDiscard::RoutingContext)
    })
    .await;
    // ASP Inactive for an unknown context: the same Error, and still active.
    asp.send(&asp_inactive(&[779])).await;
    let inactive = asp.expect(ERR).await;
    assert_eq!(inactive.contexts(), [779]);
    assert_eq!(
        gw.handle.registry().server_state("hlr"),
        Some(AsState::Active)
    );

    if let Some(read) = read(what, &[&unknown, &foreign, &two, &ack, &data, &inactive]) {
        assert_eq!(
            read.column("m3ua.message_class"),
            ["0", "0", "0", "4", "0", "0"]
        );
        assert_eq!(
            read.column("m3ua.error_code"),
            ["25", "25", "25", "", "25", "25"]
        );
        assert_eq!(
            read.column("m3ua.routing_context"),
            ["777", "200", "777,778", "100", "777", "779"]
        );
    }
    assert!(metrics::m3ua_errors(Dir::Tx, "invalid-routing-context") >= 5);
    gw.handle.shutdown();
}

/// "No NTFY on AS state change."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn every_asp_is_notified_of_the_state_of_its_server() {
    let what = "every_asp_is_notified";
    let Some(gw) = Gateway::start(what, &Setup::default()).await else {
        return;
    };
    let mut a = gw.asp("hlr-a").await;
    let mut b = gw.asp("hlr-b").await;

    // RFC 4666 4.3.4.5: "When an ASP moves from ASP-DOWN to ASP-INACTIVE
    // within a particular AS, a Notify message SHOULD be sent, by the ASP-UP
    // receptor, after sending the ASP-UP-ACK, in order to inform the ASP of
    // the current AS state."
    let a_up = a.up(Some(11), 1).await.remove(0);
    assert_eq!(a_up.status(), Some(AS_INACTIVE));
    assert_eq!(a_up.contexts(), [RC_HLR]);
    let b_up = b.up(Some(12), 1).await.remove(0);
    assert_eq!(b_up.status(), Some(AS_INACTIVE));
    a.quiet(Duration::from_millis(100)).await;

    // "A Notify message reflecting a change in the AS state MUST be sent to
    // all ASPs in the AS, except those in the ASP-DOWN state ... the Notify
    // message MUST be sent after any related acknowledgement messages".
    a.send(&asp_active(None, &[RC_HLR])).await;
    a.expect(ASPAC_ACK).await;
    let a_active = a.expect(NTFY).await;
    let b_active = b.expect(NTFY).await;
    assert_eq!(a_active.status(), Some(AS_ACTIVE));
    assert_eq!(b_active.status(), Some(AS_ACTIVE));
    a.drain(Duration::from_millis(100)).await;

    // 4.3.4.4: "If no other ASPs in the Application Server are in the state
    // ASP-ACTIVE, the SGP MUST send a Notify message ("AS-Pending") to all
    // ASPs in the AS that are in the state ASP-INACTIVE."
    a.send(&asp_inactive(&[RC_HLR])).await;
    let ack = a.expect(ASPIA_ACK).await;
    assert_eq!(ack.contexts(), [RC_HLR]);
    let pending = Instant::now();
    let a_pending = a.expect(NTFY).await;
    let b_pending = b.expect(NTFY).await;
    assert_eq!(a_pending.status(), Some(AS_PENDING));
    assert_eq!(b_pending.status(), Some(AS_PENDING));
    assert!(gw.server("hlr", AsState::Pending).await);

    // 4.3.2: "If T(r) expires before an ASP becomes ASP-ACTIVE ... The AS
    // will move to the AS-INACTIVE state if at least one ASP is in
    // ASP-INACTIVE".
    let expired = metrics::m3ua_events(M3uaEvent::RecoveryExpired);
    let a_inactive = a.expect(NTFY).await;
    let b_inactive = b.expect(NTFY).await;
    let waited = pending.elapsed();
    assert_eq!(a_inactive.status(), Some(AS_INACTIVE));
    assert_eq!(b_inactive.status(), Some(AS_INACTIVE));
    assert!(
        waited >= Duration::from_millis(280) && waited < Duration::from_millis(1500),
        "T(r) is 300 ms, the Notify came after {waited:?}"
    );
    assert!(metrics::m3ua_events(M3uaEvent::RecoveryExpired) > expired);

    // An ASP that fails: "the SGP is indicating to ASPs in the AS that one of
    // the ASPs has failed. The ASP Identifier (if available) of the failed
    // ASP MUST be placed in the message" (3.8.2).
    b.send(&asp_active(None, &[RC_HLR])).await;
    b.expect(ASPAC_ACK).await;
    b.expect(NTFY).await;
    a.expect(NTFY).await;
    b.close();
    let failure = a.expect(NTFY).await;
    assert_eq!(failure.status(), Some(ASP_FAILURE));
    assert_eq!(failure.integers(ASP_IDENTIFIER), [12]);
    assert_eq!(a.expect(NTFY).await.status(), Some(AS_PENDING));

    if let Some(read) = read(
        what,
        &[
            &a_up,
            &a_active,
            &b_active,
            &a_pending,
            &a_inactive,
            &failure,
        ],
    ) {
        assert_eq!(read.column("m3ua.message_class"), ["0"; 6]);
        assert_eq!(read.column("m3ua.message_type"), ["1"; 6]);
        assert_eq!(
            read.column("m3ua.status_type"),
            ["1", "1", "1", "1", "1", "2"]
        );
        assert_eq!(
            read.column("m3ua.status_info"),
            ["2", "3", "3", "4", "2", "3"]
        );
        assert_eq!(read.column("m3ua.routing_context"), ["100"; 6]);
        assert_eq!(read.get(5, "m3ua.asp_identifier"), "12");
    }
    assert!(metrics::m3ua_notifies(Dir::Tx, "as-pending") >= 2);
    assert!(metrics::render().contains("sigtran_as_state{as=\"hlr\"}"));
    gw.handle.shutdown();
}

/// "DATA from an ASP that is not active is dropped silently at protocol
/// level (it is counted, never answered)."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn data_from_an_asp_that_is_not_active_is_answered() {
    let what = "data_from_an_asp_that_is_not_active";
    let Some(gw) = Gateway::start(what, &Setup::default()).await else {
        return;
    };
    let mut msc = gw.active("msc-a", RC_MSC).await;
    let mut asp = gw.asp("hlr-a").await;
    let dropped = metrics::rx_discards(RxDiscard::OutOfState);

    // RFC 4666 3.8.1: "The "Unexpected Message" error MAY be sent if a
    // defined and recognized message is received that is not expected in the
    // current state ... If the Unexpected message contained Routing Contexts,
    // the Routing Contexts SHOULD be included in the Error message."
    // ASP-DOWN.
    asp.transfer(&user(Some(RC_HLR), HLR, MSC, 0, 1)).await;
    let down = asp.expect(ERR).await;
    assert_eq!(down.error_code(), Some(UNEXPECTED_MESSAGE));
    assert_eq!(down.contexts(), [RC_HLR]);
    // ASP-INACTIVE.
    asp.up(None, 1).await;
    asp.transfer(&user(None, HLR, MSC, 0, 2)).await;
    let inactive = asp.expect(ERR).await;
    assert_eq!(inactive.error_code(), Some(UNEXPECTED_MESSAGE));
    assert!(inactive.contexts().is_empty());
    assert!(metrics::rx_discards(RxDiscard::OutOfState) >= dropped + 2);
    msc.quiet(Duration::from_millis(150)).await;

    // ASP-ACTIVE: transferred, with the context of the server it goes to.
    asp.activate(RC_HLR).await;
    asp.transfer(&user(Some(RC_HLR), HLR, MSC, 3, 3)).await;
    let transferred = msc.until(DATA).await;
    assert_eq!(transferred.contexts(), [RC_MSC]);
    assert_eq!(
        transferred.protocol_data(),
        Some((HLR, MSC, SI_USER, NI, 3, vec![3, 0x55]))
    );
    assert_eq!(
        transferred.stream, 1,
        "DATA is not sent on stream 0 (1.4.7)"
    );
    // 1.4.7: "The DATA message MUST NOT be sent on stream 0." From a peer it
    // is taken all the same, and counted: one that was given a single stream
    // has no other.
    let on_stream_0 = metrics::m3ua_events(M3uaEvent::DataOnStream0);
    asp.send_on(&user(Some(RC_HLR), HLR, MSC, 3, 4), 0).await;
    assert_eq!(
        msc.until(DATA).await.protocol_data().map(|p| p.5),
        Some(vec![4, 0x55])
    );
    assert!(metrics::m3ua_events(M3uaEvent::DataOnStream0) > on_stream_0);

    if let Some(read) = read(what, &[&down, &inactive, &transferred]) {
        assert_eq!(read.column("m3ua.message_class"), ["0", "0", "1"]);
        assert_eq!(read.column("m3ua.error_code"), ["6", "6", ""]);
        assert_eq!(read.column("m3ua.routing_context"), ["100", "", "200"]);
        assert_eq!(read.get(2, "m3ua.protocol_data_opc"), "6000");
        assert_eq!(read.get(2, "m3ua.protocol_data_dpc"), "6100");
    }
    // The Diagnostic Information is the offending message (3.8.1).
    assert_eq!(
        down.value(DIAGNOSTIC),
        Some(&user(Some(RC_HLR), HLR, MSC, 0, 1)[..])
    );
    gw.handle.shutdown();
}

/// "BEAT is acknowledged but never originated."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_heartbeat_is_sent_and_a_peer_that_says_nothing_is_dropped() {
    let what = "a_heartbeat_is_sent";
    let setup = Setup {
        m3ua: "{ beat_ms: 200 }",
        ..Setup::default()
    };
    let Some(gw) = Gateway::start(what, &setup).await else {
        return;
    };
    let mut asp = gw.asp("hlr-a").await;
    asp.up(None, 1).await;

    // RFC 4666 4.3.4.6: "Either M3UA peer may optionally send Heartbeat
    // messages periodically, subject to a provisionable timer, T(beat)."
    let started = Instant::now();
    let first = asp.expect(BEAT).await;
    let data = first
        .value(HEARTBEAT_DATA)
        .expect("heartbeat data")
        .to_vec();
    asp.send(&heartbeat(BEAT_ACK, Some(&data))).await;
    let second = asp.expect(BEAT).await;
    let period = started.elapsed();
    assert!(
        period >= Duration::from_millis(350) && period < Duration::from_millis(1200),
        "two heartbeats, 200 ms apart, took {period:?}"
    );
    assert_ne!(second.value(HEARTBEAT_DATA), Some(&data[..]));

    // "Upon receiving a Heartbeat message, the M3UA peer MUST respond with a
    // Heartbeat Ack message", and the data "MUST be echoed back unchanged".
    asp.send(&heartbeat(BEAT, Some(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01])))
        .await;
    let echoed = asp.until(BEAT_ACK).await;
    assert_eq!(
        echoed.value(HEARTBEAT_DATA),
        Some(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01][..])
    );
    asp.send(&heartbeat(BEAT, None)).await;
    let bare = asp.until(BEAT_ACK).await;
    assert!(bare.parameters.is_empty());

    // An acknowledgement that returns something else is noticed.
    let mismatched = metrics::m3ua_events(M3uaEvent::BeatMismatch);
    asp.send(&heartbeat(BEAT_ACK, Some(&[9, 9, 9]))).await;
    counted("the mismatch", mismatched, || {
        metrics::m3ua_events(M3uaEvent::BeatMismatch)
    })
    .await;

    // "If no Heartbeat Ack message (or any other M3UA message) is received
    // from the M3UA peer within 2*T(beat), the remote M3UA peer is considered
    // unavailable." This peer says nothing from here on.
    let timeouts = metrics::m3ua_events(M3uaEvent::BeatTimeout);
    let silent = Instant::now();
    let mut heartbeats = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(3), asp.assoc.recv()).await {
            Ok(Ok((bytes, _))) => {
                assert_eq!(bytes[2..4], [3, 3], "only heartbeats: {bytes:02x?}");
                heartbeats += 1;
            }
            Ok(Err(_)) => break,
            Err(_) => panic!("the association was not aborted"),
        }
    }
    let gone = silent.elapsed();
    assert!(
        gone >= Duration::from_millis(350) && gone < Duration::from_millis(1500),
        "twice T(beat) is 400 ms, the association went after {gone:?}"
    );
    assert!(heartbeats <= 2, "transmission stopped");
    assert!(metrics::m3ua_events(M3uaEvent::BeatTimeout) > timeouts);
    assert!(gw.server("hlr", AsState::Down).await);

    if let Some(read) = read(what, &[&first, &second, &echoed, &bare]) {
        assert_eq!(read.column("m3ua.message_class"), ["3", "3", "3", "3"]);
        assert_eq!(read.column("m3ua.message_type"), ["3", "3", "6", "6"]);
        assert_eq!(read.get(2, "m3ua.heartbeat_data"), "deadbeef01");
        assert_eq!(read.get(3, "m3ua.heartbeat_data"), "");
        assert_eq!(read.get(0, "m3ua.heartbeat_data").len(), 16);
    }
    gw.handle.shutdown();
}

// ── Traffic modes (RFC 4666 4.3.4.3) ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn an_override_server_goes_to_the_asp_that_asks_last() {
    let what = "an_override_server";
    let setup = Setup {
        mode: "override",
        ..Setup::default()
    };
    let Some(gw) = Gateway::start(what, &setup).await else {
        return;
    };
    let mut msc = gw.active("msc-a", RC_MSC).await;
    let mut a = gw.asp("hlr-a").await;
    a.up(Some(11), 1).await;
    a.activate(RC_HLR).await;
    assert_eq!(a.expect(NTFY).await.status(), Some(AS_ACTIVE));
    let mut b = gw.asp("hlr-b").await;
    assert_eq!(b.up(Some(12), 1).await[0].status(), Some(AS_ACTIVE));
    // What `msc` is told about the point codes of `hlr` is not this test's.
    msc.drain(Duration::from_millis(100)).await;
    let takeovers = metrics::m3ua_events(M3uaEvent::Takeover);

    // "In the case of an Override mode AS, receipt of an ASP Active message at
    // an SGP causes the (re)direction of all traffic for the AS to the ASP
    // that sent the ASP Active message ... The SGP or IPSP then MUST send a
    // Notify message ("Alternate ASP_Active") to the previously active ASP".
    // 3.8.2: "The ASP Identifier (if available) of the Alternate ASP MUST be
    // placed in the message."
    b.send(&asp_active(Some(OVERRIDE), &[RC_HLR])).await;
    let ack = b.expect(ASPAC_ACK).await;
    assert_eq!(
        ack.integers(TRAFFIC_MODE),
        [OVERRIDE],
        "the mode is reflected"
    );
    assert_eq!(ack.contexts(), [RC_HLR]);
    let alternate = a.expect(NTFY).await;
    assert_eq!(alternate.status(), Some(ALTERNATE_ASP_ACTIVE));
    assert_eq!(alternate.integers(ASP_IDENTIFIER), [12]);
    assert_eq!(alternate.contexts(), [RC_HLR]);
    assert!(metrics::m3ua_events(M3uaEvent::Takeover) > takeovers);
    // The state of the server did not change: nobody is notified of one.
    b.quiet(Duration::from_millis(150)).await;
    a.quiet(Duration::from_millis(50)).await;
    assert_eq!(
        gw.handle.registry().server_state("hlr"),
        Some(AsState::Active)
    );

    // All traffic for the server goes to the ASP that took over.
    for tag in 0..4 {
        msc.transfer(&user(Some(RC_MSC), MSC, HLR, tag, tag)).await;
        let got = b.expect(DATA).await;
        assert_eq!(got.protocol_data().map(|p| p.4), Some(tag));
    }
    a.quiet(Duration::from_millis(150)).await;
    // And none is taken from the one it displaced ("SHOULD stop traffic
    // to/from that ASP").
    a.transfer(&user(Some(RC_HLR), HLR, MSC, 0, 9)).await;
    assert_eq!(a.expect(ERR).await.error_code(), Some(UNEXPECTED_MESSAGE));
    msc.quiet(Duration::from_millis(150)).await;
    // 4.3.4.4: its ASP Inactive is acknowledged and changes nothing.
    a.send(&asp_inactive(&[RC_HLR])).await;
    a.expect(ASPIA_ACK).await;
    a.quiet(Duration::from_millis(150)).await;

    if let Some(read) = read(what, &[&ack, &alternate]) {
        assert_eq!(read.column("m3ua.message_class"), ["4", "0"]);
        assert_eq!(read.column("m3ua.message_type"), ["3", "1"]);
        assert_eq!(read.get(0, "m3ua.traffic_mode_type"), "1");
        assert_eq!(read.get(1, "m3ua.status_type"), "2");
        assert_eq!(read.get(1, "m3ua.status_info"), "2");
        assert_eq!(read.get(1, "m3ua.asp_identifier"), "12");
        assert_eq!(read.column("m3ua.routing_context"), ["100", "100"]);
    }
    gw.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_traffic_mode_that_is_not_the_servers_is_refused() {
    let what = "a_traffic_mode";
    let setup = Setup {
        mode: "override",
        ..Setup::default()
    };
    let Some(gw) = Gateway::start(what, &setup).await else {
        return;
    };
    let mut asp = gw.asp("hlr-a").await;
    asp.up(None, 1).await;
    // RFC 4666 3.8.1: "The "Unsupported Traffic Mode Type" error is sent by a
    // SGP if an ASP sends an ASP Active message with an unsupported Traffic
    // Mode Type or a Traffic Mode Type that is inconsistent with the
    // presently configured mode for the Application Server."
    let mut refused = Vec::new();
    for mode in [LOADSHARE, BROADCAST, 77] {
        asp.send(&asp_active(Some(mode), &[RC_HLR])).await;
        let error = asp.expect(ERR).await;
        assert_eq!(error.error_code(), Some(UNSUPPORTED_MODE), "mode {mode}");
        assert_eq!(error.contexts(), [RC_HLR]);
        refused.push(error);
    }
    assert_eq!(
        gw.handle.registry().server_state("hlr"),
        Some(AsState::Inactive)
    );
    asp.send(&asp_active(Some(OVERRIDE), &[RC_HLR])).await;
    asp.expect(ASPAC_ACK).await;

    let refused: Vec<&Received> = refused.iter().collect();
    if let Some(read) = read(what, &refused) {
        assert_eq!(read.column("m3ua.error_code"), ["5", "5", "5"]);
        assert_eq!(read.column("m3ua.routing_context"), ["100", "100", "100"]);
    }
    assert!(metrics::m3ua_errors(Dir::Tx, "unsupported-traffic-mode-type") >= 3);
    gw.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_broadcast_server_sends_to_every_active_asp_once_it_has_enough() {
    let what = "a_broadcast_server";
    let setup = Setup {
        mode: "broadcast",
        required_asps: 2,
        ..Setup::default()
    };
    let Some(gw) = Gateway::start(what, &setup).await else {
        return;
    };
    let msc = gw.active("msc-a", RC_MSC).await;
    let mut a = gw.asp("hlr-a").await;
    let mut b = gw.asp("hlr-b").await;
    a.up(None, 1).await;
    b.up(None, 1).await;

    // RFC 4666 4.3.4.3: an SGP "MAY choose not to direct traffic to a newly
    // active ASP until it determines that there are sufficient resources ...
    // (e.g., until there are "n" ASPs in state ASP-ACTIVE in the AS). In this
    // case, the SGP or IPSP SHOULD withhold the Notify (AS-ACTIVE)".
    a.send(&asp_active(Some(BROADCAST), &[RC_HLR])).await;
    a.expect(ASPAC_ACK).await;
    a.quiet(Duration::from_millis(150)).await;
    assert_eq!(
        gw.handle.registry().server_state("hlr"),
        Some(AsState::Inactive)
    );
    b.send(&asp_active(Some(BROADCAST), &[RC_HLR])).await;
    b.expect(ASPAC_ACK).await;
    assert_eq!(a.expect(NTFY).await.status(), Some(AS_ACTIVE));
    assert_eq!(b.expect(NTFY).await.status(), Some(AS_ACTIVE));

    // "every message is sent to each of the active ASPs".
    for tag in 0..3 {
        msc.transfer(&user(Some(RC_MSC), MSC, HLR, tag, tag)).await;
        for asp in [&mut a, &mut b] {
            let got = asp.expect(DATA).await;
            assert_eq!(got.contexts(), [RC_HLR]);
            assert_eq!(got.protocol_data().map(|p| p.5), Some(vec![tag, 0x55]));
        }
    }

    // 4.3.4.4: "A Notify message ("Insufficient ASP resources active in AS")
    // MAY be sent to all inactive ASPs, if required."
    b.send(&asp_inactive(&[RC_HLR])).await;
    b.expect(ASPIA_ACK).await;
    let insufficient = b.expect(NTFY).await;
    assert_eq!(insufficient.status(), Some(INSUFFICIENT_RESOURCES));
    a.quiet(Duration::from_millis(150)).await;
    // The server stays active with the ASP it has.
    msc.transfer(&user(Some(RC_MSC), MSC, HLR, 0, 7)).await;
    a.expect(DATA).await;
    b.quiet(Duration::from_millis(150)).await;

    if let Some(read) = read(what, &[&insufficient]) {
        assert_eq!(read.get(0, "m3ua.status_type"), "2");
        assert_eq!(read.get(0, "m3ua.status_info"), "1");
    }
    gw.handle.shutdown();
}

// ── The pending server (RFC 4666 4.3.2) ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn traffic_for_a_pending_server_waits_for_the_asp_that_takes_over() {
    let what = "a_pending_server";
    let setup = Setup {
        recovery_ms: 600,
        ..Setup::default()
    };
    let Some(gw) = Gateway::start(what, &setup).await else {
        return;
    };
    let mut msc = gw.active("msc-a", RC_MSC).await;
    let mut a = gw.active("hlr-a", RC_HLR).await;
    let mut b = gw.asp("hlr-b").await;
    b.up(None, 1).await;
    msc.drain(Duration::from_millis(100)).await;

    a.send(&asp_inactive(&[RC_HLR])).await;
    a.expect(ASPIA_ACK).await;
    assert_eq!(b.expect(NTFY).await.status(), Some(AS_PENDING));
    assert!(gw.server("hlr", AsState::Pending).await);

    // "A recovery timer T(r) SHOULD be started, and all incoming signalling
    // messages SHOULD be queued by the SGP." The queue holds four here: two
    // of six are counted and gone.
    let full = metrics::m3ua_discards(M3uaDiscard::PendingFull);
    for tag in 1..=6 {
        msc.transfer(&user(Some(RC_MSC), MSC, HLR, 0, tag)).await;
    }
    counted("the queue overflow", full + 1, || {
        metrics::m3ua_discards(M3uaDiscard::PendingFull)
    })
    .await;
    b.quiet(Duration::from_millis(50)).await;
    // The server is a route all the while: its point code stays available.
    assert!(gw.handle.router().is_reachable("default", HLR));
    msc.quiet(Duration::from_millis(50)).await;

    // "If an ASP becomes ASP-ACTIVE before T(r) expires, the AS is moved to
    // the AS-ACTIVE state, and all the queued messages will be sent to the
    // ASP."
    b.send(&asp_active(None, &[RC_HLR])).await;
    b.expect(ASPAC_ACK).await;
    let mut tags = Vec::new();
    while tags.len() < 4 {
        let got = b.until(DATA).await;
        tags.push(got.protocol_data().expect("protocol data").5[0]);
    }
    assert_eq!(tags, [1, 2, 3, 4], "in the order they arrived");
    // The Notify (AS-ACTIVE) is on stream 0 and the DATA on stream 1: which
    // of them is read first is not the node's to say.
    let rest = b.drain(Duration::from_millis(100)).await;
    assert!(rest.iter().all(|m| !m.is(DATA)), "four, not more");

    // "If T(r) expires before an ASP becomes ASP-ACTIVE, and the SGP has no
    // alternative, the SGP may stop queuing messages and discard all
    // previously queued messages."
    let expired = metrics::m3ua_discards(M3uaDiscard::PendingExpired);
    b.send(&asp_inactive(&[RC_HLR])).await;
    b.expect(ASPIA_ACK).await;
    assert_eq!(b.expect(NTFY).await.status(), Some(AS_PENDING));
    for tag in 1..=2 {
        msc.transfer(&user(Some(RC_MSC), MSC, HLR, 0, tag)).await;
    }
    assert_eq!(b.expect(NTFY).await.status(), Some(AS_INACTIVE));
    counted("the expired queue", expired + 1, || {
        metrics::m3ua_discards(M3uaDiscard::PendingExpired)
    })
    .await;
    // Only now is the destination gone for the others.
    let unavailable = msc.expect(DUNA).await;
    assert_eq!(unavailable.points(), [HLR, BEHIND_HLR]);
    assert_eq!(unavailable.contexts(), [RC_MSC]);
    a.drain(Duration::from_millis(50)).await;

    if let Some(read) = read(what, &[&unavailable]) {
        assert_eq!(read.get(0, "m3ua.affected_point_code_pc"), "6000,6200");
        assert_eq!(read.get(0, "m3ua.routing_context"), "200");
    }
    gw.handle.shutdown();
}

// ── What cannot be acted on (RFC 4666 3.8.1) ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn what_cannot_be_acted_on_is_answered_with_the_error_that_says_why() {
    let what = "the_errors_of_3_8_1";
    let Some(gw) = Gateway::start(what, &Setup::default()).await else {
        return;
    };
    let mut msc = gw.active("msc-a", RC_MSC).await;
    let mut asp = gw.active("hlr-a", RC_HLR).await;
    let context = integers(ROUTING_CONTEXT, &[RC_HLR]);
    let long: Vec<u8> = (0..48).collect();

    // (what is sent, the stream, the Error Code that answers it).
    let cases: Vec<(&str, Vec<u8>, u32)> = vec![
        // 3.1.1: "The supported versions are ... 1".
        ("version 2", vec![2, 0, 3, 1, 0, 0, 0, 8], INVALID_VERSION),
        (
            "message class 7",
            message((7, 1), &[parameter(INFO_STRING, &long)]),
            UNSUPPORTED_CLASS,
        ),
        ("type 9 of class 3", message((3, 9), &[]), UNSUPPORTED_TYPE),
        ("three octets", vec![1, 0, 1], PROTOCOL_ERROR),
        (
            "a message length beyond the message",
            vec![1, 0, 3, 3, 0, 0, 0, 64],
            PROTOCOL_ERROR,
        ),
        (
            "a parameter length of 2",
            [message(ASPAC, &[]), vec![0, 6, 0, 2]].concat(),
            PARAMETER_FIELD_ERROR,
        ),
        (
            "a parameter length beyond the message",
            [message(ASPAC, &[]), vec![0, 6, 0, 0x20, 0, 0, 0, 1]].concat(),
            PARAMETER_FIELD_ERROR,
        ),
        (
            "a routing context of six octets",
            message(ASPAC, &[parameter(ROUTING_CONTEXT, &[0, 0, 0, 100, 0, 1])]),
            PARAMETER_FIELD_ERROR,
        ),
        (
            "DATA without Protocol Data",
            message(DATA, std::slice::from_ref(&context)),
            MISSING_PARAMETER,
        ),
        (
            "Protocol Data of five octets",
            message(DATA, &[parameter(PROTOCOL_DATA, &[0, 0, 0x17, 0x70, 0])]),
            PARAMETER_FIELD_ERROR,
        ),
        (
            "DUNA without an Affected Point Code",
            message(DUNA, std::slice::from_ref(&context)),
            MISSING_PARAMETER,
        ),
        (
            "a point code of 24 bits in a 14-bit network",
            ssnm(DUNA, &[RC_HLR], &[(0, 0x00FF_FFFF)]),
            INVALID_PARAMETER_VALUE,
        ),
        (
            "a registration request",
            message(REG_REQ, &[]),
            UNSUPPORTED_CLASS,
        ),
        (
            "an acknowledgement from an ASP",
            message(ASPUP_ACK, &[]),
            UNEXPECTED_MESSAGE,
        ),
        (
            "a Notify from an ASP",
            notify(AS_ACTIVE, &[RC_HLR]),
            UNEXPECTED_MESSAGE,
        ),
        (
            "a DUPU from an ASP",
            message(
                DUPU,
                &[affected(&[(0, MSC)]), integers(USER_CAUSE, &[0x0001_0003])],
            ),
            UNEXPECTED_MESSAGE,
        ),
        // 1.4.3.2: "MTP3 management messages ... MUST NOT be encapsulated as
        // Data message Payload Data".
        (
            "transfer-prohibited in a DATA message",
            data(
                Some(RC_HLR),
                HLR,
                MSC,
                SI_MANAGEMENT,
                NI,
                0,
                &about(TFP, REMOTE, 0),
            ),
            PROTOCOL_ERROR,
        ),
    ];
    let undecodable = metrics::rx_discards(RxDiscard::Undecodable);
    let parameters = metrics::rx_discards(RxDiscard::Parameter);
    let unexpected = metrics::rx_discards(RxDiscard::Unexpected);
    let management = metrics::rx_discards(RxDiscard::Management);
    let mut errors = Vec::new();
    for (name, bytes, code) in &cases {
        asp.send_on(bytes, 1).await;
        let error = asp.expect(ERR).await;
        assert_eq!(error.error_code(), Some(*code), "{name}");
        // "the Diagnostic Information parameter MUST be included with the
        // first 40 octets of the offending message".
        let diagnostic = &bytes[..bytes.len().min(40)];
        assert_eq!(error.value(DIAGNOSTIC), Some(diagnostic), "{name}");
        errors.push(error);
    }
    assert!(metrics::rx_discards(RxDiscard::Undecodable) >= undecodable + 7);
    assert!(metrics::rx_discards(RxDiscard::Parameter) >= parameters + 3);
    assert!(metrics::rx_discards(RxDiscard::Unexpected) >= unexpected + 4);
    assert!(metrics::rx_discards(RxDiscard::Management) > management);

    // "Error messages MUST NOT be generated in response to other Error
    // messages", readable or not.
    asp.send(&error(UNEXPECTED_MESSAGE, &[RC_HLR])).await;
    asp.send(&[message(ERR, &[]), vec![0, 0x0c, 0, 2]].concat())
        .await;
    asp.quiet(Duration::from_millis(200)).await;
    assert!(metrics::m3ua_errors(Dir::Rx, "unexpected-message") >= 1);

    // An ASP that is configured in no server, and one that is not up.
    let mut spare = gw.asp("spare").await;
    spare.send(&asp_active(None, &[])).await;
    let down = spare.expect(ERR).await;
    assert_eq!(down.error_code(), Some(UNEXPECTED_MESSAGE));
    spare.up(None, 0).await;
    // "The "No Configured AS for ASP" error is sent if a message is received
    // from a peer without a Routing Context parameter and it is not known by
    // configuration data which Application Servers are referenced."
    spare.send(&asp_active(None, &[])).await;
    let active = spare.expect(ERR).await;
    assert_eq!(active.error_code(), Some(NO_CONFIGURED_AS));
    spare.send(&asp_inactive(&[])).await;
    let inactive = spare.expect(ERR).await;
    assert_eq!(inactive.error_code(), Some(NO_CONFIGURED_AS));

    // After all of it the ASP is as active as it was.
    asp.transfer(&user(Some(RC_HLR), HLR, MSC, 0, 1)).await;
    msc.until(DATA).await;
    assert_eq!(
        gw.handle.registry().server_state("hlr"),
        Some(AsState::Active)
    );

    errors.extend([down, active, inactive]);
    let errors: Vec<&Received> = errors.iter().collect();
    if let Some(read) = read(what, &errors) {
        assert_eq!(
            read.column("m3ua.error_code"),
            [
                "1", "3", "4", "7", "7", "18", "18", "18", "22", "18", "22", "17", "3", "6", "6",
                "6", "7", "6", "26", "26"
            ]
        );
        assert!(read.column("m3ua.message_class").iter().all(|c| *c == "0"));
    }
    gw.handle.shutdown();
}

// ── The audit (RFC 4666 4.5.3) ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn an_audit_is_answered_for_every_destination_it_names() {
    let what = "an_audit";
    let Some(gw) = Gateway::start(what, &Setup::default()).await else {
        return;
    };
    let _msc = gw.active("msc-a", RC_MSC).await;
    let mut asp = gw.active("hlr-a", RC_HLR).await;

    // "The status of each SS7 destination requested is indicated in a DUNA
    // message (if unavailable), a DAVA message (if available)"; "An SG SHOULD
    // respond with a DUNA message when DAUD was received with an unknown
    // Signalling Point Code."
    asp.send(&ssnm(DAUD, &[RC_HLR], &[(0, MSC), (0, NOWHERE), (0, HLR)]))
        .await;
    let unavailable = asp.expect(DUNA).await;
    assert_eq!(unavailable.affected(), [(0, NOWHERE)]);
    assert_eq!(unavailable.contexts(), [RC_HLR]);
    let available = asp.expect(DAVA).await;
    assert_eq!(available.points(), [MSC, HLR]);

    // 3.4.1: a mask of 9 wildcards the last nine bits: 6000 and 6100 are in
    // that range, 6200 is not. A range no destination is in is answered as it
    // was asked.
    asp.send(&ssnm(DAUD, &[RC_HLR], &[(9, HLR), (4, 2992)]))
        .await;
    let range_unavailable = asp.expect(DUNA).await;
    assert_eq!(range_unavailable.affected(), [(4, 2992)]);
    let range = asp.expect(DAVA).await;
    assert_eq!(range.points(), [HLR, MSC]);

    // An audit from an ASP that is not active, and one for a context the ASP
    // is not configured in, are not answered with a status.
    let mut inactive = gw.asp("hlr-b").await;
    inactive.up(None, 1).await;
    inactive.send(&ssnm(DAUD, &[RC_HLR], &[(0, MSC)])).await;
    assert_eq!(
        inactive.expect(ERR).await.error_code(),
        Some(UNEXPECTED_MESSAGE)
    );
    asp.send(&ssnm(DAUD, &[RC_MSC], &[(0, MSC)])).await;
    let foreign = asp.expect(ERR).await;
    assert_eq!(foreign.error_code(), Some(INVALID_ROUTING_CONTEXT));
    assert_eq!(foreign.contexts(), [RC_MSC]);

    if let Some(read) = read(
        what,
        &[&unavailable, &available, &range_unavailable, &range],
    ) {
        assert_eq!(read.column("m3ua.message_type"), ["1", "2", "1", "2"]);
        assert_eq!(
            read.column("m3ua.affected_point_code_pc"),
            ["2999", "6100,6000", "2992", "6000,6100"]
        );
        assert_eq!(
            read.column("m3ua.affected_point_code_mask"),
            ["0", "0,0", "4", "0,0"]
        );
    }
    assert!(metrics::m3ua_management_total(Dir::Rx, "DAUD") >= 4);
    gw.handle.shutdown();
}

// ── Between an application server and a linkset (RFC 4666 1.4.3.2) ───────────

const MANAGEMENT_FIELDS: [&str; 6] = [
    "mtp3.service_indicator",
    "mtp3.opc",
    "mtp3.dpc",
    "mtp3mg.h0",
    "mtp3mg.h1",
    "mtp3mg.apc",
];

/// The node with its linkset, and the adjacent point at the other end.
async fn with_linkset(what: &str, setup: Setup, restart: bool) -> Option<(Gateway, Adjacent)> {
    let Some(adjacent) = Adjacent::spawn(ADJACENT, NODE, NI, 0, restart).await else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return None;
    };
    let setup = Setup {
        linkset: Some(adjacent.port),
        ..setup
    };
    let gw = Gateway::start(what, &setup).await?;
    Some((gw, adjacent))
}

/// The affected point codes of the next messages of one type, until all of
/// `wanted` were named: several destinations that change together may share a
/// message or not.
async fn named(asp: &mut Peer, kind: (u8, u8), wanted: &[u32]) -> Vec<Received> {
    let mut seen = Vec::new();
    let mut messages = Vec::new();
    while !wanted.iter().all(|pc| seen.contains(pc)) {
        let got = asp.until(kind).await;
        seen.extend(got.points());
        messages.push(got);
    }
    seen.sort_unstable();
    assert_eq!(seen, wanted, "exactly these destinations");
    messages
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn route_management_of_the_linkset_reaches_the_asps() {
    let what = "linkset_to_asps";
    let Some((gw, mut s)) = with_linkset(what, Setup::default(), true).await else {
        return;
    };
    assert!(gw.reachable(REMOTE, true).await);
    let mut asp = gw.active("hlr-a", RC_HLR).await;
    s.drain(Duration::from_millis(250)).await;

    // RFC 4666 1.4.3.2: "MTP3 management messages (such as TFPs or TFAs
    // received from the SS7 network) MUST NOT be encapsulated as Data message
    // Payload Data ... The SG MUST terminate these messages and generate M3UA
    // messages, as appropriate." 3.4.1: DUNA "to indicate that the SG has
    // determined that one or more SS7 destinations are unreachable".
    s.manage(0, about(TFP, REMOTE, 0));
    let prohibited = asp.expect(DUNA).await;
    assert_eq!(prohibited.points(), [REMOTE]);
    assert_eq!(prohibited.contexts(), [RC_HLR]);
    s.manage(0, about(TFA, REMOTE, 0));
    let allowed = asp.expect(DAVA).await;
    assert_eq!(allowed.points(), [REMOTE]);

    // 3.4.6: DRST "to indicate that the SG has determined that one or more
    // SS7 destinations are now restricted from the point of view of the SG".
    s.manage(0, about(TFR, REMOTE, 0));
    let restricted = asp.expect(DRST).await;
    assert_eq!(restricted.points(), [REMOTE]);
    // And "or in response to a DAUD message, if appropriate".
    sleep(Duration::from_millis(250)).await;
    asp.send(&ssnm(DAUD, &[RC_HLR], &[(0, REMOTE)])).await;
    let audited = asp.expect(DRST).await;
    assert_eq!(audited.points(), [REMOTE]);
    // 3.4.2: DAVA says "reachable (and not restricted)".
    s.manage(0, about(TFA, REMOTE, 0));
    let unrestricted = asp.expect(DAVA).await;
    assert_eq!(unrestricted.points(), [REMOTE]);
    asp.quiet(Duration::from_millis(150)).await;

    // The link fails: what was behind it, and the adjacent point, are gone.
    s.fail();
    let lost = named(&mut asp, DUNA, &[REMOTE, ADJACENT]).await;

    let mut all = vec![&prohibited, &allowed, &restricted, &audited, &unrestricted];
    all.extend(lost.iter());
    if let Some(read) = read(what, &all) {
        assert_eq!(
            read.column("m3ua.message_type")[..5],
            ["1", "2", "6", "6", "2"]
        );
        assert_eq!(
            read.column("m3ua.affected_point_code_pc")[..5],
            ["2000", "2000", "2000", "2000", "2000"]
        );
        assert!(read.column("m3ua.message_class").iter().all(|c| *c == "2"));
        assert!(read
            .column("m3ua.routing_context")
            .iter()
            .all(|c| *c == "100"));
    }
    assert!(metrics::m3ua_management_total(Dir::Tx, "DRST") >= 2);
    gw.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn what_an_asp_says_about_a_destination_reaches_the_linkset() {
    let what = "asp_to_linkset";
    let Some((gw, mut s)) = with_linkset(what, Setup::default(), true).await else {
        return;
    };
    assert!(gw.reachable(REMOTE, true).await);
    let mut asp = gw.active("hlr-a", RC_HLR).await;
    assert!(gw.reachable(BEHIND_HLR, true).await);
    s.drain(Duration::from_millis(300)).await;

    // A DUNA from the ASP about a point code behind it: the routing tables
    // follow, and the adjacent point is told (Q.704 13.2.2 ii).
    asp.send(&ssnm(DUNA, &[RC_HLR], &[(0, BEHIND_HLR)])).await;
    let prohibited = s.until(|f| f.is(TFP)).await.expect("transfer-prohibited");
    let message = prohibited.management().expect("management");
    assert_eq!(message.destination(), Some(BEHIND_HLR));
    assert_eq!((message.opc, message.dpc), (NODE, ADJACENT));
    assert!(gw.reachable(BEHIND_HLR, false).await);
    // The other point code of the server is not concerned.
    assert!(gw.handle.router().is_reachable("default", HLR));

    asp.send(&ssnm(DAVA, &[RC_HLR], &[(0, BEHIND_HLR)])).await;
    let allowed = s.until(|f| f.is(TFA)).await.expect("transfer-allowed");
    assert_eq!(
        allowed.management().and_then(|m| m.destination()),
        Some(BEHIND_HLR)
    );
    assert!(gw.reachable(BEHIND_HLR, true).await);
    // The ASP that said so is not told what it said.
    asp.quiet(Duration::from_millis(200)).await;

    if let Some(read) = m2pa_peer::wireshark(&[prohibited, allowed], &MANAGEMENT_FIELDS) {
        eprintln!("tshark, {what}:\n{}", read.lines());
        read.clean();
        assert_eq!(read.column("mtp3.service_indicator"), ["0x00", "0x00"]);
        assert_eq!(read.column("mtp3.opc"), ["1000", "1000"]);
        assert_eq!(read.column("mtp3.dpc"), ["3000", "3000"]);
        assert_eq!(read.column("mtp3mg.h0"), ["0x04", "0x04"]);
        assert_eq!(read.column("mtp3mg.h1"), ["0x01", "0x05"]);
        assert_eq!(read.column("mtp3mg.apc"), ["6200", "6200"]);
    }
    gw.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn congestion_and_user_part_unavailability_cross_the_gateway() {
    let what = "congestion";
    let Some((gw, mut s)) = with_linkset(what, Setup::default(), true).await else {
        return;
    };
    assert!(gw.reachable(REMOTE, true).await);
    let mut asp = gw.active("hlr-a", RC_HLR).await;
    s.drain(Duration::from_millis(250)).await;

    // A transfer-controlled for the point code of the server (its traffic
    // met the congestion) is not sent on as DATA: RFC 4666 3.4.4, SCON "to
    // indicate that an SG has determined that there is congestion in the SS7
    // network to one or more destinations".
    let management =
        |dpc: u32, content: &[u8]| itu_msu(SI_MANAGEMENT, NI, ADJACENT, dpc, 0, content);
    s.send(management(HLR, &about(TFC, REMOTE, 2)));
    let levelled = asp.expect(SCON).await;
    assert_eq!(levelled.points(), [REMOTE]);
    assert_eq!(levelled.contexts(), [RC_HLR]);
    assert_eq!(levelled.integers(CONGESTION), [2]);
    assert!(levelled.value(CONCERNED).is_none(), "only an ASP sends one");
    // "For MTP congestion methods without multiple congestion levels (e.g.,
    // the ITU international method) the parameter is not included."
    s.send(management(HLR, &about(TFC, REMOTE, 0)));
    let plain = asp.expect(SCON).await;
    assert!(plain.value(CONGESTION).is_none());
    // One for this node itself: 4.5.1, every active ASP is told.
    s.manage(0, about(TFC, REMOTE, 1));
    let own = asp.expect(SCON).await;
    assert_eq!(own.points(), [REMOTE]);
    assert_eq!(own.integers(CONGESTION), [1]);

    // 3.4.5: DUPU "to inform concerned ASPs that a remote peer MTP3-User Part
    // ... at an SS7 node is unavailable". User part 3 (SCCP), cause 1
    // (unequipped), from Q.704 15.17.
    let mut unavailable = about((10, 1), REMOTE, 0);
    unavailable.push(0x03 | 0x01 << 4);
    s.send(itu_msu(SI_MANAGEMENT, NI, REMOTE, HLR, 0, &unavailable));
    let user_part = asp.expect(DUPU).await;
    assert_eq!(user_part.affected(), [(0, REMOTE)]);
    assert_eq!(user_part.integers(USER_CAUSE), [0x0001_0003]);

    // Any other management message for the point code of the server has no
    // M3UA message, and is not DATA either.
    let dropped = metrics::m3ua_discards(M3uaDiscard::Management);
    s.send(management(HLR, &about(TFP, REMOTE, 0)));
    counted("the transfer-prohibited", dropped, || {
        metrics::m3ua_discards(M3uaDiscard::Management)
    })
    .await;
    asp.quiet(Duration::from_millis(150)).await;

    // 3.4.4: "Any resulting Transfer Controlled (TFC) message from the SG is
    // sent to the Concerned Point Code using the single Affected DPC
    // contained in the SCON message to populate the (affected) Destination
    // field of the TFC message".
    s.drain(Duration::from_millis(50)).await;
    asp.send(&scon(&[RC_HLR], HLR, Some(REMOTE), Some(3))).await;
    let controlled = s.until(|f| f.is(TFC)).await.expect("transfer-controlled");
    let message = controlled.management().expect("management");
    assert_eq!((message.opc, message.dpc), (NODE, REMOTE));
    assert_eq!(message.destination(), Some(HLR));
    assert_eq!(message.body[1] >> 6, 3, "the congestion status");
    // Without a Concerned Destination there is nobody to send one to.
    asp.send(&scon(&[RC_HLR], HLR, None, Some(1))).await;
    assert!(s.recv_within(Duration::from_millis(200)).await.is_none());

    if let Some(read) = read(what, &[&levelled, &plain, &own, &user_part]) {
        assert_eq!(read.column("m3ua.message_class"), ["2", "2", "2", "2"]);
        assert_eq!(read.column("m3ua.message_type"), ["4", "4", "4", "5"]);
        assert_eq!(
            read.column("m3ua.affected_point_code_pc"),
            ["2000", "2000", "2000", "2000"]
        );
        assert_eq!(read.column("m3ua.congestion_level"), ["2", "", "1", ""]);
        assert_eq!(read.get(3, "m3ua.unavailability_cause"), "1");
        assert_eq!(read.get(3, "m3ua.user_identity"), "3");
        assert_eq!(read.column("m3ua.concerned_dpc"), ["", "", "", ""]);
    }
    if let Some(read) = m2pa_peer::wireshark(&[controlled], &MANAGEMENT_FIELDS) {
        eprintln!("tshark, {what}, on the linkset:\n{}", read.lines());
        read.clean();
        assert_eq!(read.get(0, "mtp3.opc"), "1000");
        assert_eq!(read.get(0, "mtp3.dpc"), "2000");
        assert_eq!(read.get(0, "mtp3mg.h0"), "0x03");
        assert_eq!(read.get(0, "mtp3mg.h1"), "0x02");
        assert_eq!(read.get(0, "mtp3mg.apc"), "6000");
    }
    gw.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn while_the_mtp_restarts_the_destinations_are_unavailable_to_the_asps() {
    let what = "mtp_restart";
    // No traffic restart allowed from the adjacent point: the restart lasts
    // T18, 1.2 s here.
    let setup = Setup {
        t18_ms: 1_200,
        ..Setup::default()
    };
    let Some((gw, _s)) = with_linkset(what, setup, false).await else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gw.handle.registry().is_restarting() {
        assert!(Instant::now() < deadline, "the restart begins");
        sleep(Duration::from_millis(5)).await;
    }

    // RFC 4666 4.6: "When an ASP becomes active for an AS and the SG is
    // experiencing SS7 network isolation or is performing the MTP Restart
    // procedure for the AS, the SG MAY send a DUNA message for the concerned
    // destinations to the newly active ASP to prevent the ASP from sending
    // traffic."
    let mut asp = gw.asp("hlr-a").await;
    asp.up(None, 1).await;
    asp.send(&asp_active(None, &[RC_HLR])).await;
    asp.expect(ASPAC_ACK).await;
    let owed = asp.until(DUNA).await;
    assert_eq!(owed.points(), [REMOTE, ADJACENT, MSC]);
    // "If MTP restart is in progress at the SG, the SGP returns a DUNA
    // message for that destination, even if it received an indication that
    // the destination became available or restricted."
    asp.send(&ssnm(DAUD, &[RC_HLR], &[(0, REMOTE)])).await;
    let audited = asp.expect(DUNA).await;
    assert_eq!(audited.points(), [REMOTE]);
    assert!(
        gw.handle.registry().is_restarting(),
        "all of it during the restart"
    );

    // "When the SG has completed the MTP Restart procedure, the M3UA layers
    // at the SGPs inform all concerned ASPs in the ASP-ACTIVE state of any
    // available/restricted SS7 destinations, using the DAVA/DRST messages. No
    // message is necessary for those destinations still unavailable".
    let available = named(&mut asp, DAVA, &[REMOTE, ADJACENT]).await;
    assert!(!gw.handle.registry().is_restarting());
    asp.quiet(Duration::from_millis(200)).await;

    let mut all = vec![&owed, &audited];
    all.extend(available.iter());
    if let Some(read) = read(what, &all) {
        assert_eq!(read.get(0, "m3ua.message_type"), "1");
        assert_eq!(read.get(0, "m3ua.affected_point_code_pc"), "2000,3000,6100");
        assert_eq!(read.get(1, "m3ua.affected_point_code_pc"), "2000");
        assert!(read.column("m3ua.message_type")[2..]
            .iter()
            .all(|t| *t == "2"));
    }
    gw.handle.shutdown();
}

// ── This node as an ASP (RFC 4666 4.3.4, the ASP side) ───────────────────────

const RC_REMOTE: u32 = 500;
const RC_LOCAL: u32 = 600;
/// Behind the signalling gateway this node is an ASP of, and behind an ASP of
/// this node.
const FAR: u32 = 7000;
const NEAR: u32 = 7100;

/// The node as an ASP of the gateway at `port`, and as the gateway of one ASP
/// of its own.
async fn as_an_asp(what: &str) -> Option<(Gateway, Peer)> {
    let Some(listening) = Listening::bind() else {
        eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
        return None;
    };
    let yaml = format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
associations:
  - {{ id: to-gateway, adaptation: m3ua, role: client, addrs: [127.0.0.1], port: {}, m3ua: {{ ack_ms: 250, asp_id: 77 }} }}
  - {{ id: near, adaptation: m3ua, role: server, addrs: [127.0.0.1], port: 0 }}
application_servers:
  - {{ name: far, traffic_mode: override, routing_context: {RC_REMOTE}, asps: [to-gateway] }}
  - {{ name: near, traffic_mode: override, routing_context: {RC_LOCAL}, asps: [near] }}
mtp3_routes:
  - {{ dpc: {FAR}, as: far, priority: 1 }}
  - {{ dpc: {NEAR}, as: near, priority: 1 }}
"#,
        listening.port
    );
    let cfg = Config::parse(&yaml).expect("config parses");
    let router = Arc::new(Router::new(&cfg));
    let handle = match TransportHandle::start(&cfg, router).await {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("SKIP {what}: transport did not start ({error})");
            return None;
        }
    };
    let gateway = listening.accept().await.expect("the node connects");
    Some((Gateway { handle }, gateway))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn as_an_asp_the_node_asks_again_until_it_is_acknowledged() {
    let what = "as_an_asp_asks";
    let Some((gw, mut sg)) = as_an_asp(what).await else {
        return;
    };
    let timeouts = metrics::m3ua_events(M3uaEvent::AckTimeout);

    // RFC 4666 4.3.4.1: "When the ASP sends an ASP Up message, it starts
    // timer T(ack). If the ASP does not receive a response to an ASP Up
    // message within T(ack), the ASP MAY restart T(ack) and resend ASP Up
    // messages until it receives an ASP Up Ack message."
    let first = sg.expect(ASPUP).await;
    assert_eq!(first.integers(ASP_IDENTIFIER), [77]);
    let asked = Instant::now();
    let again = sg.expect(ASPUP).await;
    assert_eq!(again.frame.bytes, first.frame.bytes);
    let waited = asked.elapsed();
    assert!(
        waited >= Duration::from_millis(200) && waited < Duration::from_millis(1200),
        "T(ack) is 250 ms, the second ASP Up came after {waited:?}"
    );
    assert!(metrics::m3ua_events(M3uaEvent::AckTimeout) > timeouts);
    sg.send(&message(ASPUP_ACK, &[])).await;

    // 4.3.4.3, the same for ASP Active: the mode of the server and its
    // Routing Context.
    let active = sg.expect(ASPAC).await;
    assert_eq!(active.integers(TRAFFIC_MODE), [OVERRIDE]);
    assert_eq!(active.contexts(), [RC_REMOTE]);
    let repeated = sg.expect(ASPAC).await;
    assert_eq!(repeated.frame.bytes, active.frame.bytes);
    assert_eq!(
        gw.handle.registry().server_state("far"),
        Some(AsState::Inactive)
    );
    sg.send(&message(
        ASPAC_ACK,
        &[integers(ROUTING_CONTEXT, &[RC_REMOTE])],
    ))
    .await;
    assert!(gw.server("far", AsState::Active).await);
    // Acknowledged: nothing is asked again.
    sg.quiet(Duration::from_millis(600)).await;

    // Traffic both ways. From the gateway, a context this node is not
    // configured in is answered (3.8.1).
    let mut near = gw.active("near", RC_LOCAL).await;
    near.transfer(&user(Some(RC_LOCAL), NEAR, FAR, 2, 1)).await;
    let out = sg.until(DATA).await;
    assert_eq!(out.contexts(), [RC_REMOTE]);
    assert_eq!(
        out.protocol_data(),
        Some((NEAR, FAR, SI_USER, NI, 2, vec![1, 0x55]))
    );
    sg.transfer(&user(Some(RC_REMOTE), FAR, NEAR, 0, 2)).await;
    assert_eq!(near.until(DATA).await.contexts(), [RC_LOCAL]);
    sg.transfer(&user(Some(999), FAR, NEAR, 0, 3)).await;
    let refused = sg.until(ERR).await;
    assert_eq!(refused.error_code(), Some(INVALID_ROUTING_CONTEXT));
    assert_eq!(refused.contexts(), [999]);

    if let Some(read) = read(what, &[&first, &active, &out, &refused]) {
        assert_eq!(read.column("m3ua.message_class"), ["3", "4", "1", "0"]);
        assert_eq!(read.column("m3ua.message_type"), ["1", "1", "1", "0"]);
        assert_eq!(read.get(0, "m3ua.asp_identifier"), "77");
        assert_eq!(read.get(1, "m3ua.traffic_mode_type"), "1");
        assert_eq!(
            read.column("m3ua.routing_context"),
            ["", "500", "500", "999"]
        );
        assert_eq!(read.get(3, "m3ua.error_code"), "25");
    }
    gw.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn as_an_asp_the_node_yields_to_an_alternate_and_returns_when_asked() {
    let what = "as_an_asp_yields";
    let Some((gw, mut sg)) = as_an_asp(what).await else {
        return;
    };
    let acknowledged = message(ASPAC_ACK, &[integers(ROUTING_CONTEXT, &[RC_REMOTE])]);
    sg.expect(ASPUP).await;
    // RFC 4666 3.8.1: "silent discard is used by an ASP if it received a DATA
    // message from an SGP while it was in the ASP-INACTIVE state".
    let dropped = metrics::rx_discards(RxDiscard::OutOfState);
    sg.transfer(&user(Some(RC_REMOTE), FAR, NEAR, 0, 1)).await;
    counted("the DATA", dropped, || {
        metrics::rx_discards(RxDiscard::OutOfState)
    })
    .await;
    sg.send(&message(ASPUP_ACK, &[])).await;
    sg.expect(ASPAC).await;
    sg.send(&acknowledged).await;
    assert!(gw.server("far", AsState::Active).await);
    assert!(gw.reachable(FAR, true).await);
    let mut near = gw.active("near", RC_LOCAL).await;
    near.drain(Duration::from_millis(100)).await;

    // 4.3.4.3: "The ASP receiving this Notify MUST consider itself now in the
    // ASP-INACTIVE state". The server is not a route any more, which the ASP
    // of this node is told.
    sg.send(&notify(ALTERNATE_ASP_ACTIVE, &[RC_REMOTE])).await;
    assert!(gw.server("far", AsState::Inactive).await);
    assert_eq!(near.expect(DUNA).await.points(), [FAR]);
    near.transfer(&user(Some(RC_LOCAL), NEAR, FAR, 0, 2)).await;
    sg.quiet(Duration::from_millis(400)).await;

    // 4.3.4.5: "The ASPs remain in control of what (and when) traffic action
    // is taken." This one takes the traffic of a server that has no ASP.
    sg.send(&notify(AS_PENDING, &[RC_REMOTE])).await;
    let returning = sg.expect(ASPAC).await;
    assert_eq!(returning.contexts(), [RC_REMOTE]);
    sg.send(&acknowledged).await;
    assert!(gw.server("far", AsState::Active).await);
    assert_eq!(near.expect(DAVA).await.points(), [FAR]);

    // 4.3.4.4: "If the ASP receives an ASP Inactive Ack without having sent
    // an ASP Inactive message, the ASP should now consider itself to be in
    // the ASP-INACTIVE state. If the ASP was previously in the ASP-ACTIVE
    // state, the ASP should then initiate procedures to return itself to its
    // previous state."
    sg.send(&message(ASPIA_ACK, &[])).await;
    assert!(gw.server("far", AsState::Inactive).await);
    sg.expect(ASPAC).await;
    sg.send(&acknowledged).await;
    assert!(gw.server("far", AsState::Active).await);

    // What the gateway says about a destination is acted on.
    sg.send(&ssnm(DUNA, &[RC_REMOTE], &[(0, FAR)])).await;
    assert!(gw.reachable(FAR, false).await);
    sg.send(&ssnm(DAVA, &[RC_REMOTE], &[(0, FAR)])).await;
    assert!(gw.reachable(FAR, true).await);

    // 4.3.4.2: "If the ASP receives an ASP Down Ack without having sent an
    // ASP Down message, the ASP should now consider itself to be in the
    // ASP-DOWN state", and then return to where it was.
    sg.send(&message(ASPDN_ACK, &[])).await;
    assert!(gw.server("far", AsState::Down).await);
    sg.until(ASPUP).await;
    sg.send(&message(ASPUP_ACK, &[])).await;
    sg.until(ASPAC).await;
    sg.send(&acknowledged).await;
    assert!(gw.server("far", AsState::Active).await);

    // A request only an ASP makes is not a gateway's to send.
    sg.send(&asp_active(None, &[RC_REMOTE])).await;
    let unexpected = sg.until(ERR).await;
    assert_eq!(unexpected.error_code(), Some(UNEXPECTED_MESSAGE));

    if let Some(read) = read(what, &[&returning, &unexpected]) {
        assert_eq!(read.column("m3ua.message_class"), ["4", "0"]);
        assert_eq!(read.get(0, "m3ua.routing_context"), "500");
        assert_eq!(read.get(1, "m3ua.error_code"), "6");
    }
    gw.handle.shutdown();
}
