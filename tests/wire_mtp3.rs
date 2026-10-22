//! Level 3 of the Message Transfer Part at a transfer point, on the wire.
//!
//! The node is started on kernel SCTP loopback with three linksets and is
//! driven by the hand-written adjacent points of `tests/m2pa_peer`: every octet
//! they send and read comes from the figures of ITU-T Q.704 clause 15 and
//! Q.2210 9.8.1, not from the codec the node uses. What the node sends is read
//! back by Wireshark and the fields are asserted from what Wireshark read.
//! `SIGTRAN_REQUIRE_TSHARK=1` makes a missing `tshark` a failure; without
//! kernel SCTP every test here prints SKIP.
//!
//! ```text
//!                 A (3000)          B (4000)        C (5000)
//!                 a-0  a-1            b-0             c-0
//!                    \  |              |              /
//!                     node (1000), a transfer point
//!
//!   2000: linkset a, then linkset b          2300: linkset c
//!   2200: linksets b and c, equal priority   2999: no route
//! ```
//!
//! Every level-3 timer is a configuration key; the tests set them to hundreds
//! of milliseconds, so nothing waits on a default.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, Instant};

use siphon_sigtran::config::Config;
use siphon_sigtran::metrics::{self, Mtp3Discard, Mtp3MgKind, Retrieved, RxDiscard};
use siphon_sigtran::mtp3::management::Procedure;
use siphon_sigtran::routing::Router;
use siphon_sigtran::transport::{DestinationChange, M2paDiscard};
use siphon_sigtran::TransportHandle;

mod m2pa_peer;
use m2pa_peer::*;

const NODE: u32 = 1000;
const A: u32 = 3000;
const B: u32 = 4000;
const C: u32 = 5000;
/// Behind A, with B as the alternative.
const VIA_A: u32 = 2000;
/// Behind B and C, which share it.
const SHARED: u32 = 2200;
/// Behind C only.
const VIA_C: u32 = 2300;
/// Nothing routes there.
const NOWHERE: u32 = 2999;
/// National network.
const NI: u8 = 2;
/// The MTP testing user part (Q.704 14.2.1): Wireshark does not look inside.
const SI_USER: u8 = 8;

const MANAGEMENT_FIELDS: [&str; 10] = [
    "mtp3.service_indicator",
    "mtp3.opc",
    "mtp3.dpc",
    "mtp3.sls",
    "mtp3mg.h0",
    "mtp3mg.h1",
    "mtp3mg.apc",
    "mtp3mg.fsn",
    "mtp3mg.cbc",
    "mtp3mg.slc",
];

fn node(ports: [u16; 4], mtp3: &str, m2pa: &str) -> String {
    format!(
        r#"
node: {{ point_code: {NODE}, variant: ITU, network_indicator: national }}
mtp3: {mtp3}
associations:
  - {{ id: a-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {A}, m2pa: {m2pa} }}
  - {{ id: a-1, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {A}, m2pa: {m2pa} }}
  - {{ id: b-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {B}, m2pa: {m2pa} }}
  - {{ id: c-0, adaptation: m2pa, role: client, addrs: [127.0.0.1], port: {}, adjacent_pc: {C}, m2pa: {m2pa} }}
linksets:
  - {{ name: a, links: [{{assoc: a-0}}, {{assoc: a-1}}], link_test: {FAST_LINK_TEST} }}
  - {{ name: b, links: [{{assoc: b-0}}], link_test: {FAST_LINK_TEST} }}
  - {{ name: c, links: [{{assoc: c-0}}], link_test: {FAST_LINK_TEST} }}
mtp3_routes:
  - {{ dpc: {VIA_A}, linkset: a, priority: 1 }}
  - {{ dpc: {VIA_A}, linkset: b, priority: 2 }}
  - {{ dpc: {SHARED}, linkset: b, priority: 1 }}
  - {{ dpc: {SHARED}, linkset: c, priority: 1 }}
  - {{ dpc: {VIA_C}, linkset: c, priority: 1 }}
"#,
        ports[0], ports[1], ports[2], ports[3]
    )
}

/// The node and its four links.
struct Network {
    handle: TransportHandle,
    a0: Adjacent,
    a1: Adjacent,
    b: Adjacent,
    c: Adjacent,
}

impl Network {
    /// Start the node with every link up and every adjacent point having sent
    /// traffic restart allowed. `None` with a SKIP without kernel SCTP.
    async fn start(what: &str) -> Option<Self> {
        Self::start_with(what, FAST_MTP3, FAST_M2PA, true).await
    }

    async fn start_with(what: &str, mtp3: &str, m2pa: &str, restart: bool) -> Option<Self> {
        let mut network = Self::connect(what, mtp3, m2pa, restart).await?;
        for dpc in [VIA_A, SHARED, VIA_C, A, B, C] {
            assert!(network.reachable(dpc, true).await, "{dpc} is reachable");
        }
        network.quiet().await;
        Some(network)
    }

    /// Start the node and its peers and wait for nothing.
    async fn connect(what: &str, mtp3: &str, m2pa: &str, restart: bool) -> Option<Self> {
        let spawn = |pc, slc| Adjacent::spawn(pc, NODE, NI, slc, restart);
        let (Some(a0), Some(a1), Some(b), Some(c)) = (
            spawn(A, 0).await,
            spawn(A, 1).await,
            spawn(B, 0).await,
            spawn(C, 0).await,
        ) else {
            eprintln!("SKIP {what}: no kernel SCTP (load `modprobe sctp`)");
            return None;
        };
        let yaml = node([a0.port, a1.port, b.port, c.port], mtp3, m2pa);
        let cfg = Config::parse(&yaml).expect("config parses");
        let router = Arc::new(Router::new(&cfg));
        let handle = match TransportHandle::start(&cfg, router).await {
            Ok(handle) => handle,
            Err(error) => {
                eprintln!("SKIP {what}: transport did not start ({error})");
                return None;
            }
        };
        Some(Self {
            handle,
            a0,
            a1,
            b,
            c,
        })
    }

    /// Wait until the node's view of a destination is `wanted`.
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

    /// Let what the node sends at start (transfer-prohibited, traffic restart
    /// allowed) arrive, and forget it.
    async fn quiet(&mut self) {
        let wait = Duration::from_millis(250);
        tokio::join!(
            self.a0.drain(wait),
            self.a1.drain(wait),
            self.b.drain(wait),
            self.c.drain(wait)
        );
    }
}

/// A message of the test user part from `opc` for `dpc`.
fn user(opc: u32, dpc: u32, sls: u8, tag: u8) -> Vec<u8> {
    itu_msu(SI_USER, NI, opc, dpc, sls, &[0xC0, 0xDE, tag])
}

/// The tag of a message built by [`user`].
fn tag(frame: &Frame) -> u8 {
    *frame
        .label()
        .expect("a label")
        .payload
        .last()
        .expect("a tag")
}

/// Wait until a counter has moved at least `by` past `before`.
async fn counted(read: impl Fn() -> u64, before: u64, by: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if read() >= before + by {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

/// The user part messages among some frames, by tag.
fn tags(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .filter(|f| f.management().is_none())
        .map(tag)
        .collect()
}

/// A slower T7 for the tests that stop a peer's acknowledgements on purpose:
/// the link must fail when the test says, not by itself.
const PATIENT_M2PA: &str = "{ t1_ms: 2000, t2_ms: 300, t3_ms: 1000, t4n_ms: 60, t4e_ms: 20, \
                            t6_ms: 300, t7_ms: 3000, proving_interval_ms: 15, restart_ms: 100 }";

/// Have Wireshark read management messages and print them.
fn dissect(what: &str, frames: &[Frame]) -> Option<Read> {
    let read = wireshark(frames, &MANAGEMENT_FIELDS)?;
    read.clean();
    println!("{what}:\n{}", read.lines());
    Some(read)
}

// ── The reported faults ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_without_a_route_is_answered_with_transfer_prohibited() {
    let what = "a_message_without_a_route";
    let Some(mut net) = Network::start(what).await else {
        return;
    };

    // Q.704 13.2.2 iii): "When a message destined to signalling point X is
    // received at signalling transfer point Y and Y is unable to transfer the
    // message, and if no corresponding timer T8 is running. In this case the
    // transfer-prohibited message is sent to the adjacent signalling point from
    // which the message concerned was received (Response Method)."
    net.b.send(user(B, NOWHERE, 3, 1));
    let tfp = net
        .b
        .until(|f| f.is(TFP))
        .await
        .expect("transfer-prohibited for a destination without a route");
    let read = tfp.management().unwrap();
    assert_eq!((read.opc, read.dpc), (NODE, B));
    assert_eq!(read.destination(), Some(NOWHERE));

    // "Within T8 after the last transfer-prohibited message was transmitted
    // ... no transfer prohibited message will be sent via the Response Method
    // referring to that destination."
    net.b.send(user(B, NOWHERE, 3, 2));
    net.b.send(user(B, NOWHERE, 3, 3));
    let quiet = net.b.drain(Duration::from_millis(150)).await;
    assert!(
        quiet.iter().all(|f| !f.is(TFP)),
        "no second transfer-prohibited while T8 runs"
    );
    // T8 is 300 ms here: after it, the response method answers again.
    sleep(Duration::from_millis(250)).await;
    net.b.send(user(B, NOWHERE, 3, 4));
    let again = net
        .b
        .until(|f| f.is(TFP))
        .await
        .expect("transfer-prohibited again after T8");

    let Some(read) = dissect(what, &[tfp, again]) else {
        return;
    };
    for row in 0..2 {
        assert_eq!(read.get(row, "mtp3.service_indicator"), "0x00");
        assert_eq!(read.get(row, "mtp3.opc"), NODE.to_string());
        assert_eq!(read.get(row, "mtp3.dpc"), B.to_string());
        assert_eq!(read.get(row, "mtp3mg.h0"), "0x04");
        assert_eq!(read.get(row, "mtp3mg.h1"), "0x01", "transfer-prohibited");
        assert_eq!(read.get(row, "mtp3mg.apc"), NOWHERE.to_string());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_that_becomes_inaccessible_is_announced_and_so_is_its_return() {
    let what = "a_destination_that_becomes_inaccessible";
    let Some(mut net) = Network::start(what).await else {
        return;
    };

    // The only linkset toward 2300 goes down. Q.704 13.2.2 ii): "When
    // signalling transfer point Y recognizes the inaccessibility of signalling
    // point X ... a transfer-prohibited message is sent to all accessible
    // adjacent signalling points (Broadcast method)".
    net.c.fail();
    net.c.restart_allowed(true);
    assert!(net.reachable(VIA_C, false).await, "2300 is gone");
    let about_c = |f: &Frame| f.is(TFP) && f.management().unwrap().destination() == Some(VIA_C);
    let to_b = net.b.until(about_c).await.expect("B is told");
    let mut to_a = net.a0.drain(Duration::from_millis(200)).await;
    to_a.extend(net.a1.drain(Duration::from_millis(50)).await);
    let to_a: Vec<Frame> = to_a.into_iter().filter(about_c).collect();
    assert_eq!(to_a.len(), 1, "A is told once, on one of its links");

    // And back. 13.3.2 ii): "When signalling transfer point Y recognizes that
    // it is again able to transfer signalling traffic destined to signalling
    // point X ... a transfer-allowed message is sent to all accessible adjacent
    // signalling points".
    net.c.restore();
    assert!(net.reachable(VIA_C, true).await, "2300 is back");
    let allowed = |f: &Frame| f.is(TFA) && f.management().unwrap().destination() == Some(VIA_C);
    let back_b = net.b.until(allowed).await.expect("B is told it is back");
    let mut back_a = net.a0.drain(Duration::from_millis(200)).await;
    back_a.extend(net.a1.drain(Duration::from_millis(50)).await);
    let back_a: Vec<Frame> = back_a.into_iter().filter(allowed).collect();
    assert_eq!(back_a.len(), 1, "A is told once");

    let frames = [to_b, to_a[0].clone(), back_b, back_a[0].clone()];
    let Some(read) = dissect(what, &frames) else {
        return;
    };
    assert_eq!(read.column("mtp3mg.h0"), ["0x04"; 4]);
    assert_eq!(read.column("mtp3mg.h1"), ["0x01", "0x01", "0x05", "0x05"]);
    assert_eq!(read.column("mtp3mg.apc"), [VIA_C.to_string().as_str(); 4]);
    assert_eq!(
        read.column("mtp3.dpc"),
        [
            B.to_string().as_str(),
            A.to_string().as_str(),
            B.to_string().as_str(),
            A.to_string().as_str()
        ]
    );
    assert_eq!(read.column("mtp3.opc"), [NODE.to_string().as_str(); 4]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_prohibited_from_an_adjacent_point_diverts_the_traffic() {
    let what = "transfer_prohibited_from_an_adjacent_point";
    let Some(mut net) = Network::start(what).await else {
        return;
    };

    net.c.send(user(C, VIA_A, 0, 1));
    let first = tokio::select! {
        f = net.a0.traffic() => f,
        f = net.a1.traffic() => f,
    }
    .expect("the normal route is linkset a");
    assert_eq!(tag(&first), 1);

    // Q.704 13.2.3: "When a signalling point receives a transfer-prohibited
    // message from signalling transfer point Y, it performs the actions
    // specified in clause 7", forced rerouting to the alternative route.
    net.a0.manage(0, about(TFP, VIA_A, 0));
    sleep(Duration::from_millis(50)).await;
    net.c.send(user(C, VIA_A, 0, 2));
    let diverted = net.b.traffic().await.expect("2000 now goes by linkset b");
    assert_eq!(tag(&diverted), 2);
    let label = diverted.label().unwrap();
    assert_eq!((label.opc, label.dpc, label.sls), (C, VIA_A, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routes_of_equal_priority_share_the_load_by_sls() {
    let what = "routes_of_equal_priority";
    let Some(mut net) = Network::start(what).await else {
        return;
    };

    // Q.704 2.3.2: "load sharing between links not belonging to the same link
    // set ... traffic relating to a given destination is shared (on the basis
    // of the signalling link selection field)".
    for round in 0..2u8 {
        for sls in 0..16u8 {
            net.a0.send(user(A, SHARED, sls, round << 4 | sls));
        }
    }
    let on_b = net.b.drain(Duration::from_millis(400)).await;
    let on_c = net.c.drain(Duration::from_millis(100)).await;
    let sls_of = |frames: &[Frame]| -> Vec<u8> {
        frames
            .iter()
            .filter(|f| f.management().is_none())
            .map(|f| f.label().unwrap().sls)
            .collect()
    };
    let (b, c) = (sls_of(&on_b), sls_of(&on_c));
    assert_eq!(b.len() + c.len(), 32, "nothing lost: b {b:?} c {c:?}");
    assert_eq!(b.len(), 16, "half of the selection codes on each linkset");
    // "all the messages having the same routing label ... are routed via the
    // same signalling links": a code never appears on both.
    assert!(b.iter().all(|sls| !c.contains(sls)), "b {b:?} c {c:?}");
    // Each code twice, in the order sent.
    let tags = |frames: &[Frame], sls: u8| -> Vec<u8> {
        frames
            .iter()
            .filter(|f| f.management().is_none() && f.label().unwrap().sls == sls)
            .map(tag)
            .collect()
    };
    for sls in 0..16u8 {
        let seen = if b.contains(&sls) {
            tags(&on_b, sls)
        } else {
            tags(&on_c, sls)
        };
        assert_eq!(seen, [sls, 0x10 | sls], "selection code {sls} in sequence");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_set_test_for_this_node_is_answered() {
    let what = "a_route_set_test";
    let Some(mut net) = Network::start(what).await else {
        return;
    };

    // A believes 2300 is prohibited through this node; it is not. Q.704
    // 13.5.4: "a transfer-allowed message, referring to the destination the
    // accessibility of which is tested, if the signalling transfer point can
    // reach the indicated destination via a signalling link not connected to
    // the signalling point from which the signalling-route-set-test message
    // was received".
    net.a1.manage(0, about(RST, VIA_C, 0));
    let tfa = tokio::select! {
        f = net.a0.until(|f| f.is(TFA)) => f,
        f = net.a1.until(|f| f.is(TFA)) => f,
    }
    .expect("the route set test is answered");
    let read = tfa.management().unwrap();
    assert_eq!(
        (read.opc, read.dpc, read.destination()),
        (NODE, A, Some(VIA_C))
    );

    let Some(read) = dissect(what, &[tfa]) else {
        return;
    };
    assert_eq!(read.get(0, "mtp3mg.h0"), "0x04");
    assert_eq!(read.get(0, "mtp3mg.h1"), "0x05", "transfer-allowed");
    assert_eq!(read.get(0, "mtp3mg.apc"), VIA_C.to_string());
}

// ── Clause 5: changeover ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changeover_and_changeback_lose_and_duplicate_nothing() {
    let what = "changeover_and_changeback";
    let Some(mut net) = Network::start_with(what, FAST_MTP3, PATIENT_M2PA, true).await else {
        return;
    };
    let resent = metrics::mtp3_retrieved_total(Retrieved::Resent);
    let confirmed = metrics::mtp3_retrieved_total(Retrieved::Confirmed);
    let acknowledged = metrics::mtp3_procedures(Procedure::ChangeoverAcknowledged);

    // The far end sends enough on a-0 first that its sequence number does not
    // fit the seven bits of a changeover order (Q.704 15.4): what the node
    // names later has to be the 24-bit number of RFC 4165.
    for n in 0..140u8 {
        net.a0.send(user(A, VIA_C, 0, n));
    }
    let carried = net.c.drain(Duration::from_millis(300)).await;
    assert_eq!(tags(&carried).len(), 140);

    // Six messages for 2000 with selection code 0: link a-0 carries them
    // (Q.704 2.3.2 a). Its far end takes them and acknowledges none.
    net.a0.acknowledge(false);
    for n in 1..=6 {
        net.c.send(user(C, VIA_A, 0, n));
    }
    let mut on_a0 = Vec::new();
    for _ in 0..6 {
        on_a0.push(net.a0.traffic().await.expect("carried on a-0"));
    }
    assert_eq!(tags(&on_a0), [1, 2, 3, 4, 5, 6]);

    // The link fails. 5.4.1: "a changeover order is sent to the remote
    // signalling point"; 5.4.2: with "the identity of the unavailable
    // signalling link" and "the forward sequence number of the last message
    // signal unit accepted from the unavailable signalling link". On an M2PA
    // link that is an extended changeover order (RFC 4165 4.2.3).
    let last_from_a = net.a0.last_sent();
    assert!(last_from_a > 127, "more than seven bits: {last_from_a}");
    net.a0.fail();
    let order = net
        .a1
        .until(|f| f.is(XCO))
        .await
        .expect("a changeover order");
    let read = order.management().unwrap();
    assert_eq!((read.opc, read.dpc, read.slc), (NODE, A, 0));
    assert_eq!(read.extended_fsn(), Some(last_from_a));

    // Traffic for the failed link that arrives now waits (5.3.1 a, 5.5).
    net.c.send(user(C, VIA_A, 0, 7));
    net.c.send(user(C, VIA_A, 0, 8));
    let waiting = net.a1.drain(Duration::from_millis(100)).await;
    assert!(
        tags(&waiting).is_empty(),
        "held until the buffer is updated"
    );

    // The far end accepted the first four. 5.4.3: "The message signal units
    // successive to that indicated by the message are those which have to be
    // retransmitted on the alternative signalling link(s)"; 5.5: then what
    // was not yet sent, "in such a way that the correct message sequence is
    // maintained".
    net.a1.manage(0, extended_changeover(XCA, on_a0[3].fsn()));
    let mut diverted = Vec::new();
    for _ in 0..4 {
        diverted.push(net.a1.traffic().await.expect("diverted to a-1"));
    }
    assert_eq!(tags(&diverted), [5, 6, 7, 8], "nothing lost, nothing twice");
    let more = net.a1.drain(Duration::from_millis(150)).await;
    assert!(
        tags(&more).is_empty(),
        "nothing sent twice: {:?}",
        tags(&more)
    );
    assert!(
        counted(
            || metrics::mtp3_retrieved_total(Retrieved::Resent),
            resent,
            2
        )
        .await
    );
    assert!(
        counted(
            || metrics::mtp3_retrieved_total(Retrieved::Confirmed),
            confirmed,
            4
        )
        .await
    );
    assert!(metrics::mtp3_procedures(Procedure::ChangeoverAcknowledged) > acknowledged);
    // New traffic takes the alternative link directly.
    net.c.send(user(C, VIA_A, 0, 9));
    assert_eq!(tag(&net.a1.traffic().await.expect("on a-1")), 9);

    // The link returns. 6.3.1: "i) transmission of the concerned traffic on
    // the alternative signalling link is stopped; such traffic is stored in a
    // changeback buffer; ii) a changeback declaration is sent to the remote
    // signalling point of the signalling link made available via the
    // concerned alternative signalling link".
    net.a0.acknowledge(true);
    net.a0.restore();
    let declaration = net
        .a1
        .until(|f| f.is(CBD))
        .await
        .expect("a changeback declaration");
    let read = declaration.management().unwrap();
    assert_eq!(
        (read.opc, read.dpc, read.slc),
        (NODE, A, 0),
        "about link code 0"
    );
    let code = read.changeback_code().unwrap();
    net.c.send(user(C, VIA_A, 0, 10));
    net.c.send(user(C, VIA_A, 0, 11));
    let (on_a0, on_a1) = tokio::join!(
        net.a0.drain(Duration::from_millis(100)),
        net.a1.drain(Duration::from_millis(100))
    );
    assert!(
        tags(&on_a0).is_empty() && tags(&on_a1).is_empty(),
        "held until the declaration is acknowledged"
    );
    // 6.3.2: "The concerned signalling point will restart diverted traffic
    // over the signalling link made available when it receives a changeback
    // acknowledgement".
    net.a1.manage(0, changeback(CBA, code));
    let back = [
        net.a0.traffic().await.expect("on a-0 again"),
        net.a0.traffic().await.expect("on a-0 again"),
    ];
    assert_eq!(tags(&back), [10, 11]);

    let Some(read) = dissect(what, &[order, declaration]) else {
        return;
    };
    assert_eq!(read.column("mtp3.service_indicator"), ["0x00"; 2]);
    assert_eq!(read.column("mtp3.opc"), [NODE.to_string().as_str(); 2]);
    assert_eq!(read.column("mtp3.dpc"), [A.to_string().as_str(); 2]);
    assert_eq!(
        read.column("mtp3.sls"),
        ["0"; 2],
        "the code of the link concerned"
    );
    assert_eq!(read.column("mtp3mg.h0"), ["0x01"; 2]);
    assert_eq!(
        read.get(0, "mtp3mg.h1"),
        "0x03",
        "extended changeover order"
    );
    assert_eq!(read.get(0, "mtp3mg.fsn"), last_from_a.to_string());
    assert_eq!(read.get(1, "mtp3mg.h1"), "0x05", "changeback declaration");
    assert_eq!(read.get(1, "mtp3mg.cbc"), code.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changeover_order_from_the_far_end_is_obeyed_and_acknowledged() {
    let what = "a_changeover_order_from_the_far_end";
    let Some(mut net) = Network::start_with(what, FAST_MTP3, PATIENT_M2PA, true).await else {
        return;
    };
    net.a0.acknowledge(false);
    for n in 1..=3 {
        net.c.send(user(C, VIA_A, 0, n));
    }
    let mut on_a0 = Vec::new();
    for _ in 0..3 {
        on_a0.push(net.a0.traffic().await.expect("carried on a-0"));
    }
    let last_from_a = net.a0.last_sent();

    // The far end orders changeover from a link that is up here, having
    // accepted two of the three. Q.704 3.2.2: "a signalling link which is
    // available (not blocked) is recognized by level 3 as failed when a
    // changeover order is received." 5.4.1: "In the case that the changeover
    // was initiated by the reception of a changeover order, a changeover
    // acknowledgement is sent instead."
    net.a1.manage(0, extended_changeover(XCO, on_a0[1].fsn()));
    let ack = net
        .a1
        .until(|f| f.is(XCA))
        .await
        .expect("an extended changeover acknowledgement");
    let read = ack.management().unwrap();
    assert_eq!((read.opc, read.dpc, read.slc), (NODE, A, 0));
    assert_eq!(read.extended_fsn(), Some(last_from_a));
    // The third message, and only it, is sent again on the other link.
    let again = net.a1.traffic().await.expect("the third again");
    assert_eq!(tag(&again), 3);
    net.a0.acknowledge(true);

    let Some(read) = dissect(what, &[ack]) else {
        return;
    };
    assert_eq!(read.get(0, "mtp3mg.h0"), "0x01");
    assert_eq!(
        read.get(0, "mtp3mg.h1"),
        "0x04",
        "extended changeover acknowledgement"
    );
    assert_eq!(read.get(0, "mtp3mg.fsn"), last_from_a.to_string());
    assert_eq!(read.get(0, "mtp3.sls"), "0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_whose_association_is_lost_changes_over_too() {
    let what = "association_lost";
    let Some(mut net) = Network::start_with(what, FAST_MTP3, PATIENT_M2PA, true).await else {
        return;
    };
    net.a0.acknowledge(false);
    for n in 1..=3 {
        net.c.send(user(C, VIA_A, 0, n));
    }
    let mut on_a0 = Vec::new();
    for _ in 0..3 {
        on_a0.push(net.a0.traffic().await.expect("carried on a-0"));
    }
    let last_from_a = net.a0.last_sent();

    // The association goes (RFC 4165 4.1.7: "the link SHALL be considered to
    // be out of service"). What the link held outlives it: the changeover
    // order names the same number, and the retrieval sends the same messages.
    net.a0.close();
    let order = net
        .a1
        .until(|f| f.is(XCO))
        .await
        .expect("a changeover order");
    assert_eq!(
        order.management().unwrap().extended_fsn(),
        Some(last_from_a)
    );
    net.c.send(user(C, VIA_A, 0, 4));
    net.a1.manage(0, extended_changeover(XCA, on_a0[0].fsn()));
    let mut diverted = Vec::new();
    for _ in 0..3 {
        diverted.push(net.a1.traffic().await.expect("diverted to a-1"));
    }
    assert_eq!(tags(&diverted), [2, 3, 4]);
    // The link is gone for good; what is routed to its codes goes by a-1.
    net.c.send(user(C, VIA_A, 0, 5));
    assert_eq!(tag(&net.a1.traffic().await.expect("on a-1")), 5);
    let more = net.a1.drain(Duration::from_millis(100)).await;
    assert!(tags(&more).is_empty(), "nothing twice: {:?}", tags(&more));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_linkset_that_cannot_be_asked_changes_over_after_t1() {
    let what = "time_controlled_changeover";
    let Some(mut net) = Network::start_with(what, FAST_MTP3, PATIENT_M2PA, true).await else {
        return;
    };
    let lost = metrics::m2pa_discards(M2paDiscard::TxLostOnFailure);
    let timed = metrics::mtp3_procedures(Procedure::ChangeoverTimeControlled);

    // 2200 with an odd selection code goes by linkset c, which has one link.
    net.c.acknowledge(false);
    for n in 1..=3 {
        net.a0.send(user(A, SHARED, 1, n));
    }
    for n in 1..=3 {
        assert_eq!(tag(&net.c.traffic().await.expect("carried on c-0")), n);
    }
    // It fails, and nothing else leads to C. Q.704 5.6.2 i): "No signalling
    // path exists between the two ends of the unavailable link, so that the
    // exchange of changeover messages is impossible ... after the expiry of a
    // time T1, it starts signalling traffic not yet transmitted on the
    // unavailable signalling link on the alternative link(s)".
    net.c.fail();
    sleep(Duration::from_millis(30)).await;
    net.a0.send(user(A, SHARED, 1, 4));
    net.a0.send(user(A, SHARED, 1, 5));
    let early = net.b.drain(Duration::from_millis(60)).await;
    assert!(tags(&early).is_empty(), "withheld for T1 (150 ms here)");
    let on_b = [
        net.b.traffic().await.expect("on linkset b after T1"),
        net.b.traffic().await.expect("on linkset b after T1"),
    ];
    assert_eq!(
        tags(&on_b),
        [4, 5],
        "what was not yet transmitted, in order"
    );
    // What was sent and never acknowledged is not sent again (it could be a
    // duplicate), and is counted as possibly lost.
    assert!(
        counted(
            || metrics::m2pa_discards(M2paDiscard::TxLostOnFailure),
            lost,
            3
        )
        .await
    );
    assert!(metrics::mtp3_procedures(Procedure::ChangeoverTimeControlled) > timed);
    let late = net.b.drain(Duration::from_millis(150)).await;
    assert!(tags(&late).is_empty(), "nothing twice: {:?}", tags(&late));
}

// ── Clauses 8 and 13.5: controlled rerouting and the route set test ──────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prohibited_route_is_tested_and_taken_back_under_t6() {
    let what = "a_prohibited_route";
    let Some(mut net) = Network::start(what).await else {
        return;
    };
    net.a0.manage(0, about(TFP, VIA_A, 0));
    // 13.2.2 i): B is now routed through for 2000 and must not send it here.
    let to_b = net
        .b
        .until(|f| f.is(TFP) && f.management().unwrap().destination() == Some(VIA_A))
        .await
        .expect("transfer-prohibited toward the point newly routed through");

    // 13.5.2: "a signalling-route-set-test message is sent to that signalling
    // transfer point referring to the destination declared inaccessible ...
    // every T10 period" (250 ms here).
    let started = Instant::now();
    let first = net.a0.until(|f| f.is(RST)).await.expect("a route set test");
    let second = net.a0.until(|f| f.is(RST)).await.expect("and another");
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "one per T10"
    );
    assert_eq!(first.management().unwrap().destination(), Some(VIA_A));

    // 8.2.1: on the transfer-allowed, traffic for 2000 is "stored in a
    // controlled rerouting buffer; a timer T6 is started", and restarts on the
    // route made available "starting with the content of the controlled
    // rerouting buffer".
    net.a0.manage(0, about(TFA, VIA_A, 0));
    sleep(Duration::from_millis(40)).await;
    let sent = Instant::now();
    for n in 1..=3 {
        net.c.send(user(C, VIA_A, 0, n));
    }
    let held = net.b.drain(Duration::from_millis(80)).await;
    assert!(
        tags(&held).is_empty(),
        "not on the alternative route any more"
    );
    // 13.3.2 i): B is no longer routed through, and is told when the
    // rerouting starts (8.2.1 b).
    let allowed = held
        .iter()
        .find(|f| f.is(TFA) && f.management().unwrap().destination() == Some(VIA_A))
        .cloned()
        .expect("transfer-allowed toward the point no longer routed through");
    let mut back = Vec::new();
    for _ in 0..3 {
        back.push(net.a0.traffic().await.expect("on the normal route again"));
    }
    assert_eq!(tags(&back), [1, 2, 3], "in sequence");
    assert!(
        sent.elapsed() >= Duration::from_millis(100),
        "held for T6 (200 ms here), released after {:?}",
        sent.elapsed()
    );
    // And the test stops.
    let after = net.a0.drain(Duration::from_millis(400)).await;
    assert!(
        after.iter().all(|f| !f.is(RST)),
        "no test for an allowed route"
    );

    let Some(read) = dissect(what, &[to_b, first, second, allowed]) else {
        return;
    };
    assert_eq!(read.column("mtp3mg.h0"), ["0x04", "0x05", "0x05", "0x04"]);
    assert_eq!(read.column("mtp3mg.h1"), ["0x01", "0x01", "0x01", "0x05"]);
    assert_eq!(read.column("mtp3mg.apc"), [VIA_A.to_string().as_str(); 4]);
    assert_eq!(
        read.column("mtp3.dpc"),
        [
            B.to_string().as_str(),
            A.to_string().as_str(),
            A.to_string().as_str(),
            B.to_string().as_str()
        ]
    );
}

// ── Clause 10: management inhibiting ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_is_inhibited_tested_and_uninhibited_at_the_far_ends_request() {
    let what = "inhibit";
    let Some(mut net) = Network::start(what).await else {
        return;
    };
    // 10.2 d): "it sends an inhibit acknowledgement to signalling point X and
    // marks the link remotely inhibited. If the link concerned is currently
    // carrying traffic, signalling point Y sends the inhibit acknowledgement
    // via that link and diverts subsequent traffic for it, using the time
    // controlled changeover procedure."
    net.a0.manage(0, signal(LIN));
    let lia = net
        .a0
        .until(|f| f.is(LIA))
        .await
        .expect("acknowledged on the link itself");
    assert_eq!(lia.management().unwrap().slc, 0);
    sleep(Duration::from_millis(250)).await; // T1 is 150 ms here.
    net.c.send(user(C, VIA_A, 0, 1));
    assert_eq!(tag(&net.a1.traffic().await.expect("diverted to a-1")), 1);

    // 10.6.2: "a remote inhibit test message is sent ... and timer T23 is
    // restarted" (400 ms here).
    let lrt = net
        .a0
        .until(|f| f.is(LRT))
        .await
        .expect("a remote inhibit test");

    // 10.3.1 c): "returns an uninhibit acknowledgement message ... and cancels
    // the remote inhibit indication ... it is put in the available state and
    // changeback is initiated."
    net.a0.manage(0, signal(LUN));
    let lua = net
        .a0
        .until(|f| f.is(LUA))
        .await
        .expect("uninhibit acknowledged");
    let declaration = net
        .a1
        .until(|f| f.is(CBD))
        .await
        .expect("changeback follows");
    net.a1.manage(
        0,
        changeback(
            CBA,
            declaration.management().unwrap().changeback_code().unwrap(),
        ),
    );
    sleep(Duration::from_millis(50)).await;
    net.c.send(user(C, VIA_A, 0, 2));
    assert_eq!(tag(&net.a0.traffic().await.expect("on a-0 again")), 2);

    // 10.2 c): inhibiting the only link toward 2300 "will result in a
    // destination becoming inaccessible": "an inhibit denied message is
    // returned".
    net.c.manage(0, signal(LIN));
    let lid = net.c.until(|f| f.is(LID)).await.expect("inhibit denied");
    assert!(net.handle.router().is_reachable("default", VIA_C));

    let Some(read) = dissect(what, &[lia, lrt, lua, lid]) else {
        return;
    };
    assert_eq!(read.column("mtp3mg.h0"), ["0x06"; 4]);
    assert_eq!(read.column("mtp3mg.h1"), ["0x03", "0x08", "0x04", "0x05"]);
    assert_eq!(read.column("mtp3.sls"), ["0"; 4]);
    assert_eq!(
        read.column("mtp3.dpc"),
        [
            A.to_string().as_str(),
            A.to_string().as_str(),
            A.to_string().as_str(),
            C.to_string().as_str()
        ]
    );
}

// ── Clause 9: MTP restart ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarting_node_discards_traffic_and_then_says_restart_allowed() {
    let what = "restart";
    // No adjacent point says traffic restart allowed: the first phase lasts
    // the whole of T18, and an adjacent point that returns is waited for T21.
    let mtp3 = "{ t1_ms: 150, t2_ms: 400, t3_ms: 150, t6_ms: 200, t8_ms: 300, t10_ms: 250, \
                t18_ms: 1200, t19_ms: 500, t20_ms: 4000, t21_ms: 3000 }";
    let Some(mut net) = Network::connect(what, mtp3, FAST_M2PA, false).await else {
        return;
    };
    let discarded = metrics::mtp3_discards(Mtp3Discard::Restarting);
    // Q.704 9.2.1: "A signalling point starts the MTP restart procedure when
    // its first link is in service at level 2."
    let deadline = Instant::now() + Duration::from_secs(5);
    while !net.handle.registry().is_restarting() {
        assert!(Instant::now() < deadline, "the restart begins");
        sleep(Duration::from_millis(5)).await;
    }
    let began = Instant::now();
    // Give the other links the time to pass their test, inside T18.
    sleep(Duration::from_millis(400)).await;
    assert!(net.handle.registry().is_restarting());
    assert!(!net.handle.router().is_reachable("default", VIA_C));

    // 9.6.6: "All messages to another destination received at a signalling
    // point whose MTP is restarting are discarded."
    net.b.send(user(B, VIA_C, 0, 1));
    assert!(
        counted(
            || metrics::mtp3_discards(Mtp3Discard::Restarting),
            discarded,
            1
        )
        .await
    );
    // 9.2.2: nothing but link tests leaves in the first phase.
    for peer in [&net.a0, &net.a1, &net.b, &net.c] {
        assert!(
            peer.frames().iter().all(|f| f.management().is_none()),
            "no management message before the second phase"
        );
        assert!(peer.frames().iter().any(|f| f.link_test().is_some()));
    }

    // 9.2.4: "When T20 is stopped or expires, the restarting MTP ... sends
    // traffic restart allowed messages to all adjacent signalling points".
    // 9.2.2: after the transfer-prohibited messages of the second phase.
    let mut seen = net.b.drain(Duration::from_millis(1300)).await;
    assert!(
        began.elapsed() >= Duration::from_millis(1200),
        "not before T18"
    );
    let restart = seen
        .iter()
        .position(|f| f.is(TRA))
        .expect("traffic restart allowed");
    assert_eq!(seen.len(), restart + 1, "it is the last word");
    assert!(seen[..restart].iter().all(|f| f.is(TFP)));
    // 13.2.2 i): 2200 is routed through B.
    assert!(seen[..restart]
        .iter()
        .any(|f| f.management().unwrap().destination() == Some(SHARED)));
    assert!(!net.handle.registry().is_restarting());
    assert!(
        tags(&net.c.drain(Duration::from_millis(50)).await).is_empty(),
        "the discarded message stays discarded"
    );
    net.b.send(user(B, VIA_C, 0, 2));
    assert_eq!(
        tag(&net.c.traffic().await.expect("traffic after the restart")),
        2
    );

    // An adjacent point that was inaccessible returns. 9.3.2: "X starts a
    // timer T21 ... X sends any necessary TFP and TFR messages to Y; then X
    // sends a traffic restart allowed message". 9.6.7: until it has restarted,
    // messages "destined to or through the signalling point whose MTP is
    // restarting, are discarded".
    net.c.fail();
    assert!(net.reachable(VIA_C, false).await);
    net.quiet().await;
    net.c.restore();
    let to_c = net
        .c
        .until(|f| f.is(TRA))
        .await
        .expect("restart allowed toward C");
    sleep(Duration::from_millis(150)).await;
    assert!(
        !net.handle.router().is_reachable("default", VIA_C),
        "no traffic through C before it says restart allowed"
    );
    net.c.manage(0, signal(TRA));
    assert!(net.reachable(VIA_C, true).await, "C restarted");

    seen.truncate(restart + 1);
    seen.push(to_c);
    let frames: Vec<Frame> = seen.split_off(restart);
    let Some(read) = dissect(what, &frames) else {
        return;
    };
    assert_eq!(read.column("mtp3mg.h0"), ["0x07"; 2]);
    assert_eq!(
        read.column("mtp3mg.h1"),
        ["0x01"; 2],
        "traffic restart allowed"
    );
    assert_eq!(
        read.column("mtp3.dpc"),
        [B.to_string().as_str(), C.to_string().as_str()]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unexpected_restart_allowed_is_answered_once_per_t19() {
    let what = "unexpected_restart_allowed";
    let Some(mut net) = Network::start(what).await else {
        return;
    };
    // T19 (500 ms here) still runs from the node's own restart.
    sleep(Duration::from_millis(550)).await;
    // Q.704 9.5.1: "X sends to Y any necessary TFP and TFR messages if X has
    // the transfer function, and a TRA message to Y. In addition, X starts a
    // timer T19 associated with Y."
    net.b.manage(0, signal(TRA));
    let answer = net.b.drain(Duration::from_millis(200)).await;
    let codes: Vec<(u8, u8)> = answer
        .iter()
        .map(|f| f.management().unwrap().code)
        .collect();
    assert_eq!(codes, [TFP, TRA], "2200 is routed through B: {answer:?}");
    assert_eq!(answer[0].management().unwrap().destination(), Some(SHARED));
    // 9.5.2: "this TRA is discarded and no further action is necessary."
    net.b.manage(0, signal(TRA));
    assert!(net.b.drain(Duration::from_millis(200)).await.is_empty());
}

// ── Congestion, the published changes, and malformed input ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changes_of_a_destination_are_published_and_transfer_controlled_is_counted() {
    let what = "published";
    let Some(net) = Network::start(what).await else {
        return;
    };
    let mut changes = net.handle.registry().destination_changes();
    let congestion = metrics::mtp3mg_events(VIA_C, Mtp3MgKind::Congestion);

    // Q.704 13.6: the transfer-controlled "convey[s] the congestion indication
    // from the SP where congestion was detected to the originating SP". This
    // node counts it and publishes it; its routing does not change.
    net.a0.manage(0, about(TFC, VIA_C, 1));
    let change = tokio::time::timeout(Duration::from_secs(5), changes.recv())
        .await
        .expect("published")
        .expect("a change");
    assert_eq!(
        change,
        DestinationChange::Congested {
            dpc: VIA_C,
            status: 1
        }
    );
    assert!(metrics::mtp3mg_events(VIA_C, Mtp3MgKind::Congestion) > congestion);
    assert!(net.handle.router().is_reachable("default", VIA_C));

    // The one place that says a destination became inaccessible or accessible.
    net.c.fail();
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let change = tokio::time::timeout(Duration::from_secs(5), changes.recv())
            .await
            .expect("published")
            .expect("a change");
        seen.push(change);
    }
    seen.sort_by_key(|c| match c {
        DestinationChange::Inaccessible { dpc } => *dpc,
        _ => 0,
    });
    assert_eq!(
        seen,
        [
            DestinationChange::Inaccessible { dpc: VIA_C },
            DestinationChange::Inaccessible { dpc: C }
        ]
    );
    net.c.restart_allowed(true);
    net.c.restore();
    let mut back = Vec::new();
    while back.len() < 2 {
        let change = tokio::time::timeout(Duration::from_secs(5), changes.recv())
            .await
            .expect("published")
            .expect("a change");
        back.push(change);
    }
    assert!(back.contains(&DestinationChange::Accessible { dpc: VIA_C }));
    assert!(back.contains(&DestinationChange::Accessible { dpc: C }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_management_is_counted_and_the_node_goes_on() {
    let what = "malformed";
    let Some(mut net) = Network::start(what).await else {
        return;
    };
    let undecodable = metrics::rx_discards(RxDiscard::Undecodable);
    let not_acted_on = metrics::mtp3_discards(Mtp3Discard::Management);

    let malformed: [&[u8]; 7] = [
        &[],                 // no heading code
        &[0x14],             // transfer-prohibited without a destination
        &[0x14, 0xD0],       // with half of one
        &[0x31, 0x01, 0x02], // an extended changeover order one octet short
        &[0x51],             // a changeback declaration without its code
        &[0x0F],             // a heading code Table 1/Q.704 leaves spare
        &[0xF9],
    ];
    for content in malformed {
        net.a0.manage(0, content.to_vec());
    }
    assert!(
        counted(
            || metrics::rx_discards(RxDiscard::Undecodable),
            undecodable,
            malformed.len() as u64
        )
        .await,
        "each is counted where it is dropped"
    );
    // Well formed, and about something that is not there: a link code the
    // linkset does not have, a route that does not exist, a message from a
    // point that is not adjacent, an acknowledgement of nothing.
    net.a0.manage(9, extended_changeover(XCO, 5));
    net.a0.manage(0, about(TFP, VIA_C, 0));
    net.a0.send(itu_msu(
        SI_MANAGEMENT,
        NI,
        6000,
        NODE,
        0,
        &about(TFP, VIA_A, 0),
    ));
    net.a1.manage(0, extended_changeover(XCA, 5));
    net.a1.manage(1, changeback(CBA, 200));
    assert!(
        counted(
            || metrics::mtp3_discards(Mtp3Discard::Management),
            not_acted_on,
            5
        )
        .await
    );

    // Nothing of it changed anything: the links carry traffic and management
    // is answered.
    for dpc in [VIA_A, SHARED, VIA_C] {
        assert!(net.handle.router().is_reachable("default", dpc));
    }
    net.c.send(user(C, VIA_A, 0, 1));
    assert_eq!(tag(&net.a0.traffic().await.expect("a-0 still carries")), 1);
    net.a0.manage(0, about(RST, VIA_C, 0));
    assert!(net.a0.until(|f| f.is(TFA)).await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_links_of_a_linkset_share_the_load_by_sls() {
    let what = "the_links_of_a_linkset";
    let Some(mut net) = Network::start(what).await else {
        return;
    };
    // Q.704 2.3.2 a), Figure 4: "the traffic flow carried by a link set is
    // shared (on the basis of the signalling link selection field) between
    // different signalling links belonging to the link set".
    for round in 0..2u8 {
        for sls in 0..16u8 {
            net.c.send(user(C, VIA_A, sls, round << 4 | sls));
        }
    }
    let (on_a0, on_a1) = tokio::join!(
        net.a0.drain(Duration::from_millis(400)),
        net.a1.drain(Duration::from_millis(400))
    );
    let sls_of = |frames: &[Frame]| -> Vec<u8> {
        frames
            .iter()
            .filter(|f| f.management().is_none())
            .map(|f| f.label().unwrap().sls)
            .collect()
    };
    let even: Vec<u8> = (0..2).flat_map(|_| (0..16).step_by(2)).collect();
    let odd: Vec<u8> = (0..2).flat_map(|_| (1..16).step_by(2)).collect();
    assert_eq!(
        sls_of(&on_a0),
        even,
        "codes XXX0 on the first link, in order"
    );
    assert_eq!(sls_of(&on_a1), odd, "codes XXX1 on the second");
    // The label goes out as it came in: the selection code is not rewritten.
    for frame in on_a0
        .iter()
        .chain(on_a1.iter())
        .filter(|f| f.management().is_none())
    {
        let label = frame.label().unwrap();
        assert_eq!((label.opc, label.dpc), (C, VIA_A));
        assert_eq!(tag(frame) & 0x0F, label.sls);
    }
}
