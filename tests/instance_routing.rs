//! An STP routes a message for a global title shared by several instances of
//! one function: a message carrying a transaction id goes to the instance the
//! id names, a TC-BEGIN is shared over the instances that are reachable.

use sccp::{GlobalTitle, SccpAddress, SccpMessage, SubsystemNumber, UnitData};
use tcap::{Begin, Continue, End, TcapMessage};

use siphon_sigtran::mtp3::route::Destination;
use siphon_sigtran::routing::{Inbound, RouteDecision, Router};
use siphon_sigtran::sccp::GttSelector;
use siphon_sigtran::tid;
use siphon_sigtran::Config;

const STP_PC: u32 = 100;
/// The shared global title of the function (test range).
const SHARED_GT: &str = "15550110";
/// Point codes of the three instances.
const INSTANCES: [(u32, u32); 3] = [(0, 110), (1, 111), (2, 112)];

fn config() -> Config {
    Config::parse(
        r#"
node: { point_code: 100, variant: ITU, network_indicator: international }
associations:
  - { id: asp-0, adaptation: m3ua, role: server, addrs: [192.0.2.10], port: 2905 }
  - { id: asp-1, adaptation: m3ua, role: server, addrs: [192.0.2.11], port: 2905 }
  - { id: asp-2, adaptation: m3ua, role: server, addrs: [192.0.2.12], port: 2905 }
application_servers:
  - { name: inst-0, traffic_mode: override, routing_context: 110, asps: [asp-0] }
  - { name: inst-1, traffic_mode: override, routing_context: 111, asps: [asp-1] }
  - { name: inst-2, traffic_mode: override, routing_context: 112, asps: [asp-2] }
mtp3_routes:
  - { dpc: 110, as: inst-0, priority: 1 }
  - { dpc: 111, as: inst-1, priority: 1 }
  - { dpc: 112, as: inst-2, priority: 1 }
sccp:
  local_ssns: [6]
  gtt_groups:
    - name: fn
      mode: instance
      instance_bits: 2
      members:
        - { dpc: 110, ssn: 8, instance: 0 }
        - { dpc: 111, ssn: 8, instance: 1 }
        - { dpc: 112, ssn: 8, instance: 2 }
  gtt:
    - { match: { gt_prefix: "15550110" }, to: { group: fn } }
"#,
    )
    .expect("config parses")
}

/// One STP pod: its own router, its own round-robin cursor.
fn pod() -> Router {
    let router = Router::new(&config());
    for index in 0..3 {
        router.note_as_up("default", &format!("inst-{index}"));
    }
    router
}

fn selector() -> GttSelector {
    GttSelector::from_digits(SHARED_GT)
}

fn gt(digits: &str) -> GlobalTitle {
    GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: if digits.len() % 2 == 1 { 1 } else { 2 },
        nature_of_address: 4,
        digits: digits.to_string(),
    }
}

/// The SCCP UDT a peer sends to the shared global title, carrying `message`.
fn udt_to_shared_gt(message: &TcapMessage) -> SccpMessage {
    let bytes = tcap::encode(message).expect("encode tcap");
    let called = SccpAddress::with_gt(gt(SHARED_GT), Some(SubsystemNumber::Msc));
    let calling = SccpAddress::with_gt(gt("15550199"), Some(SubsystemNumber::Hlr));
    let encoded = UnitData::new(called, calling, bytes)
        .encode()
        .expect("encode sccp");
    SccpMessage::decode(&encoded).expect("decode sccp")
}

fn end_for(instance: u32, counter: u32) -> TcapMessage {
    TcapMessage::End(End {
        dtid: tid::compose(2, instance, counter)
            .to_be_bytes()
            .to_vec()
            .into(),
        dialogue_portion: None,
        components: None,
    })
}

fn continue_for(instance: u32, counter: u32) -> TcapMessage {
    TcapMessage::Continue(Continue {
        otid: vec![0, 0, 0, 7].into(),
        dtid: tid::compose(2, instance, counter)
            .to_be_bytes()
            .to_vec()
            .into(),
        dialogue_portion: None,
        components: None,
    })
}

fn begin() -> TcapMessage {
    TcapMessage::Begin(Begin {
        otid: vec![0, 0, 0, 9].into(),
        dialogue_portion: None,
        components: None,
    })
}

/// What the STP's transport builds from the MSU: the same function it calls.
fn inbound(message: &TcapMessage) -> Inbound {
    let sccp = udt_to_shared_gt(message);
    Inbound {
        dpc: STP_PC,
        cdpa: Some(selector()),
        called_ssn: Some(8),
        tcap_dtid: siphon_sigtran::transport::tcap_dtid(&sccp),
        ..Default::default()
    }
}

fn routed_to(router: &Router, message: &TcapMessage) -> (u32, bool) {
    match router.route_for("default", &inbound(message), 0) {
        RouteDecision::RouteTo { dpc, via, .. } => (dpc, via.is_some()),
        other => panic!("expected RouteTo, got {other:?}"),
    }
}

#[test]
fn an_end_reaches_the_instance_its_dtid_names_at_any_stp_pod() {
    // Three STP pods, each with its own state; none has seen the dialogue.
    let pods = [pod(), pod(), pod()];
    for (instance, point_code) in INSTANCES {
        for stp in &pods {
            for counter in [1, 77, 123_456] {
                assert_eq!(
                    routed_to(stp, &end_for(instance, counter)),
                    (point_code, true),
                    "TC-END for instance {instance}"
                );
            }
        }
    }
}

#[test]
fn a_continue_is_routed_on_its_dtid_not_its_otid() {
    let stp = pod();
    // The OTID (the peer's own id) is 7 in every message; the DTID decides.
    for (instance, point_code) in INSTANCES {
        assert_eq!(
            routed_to(&stp, &continue_for(instance, 5)),
            (point_code, true)
        );
    }
}

#[test]
fn begins_are_shared_over_the_instances() {
    let stp = pod();
    let mut hits = std::collections::BTreeMap::new();
    for _ in 0..9 {
        let (dpc, routable) = routed_to(&stp, &begin());
        assert!(routable);
        *hits.entry(dpc).or_insert(0) += 1;
    }
    assert_eq!(hits.len(), 3, "every instance gets begins: {hits:?}");
    assert!(hits.values().all(|n| *n == 3), "evenly: {hits:?}");
}

#[test]
fn a_begin_skips_an_instance_that_is_down() {
    let stp = pod();
    stp.note_as_down("default", "inst-1");
    for _ in 0..8 {
        let (dpc, routable) = routed_to(&stp, &begin());
        assert_ne!(dpc, 111, "no begin to the instance that is down");
        assert!(routable);
    }
}

#[test]
fn an_end_for_a_down_instance_is_undeliverable_not_rehomed() {
    let stp = pod();
    stp.note_as_down("default", "inst-1");
    // The dialogue lives on instance 1 only: it is not handed to another.
    assert_eq!(routed_to(&stp, &end_for(1, 3)), (111, false));
}

#[test]
fn a_begin_with_every_instance_down_has_no_route() {
    let stp = pod();
    for index in 0..3 {
        stp.note_as_down("default", &format!("inst-{index}"));
    }
    let (_, routable) = routed_to(&stp, &begin());
    assert!(!routable);
}

#[test]
fn an_id_that_is_not_an_instances_is_shared_like_a_begin() {
    let stp = pod();
    // No marker bit: not an id any instance allocated.
    let foreign = TcapMessage::End(End {
        dtid: vec![0, 0, 0, 3].into(),
        dialogue_portion: None,
        components: None,
    });
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..6 {
        seen.insert(routed_to(&stp, &foreign).0);
    }
    assert_eq!(seen.len(), 3);
    // A well-formed id of an instance index the group does not have (3 of 2 bits).
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..6 {
        seen.insert(routed_to(&stp, &end_for(3, 1)).0);
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn the_route_to_an_instance_goes_over_its_application_server() {
    let stp = pod();
    let decision = stp.route_for("default", &inbound(&end_for(2, 1)), 0);
    match decision {
        RouteDecision::RouteTo { dpc, via, .. } => {
            assert_eq!(dpc, 112);
            assert_eq!(via, Some(Destination::ApplicationServer("inst-2".into())));
        }
        other => panic!("expected RouteTo, got {other:?}"),
    }
}

#[test]
fn only_a_domain_with_an_instance_group_asks_for_the_dtid() {
    assert!(pod().tenant_has_instance_groups("default"));
    let plain = Router::new(
        &Config::parse("node: { point_code: 100, variant: ITU }\nsccp: { local_ssns: [6] }\n")
            .unwrap(),
    );
    assert!(!plain.tenant_has_instance_groups("default"));
}
