//! The crate logs through `tracing` under the `siphon_sigtran` target, with the
//! values as structured fields, so a host subscriber (siphon's) can level,
//! filter and format the lines like those of every other extension. These tests
//! install a capturing subscriber and drive the public dialogue engine through
//! a warn path and a debug path. Every value is synthetic: decimal point codes,
//! `+1-555-01xx` global titles.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{End, TcapMessage};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

use siphon_sigtran::config::Tcap;
use siphon_sigtran::dialogue::DialogueEngine;
use siphon_sigtran::transport::Msu;

const OUR_PC: u32 = 1000;
const PEER_PC: u32 = 4000;
const OUR_GT: &str = "15550100";
const PEER_GT: &str = "15550170";
const SI_SCCP: u8 = 3;
const SI_ISUP: u8 = 5;

/// One captured event: target, level and every field, `message` included.
#[derive(Debug, Clone)]
struct Captured {
    target: String,
    level: Level,
    fields: BTreeMap<String, String>,
}

impl Captured {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Captured>>>);

impl<S: Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(Captured {
            target: event.metadata().target().to_string(),
            level: *event.metadata().level(),
            fields: fields.0,
        });
    }
}

/// Run `f` with a capturing subscriber as this thread's default and return
/// what was logged.
fn capture(f: impl FnOnce()) -> Vec<Captured> {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    tracing::subscriber::with_default(subscriber, f);
    let events = capture.0.lock().unwrap().clone();
    events
}

fn gt(digits: &str) -> GlobalTitle {
    GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    }
}

fn msu(si: u8, payload: Vec<u8>) -> Msu {
    Msu {
        opc: PEER_PC,
        dpc: OUR_PC,
        si,
        ni: 0,
        mp: 0,
        sls: 0,
        payload,
    }
}

/// Every event the crate emits carries its target, and no message repeats the
/// old stderr prefix.
fn assert_crate_style(events: &[Captured]) {
    for event in events {
        assert_eq!(event.target, "siphon_sigtran", "{event:?}");
        let message = event.field("message").unwrap_or_default();
        assert!(!message.starts_with("siphon-sigtran"), "{event:?}");
    }
}

#[test]
fn a_message_that_is_not_sccp_is_dropped_with_a_warning() {
    let engine = DialogueEngine::new(Tcap::default());
    let events = capture(|| {
        assert!(engine
            .deliver(&msu(SI_ISUP, vec![0x01, 0x02]), "peer-a")
            .is_empty());
    });

    assert_crate_style(&events);
    let dropped = events
        .iter()
        .find(|e| e.field("message") == Some("dropped a received message"))
        .unwrap_or_else(|| panic!("no drop event in {events:?}"));
    assert_eq!(dropped.level, Level::WARN);
    assert_eq!(dropped.field("association"), Some("peer-a"));
    assert_eq!(dropped.field("opc"), Some("4000"));
    assert_eq!(dropped.field("dpc"), Some("1000"));
    assert_eq!(dropped.field("si"), Some("5"));
    assert_eq!(dropped.field("detail"), Some("not an SCCP message"));
}

#[test]
fn an_end_for_a_transaction_that_is_not_open_is_logged_at_debug() {
    let engine = DialogueEngine::new(Tcap::default());
    let end = End {
        dtid: vec![0x80, 0x00, 0x00, 0x03].into(),
        dialogue_portion: None,
        components: None,
    };
    let tcap_bytes = tcap::encode(&TcapMessage::End(end)).unwrap();
    let called = SccpAddress::with_gt(gt(OUR_GT), Some(SubsystemNumber::Hlr));
    let calling = SccpAddress::with_gt(gt(PEER_GT), Some(SubsystemNumber::Msc));
    let udt = UnitData::new(called, calling, tcap_bytes).encode().unwrap();

    let events = capture(|| {
        assert!(engine.deliver(&msu(SI_SCCP, udt), "peer-a").is_empty());
    });

    assert_crate_style(&events);
    let discarded = events
        .iter()
        .find(|e| e.field("transaction") == Some("80000003"))
        .unwrap_or_else(|| panic!("no discard event in {events:?}"));
    assert_eq!(discarded.level, Level::DEBUG);
    assert!(discarded
        .field("message")
        .is_some_and(|m| m.starts_with("tcap: discarded an End")));
}
