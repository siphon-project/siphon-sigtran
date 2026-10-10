//! The global titles of a dialogue the node starts, read back by Wireshark.
//!
//! Compiles only with `--features python`: the titles under test are the ones a
//! script names in `node.originate(...)` / `gsm_map.begin(...)`.
//!
//! ITU-T Q.713 3.4.2.3: the address signals are BCD, two to an octet, and the
//! title says whether their number is odd or even. A receiver drops the last
//! half octet of a title marked odd, so a title of ten or twelve digits marked
//! odd arrives one digit short. Each title here is checked twice: against the
//! octets written out by hand from the recommendation, and against what the
//! Wireshark SCCP dissector reads from the frame.
//!
//! All values are synthetic (test PLMN 001/01, `+1-555-01xx`, decimal PCs).

#![cfg(feature = "python")]

mod common;

use std::ffi::CString;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use siphon_sigtran::transport::Msu;

/// `(called, calling)` global titles of ten, eleven and twelve digits.
const TITLES: [(&str, &str); 3] = [
    ("1555010012", "1555017098"),
    ("15550100123", "15550170987"),
    ("155501001234", "155501709876"),
];

/// The called party address of each, by hand: address indicator `12` (route on
/// GT, GTI 4, SSN present), SSN 8, TT 0, numbering plan 1 with encoding scheme 2
/// (even) or 1 (odd), nature of address 4, then the digits, filler 0 after an
/// odd count.
const CALLED: [&[u8]; 3] = [
    &[0x12, 0x08, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21],
    &[
        0x12, 0x08, 0x00, 0x11, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21, 0x03,
    ],
    &[
        0x12, 0x08, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21, 0x43,
    ],
];

/// The calling party address of each.
const CALLING: [&[u8]; 3] = [
    &[0x12, 0x08, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x07, 0x89],
    &[
        0x12, 0x08, 0x00, 0x11, 0x04, 0x51, 0x55, 0x10, 0x07, 0x89, 0x07,
    ],
    &[
        0x12, 0x08, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x07, 0x89, 0x67,
    ],
];

const SCRIPT: &str = r#"
import siphon
from siphon import gsm_map

CONFIG = """
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: peer, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
application_servers:
  - { name: peer, traffic_mode: override, routing_context: 100, asps: [peer] }
mtp3_routes:
  - { dpc: 2000, as: peer, priority: 1 }
sccp:
  local_ssns: [8]
"""
node = siphon.configure(CONFIG)

TPDU = bytes([0x04, 0x08, 0x91, 0x51, 0x55, 0x10, 0x10, 0x00, 0x04,
              0x22, 0x70, 0x21, 0x41, 0x30, 0x00, 0x00, 0x02, 0x68, 0x69])

BEGINS = []
for called, calling in TITLES:
    begin = node.originate(
        invoke=gsm_map.mt_forward_sm(imsi="001010000000042", sc_addr="15550100", tpdu=TPDU),
        on_reply=lambda dlg, peer: None,
        called_gt=called, called_ssn=8, calling_gt=calling, calling_ssn=8, dpc=2000,
        ac=gsm_map.AC.short_msg_mt_relay,
    )
    BEGINS.append(begin[0])
"#;

/// Run the script and return the SCCP payload of each Begin.
fn originate() -> Vec<Vec<u8>> {
    Python::attach(|py| {
        let siphon = PyModule::new(py, "siphon").expect("module");
        siphon_sigtran::python::register(py, &siphon).expect("register");
        py.import("sys")
            .and_then(|sys| sys.getattr("modules"))
            .and_then(|modules| modules.set_item("siphon", &siphon))
            .expect("sys.modules");

        let globals = PyDict::new(py);
        let titles = PyList::new(py, TITLES).expect("titles");
        globals.set_item("TITLES", titles).expect("TITLES");
        let code = CString::new(SCRIPT).expect("no NUL in the script");
        if let Err(e) = py.run(code.as_c_str(), Some(&globals), None) {
            e.print(py);
            panic!("script raised");
        }
        let begins = globals
            .get_item("BEGINS")
            .expect("BEGINS lookup")
            .expect("script sets BEGINS");
        begins
            .cast::<PyList>()
            .expect("BEGINS is a list")
            .iter()
            .map(|b| b.cast::<PyBytes>().expect("bytes").as_bytes().to_vec())
            .collect()
    })
}

/// The called and calling party addresses of a UDT, as they are on the wire.
fn addresses(udt: &[u8]) -> (&[u8], &[u8]) {
    let field = |pointer: usize| {
        let start = pointer + usize::from(udt[pointer]);
        let len = usize::from(udt[start]);
        &udt[start + 1..start + 1 + len]
    };
    (field(2), field(3))
}

#[test]
fn an_originated_global_title_keeps_every_digit() {
    let begins = originate();
    assert_eq!(begins.len(), TITLES.len());

    for (i, sccp) in begins.iter().enumerate() {
        let (called, calling) = addresses(sccp);
        assert_eq!(called, CALLED[i], "called {}", TITLES[i].0);
        assert_eq!(calling, CALLING[i], "calling {}", TITLES[i].1);
    }

    let msus: Vec<Msu> = begins
        .into_iter()
        .map(|payload| Msu {
            opc: 1000,
            dpc: 2000,
            si: 3,
            ni: 0,
            mp: 0,
            sls: 0,
            payload,
        })
        .collect();
    let refs: Vec<&Msu> = msus.iter().collect();
    let Some(wireshark) = common::dissect_all(&refs) else {
        return;
    };
    wireshark
        .show_all("sccp.called.gti", &["0x04"; 3])
        .show_all("sccp.calling.gti", &["0x04"; 3])
        .show_all("sccp.called.es", &["0x02", "0x01", "0x02"])
        .show_all("sccp.calling.es", &["0x02", "0x01", "0x02"])
        .show_all(
            "sccp.called.digits",
            &[TITLES[0].0, TITLES[1].0, TITLES[2].0],
        )
        .show_all(
            "sccp.calling.digits",
            &[TITLES[0].1, TITLES[1].1, TITLES[2].1],
        );
}
