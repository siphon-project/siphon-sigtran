//! The harness the script-driven wire tests share: mount the addon, run a
//! script that leaves its frames in `FRAMES`, frame them as M3UA over SCTP in
//! a pcap and read them with tshark. Each test binary that uses it is its own
//! process, so the scripts never share the process-wide node.
#![allow(dead_code)]

use std::ffi::CString;
use std::io::Write as _;
use std::process::Command;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use mtp3::NetworkIndicator;

const PPID_M3UA: u32 = 3;
const SI_SCCP: u8 = 3;

/// Mount the addon onto a throwaway `siphon` module and register it in
/// `sys.modules`, exactly as a composing siphon binary does at startup.
pub fn mount(py: Python<'_>) -> PyResult<()> {
    let siphon = pyo3::types::PyModule::new(py, "siphon")?;
    siphon_sigtran::python::register(py, &siphon)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("siphon", &siphon)?;
    Ok(())
}

/// One `(opc, dpc, sccp)` frame the script produced.
pub struct Frame {
    pub opc: u32,
    pub dpc: u32,
    pub sccp: Vec<u8>,
}

/// Run `script` and pull back the frames it left in its `FRAMES` dict.
pub fn run(script: &str) -> Vec<(String, Vec<Frame>)> {
    Python::attach(|py| {
        mount(py).expect("mount addon");
        let globals = PyDict::new(py);
        let code = CString::new(script).expect("no NUL in the addon script");
        if let Err(e) = py.run(code.as_c_str(), Some(&globals), None) {
            e.print(py);
            panic!("addon script raised");
        }
        let frames_obj = globals
            .get_item("FRAMES")
            .expect("FRAMES lookup")
            .expect("script must set FRAMES");
        let frames = frames_obj.cast::<PyDict>().expect("FRAMES is a dict");

        let mut out = Vec::new();
        for (name, list) in frames.iter() {
            let name: String = name.extract().expect("flow name");
            let list = list.cast::<PyList>().expect("frame list");
            let mut flow = Vec::new();
            for item in list.iter() {
                let tuple = item;
                let opc: u32 = tuple.get_item(0).unwrap().extract().unwrap();
                let dpc: u32 = tuple.get_item(1).unwrap().extract().unwrap();
                let sccp: Vec<u8> = tuple
                    .get_item(2)
                    .unwrap()
                    .cast::<PyBytes>()
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                flow.push(Frame { opc, dpc, sccp });
            }
            out.push((name, flow));
        }
        out
    })
}

// ── M3UA / SCTP / pcap framing (synthetic loopback envelope for dissection) ───

fn m3ua_data(sccp: &[u8], opc: u32, dpc: u32) -> Vec<u8> {
    let pd = m3ua::ProtocolData::new(
        opc,
        dpc,
        SI_SCCP,
        NetworkIndicator::International.bits(),
        0,
        0,
        sccp.to_vec(),
    );
    m3ua::M3uaMessage::data(None, Some(1), pd, None).encode()
}

/// One SCTP packet (common header + a single DATA chunk) around `payload`.
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

pub fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Write `flow`'s frames to a pcap, dissect them clean in tshark (no BER /
/// malformed / expert error, and the chain reaches `want_proto`), and — when
/// `SIGTRAN_PCAP_DIR` names a directory — keep it as `<name>.pcap` for review.
pub fn dissect(name: &str, flow: &[Frame], want_proto: &str) {
    let eth: Vec<Vec<u8>> = flow
        .iter()
        .enumerate()
        .map(|(i, fr)| {
            eth_ipv4_sctp(&sctp_packet(
                &m3ua_data(&fr.sccp, fr.opc, fr.dpc),
                PPID_M3UA,
                1,
                i as u32 + 1,
            ))
        })
        .collect();

    let keep = std::env::var("SIGTRAN_PCAP_DIR").ok();
    let path = match &keep {
        Some(dir) => std::path::PathBuf::from(dir).join(format!("{name}.pcap")),
        None => std::env::temp_dir().join(format!("sigtran_py_{name}_{}.pcap", std::process::id())),
    };
    write_pcap(&path, &eth).expect("write pcap");

    let out = Command::new("tshark")
        .args(["-r", path.to_str().unwrap(), "-V"])
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

    if let Some(dir) = &keep {
        eprintln!(
            "wire_python: kept {}/{name}.pcap ({} frames)",
            dir,
            flow.len()
        );
    } else {
        let _ = std::fs::remove_file(&path);
    }

    assert!(bad.is_empty(), "tshark flagged {name}:\n{}", bad.join("\n"));
    assert!(
        proto_text.lines().any(|l| l.contains(want_proto)),
        "{name} did not dissect through {want_proto}: {}",
        proto_text.trim()
    );
}

/// The values tshark reads for `field` in each frame of `flow`, one string per
/// frame (empty where the frame has none).
pub fn fields(name: &str, flow: &[Frame], field: &str) -> Vec<String> {
    let eth: Vec<Vec<u8>> = flow
        .iter()
        .enumerate()
        .map(|(i, fr)| {
            eth_ipv4_sctp(&sctp_packet(
                &m3ua_data(&fr.sccp, fr.opc, fr.dpc),
                PPID_M3UA,
                1,
                i as u32 + 1,
            ))
        })
        .collect();
    let path = std::env::temp_dir().join(format!(
        "sigtran_py_{name}_fields_{}.pcap",
        std::process::id()
    ));
    write_pcap(&path, &eth).expect("write pcap");
    let out = Command::new("tshark")
        .args(["-r", path.to_str().unwrap(), "-T", "fields", "-e", field])
        .output()
        .expect("run tshark -T fields");
    let _ = std::fs::remove_file(&path);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}
