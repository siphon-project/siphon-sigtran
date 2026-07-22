//! Full multi-leg SS7 dialogues driven from a **siphon addon Python script**,
//! captured to pcaps.
//!
//! Compiles only with `--features python`, so siphon-sip is in the build graph
//! and the addon is exercised exactly as a composing siphon binary drives it:
//! mount the `ss7` / `gsm_map` / `gsm_cap` namespaces, run a script, and let it
//! program + drive the node through the real addon API.
//!
//! The script drives two complete TCAP dialogues end to end:
//!
//!   * a **concatenated SMS the node ORIGINATES** as the SMSC — Begin(mt-forwardSM
//!     segment 1, `moreMessagesToSend`) → the VMSC's ack → Continue(segment 2) →
//!     the VMSC's closing End. The node's outbound legs come from
//!     `node.originate(...)` + the `on_reply` callback; the VMSC's acks are
//!     assembled the same way a peer would send them.
//!   * a **CAMEL session the node TERMINATES** as the SCP — the SSF's
//!     Begin(initialDP) → Continue(requestReportBCSMEvent + continue) → the SSF's
//!     closing End. The SCP's response is driven by an `@gsm_cap.on_operation`
//!     handler.
//!
//! The script hands back the SCCP payloads it produced, tagged with their MTP3
//! routing label; this harness frames them as M3UA over SCTP, writes one pcap per
//! flow, and (when tshark is installed) asserts each dissects clean through the
//! GSM SMS / CAMEL dissectors. Set `SIGTRAN_PCAP_DIR=<dir>` to keep the pcaps.
//!
//! All values are synthetic (test PLMN 001/01, `+1-555-01xx`, decimal PCs).

#![cfg(feature = "python")]

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
fn mount(py: Python<'_>) -> PyResult<()> {
    let siphon = pyo3::types::PyModule::new(py, "siphon")?;
    siphon_sigtran::python::register(py, &siphon)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("siphon", &siphon)?;
    Ok(())
}

/// The addon script: it configures the node, then drives both full dialogues
/// through the real `gsm_map` / `gsm_cap` API, collecting `(opc, dpc, sccp)`
/// tuples per flow into a module-level `FRAMES` dict.
const SCRIPT: &str = r#"
import siphon
from siphon import gsm_map, gsm_cap

CONFIG = """
node: { point_code: 1000, variant: ITU, network_indicator: international }
associations:
  - { id: peer, adaptation: m3ua, role: server, addrs: [10.1.0.10], port: 2905 }
application_servers:
  - { name: peer, traffic_mode: override, routing_context: 100, asps: [peer] }
mtp3_routes:
  - { dpc: 2000, as: peer, priority: 1 }
sccp:
  local_ssns: [8, 146]
"""
node = siphon.configure(CONFIG)

SMSC = "15550100"; VMSC = "15550180"; SC = "15550100"; IMSI = "001010000000042"

def _udh(part, payload):
    udh = bytes([0x05, 0x00, 0x03, 0x42, 0x02, part])       # concat IE, ref 0x42, 2 parts, #part
    tpdu = bytes([0x40, 0x08, 0x91, 0x51, 0x55, 0x10, 0x10,  # SMS-DELIVER, UDHI, TP-OA +15550101
                  0x00, 0x04,                                 # TP-PID, TP-DCS 8-bit
                  0x22, 0x70, 0x21, 0x41, 0x30, 0x00, 0x00])  # TP-SCTS
    return tpdu + bytes([len(udh) + len(payload)]) + udh + payload

PART1 = _udh(1, b"Concatenated SMS, segment one. ")
PART2 = _udh(2, b"Segment two, and the end.")

# ── Concat SMS: the node (SMSC) ORIGINATES a 2-segment MT delivery ─────────────
concat = []

def on_ack(dlg, peer):
    # The VMSC acked segment 1 (a Continue); send segment 2, then it ends the dialogue.
    if not peer.is_end:
        dlg.invoke(gsm_map.mt_forward_sm(imsi=IMSI, sc_addr=SC, tpdu=PART2,
                                         more_messages_to_send=False))
        dlg.send()

begin = node.originate(
    invoke=gsm_map.mt_forward_sm(imsi=IMSI, sc_addr=SC, tpdu=PART1, more_messages_to_send=True),
    on_reply=on_ack,
    called_gt=VMSC, called_ssn=8, calling_gt=SMSC, calling_ssn=8, dpc=2000,
    ac=gsm_map.AC.short_msg_mt_relay,
)
concat.append((1000, 2000, begin[0]))                                  # SMSC -> VMSC: Begin(seg 1, more)
otid = node.decode(begin[0]).otid
ack1 = node.assemble_continue(dtid=otid, staged=gsm_map.mt_forward_sm_res(), invoke_id=1)
concat.append((2000, 1000, ack1))                                      # VMSC -> SMSC: Continue(ack 1)
seg2 = node.deliver(ack1, opc=2000, dpc=1000)                          # on_ack fires -> Continue(seg 2)
concat.append((1000, 2000, seg2[0]))                                   # SMSC -> VMSC: Continue(seg 2)
end = node.assemble_end(dtid=otid, staged=gsm_map.mt_forward_sm_res(), invoke_id=2)
concat.append((2000, 1000, end))                                       # VMSC -> SMSC: End(ack 2), close
node.deliver(end, opc=2000, dpc=1000)                                  # drive the close (no output)

# ── CAMEL: the node (SCP) TERMINATES an initialDP and drives the session ───────
@gsm_cap.on_operation("initial-dp")
def scp(dlg, view):
    if view.is_peer_turn:            # the SSF closed the dialogue; nothing to do
        return
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(9, 1)]))  # arm oDisconnect (notify+continue)
    dlg.invoke(gsm_cap.continue_())                                 # let the call proceed
    dlg.send()                       # Continue, hold the dialogue open

camel = []
idp = node.assemble_begin(op="initial-dp", called_gt="15550142", called_ssn=146,
                          calling_gt="15550101", ac=gsm_cap.AC.gsm_ssf_scf)
camel.append((4000, 1000, idp))                                        # SSF -> SCP: Begin(initialDP)
resp = node.deliver(idp, opc=4000, dpc=1000)                           # SCP -> SSF: Continue(RRBE + continue)
camel.append((1000, 4000, resp[0]))
sotid = node.decode(resp[0]).otid
close = node.assemble_end(dtid=sotid)                                  # SSF -> SCP: End, close
camel.append((4000, 1000, close))
node.deliver(close, opc=4000, dpc=1000)

FRAMES = {"concat_sms": concat, "camel_session": camel}
"#;

/// One `(opc, dpc, sccp)` frame the script produced.
struct Frame {
    opc: u32,
    dpc: u32,
    sccp: Vec<u8>,
}

/// Run the addon script and pull back the frames it produced per flow.
fn run_script() -> Vec<(String, Vec<Frame>)> {
    Python::attach(|py| {
        mount(py).expect("mount addon");
        let globals = PyDict::new(py);
        let code = CString::new(SCRIPT).expect("no NUL in the addon script");
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

fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Write `flow`'s frames to a pcap, dissect them clean in tshark (no BER /
/// malformed / expert error, and the chain reaches `want_proto`), and — when
/// `SIGTRAN_PCAP_DIR` names a directory — keep it as `<name>.pcap` for review.
fn dissect(name: &str, flow: &[Frame], want_proto: &str) {
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

#[test]
fn python_driven_concat_sms_and_camel_capture() {
    let flows = run_script();

    // Sanity on the shapes the script produced (independent of tshark).
    let concat = &flows
        .iter()
        .find(|(n, _)| n == "concat_sms")
        .expect("concat_sms")
        .1;
    let camel = &flows
        .iter()
        .find(|(n, _)| n == "camel_session")
        .expect("camel_session")
        .1;
    assert_eq!(concat.len(), 4, "concat SMS is a 4-message dialogue");
    assert_eq!(camel.len(), 3, "CAMEL session is a 3-message dialogue");

    if !tshark_available() {
        eprintln!(
            "SKIP wire_python dissection: tshark not installed (flows still driven by the script)"
        );
        return;
    }
    dissect("concat_sms", concat, "gsm_sms");
    dissect("camel_session", camel, "camel");
}
