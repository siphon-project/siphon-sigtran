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
#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads

mod python_wire;
use python_wire::{dissect, run, tshark_available, Frame};

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
    dlg.invoke(gsm_cap.request_report_bcsm_event(events=[(9, 1, 1)]))  # arm oDisconnect on leg 1 (notify+continue)
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

/// Run the addon script and pull back the frames it produced per flow.
fn run_script() -> Vec<(String, Vec<Frame>)> {
    run(SCRIPT)
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
