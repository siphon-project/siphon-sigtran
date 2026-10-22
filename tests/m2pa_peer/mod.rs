//! A hand-written M2PA peer for the wire tests, and the Wireshark reader that
//! checks what the node put on the association.
//!
//! Nothing here uses the `m2pa` or `mtp3` codec crates: every octet is written
//! and read from the figures of RFC 4165 2.1 to 2.3, ITU-T Q.704 15.2 (the
//! label) and Q.707 5.4 (the link test), so a fault in the codec the node uses
//! cannot hide on both ends.
#![allow(dead_code)]

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_sctp::{SctpAssociation, SctpConfig, SctpListener};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub const PPID_M2PA: u32 = 5;

/// Link Status values, RFC 4165 2.3.2.
pub const ALIGNMENT: u32 = 1;
pub const PROVING_NORMAL: u32 = 2;
pub const PROVING_EMERGENCY: u32 = 3;
pub const READY: u32 = 4;
pub const PROCESSOR_OUTAGE: u32 = 5;
pub const PROCESSOR_RECOVERED: u32 = 6;
pub const BUSY: u32 = 7;
pub const BUSY_ENDED: u32 = 8;
pub const OUT_OF_SERVICE: u32 = 9;

/// The value both sequence numbers have before the first User Data message.
pub const INITIAL: u32 = 0x00FF_FFFF;

/// The fast level-2 and link test timers the wire tests give the node, as the
/// `m2pa:` block of an association and the `link_test:` block of a linkset.
pub const FAST_M2PA: &str = "{ t1_ms: 2000, t2_ms: 2000, t3_ms: 1000, t4n_ms: 60, t4e_ms: 20, \
                             t6_ms: 300, t7_ms: 400, proving_interval_ms: 15, restart_ms: 100 }";
pub const FAST_LINK_TEST: &str = "{ t1_ms: 300, t2_ms: 30000, pattern: \"0102030405\" }";
/// The same with a short interval, for the periodic test.
pub const PERIODIC_LINK_TEST: &str = "{ t1_ms: 300, t2_ms: 400, pattern: \"0102030405\" }";
/// The pattern of [`FAST_LINK_TEST`].
pub const NODE_PATTERN: [u8; 5] = [1, 2, 3, 4, 5];

// ── Encoding, from the specifications ────────────────────────────────────────

/// Common header (version 1, spare, class 11, type, length) and the M2PA
/// header (unused, BSN, unused, FSN), RFC 4165 2.1 and 2.2.
fn header(message_type: u8, bsn: u32, fsn: u32, body: usize) -> Vec<u8> {
    let mut v = vec![0x01, 0x00, 0x0b, message_type];
    v.extend_from_slice(&((16 + body) as u32).to_be_bytes());
    v.extend_from_slice(&(bsn & INITIAL).to_be_bytes());
    v.extend_from_slice(&(fsn & INITIAL).to_be_bytes());
    v
}

/// A Link Status message.
pub fn link_status(state: u32, bsn: u32, fsn: u32) -> Vec<u8> {
    let mut v = header(2, bsn, fsn, 4);
    v.extend_from_slice(&state.to_be_bytes());
    v
}

/// A User Data message: the priority octet (spare for ITU) and the MSU, or
/// nothing at all for an acknowledgement.
pub fn user_data(bsn: u32, fsn: u32, msu: &[u8]) -> Vec<u8> {
    if msu.is_empty() {
        return header(1, bsn, fsn, 0);
    }
    let mut v = header(1, bsn, fsn, 1 + msu.len());
    v.push(0x00);
    v.extend_from_slice(msu);
    v
}

/// An ITU MSU: the service information octet (network indicator in the two
/// high bits, service indicator in the low four), the 32-bit label of Q.704
/// 15.2 sent least significant octet first (DPC 14 bits, OPC 14 bits, SLS or
/// SLC 4 bits), then the user part.
pub fn itu_msu(si: u8, ni: u8, opc: u32, dpc: u32, sls: u8, payload: &[u8]) -> Vec<u8> {
    let label = (dpc & 0x3FFF) | (opc & 0x3FFF) << 14 | u32::from(sls & 0x0F) << 28;
    let mut v = vec![ni << 6 | (si & 0x0F)];
    v.extend_from_slice(&label.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// The content of a signalling link test message (Q.707 5.4): heading H0 0001
/// with H1 0001 (SLTM) or 0010 (SLTA), the length above four spare bits, the
/// pattern.
pub fn link_test(acknowledgement: bool, pattern: &[u8]) -> Vec<u8> {
    let mut v = vec![if acknowledgement { 0x21 } else { 0x11 }];
    v.push((pattern.len() as u8) << 4);
    v.extend_from_slice(pattern);
    v
}

// ── Decoding, from the specifications ────────────────────────────────────────

/// One message the node sent, with the stream it arrived on.
#[derive(Debug, Clone)]
pub struct Frame {
    pub bytes: Vec<u8>,
    pub stream: u16,
    pub ppid: u32,
}

/// The routing label and content of an MSU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub si: u8,
    pub ni: u8,
    pub opc: u32,
    pub dpc: u32,
    pub sls: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn is_status(&self) -> bool {
        self.bytes.get(3) == Some(&2)
    }

    pub fn is_data(&self) -> bool {
        self.bytes.get(3) == Some(&1)
    }

    pub fn bsn(&self) -> u32 {
        u32::from_be_bytes([0, self.bytes[9], self.bytes[10], self.bytes[11]])
    }

    pub fn fsn(&self) -> u32 {
        u32::from_be_bytes([0, self.bytes[13], self.bytes[14], self.bytes[15]])
    }

    /// The state of a Link Status message.
    pub fn status(&self) -> Option<u32> {
        if !self.is_status() {
            return None;
        }
        let s = self.bytes.get(16..20)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// The MSU of a User Data message (after the priority octet). `None` for a
    /// Link Status and for an acknowledgement.
    pub fn msu(&self) -> Option<&[u8]> {
        if !self.is_data() || self.bytes.len() <= 17 {
            return None;
        }
        Some(&self.bytes[17..])
    }

    /// Whether this is a User Data message with no Data field.
    pub fn is_ack(&self) -> bool {
        self.is_data() && self.bytes.len() == 16
    }

    pub fn label(&self) -> Option<Label> {
        let msu = self.msu()?;
        let word = u32::from_le_bytes([*msu.get(1)?, *msu.get(2)?, *msu.get(3)?, *msu.get(4)?]);
        Some(Label {
            si: msu[0] & 0x0F,
            ni: msu[0] >> 6,
            dpc: word & 0x3FFF,
            opc: (word >> 14) & 0x3FFF,
            sls: (word >> 28) as u8,
            payload: msu[5..].to_vec(),
        })
    }

    /// `(is an acknowledgement, pattern)` when this is a signalling link test
    /// message.
    pub fn link_test(&self) -> Option<(bool, Vec<u8>)> {
        let label = self.label()?;
        if label.si != 1 {
            return None;
        }
        let heading = *label.payload.first()?;
        let length = usize::from(*label.payload.get(1)? >> 4);
        let pattern = label.payload.get(2..2 + length)?.to_vec();
        match heading {
            0x11 => Some((false, pattern)),
            0x21 => Some((true, pattern)),
            _ => None,
        }
    }
}

// ── The peer ─────────────────────────────────────────────────────────────────

/// One end of an M2PA link, driven step by step by a test. It keeps its own
/// sequence numbers and every frame the node sent.
pub struct Peer {
    pub assoc: Arc<SctpAssociation>,
    /// Everything received from the node, in order.
    pub log: Vec<Frame>,
    /// FSN of the last User Data message this peer sent.
    pub fsn_out: u32,
    /// FSN of the last User Data message this peer accepted.
    pub fsn_in: u32,
    /// This peer's point code and the node's, for the labels it writes.
    pub pc: u32,
    pub node_pc: u32,
    pub ni: u8,
    pub slc: u8,
}

/// A listener for the node to connect to (the node is the `client`).
pub struct Listening {
    listener: SctpListener,
    pub port: u16,
}

impl Listening {
    pub fn bind() -> Option<Self> {
        let cfg = SctpConfig::new().nodelay(true);
        let listener = SctpListener::bind_config("127.0.0.1:0".parse().ok()?, &cfg).ok()?;
        let port = listener.local_addr().ok()?.port();
        Some(Self { listener, port })
    }

    /// Wait for the node's association.
    pub async fn accept(&self, pc: u32, node_pc: u32, ni: u8) -> Option<Peer> {
        let (assoc, _) = timeout(Duration::from_secs(5), self.listener.accept())
            .await
            .ok()?
            .ok()?;
        Some(Peer::new(Arc::new(assoc), pc, node_pc, ni))
    }
}

impl Peer {
    pub fn new(assoc: Arc<SctpAssociation>, pc: u32, node_pc: u32, ni: u8) -> Self {
        Self {
            assoc,
            log: Vec::new(),
            fsn_out: INITIAL,
            fsn_in: INITIAL,
            pc,
            node_pc,
            ni,
            slc: 0,
        }
    }

    /// Connect to a node that listens (the node is the `server`).
    pub async fn connect(
        addr: std::net::SocketAddr,
        pc: u32,
        node_pc: u32,
        ni: u8,
    ) -> Option<Self> {
        let cfg = SctpConfig::new().nodelay(true);
        let assoc = SctpAssociation::connect_with(addr, &cfg).await.ok()?;
        Some(Self::new(Arc::new(assoc), pc, node_pc, ni))
    }

    /// The next message from the node, within `wait`. A message that is not
    /// M2PA is a test failure: the node must not send one on this association.
    pub async fn recv_within(&mut self, wait: Duration) -> Option<Frame> {
        let (bytes, info) = timeout(wait, self.assoc.recv()).await.ok()?.ok()?;
        assert_eq!(info.ppid, PPID_M2PA, "payload protocol identifier");
        assert!(bytes.len() >= 16, "an M2PA message has two headers");
        let frame = Frame {
            bytes,
            stream: info.stream,
            ppid: info.ppid,
        };
        self.log.push(frame.clone());
        Some(frame)
    }

    pub async fn recv(&mut self) -> Option<Frame> {
        self.recv_within(Duration::from_secs(5)).await
    }

    /// Send a Link Status on a stream, with this peer's sequence numbers.
    pub async fn status_on(&self, state: u32, stream: u16) {
        let bytes = link_status(state, self.fsn_in, self.fsn_out);
        self.assoc
            .send(&bytes, stream, PPID_M2PA)
            .await
            .expect("send link status");
    }

    /// Send a Link Status on the Link Status stream.
    pub async fn status(&self, state: u32) {
        self.status_on(state, 0).await;
    }

    /// Send raw octets on a stream.
    pub async fn raw(&self, bytes: &[u8], stream: u16) {
        self.assoc
            .send(bytes, stream, PPID_M2PA)
            .await
            .expect("send raw");
    }

    /// Send an MSU as the next User Data message.
    pub async fn send_msu(&mut self, msu: &[u8]) {
        self.fsn_out = (self.fsn_out + 1) & INITIAL;
        let bytes = user_data(self.fsn_in, self.fsn_out, msu);
        self.raw(&bytes, 1).await;
    }

    /// Acknowledge everything accepted so far with an empty User Data message.
    pub async fn ack(&self) {
        self.raw(&user_data(self.fsn_in, self.fsn_out, &[]), 1)
            .await;
    }

    /// Note a User Data message from the node as accepted, and acknowledge it.
    pub async fn accept_and_ack(&mut self, frame: &Frame) {
        if frame.msu().is_some() {
            self.fsn_in = frame.fsn();
            self.ack().await;
        }
    }

    /// The next message from the node that satisfies `wanted`, skipping (and
    /// acknowledging, when `ack` is set) everything before it.
    pub async fn until(&mut self, ack: bool, wanted: impl Fn(&Frame) -> bool) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.checked_duration_since(tokio::time::Instant::now())?;
            let frame = self.recv_within(left).await?;
            if ack {
                self.accept_and_ack(&frame).await;
            }
            if wanted(&frame) {
                return Some(frame);
            }
        }
    }

    /// Run alignment as Q.703 clause 7 and RFC 4165 4.1.3 have a peer do it:
    /// Out of Service, Alignment; on the node's Alignment or Proving, Proving
    /// Normal; after the node's first Proving, a short proving period; Ready;
    /// done when the node's Ready has arrived.
    pub async fn align(&mut self) {
        self.status(OUT_OF_SERVICE).await;
        self.status(ALIGNMENT).await;
        let mut proving_sent = false;
        let mut ready_sent = false;
        loop {
            let frame = self.recv().await.expect("the node takes part in alignment");
            match frame.status() {
                Some(ALIGNMENT) if !proving_sent => {
                    self.status(PROVING_NORMAL).await;
                    proving_sent = true;
                }
                Some(PROVING_NORMAL | PROVING_EMERGENCY) => {
                    if !proving_sent {
                        self.status(PROVING_NORMAL).await;
                        proving_sent = true;
                    }
                    if !ready_sent {
                        // This peer's proving period: a few messages, then Ready.
                        self.status(PROVING_NORMAL).await;
                        self.status(READY).await;
                        ready_sent = true;
                    }
                }
                Some(READY) => {
                    assert!(ready_sent, "the node is ready before it proved");
                    return;
                }
                _ => {}
            }
        }
    }

    /// Align again after the node took the link out and sent Alignment: the
    /// sequence numbers start over, Proving Normal answers its Alignment, and
    /// one short proving period and Ready follow its first Proving. Returns the
    /// node's link test message, not yet acknowledged.
    pub async fn realign(&mut self) -> Frame {
        self.fsn_in = INITIAL;
        self.fsn_out = INITIAL;
        self.status(PROVING_NORMAL).await;
        let mut ready_sent = false;
        loop {
            let frame = self.recv().await.expect("alignment continues");
            match frame.status() {
                Some(PROVING_NORMAL | PROVING_EMERGENCY) if !ready_sent => {
                    self.status(PROVING_NORMAL).await;
                    self.status(READY).await;
                    ready_sent = true;
                }
                Some(_) => {}
                None if frame.link_test().is_some() => return frame,
                None => {}
            }
        }
    }

    /// Answer the node's signalling link test: wait for its SLTM, acknowledge
    /// the User Data, and send the SLTA Q.707 2.2 asks for. Returns the SLTM.
    pub async fn answer_link_test(&mut self) -> Frame {
        let sltm = self
            .until(true, |f| matches!(f.link_test(), Some((false, _))))
            .await
            .expect("the node tests the link");
        let (_, pattern) = sltm.link_test().expect("an SLTM");
        let label = sltm.label().expect("a label");
        let slta = itu_msu(
            1,
            self.ni,
            self.pc,
            label.opc,
            label.sls,
            &link_test(true, &pattern),
        );
        self.send_msu(&slta).await;
        sltm
    }

    /// Acknowledge what the node sends for `wait` and forget it: the traffic
    /// restart allowed and the transfer-prohibited messages a transfer point
    /// sends an adjacent point whose linkset became available (ITU-T Q.704
    /// 9.3.2, 13.2.2), and its link test, which is answered.
    pub async fn quiet(&mut self, wait: Duration) {
        let deadline = tokio::time::Instant::now() + wait;
        while let Some(left) = deadline.checked_duration_since(tokio::time::Instant::now()) {
            let Some(frame) = self.recv_within(left).await else {
                break;
            };
            self.accept_and_ack(&frame).await;
            if let Some((false, pattern)) = frame.link_test() {
                let Some(label) = frame.label() else { continue };
                let slta = itu_msu(
                    1,
                    self.ni,
                    self.pc,
                    label.opc,
                    label.sls,
                    &link_test(true, &pattern),
                );
                self.send_msu(&slta).await;
            }
        }
    }

    /// The next MSU from the node that is neither a link test nor signalling
    /// network management (service indicators 1 and 0). Everything is
    /// acknowledged on the way, and a link test from the node is answered.
    pub async fn next_msu(&mut self) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.checked_duration_since(tokio::time::Instant::now())?;
            let frame = self.recv_within(left).await?;
            self.accept_and_ack(&frame).await;
            match frame.link_test() {
                Some((false, pattern)) => {
                    let label = frame.label()?;
                    let slta = itu_msu(
                        1,
                        self.ni,
                        self.pc,
                        label.opc,
                        label.sls,
                        &link_test(true, &pattern),
                    );
                    self.send_msu(&slta).await;
                }
                Some((true, _)) => {}
                None if frame.management().is_some() => {}
                None if frame.msu().is_some() => return Some(frame),
                None => {}
            }
        }
    }

    /// Align and pass the node's link test: the link is available afterwards.
    pub async fn bring_up(&mut self) {
        self.align().await;
        self.answer_link_test().await;
    }
}

// ── A peer that runs by itself ───────────────────────────────────────────────

/// A conformant peer in a task of its own, for the scenarios that are about
/// routing and only need a linkset that stays up: it listens, aligns, answers
/// the link test, says traffic may restart once the link is available (ITU-T
/// Q.704 9.3.2), acknowledges every User Data message, and hands the MSUs of
/// user parts to the test.
pub struct AutoPeer {
    pub port: u16,
    rx: mpsc::Receiver<Vec<u8>>,
    task: JoinHandle<()>,
}

impl AutoPeer {
    pub async fn spawn(pc: u32, node_pc: u32, ni: u8) -> Option<Self> {
        let listening = Listening::bind()?;
        let port = listening.port;
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let Some(mut peer) = listening.accept(pc, node_pc, ni).await else {
                return;
            };
            // Alignment as Q.703 clause 7 has it, for as often as the node
            // starts it: Proving Normal in answer to its Alignment, a short
            // proving period and Ready once it proves too.
            peer.status(OUT_OF_SERVICE).await;
            peer.status(ALIGNMENT).await;
            let (mut proving_sent, mut ready_sent) = (false, false);
            let mut restart_due = true;
            while let Ok((bytes, info)) = peer.assoc.recv().await {
                let frame = Frame {
                    bytes,
                    stream: info.stream,
                    ppid: info.ppid,
                };
                match frame.status() {
                    Some(OUT_OF_SERVICE) => {
                        peer.fsn_in = INITIAL;
                        peer.fsn_out = INITIAL;
                        proving_sent = false;
                        ready_sent = false;
                        restart_due = true;
                        continue;
                    }
                    Some(ALIGNMENT) => {
                        if !proving_sent {
                            peer.status(PROVING_NORMAL).await;
                            proving_sent = true;
                        }
                        continue;
                    }
                    Some(PROVING_NORMAL | PROVING_EMERGENCY) => {
                        if !proving_sent {
                            peer.status(PROVING_NORMAL).await;
                            proving_sent = true;
                        }
                        if !ready_sent {
                            peer.status(PROVING_NORMAL).await;
                            peer.status(READY).await;
                            ready_sent = true;
                        }
                        continue;
                    }
                    _ => {}
                }
                let Some(label) = frame.label() else { continue };
                peer.accept_and_ack(&frame).await;
                match frame.link_test() {
                    Some((false, pattern)) => {
                        let slta =
                            itu_msu(1, ni, pc, label.opc, label.sls, &link_test(true, &pattern));
                        peer.send_msu(&slta).await;
                        if restart_due {
                            restart_due = false;
                            let tra = itu_msu(SI_MANAGEMENT, ni, pc, node_pc, 0, &signal(TRA));
                            peer.send_msu(&tra).await;
                        }
                    }
                    Some((true, _)) => {}
                    // Signalling network management is for this peer, not
                    // something the node forwarded.
                    None if frame.management().is_some() => {}
                    None => {
                        if tx.send(frame.bytes.clone()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Some(Self { port, rx, task })
    }

    /// The next User Data message the node forwarded over the link.
    pub async fn recv_out(&mut self) -> Option<Vec<u8>> {
        timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .ok()
            .flatten()
    }
}

impl Drop for AutoPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── Wireshark as the independent reader ──────────────────────────────────────

fn tool(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether `tshark` is installed. Without it the dissection is skipped with a
/// message, unless `SIGTRAN_REQUIRE_TSHARK` is set, which makes that a failure.
pub fn tshark_available() -> bool {
    if tool("tshark") {
        return true;
    }
    let message = "tshark not found: the independent Wireshark dissection is skipped";
    assert!(
        std::env::var_os("SIGTRAN_REQUIRE_TSHARK").is_none(),
        "SIGTRAN_REQUIRE_TSHARK is set but {message}"
    );
    eprintln!("SKIP: {message}");
    false
}

/// The field names this `tshark` knows.
fn known_fields() -> &'static str {
    static FIELDS: OnceLock<String> = OnceLock::new();
    FIELDS.get_or_init(|| {
        let out = Command::new("tshark")
            .args(["-G", "fields"])
            .output()
            .expect("run tshark -G fields");
        String::from_utf8_lossy(&out.stdout).into_owned()
    })
}

/// The names this `tshark` has for a field. A few were renamed between
/// Wireshark releases, and one release can know two of them and fill either:
/// every known alternative is asked for, and the first one with a value read.
fn field_names(wanted: &str) -> Vec<&str> {
    let known = |name: &str| {
        known_fields()
            .lines()
            .any(|l| l.split('\t').nth(2) == Some(name))
    };
    let alternatives: &[&str] = match wanted {
        "mtp3mg.test.pattern" => &["mtp3mg.test.pattern", "mtp3mg.test_pattern"],
        "m2pa.priority" => &["m2pa.priority", "m2pa.pri"],
        _ => &[],
    };
    let found: Vec<&str> = alternatives.iter().copied().filter(|n| known(n)).collect();
    if found.is_empty() {
        vec![wanted]
    } else {
        found
    }
}

/// One SCTP packet with a single DATA chunk in IPv4 in Ethernet.
fn ethernet_frame(frame: &Frame, tsn: u32) -> Vec<u8> {
    let mut chunk = vec![0x00, 0x03];
    chunk.extend_from_slice(&((16 + frame.bytes.len()) as u16).to_be_bytes());
    chunk.extend_from_slice(&tsn.to_be_bytes());
    chunk.extend_from_slice(&frame.stream.to_be_bytes());
    chunk.extend_from_slice(&0u16.to_be_bytes());
    chunk.extend_from_slice(&frame.ppid.to_be_bytes());
    chunk.extend_from_slice(&frame.bytes);
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    let mut sctp = Vec::new();
    sctp.extend_from_slice(&3565u16.to_be_bytes());
    sctp.extend_from_slice(&3565u16.to_be_bytes());
    sctp.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    sctp.extend_from_slice(&0u32.to_be_bytes());
    sctp.extend_from_slice(&chunk);

    let mut out = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
    out.extend_from_slice(&[0x45, 0x00]);
    out.extend_from_slice(&((20 + sctp.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 132, 0, 0]);
    out.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
    out.extend_from_slice(&sctp);
    out
}

fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&262_144u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, frame) in frames.iter().enumerate() {
        out.extend_from_slice(&(i as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// What Wireshark read: one row per frame, one column per field asked for.
pub struct Read {
    fields: Vec<String>,
    pub rows: Vec<Vec<String>>,
    /// Lines of the verbose dissection that report a malformed frame.
    pub complaints: Vec<String>,
}

impl Read {
    /// The value of `field` in frame `row` (empty when the frame has none).
    #[track_caller]
    pub fn get(&self, row: usize, field: &str) -> &str {
        let column = self
            .fields
            .iter()
            .position(|f| f == field)
            .unwrap_or_else(|| panic!("{field} was not asked for"));
        &self.rows[row][column]
    }

    /// Every frame's value of `field`, in order.
    #[track_caller]
    pub fn column(&self, field: &str) -> Vec<&str> {
        (0..self.rows.len()).map(|r| self.get(r, field)).collect()
    }

    /// One line per frame, for a failure message or `--nocapture`.
    pub fn lines(&self) -> String {
        self.rows
            .iter()
            .map(|row| {
                self.fields
                    .iter()
                    .zip(row)
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(f, v)| format!("{f}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Wireshark found nothing malformed in any frame.
    #[track_caller]
    pub fn clean(&self) -> &Self {
        assert!(
            self.complaints.is_empty(),
            "Wireshark flagged what the node sent:\n{}\n{}",
            self.complaints.join("\n"),
            self.lines()
        );
        self
    }
}

/// Have `tshark` read frames the node sent and report `fields` for each.
/// `None` when `tshark` is not installed (see [`tshark_available`]).
pub fn wireshark(frames: &[Frame], fields: &[&str]) -> Option<Read> {
    dissect(frames, fields, "f")
}

/// [`wireshark`] with every occurrence of a field in a frame, separated by
/// commas: for a parameter that is a list.
pub fn wireshark_every(frames: &[Frame], fields: &[&str]) -> Option<Read> {
    dissect(frames, fields, "a")
}

fn dissect(frames: &[Frame], fields: &[&str], occurrence: &str) -> Option<Read> {
    if !tshark_available() {
        return None;
    }
    let packets: Vec<Vec<u8>> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| ethernet_frame(f, i as u32 + 1))
        .collect();
    let directory = std::env::temp_dir().join(format!(
        "sigtran-m2pa-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("temporary directory");
    let capture = directory.join("frames.pcap");
    std::fs::write(&capture, pcap(&packets)).expect("write pcap");

    let run = |args: &[&str]| {
        let out = Command::new("tshark")
            .env("WIRESHARK_CONFIG_DIR", &directory)
            .env("XDG_CONFIG_HOME", &directory)
            .arg("-r")
            .arg(&capture)
            .args(["-d", "sctp.ppi==5,m2pa"])
            .args(args)
            .output()
            .expect("run tshark");
        assert!(
            out.status.success(),
            "tshark failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let names: Vec<Vec<&str>> = fields.iter().map(|f| field_names(f)).collect();
    let occurrence = format!("occurrence={occurrence}");
    let mut args = vec![
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "aggregator=,",
        "-E",
        &occurrence,
    ];
    for name in names.iter().flatten() {
        args.push("-e");
        args.push(name);
    }
    let table = run(&args);
    let verbose = run(&["-V"]);
    let _ = std::fs::remove_dir_all(&directory);

    // One column per field asked for: the first of its names that has a value.
    let rows: Vec<Vec<String>> = table
        .lines()
        .map(|line| {
            let mut columns = line.split('|');
            names
                .iter()
                .map(|alternatives| {
                    alternatives
                        .iter()
                        .filter_map(|_| columns.next())
                        .find(|v| !v.is_empty())
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    assert_eq!(rows.len(), frames.len(), "one row per frame:\n{table}");
    let complaints = verbose
        .lines()
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            l.contains("malformed")
                || l.contains("dissector bug")
                || l.contains("beyond the end")
                || (l.contains("expert info") && (l.contains("error") || l.contains("warn")))
        })
        .map(|l| l.trim().to_string())
        .collect();
    Some(Read {
        fields: fields.iter().map(|f| f.to_string()).collect(),
        rows,
        complaints,
    })
}

// ── Signalling network management, from ITU-T Q.704 clause 15 ────────────────
//
// Written from the figures: the heading octet is H0 in the low half and H1 in
// the high half (15.3); a destination is 14 bits sent least significant octet
// first with two spare bits above it (Figure 18); the extended changeover
// messages carry a 24-bit sequence number (Q.2210 9.8.1, Figure 3).

/// The service indicator of signalling network management (Q.704 14.2.1).
pub const SI_MANAGEMENT: u8 = 0;

/// Heading codes `(H0, H1)` of Table 1/Q.704 and Q.2210 9.8.1.
pub const COO: (u8, u8) = (1, 1);
pub const COA: (u8, u8) = (1, 2);
pub const XCO: (u8, u8) = (1, 3);
pub const XCA: (u8, u8) = (1, 4);
pub const CBD: (u8, u8) = (1, 5);
pub const CBA: (u8, u8) = (1, 6);
pub const ECO: (u8, u8) = (2, 1);
pub const ECA: (u8, u8) = (2, 2);
pub const TFC: (u8, u8) = (3, 2);
pub const TFP: (u8, u8) = (4, 1);
pub const TFR: (u8, u8) = (4, 3);
pub const TFA: (u8, u8) = (4, 5);
pub const RST: (u8, u8) = (5, 1);
pub const RSR: (u8, u8) = (5, 2);
pub const LIN: (u8, u8) = (6, 1);
pub const LUN: (u8, u8) = (6, 2);
pub const LIA: (u8, u8) = (6, 3);
pub const LUA: (u8, u8) = (6, 4);
pub const LID: (u8, u8) = (6, 5);
pub const LFU: (u8, u8) = (6, 6);
pub const LLT: (u8, u8) = (6, 7);
pub const LRT: (u8, u8) = (6, 8);
pub const TRA: (u8, u8) = (7, 1);

fn heading(code: (u8, u8)) -> u8 {
    (code.0 & 0x0F) | (code.1 & 0x0F) << 4
}

/// A message that is its heading only (15.6, 15.11, 15.12).
pub fn signal(code: (u8, u8)) -> Vec<u8> {
    vec![heading(code)]
}

/// A message about a destination: TFP, TFR, TFA, RST, RSR (15.7 to 15.10), or
/// TFC with a congestion status in the two bits above it (15.15).
pub fn about(code: (u8, u8), destination: u32, upper: u8) -> Vec<u8> {
    vec![
        heading(code),
        destination as u8,
        ((destination >> 8) as u8 & 0x3F) | (upper & 0x03) << 6,
    ]
}

/// An extended changeover order or acknowledgement (Q.2210 9.8.1).
pub fn extended_changeover(code: (u8, u8), fsn: u32) -> Vec<u8> {
    vec![
        heading(code),
        fsn as u8,
        (fsn >> 8) as u8,
        (fsn >> 16) as u8,
    ]
}

/// A changeover order or acknowledgement with a 7-bit number (15.4).
pub fn changeover(code: (u8, u8), fsn: u8) -> Vec<u8> {
    vec![heading(code), fsn & 0x7F]
}

/// A changeback declaration or acknowledgement (15.5).
pub fn changeback(code: (u8, u8), changeback_code: u8) -> Vec<u8> {
    vec![heading(code), changeback_code]
}

/// A management message as this peer read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Management {
    pub code: (u8, u8),
    pub opc: u32,
    pub dpc: u32,
    pub slc: u8,
    /// The octets after the heading.
    pub body: Vec<u8>,
}

impl Management {
    /// The 14-bit destination of a message about one.
    pub fn destination(&self) -> Option<u32> {
        let low = *self.body.first()?;
        let high = *self.body.get(1)?;
        Some(u32::from(low) | u32::from(high & 0x3F) << 8)
    }

    /// The 24-bit sequence number of an extended changeover message.
    pub fn extended_fsn(&self) -> Option<u32> {
        let b = self.body.get(..3)?;
        Some(u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16)
    }

    /// The changeback code.
    pub fn changeback_code(&self) -> Option<u8> {
        self.body.first().copied()
    }
}

impl Frame {
    /// The management message in this frame, if it is one.
    pub fn management(&self) -> Option<Management> {
        let label = self.label()?;
        if label.si != SI_MANAGEMENT {
            return None;
        }
        let heading = *label.payload.first()?;
        Some(Management {
            code: (heading & 0x0F, heading >> 4),
            opc: label.opc,
            dpc: label.dpc,
            slc: label.sls,
            body: label.payload[1..].to_vec(),
        })
    }

    /// Whether this is the management message `code`.
    pub fn is(&self, code: (u8, u8)) -> bool {
        self.management().is_some_and(|m| m.code == code)
    }
}

/// The level-3 timers the wire tests give the node (the `mtp3:` block): the
/// restart of a node that nobody answers ends after `t18_ms`, and an adjacent
/// point that sends no traffic restart allowed is waited for `t21_ms`.
pub const FAST_MTP3: &str = "{ t1_ms: 150, t2_ms: 400, t3_ms: 150, t4_ms: 200, t5_ms: 200, \
                             t6_ms: 200, t8_ms: 300, t10_ms: 250, t12_ms: 200, t13_ms: 200, \
                             t18_ms: 60, t19_ms: 500, t20_ms: 2000, t21_ms: 300, t23_ms: 400 }";

// ── An adjacent signalling point that runs by itself ─────────────────────────

/// What a test tells a link of an [`Adjacent`] to do.
enum Order {
    /// Send this MSU as the next User Data message.
    Send(Vec<u8>),
    /// Stop, or resume, acknowledging what the node sends.
    Acknowledge(bool),
    /// Take the link out of service (Link Status Out of Service) and, while
    /// `down` is set, do not take part in alignment.
    Fail,
    /// Take part in alignment again.
    Restore,
    /// Whether traffic restart allowed follows the next link test.
    Restart(bool),
    /// Drop the association.
    Close,
}

/// One link toward the node, run by a task: it aligns as Q.703 clause 7 has a
/// peer do it, answers the node's link test, acknowledges User Data, and hands
/// every MSU that is not a link test to the test. The test sends through it,
/// fails it, and stops its acknowledgements.
pub struct Adjacent {
    pub port: u16,
    pub pc: u32,
    pub node_pc: u32,
    pub ni: u8,
    pub slc: u8,
    orders: mpsc::UnboundedSender<Order>,
    received: mpsc::UnboundedReceiver<Frame>,
    log: Arc<std::sync::Mutex<Vec<Frame>>>,
    /// FSN of the last User Data message this link sent.
    sent: Arc<AtomicU32>,
    task: JoinHandle<()>,
}

impl Adjacent {
    /// Listen for the node (it is the `client`). With `restart` set the peer
    /// sends traffic restart allowed once the link has passed its test, as
    /// Q.704 9.3.2 has an adjacent point do.
    pub async fn spawn(pc: u32, node_pc: u32, ni: u8, slc: u8, restart: bool) -> Option<Self> {
        let listening = Listening::bind()?;
        let port = listening.port;
        let (orders, mut order_rx) = mpsc::unbounded_channel();
        let (received_tx, received) = mpsc::unbounded_channel();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let task_log = log.clone();
        let sent = Arc::new(AtomicU32::new(INITIAL));
        let task_sent = sent.clone();
        let task = tokio::spawn(async move {
            let Some(mut peer) = listening.accept(pc, node_pc, ni).await else {
                return;
            };
            peer.slc = slc;
            peer.status(OUT_OF_SERVICE).await;
            peer.status(ALIGNMENT).await;
            let (mut proving_sent, mut ready_sent) = (false, false);
            let mut acknowledging = true;
            // The FSN of the last User Data message seen, acknowledged or not.
            let mut seen = INITIAL;
            let mut down = false;
            // Traffic restart allowed is due after the next link test.
            let mut restart_due = restart;
            loop {
                task_sent.store(peer.fsn_out, Ordering::Relaxed);
                tokio::select! {
                    order = order_rx.recv() => match order {
                        None | Some(Order::Close) => break,
                        Some(Order::Restart(on)) => restart_due = on,
                        Some(Order::Send(msu)) => peer.send_msu(&msu).await,
                        Some(Order::Acknowledge(on)) => {
                            acknowledging = on;
                            if on {
                                peer.fsn_in = seen;
                                peer.ack().await;
                            }
                        }
                        Some(Order::Fail) => {
                            down = true;
                            peer.status(OUT_OF_SERVICE).await;
                            peer.fsn_in = INITIAL;
                            peer.fsn_out = INITIAL;
                            seen = INITIAL;
                            proving_sent = false;
                            ready_sent = false;
                        }
                        Some(Order::Restore) => {
                            down = false;
                            peer.status(ALIGNMENT).await;
                        }
                    },
                    got = peer.assoc.recv() => {
                        let Ok((bytes, info)) = got else { break };
                        let frame = Frame { bytes, stream: info.stream, ppid: info.ppid };
                        task_log.lock().unwrap().push(frame.clone());
                        match frame.status() {
                            Some(OUT_OF_SERVICE) => {
                                peer.fsn_in = INITIAL;
                                peer.fsn_out = INITIAL;
                                seen = INITIAL;
                                proving_sent = false;
                                ready_sent = false;
                                continue;
                            }
                            Some(_) if down => continue,
                            Some(ALIGNMENT) => {
                                if !proving_sent {
                                    peer.status(PROVING_NORMAL).await;
                                    proving_sent = true;
                                }
                                continue;
                            }
                            Some(PROVING_NORMAL | PROVING_EMERGENCY) => {
                                if !proving_sent {
                                    peer.status(PROVING_NORMAL).await;
                                    proving_sent = true;
                                }
                                if !ready_sent {
                                    peer.status(PROVING_NORMAL).await;
                                    peer.status(READY).await;
                                    ready_sent = true;
                                }
                                continue;
                            }
                            Some(_) => continue,
                            None => {}
                        }
                        if down {
                            continue;
                        }
                        let Some(label) = frame.label() else { continue };
                        seen = frame.fsn();
                        if acknowledging {
                            peer.accept_and_ack(&frame).await;
                        }
                        match frame.link_test() {
                            Some((false, pattern)) => {
                                let slta = itu_msu(
                                    1, ni, pc, label.opc, label.sls, &link_test(true, &pattern),
                                );
                                peer.send_msu(&slta).await;
                                if restart_due {
                                    restart_due = false;
                                    let tra = itu_msu(SI_MANAGEMENT, ni, pc, node_pc, 0, &signal(TRA));
                                    peer.send_msu(&tra).await;
                                }
                            }
                            Some((true, _)) => {}
                            None => {
                                if received_tx.send(frame).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        Some(Self {
            port,
            pc,
            node_pc,
            ni,
            slc,
            orders,
            received,
            log,
            sent,
            task,
        })
    }

    /// The FSN of the last User Data message this link sent to the node: what
    /// the node has to name in a changeover order for the link.
    pub fn last_sent(&self) -> u32 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Whether traffic restart allowed follows the next link test (Q.704
    /// 9.3.2: an adjacent point does that when this node was inaccessible to
    /// it, not when one of several links returns).
    pub fn restart_allowed(&self, on: bool) {
        let _ = self.orders.send(Order::Restart(on));
    }

    /// Send an MSU to the node on this link.
    pub fn send(&self, msu: Vec<u8>) {
        let _ = self.orders.send(Order::Send(msu));
    }

    /// Send a management message to the node on this link, about link code
    /// `slc` (0 for a message that is not about a link).
    pub fn manage(&self, slc: u8, content: Vec<u8>) {
        self.send(itu_msu(
            SI_MANAGEMENT,
            self.ni,
            self.pc,
            self.node_pc,
            slc,
            &content,
        ));
    }

    /// Stop, or resume, acknowledging what the node sends.
    pub fn acknowledge(&self, on: bool) {
        let _ = self.orders.send(Order::Acknowledge(on));
    }

    /// Fail the link at level 2 and keep it down.
    pub fn fail(&self) {
        let _ = self.orders.send(Order::Fail);
    }

    /// Drop the SCTP association of the link, for good.
    pub fn close(&self) {
        let _ = self.orders.send(Order::Close);
    }

    /// Let the link align again.
    pub fn restore(&self) {
        let _ = self.orders.send(Order::Restore);
    }

    /// The next MSU from the node that is not a link test, within `wait`.
    pub async fn recv_within(&mut self, wait: Duration) -> Option<Frame> {
        timeout(wait, self.received.recv()).await.ok().flatten()
    }

    /// The next MSU from the node that satisfies `wanted`, skipping the others.
    pub async fn until(&mut self, wanted: impl Fn(&Frame) -> bool) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.checked_duration_since(tokio::time::Instant::now())?;
            let frame = self.recv_within(left).await?;
            if wanted(&frame) {
                return Some(frame);
            }
        }
    }

    /// The next MSU of a user part (not management, not a link test).
    pub async fn traffic(&mut self) -> Option<Frame> {
        self.until(|f| f.management().is_none()).await
    }

    /// Every MSU that arrives within `wait`.
    pub async fn drain(&mut self, wait: Duration) -> Vec<Frame> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + wait;
        while let Some(left) = deadline.checked_duration_since(tokio::time::Instant::now()) {
            match self.recv_within(left).await {
                Some(frame) => out.push(frame),
                None => break,
            }
        }
        out
    }

    /// Everything the node sent on this link so far, statuses included.
    pub fn frames(&self) -> Vec<Frame> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Adjacent {
    fn drop(&mut self) {
        self.task.abort();
    }
}
