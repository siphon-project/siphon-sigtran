//! A hand-written M3UA peer for the wire tests.
//!
//! Nothing here uses the `m3ua` codec crate: every octet is written and read
//! from the figures of RFC 4666 (3.1 the common header, 3.2 the parameter
//! format, 3.3.1 Protocol Data, 3.4 the SSNM messages, 3.5 and 3.7 the ASP
//! state and traffic maintenance messages, 3.8 Error and Notify), so a fault
//! in the codec the node uses cannot hide on both ends. What the node sends is
//! kept as [`Frame`]s for the Wireshark reader of `tests/m2pa_peer`.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_sctp::{SctpAssociation, SctpConfig, SctpListener};
use tokio::time::timeout;

use crate::m2pa_peer::Frame;

pub const PPID_M3UA: u32 = 3;

/// How long `next` waits for a message the test expects. It returns as soon as
/// the message arrives, so this only bounds a failure; the timing a test does
/// check is measured with its own bounds. 3 s ran out on a loaded runner.
const NEXT_DEADLINE: Duration = Duration::from_secs(15);

// Message classes and types (3.1.2).
pub const ERR: (u8, u8) = (0, 0);
pub const NTFY: (u8, u8) = (0, 1);
pub const DATA: (u8, u8) = (1, 1);
pub const DUNA: (u8, u8) = (2, 1);
pub const DAVA: (u8, u8) = (2, 2);
pub const DAUD: (u8, u8) = (2, 3);
pub const SCON: (u8, u8) = (2, 4);
pub const DUPU: (u8, u8) = (2, 5);
pub const DRST: (u8, u8) = (2, 6);
pub const ASPUP: (u8, u8) = (3, 1);
pub const ASPDN: (u8, u8) = (3, 2);
pub const BEAT: (u8, u8) = (3, 3);
pub const ASPUP_ACK: (u8, u8) = (3, 4);
pub const ASPDN_ACK: (u8, u8) = (3, 5);
pub const BEAT_ACK: (u8, u8) = (3, 6);
pub const ASPAC: (u8, u8) = (4, 1);
pub const ASPIA: (u8, u8) = (4, 2);
pub const ASPAC_ACK: (u8, u8) = (4, 3);
pub const ASPIA_ACK: (u8, u8) = (4, 4);
pub const REG_REQ: (u8, u8) = (9, 1);

// Parameter tags (3.2).
pub const INFO_STRING: u16 = 0x0004;
pub const ROUTING_CONTEXT: u16 = 0x0006;
pub const DIAGNOSTIC: u16 = 0x0007;
pub const HEARTBEAT_DATA: u16 = 0x0009;
pub const TRAFFIC_MODE: u16 = 0x000b;
pub const ERROR_CODE: u16 = 0x000c;
pub const STATUS: u16 = 0x000d;
pub const ASP_IDENTIFIER: u16 = 0x0011;
pub const AFFECTED: u16 = 0x0012;
pub const USER_CAUSE: u16 = 0x0204;
pub const CONGESTION: u16 = 0x0205;
pub const CONCERNED: u16 = 0x0206;
pub const PROTOCOL_DATA: u16 = 0x0210;

// Traffic Mode Type (3.7.1).
pub const OVERRIDE: u32 = 1;
pub const LOADSHARE: u32 = 2;
pub const BROADCAST: u32 = 3;

// Error codes (3.8.1).
pub const INVALID_VERSION: u32 = 0x01;
pub const UNSUPPORTED_CLASS: u32 = 0x03;
pub const UNSUPPORTED_TYPE: u32 = 0x04;
pub const UNSUPPORTED_MODE: u32 = 0x05;
pub const UNEXPECTED_MESSAGE: u32 = 0x06;
pub const PROTOCOL_ERROR: u32 = 0x07;
pub const INVALID_PARAMETER_VALUE: u32 = 0x11;
pub const PARAMETER_FIELD_ERROR: u32 = 0x12;
pub const MISSING_PARAMETER: u32 = 0x16;
pub const INVALID_ROUTING_CONTEXT: u32 = 0x19;
pub const NO_CONFIGURED_AS: u32 = 0x1a;

// Status (3.8.2): type, information.
pub const AS_INACTIVE: (u16, u16) = (1, 2);
pub const AS_ACTIVE: (u16, u16) = (1, 3);
pub const AS_PENDING: (u16, u16) = (1, 4);
pub const INSUFFICIENT_RESOURCES: (u16, u16) = (2, 1);
pub const ALTERNATE_ASP_ACTIVE: (u16, u16) = (2, 2);
pub const ASP_FAILURE: (u16, u16) = (2, 3);

// ── Encoding, from the figures ───────────────────────────────────────────────

/// One parameter (3.2): tag, length of tag, length and value, the value, and
/// padding to a multiple of four octets that the length does not count.
pub fn parameter(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_be_bytes().to_vec();
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// A parameter whose value is a list of 32-bit integers.
pub fn integers(tag: u16, values: &[u32]) -> Vec<u8> {
    parameter(tag, &words(values))
}

/// A message (3.1): version 1, a reserved octet, class, type, and the length
/// of the whole message.
pub fn message(kind: (u8, u8), parameters: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parameters.concat();
    let mut out = vec![1, 0, kind.0, kind.1];
    out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A message with the Routing Context parameter when `contexts` has any.
fn with_contexts(kind: (u8, u8), contexts: &[u32], mut rest: Vec<Vec<u8>>) -> Vec<u8> {
    let mut parameters = Vec::new();
    if !contexts.is_empty() {
        parameters.push(integers(ROUTING_CONTEXT, contexts));
    }
    parameters.append(&mut rest);
    message(kind, &parameters)
}

/// ASP Up (3.5.1).
pub fn asp_up(identifier: Option<u32>) -> Vec<u8> {
    let parameters: Vec<Vec<u8>> = identifier
        .map(|id| integers(ASP_IDENTIFIER, &[id]))
        .into_iter()
        .collect();
    message(ASPUP, &parameters)
}

/// ASP Active (3.7.1): Traffic Mode Type, then Routing Context.
pub fn asp_active(mode: Option<u32>, contexts: &[u32]) -> Vec<u8> {
    let mut parameters = Vec::new();
    if let Some(mode) = mode {
        parameters.push(integers(TRAFFIC_MODE, &[mode]));
    }
    if !contexts.is_empty() {
        parameters.push(integers(ROUTING_CONTEXT, contexts));
    }
    message(ASPAC, &parameters)
}

/// ASP Inactive (3.7.3).
pub fn asp_inactive(contexts: &[u32]) -> Vec<u8> {
    with_contexts(ASPIA, contexts, Vec::new())
}

/// Heartbeat or Heartbeat Ack (3.5.5, 3.5.6).
pub fn heartbeat(kind: (u8, u8), data: Option<&[u8]>) -> Vec<u8> {
    let parameters: Vec<Vec<u8>> = data
        .map(|d| parameter(HEARTBEAT_DATA, d))
        .into_iter()
        .collect();
    message(kind, &parameters)
}

/// The Protocol Data parameter (3.3.1): OPC, DPC, SI, NI, MP, SLS and the
/// user protocol data.
pub fn protocol_data(opc: u32, dpc: u32, si: u8, ni: u8, sls: u8, user: &[u8]) -> Vec<u8> {
    let mut value = opc.to_be_bytes().to_vec();
    value.extend_from_slice(&dpc.to_be_bytes());
    value.extend_from_slice(&[si, ni, 0, sls]);
    value.extend_from_slice(user);
    parameter(PROTOCOL_DATA, &value)
}

/// DATA (3.3.1) with an optional Routing Context.
pub fn data(
    context: Option<u32>,
    opc: u32,
    dpc: u32,
    si: u8,
    ni: u8,
    sls: u8,
    user: &[u8],
) -> Vec<u8> {
    let contexts: Vec<u32> = context.into_iter().collect();
    with_contexts(
        DATA,
        &contexts,
        vec![protocol_data(opc, dpc, si, ni, sls, user)],
    )
}

/// The Affected Point Code parameter (3.4.1): a mask octet and a 24-bit point
/// code per entry.
pub fn affected(entries: &[(u8, u32)]) -> Vec<u8> {
    let value: Vec<u8> = entries
        .iter()
        .flat_map(|(mask, pc)| {
            let pc = pc.to_be_bytes();
            [*mask, pc[1], pc[2], pc[3]]
        })
        .collect();
    parameter(AFFECTED, &value)
}

/// DUNA, DAVA, DAUD or DRST (3.4.1 to 3.4.3, 3.4.6).
pub fn ssnm(kind: (u8, u8), contexts: &[u32], entries: &[(u8, u32)]) -> Vec<u8> {
    with_contexts(kind, contexts, vec![affected(entries)])
}

/// SCON (3.4.4): Affected Point Code, Concerned Destination, Congestion
/// Indications.
pub fn scon(contexts: &[u32], pc: u32, concerned: Option<u32>, level: Option<u8>) -> Vec<u8> {
    let mut rest = vec![affected(&[(0, pc)])];
    if let Some(concerned) = concerned {
        rest.push(integers(CONCERNED, &[concerned & 0x00FF_FFFF]));
    }
    if let Some(level) = level {
        rest.push(integers(CONGESTION, &[u32::from(level)]));
    }
    with_contexts(SCON, contexts, rest)
}

/// Notify (3.8.2): Status, then Routing Context.
pub fn notify(status: (u16, u16), contexts: &[u32]) -> Vec<u8> {
    let value = u32::from(status.0) << 16 | u32::from(status.1);
    let mut parameters = vec![integers(STATUS, &[value])];
    if !contexts.is_empty() {
        parameters.push(integers(ROUTING_CONTEXT, contexts));
    }
    message(NTFY, &parameters)
}

/// Error (3.8.1): Error Code, then Routing Context.
pub fn error(code: u32, contexts: &[u32]) -> Vec<u8> {
    let mut parameters = vec![integers(ERROR_CODE, &[code])];
    if !contexts.is_empty() {
        parameters.push(integers(ROUTING_CONTEXT, contexts));
    }
    message(ERR, &parameters)
}

// ── Decoding, from the figures ───────────────────────────────────────────────

/// A message the node sent, read by hand.
#[derive(Debug, Clone)]
pub struct Received {
    pub kind: (u8, u8),
    pub stream: u16,
    pub parameters: Vec<(u16, Vec<u8>)>,
    pub frame: Frame,
}

impl Received {
    /// Read the common header and the parameters. `None` when the octets are
    /// not a well-formed message: the node must not send such.
    pub fn read(frame: Frame) -> Option<Self> {
        let b = &frame.bytes;
        if b.len() < 8 || b[0] != 1 {
            return None;
        }
        let length = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as usize;
        if length != b.len() {
            return None;
        }
        let mut parameters = Vec::new();
        let mut at = 8;
        while at < b.len() {
            let tag = u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]);
            let len = u16::from_be_bytes([*b.get(at + 2)?, *b.get(at + 3)?]) as usize;
            if len < 4 {
                return None;
            }
            parameters.push((tag, b.get(at + 4..at + len)?.to_vec()));
            at += len.div_ceil(4) * 4;
        }
        Some(Self {
            kind: (b[2], b[3]),
            stream: frame.stream,
            parameters,
            frame,
        })
    }

    pub fn is(&self, kind: (u8, u8)) -> bool {
        self.kind == kind
    }

    pub fn value(&self, tag: u16) -> Option<&[u8]> {
        self.parameters
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| v.as_slice())
    }

    /// The 32-bit integers of a parameter.
    pub fn integers(&self, tag: u16) -> Vec<u32> {
        self.value(tag)
            .unwrap_or_default()
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    pub fn contexts(&self) -> Vec<u32> {
        self.integers(ROUTING_CONTEXT)
    }

    pub fn error_code(&self) -> Option<u32> {
        self.integers(ERROR_CODE).first().copied()
    }

    /// The Status of a Notify: type, information.
    pub fn status(&self) -> Option<(u16, u16)> {
        self.integers(STATUS)
            .first()
            .map(|v| ((v >> 16) as u16, *v as u16))
    }

    /// The entries of the Affected Point Code parameter: mask, point code.
    pub fn affected(&self) -> Vec<(u8, u32)> {
        self.integers(AFFECTED)
            .iter()
            .map(|v| ((v >> 24) as u8, v & 0x00FF_FFFF))
            .collect()
    }

    /// The point codes of the Affected Point Code parameter.
    pub fn points(&self) -> Vec<u32> {
        self.affected().iter().map(|(_, pc)| *pc).collect()
    }

    /// Protocol Data: OPC, DPC, SI, NI, SLS and the user data.
    pub fn protocol_data(&self) -> Option<(u32, u32, u8, u8, u8, Vec<u8>)> {
        let v = self.value(PROTOCOL_DATA)?;
        if v.len() < 12 {
            return None;
        }
        Some((
            u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
            u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
            v[8],
            v[9],
            v[11],
            v[12..].to_vec(),
        ))
    }
}

// ── The peer ─────────────────────────────────────────────────────────────────

/// One end of an M3UA association with the node: an ASP that connected to it,
/// or a signalling gateway it connected to.
pub struct Peer {
    pub assoc: Arc<SctpAssociation>,
    /// Everything received from the node, in order.
    pub log: Vec<Frame>,
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

    pub async fn accept(&self) -> Option<Peer> {
        let (assoc, _) = timeout(Duration::from_secs(5), self.listener.accept())
            .await
            .ok()?
            .ok()?;
        Some(Peer {
            assoc: Arc::new(assoc),
            log: Vec::new(),
        })
    }
}

impl Peer {
    /// Connect to a node that listens (the node is the `server`).
    pub async fn connect(addr: SocketAddr) -> Option<Self> {
        let cfg = SctpConfig::new().nodelay(true);
        let assoc = SctpAssociation::connect_with(addr, &cfg).await.ok()?;
        Some(Self {
            assoc: Arc::new(assoc),
            log: Vec::new(),
        })
    }

    /// Send a management message, on stream 0 (1.4.7).
    pub async fn send(&self, bytes: &[u8]) {
        self.send_on(bytes, 0).await;
    }

    /// Send a DATA message, on stream 1.
    pub async fn transfer(&self, bytes: &[u8]) {
        self.send_on(bytes, 1).await;
    }

    pub async fn send_on(&self, bytes: &[u8], stream: u16) {
        self.assoc
            .send(bytes, stream, PPID_M3UA)
            .await
            .expect("send to the node");
    }

    /// The next message from the node within `wait`. One that is not M3UA, or
    /// not well formed, is a test failure.
    pub async fn within(&mut self, wait: Duration) -> Option<Received> {
        let (bytes, info) = timeout(wait, self.assoc.recv()).await.ok()?.ok()?;
        assert_eq!(info.ppid, PPID_M3UA, "payload protocol identifier");
        let frame = Frame {
            bytes,
            stream: info.stream,
            ppid: info.ppid,
        };
        self.log.push(frame.clone());
        Some(Received::read(frame.clone()).unwrap_or_else(|| {
            panic!(
                "the node sent what is not an M3UA message: {:02x?}",
                frame.bytes
            )
        }))
    }

    /// The next message from the node.
    pub async fn next(&mut self) -> Received {
        self.within(NEXT_DEADLINE)
            .await
            .expect("a message from the node")
    }

    /// The next message, which has to be of this type.
    pub async fn expect(&mut self, kind: (u8, u8)) -> Received {
        let got = self.next().await;
        assert_eq!(got.kind, kind, "class and type of {:02x?}", got.frame.bytes);
        got
    }

    /// The next message of this type; whatever comes before it is kept in the
    /// log and passed by.
    pub async fn until(&mut self, kind: (u8, u8)) -> Received {
        loop {
            let got = self.next().await;
            if got.is(kind) {
                return got;
            }
        }
    }

    /// Everything the node sends within `wait`.
    pub async fn drain(&mut self, wait: Duration) -> Vec<Received> {
        let mut out = Vec::new();
        while let Some(got) = self.within(wait).await {
            out.push(got);
        }
        out
    }

    /// The node sends nothing for `wait`.
    pub async fn quiet(&mut self, wait: Duration) {
        if let Some(got) = self.within(wait).await {
            panic!("the node sent {:?}: {:02x?}", got.kind, got.frame.bytes);
        }
    }

    /// Come up as an ASP: ASP Up, its acknowledgement, and the Notify that
    /// says what state each server of `contexts` is in.
    pub async fn up(&mut self, identifier: Option<u32>, contexts: usize) -> Vec<Received> {
        self.send(&asp_up(identifier)).await;
        self.expect(ASPUP_ACK).await;
        let mut notified = Vec::new();
        for _ in 0..contexts {
            notified.push(self.expect(NTFY).await);
        }
        notified
    }

    /// Become active in one server: ASP Active and its acknowledgement.
    pub async fn activate(&mut self, context: u32) -> Received {
        self.send(&asp_active(None, &[context])).await;
        self.expect(ASPAC_ACK).await
    }

    /// Drop the association.
    pub fn close(self) {}
}

/// The frames of some messages, for the Wireshark reader.
pub fn frames(received: &[&Received]) -> Vec<Frame> {
    received.iter().map(|r| r.frame.clone()).collect()
}
