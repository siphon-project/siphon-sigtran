//! MSU framing: the boundary between an SCTP payload and the MTP3 routing layer.
//!
//! Inbound, we extract the Q.704 routing label (OPC/DPC/SLS/SI/NI) and the
//! MTP3-user payload from either an **M3UA DATA** message (the Protocol Data
//! parameter, RFC 4666 §3.3.1) or an **M2PA User Data** message carrying a
//! hand-rolled MTP3 MSU (RFC 4165 §3.2). Outbound, we wrap an [`Msu`] for the
//! egress transport again.
//!
//! # Point-code width
//!
//! M3UA carries OPC/DPC as 32-bit fields, so that path is variant-independent.
//! The M2PA MSU routing label is packed to a specific width; this module packs
//! the **ITU 14-bit** layout (14-bit PCs, 4-bit SLS), the same layout the codec
//! crates' point codes use for ITU. ANSI (24-bit) M2PA MSUs are not framed yet;
//! [`wrap_m2pa`] / [`extract_m2pa`] assume ITU. The M3UA path has no such limit.

use m2pa::{M2paMessage, UserDataMessage};
use m3ua::{M3uaMessage, MessageType, ProtocolData};

use super::TransportError;

/// SCCP Service Indicator (ITU-T Q.704 Table 1): `SI = 3`.
pub const SI_SCCP: u8 = 3;

/// A decoded MSU at the MTP3-user boundary: the routing label plus the payload.
///
/// This is what a relay reads to route by DPC and what it re-wraps for the
/// egress transport. The `si`/`ni` are preserved so a non-SCCP user part (ISUP
/// `SI=5`, network management, …) transits with its Service Indicator intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msu {
    /// Originating Point Code (value; variant is the node's).
    pub opc: u32,
    /// Destination Point Code (value).
    pub dpc: u32,
    /// Service Indicator (SCCP = 3, ISUP = 5, …).
    pub si: u8,
    /// Network Indicator (international / national).
    pub ni: u8,
    /// Message priority (ANSI/China; ITU ignores it).
    pub mp: u8,
    /// Signalling Link Selection.
    pub sls: u8,
    /// The MTP3-user payload (e.g. the encoded SCCP message).
    pub payload: Vec<u8>,
}

/// Extract an [`Msu`] from an **M3UA DATA** message. Errors if the message is
/// not a DATA (an ASPSM/ASPTM/SSNM message reached here by mistake).
pub fn extract_m3ua(payload: &[u8]) -> Result<Msu, TransportError> {
    let msg = M3uaMessage::decode(payload)?;
    if msg.message_type != MessageType::Data {
        return Err(TransportError::Framing(format!(
            "expected M3UA DATA, got {}",
            msg.message_type
        )));
    }
    let pd = msg.protocol_data()?;
    Ok(Msu {
        opc: pd.opc,
        dpc: pd.dpc,
        si: pd.si,
        ni: pd.ni,
        mp: pd.mp,
        sls: pd.sls,
        payload: pd.user_data,
    })
}

/// Extract an [`Msu`] from an **M2PA User Data** message. Returns `Ok(None)` for
/// a Link Status message (alignment, handled elsewhere).
pub fn extract_m2pa(payload: &[u8]) -> Result<Option<Msu>, TransportError> {
    match M2paMessage::decode(payload)? {
        M2paMessage::UserData { message, .. } => Ok(Some(parse_itu_msu(&message.msu)?)),
        M2paMessage::LinkStatus { .. } => Ok(None),
    }
}

/// Wrap an [`Msu`] in an **M3UA DATA** message with an optional routing context
/// (an AS's, for the egress ASP). SCTP stream 1, PPID 3.
pub fn wrap_m3ua(msu: &Msu, routing_context: Option<u32>) -> Vec<u8> {
    let pd = ProtocolData::new(
        msu.opc,
        msu.dpc,
        msu.si,
        msu.ni,
        msu.mp,
        msu.sls,
        msu.payload.clone(),
    );
    M3uaMessage::data(None, routing_context, pd, None).encode()
}

/// Wrap an [`Msu`] in an **M2PA User Data** message carrying a hand-rolled ITU
/// MTP3 MSU. SCTP stream 1, PPID 5. BSN/FSN idle (`0xFFFFFF`).
pub fn wrap_m2pa(msu: &Msu) -> Result<Vec<u8>, TransportError> {
    let raw = build_itu_msu(msu);
    M2paMessage::UserData {
        bsn: 0xFF_FFFF,
        fsn: 0xFF_FFFF,
        message: UserDataMessage::new(msu.mp, raw),
    }
    .encode()
    .map_err(TransportError::from)
}

/// Build the ITU-14-bit Q.704 MSU bytes for an [`Msu`]: SIO + 32-bit routing
/// label (little-endian: DPC[0..14] OPC[14..28] SLS[28..32]) + SIF.
fn build_itu_msu(msu: &Msu) -> Vec<u8> {
    let sio = ((msu.ni & 0x03) << 6) | (msu.si & 0x0F);
    let label: u32 =
        (msu.dpc & 0x3FFF) | ((msu.opc & 0x3FFF) << 14) | (((msu.sls as u32) & 0x0F) << 28);
    let mut out = Vec::with_capacity(5 + msu.payload.len());
    out.push(sio);
    out.extend_from_slice(&label.to_le_bytes());
    out.extend_from_slice(&msu.payload);
    out
}

/// Parse the ITU-14-bit MSU bytes back into an [`Msu`].
fn parse_itu_msu(raw: &[u8]) -> Result<Msu, TransportError> {
    if raw.len() < 5 {
        return Err(TransportError::Framing(format!(
            "MTP3 MSU too short: {} bytes",
            raw.len()
        )));
    }
    let sio = raw[0];
    let si = sio & 0x0F;
    let ni = (sio >> 6) & 0x03;
    let label = u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]);
    let dpc = label & 0x3FFF;
    let opc = (label >> 14) & 0x3FFF;
    let sls = ((label >> 28) & 0x0F) as u8;
    Ok(Msu {
        opc,
        dpc,
        si,
        ni,
        mp: 0,
        sls,
        payload: raw[5..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Msu {
        Msu {
            opc: 4107,
            dpc: 8209,
            si: SI_SCCP,
            ni: 0,
            mp: 0,
            sls: 7,
            payload: vec![0x09, 0x81, 0x03, 0x0e, 0x19],
        }
    }

    #[test]
    fn m3ua_wrap_extract_round_trip() {
        let msu = sample();
        let bytes = wrap_m3ua(&msu, Some(100));
        let back = extract_m3ua(&bytes).unwrap();
        assert_eq!(back, msu);
    }

    #[test]
    fn m2pa_wrap_extract_round_trip() {
        let msu = sample();
        let bytes = wrap_m2pa(&msu).unwrap();
        let back = extract_m2pa(&bytes).unwrap().expect("user data");
        assert_eq!(back, msu);
    }

    #[test]
    fn m2pa_link_status_extracts_none() {
        use m2pa::{LinkState, LinkStatusMessage};
        let ls = M2paMessage::LinkStatus {
            bsn: 0xFF_FFFF,
            fsn: 0xFF_FFFF,
            message: LinkStatusMessage::new(LinkState::Ready),
        }
        .encode()
        .unwrap();
        assert_eq!(extract_m2pa(&ls).unwrap(), None);
    }

    #[test]
    fn si_is_preserved_for_non_sccp() {
        // ISUP (SI=5) must transit with its Service Indicator intact.
        let mut msu = sample();
        msu.si = 5;
        let back = extract_m2pa(&wrap_m2pa(&msu).unwrap()).unwrap().unwrap();
        assert_eq!(back.si, 5);
        let back3 = extract_m3ua(&wrap_m3ua(&msu, None)).unwrap();
        assert_eq!(back3.si, 5);
    }

    #[test]
    fn extract_m3ua_rejects_non_data() {
        let aspup = M3uaMessage::asp_up(None, None).encode();
        assert!(extract_m3ua(&aspup).is_err());
    }
}
