//! MSU framing: the boundary between an SCTP payload and the MTP3 routing layer.
//!
//! Inbound, we extract the Q.704 routing label (OPC/DPC/SLS/SI/NI) and the
//! MTP3-user payload from either an **M3UA DATA** message (the Protocol Data
//! parameter, RFC 4666 §3.3.1) or an **M2PA User Data** message carrying an
//! MTP3 MSU (RFC 4165 §3.2). Outbound, we wrap an [`Msu`] for the egress
//! transport again.
//!
//! # Point-code width
//!
//! M3UA carries OPC/DPC as 32-bit fields, so that path is variant-independent.
//! The M2PA MSU routing label has a variant-specific width; the `mtp3` crate's
//! [`Mtp3Msu`] codec owns that layout. This module frames the **ITU 14-bit**
//! variant (14-bit PCs, 4-bit SLS). ANSI (24-bit) M2PA MSUs are not framed yet;
//! [`wrap_m2pa`] / [`extract_m2pa`] pass [`Variant::Itu`]. The M3UA path has no
//! such limit.

use m2pa::{M2paMessage, UserDataMessage};
use m3ua::{M3uaMessage, MessageType, ProtocolData};
use mtp3::{Mtp3Msu, NetworkIndicator, PointCode, ServiceIndicator, Variant};

use super::TransportError;

/// SCCP Service Indicator (ITU-T Q.704 Table 1): `SI = 3`.
pub const SI_SCCP: u8 = 3;

/// ISUP Service Indicator (ITU-T Q.704 Table 1): `SI = 5`. The transit path
/// decodes this only when a tenant has ISUP screening configured.
pub const SI_ISUP: u8 = 5;

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
        M2paMessage::UserData { message, .. } => {
            let m = Mtp3Msu::decode(&message.msu, Variant::Itu)
                .map_err(|e| TransportError::Framing(e.to_string()))?;
            Ok(Some(Msu {
                opc: m.opc.value(),
                dpc: m.dpc.value(),
                si: m.si.0,
                ni: m.ni.bits(),
                mp: m.mp,
                sls: m.sls,
                payload: m.data,
            }))
        }
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

/// Wrap an [`Msu`] in an **M2PA User Data** message carrying an ITU MTP3 MSU
/// (encoded by [`Mtp3Msu`]). SCTP stream 1, PPID 5. BSN/FSN idle (`0xFFFFFF`).
pub fn wrap_m2pa(msu: &Msu) -> Result<Vec<u8>, TransportError> {
    let raw = Mtp3Msu {
        si: ServiceIndicator(msu.si),
        ni: NetworkIndicator::from_bits(msu.ni),
        mp: msu.mp,
        opc: itu_pc(msu.opc)?,
        dpc: itu_pc(msu.dpc)?,
        sls: msu.sls,
        data: msu.payload.clone(),
    }
    .encode(Variant::Itu);
    M2paMessage::UserData {
        bsn: 0xFF_FFFF,
        fsn: 0xFF_FFFF,
        message: UserDataMessage::new(msu.mp, raw),
    }
    .encode()
    .map_err(TransportError::from)
}

/// Build an ITU point code from a routing-label value, masking to the 14-bit
/// field (the ITU M2PA layout carries 14 bits, so a wider value can't be framed).
fn itu_pc(value: u32) -> Result<PointCode, TransportError> {
    PointCode::from_value(value & 0x3FFF, Variant::Itu)
        .map_err(|e| TransportError::Framing(e.to_string()))
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
