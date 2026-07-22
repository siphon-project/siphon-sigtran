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
use sccp::{
    ExtendedUnitData, GlobalTitle as SccpGt, ReturnCause, SccpAddress, SccpMessage,
    SubsystemNumber, UnitData, UnitDataService,
};
use sua::{GlobalTitle as SuaGt, MessageType as SuaType, RoutingIndicator, SuaAddress, SuaMessage};

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

// ── SUA (RFC 3868) framing + the CLDT ⇄ SCCP-user bridge ─────────────────────
//
// SUA carries the SCCP user (TCAP) with GT/SSN/PC addressing instead of an MTP3
// routing label. A connectionless CLDT interworks one-for-one with an SCCP
// UDT/XUDT (and CLDR with a UDTS), so an inbound CLDT is bridged into an
// [`Msu`] whose payload is the equivalent SCCP message: from there it routes
// through the exact same GTT / content / local-termination engine as
// SCCP-over-M3UA, and an egress to a `sua` AS re-wraps the routed SCCP-user in a
// CLDT. Only the connectionless set is bridged; the connection-oriented set
// (CORE/COAK/CODT/CODA/…) is out of scope, see [`extract_sua`].

/// SCTP Payload Protocol Identifier for SUA (RFC 3868 §1.5 / IANA).
pub const PPID_SUA: u32 = 4;

/// Extract an [`Msu`] from a **SUA CLDT / CLDR** by bridging it to the equivalent
/// SCCP message (UDT/XUDT for a CLDT, UDTS for a CLDR), so the router sees the
/// called party exactly as it would an SCCP UDT arriving over M3UA. `node_pc` is
/// the node's own point code: a GT-routed CLDT is stamped with it (so the router
/// climbs the SCCP/GTT stack), while a route-on-SSN+PC CLDT keeps the addressed
/// point code (so it transits by DPC).
///
/// Errors on any message outside the connectionless set (the connection-oriented
/// CORE/CODT/… are not bridged this phase).
pub fn extract_sua(payload: &[u8], node_pc: u32, node_ni: u8) -> Result<Msu, TransportError> {
    let msg = SuaMessage::decode(payload)?;
    match msg.message_type {
        SuaType::Cldt => cldt_to_msu(&msg, node_pc, node_ni),
        SuaType::Cldr => cldr_to_msu(&msg, node_pc, node_ni),
        other => Err(TransportError::Framing(format!(
            "expected SUA CLDT/CLDR, got {other}"
        ))),
    }
}

/// Bridge a CLDT to an [`Msu`] carrying the equivalent SCCP UDT (or XUDT when the
/// CLDT carries an SS7 hop counter, so the SCCP hop-counter guard applies on a
/// GTT relay exactly as it would for a native XUDT).
fn cldt_to_msu(msg: &SuaMessage, node_pc: u32, node_ni: u8) -> Result<Msu, TransportError> {
    let dest = msg.destination_address()?;
    let src = msg.source_address()?;
    let data = msg.data().unwrap_or(&[]).to_vec();
    let protocol_class = msg.protocol_class().unwrap_or(0);
    let called = sua_addr_to_sccp(&dest);
    let calling = sua_addr_to_sccp(&src);

    let sccp = match msg.ss7_hop_count() {
        Some(hop) => {
            let mut x = ExtendedUnitData::new(called, calling, data);
            x.protocol_class = protocol_class;
            x.hop_counter = hop;
            SccpMessage::Xudt(x)
        }
        None => {
            let mut u = UnitData::new(called, calling, data);
            u.protocol_class = protocol_class;
            SccpMessage::Udt(u)
        }
    };
    Ok(Msu {
        opc: src.point_code.unwrap_or(0),
        dpc: sua_dest_dpc(&dest, node_pc),
        si: SI_SCCP,
        ni: node_ni,
        mp: 0,
        sls: (msg.sequence_control().unwrap_or(0) & 0xFF) as u8,
        payload: sccp.encode()?,
    })
}

/// Bridge a CLDR (connectionless error response) to an [`Msu`] carrying the
/// equivalent SCCP UDTS, mapping the SUA SCCP-Cause value onto the SCCP return
/// cause.
fn cldr_to_msu(msg: &SuaMessage, node_pc: u32, node_ni: u8) -> Result<Msu, TransportError> {
    let dest = msg.destination_address()?;
    let src = msg.source_address()?;
    let data = msg.data().unwrap_or(&[]).to_vec();
    let (_cause_type, cause_value) = msg.sccp_cause().unwrap_or((0, 0));
    let called = sua_addr_to_sccp(&dest);
    let calling = sua_addr_to_sccp(&src);
    let udts = UnitDataService::new(ReturnCause::from_u8(cause_value), called, calling, data);
    Ok(Msu {
        opc: src.point_code.unwrap_or(0),
        dpc: sua_dest_dpc(&dest, node_pc),
        si: SI_SCCP,
        ni: node_ni,
        mp: 0,
        sls: 0,
        payload: SccpMessage::Udts(udts).encode()?,
    })
}

/// The DPC to stamp on the bridged MSU: a route-on-SSN+PC address keeps its
/// point code (transit by DPC), everything else (route-on-GT) is stamped with the
/// node's own PC so the router runs GTT on the called-party global title.
fn sua_dest_dpc(dest: &SuaAddress, node_pc: u32) -> u32 {
    match dest.routing_indicator {
        RoutingIndicator::RouteOnSsnAndPc | RoutingIndicator::RouteOnSsnAndIp => {
            dest.point_code.unwrap_or(node_pc)
        }
        _ => node_pc,
    }
}

/// Wrap an [`Msu`] (whose payload is an SCCP connectionless message) in a **SUA
/// CLDT / CLDR** for an egress `sua` AS, stamping the AS's routing context. A
/// data message (UDT/XUDT/LUDT) becomes a CLDT; a service message
/// (UDTS/XUDTS/LUDTS) becomes a CLDR. SCTP PPID 4.
///
/// SUA carries only the SCCP user, so a non-SCCP MSU (an ISUP `SI=5` transit,
/// say) cannot be framed for SUA; that returns an error the caller logs.
pub fn wrap_sua(msu: &Msu, routing_context: u32) -> Result<Vec<u8>, TransportError> {
    if msu.si != SI_SCCP {
        return Err(TransportError::Framing(format!(
            "sua carries only the SCCP user (SI=3); cannot wrap SI={}",
            msu.si
        )));
    }
    let sccp = SccpMessage::decode(&msu.payload)?;
    let source = sccp_addr_to_sua(sccp.calling_party());
    let destination = sccp_addr_to_sua(sccp.called_party());
    let data = sccp.data().to_vec();
    let seq = msu.sls as u32;

    let msg = match &sccp {
        SccpMessage::Udt(m) => SuaMessage::cldt(
            routing_context,
            m.protocol_class,
            &source,
            &destination,
            seq,
            None,
            data,
        )?,
        SccpMessage::Xudt(m) => SuaMessage::cldt(
            routing_context,
            m.protocol_class,
            &source,
            &destination,
            seq,
            Some(m.hop_counter),
            data,
        )?,
        SccpMessage::Ludt(m) => SuaMessage::cldt(
            routing_context,
            m.protocol_class,
            &source,
            &destination,
            seq,
            Some(m.hop_counter),
            data,
        )?,
        SccpMessage::Udts(m) => SuaMessage::cldr(
            routing_context,
            0,
            m.return_cause.value(),
            &source,
            &destination,
            Some(data),
        )?,
        SccpMessage::Xudts(m) => SuaMessage::cldr(
            routing_context,
            0,
            m.return_cause.value(),
            &source,
            &destination,
            Some(data),
        )?,
        SccpMessage::Ludts(m) => SuaMessage::cldr(
            routing_context,
            0,
            m.return_cause.value(),
            &source,
            &destination,
            Some(data),
        )?,
    };
    Ok(msg.encode())
}

/// Translate an SCCP party address into the equivalent SUA address (calling →
/// source, called → destination). GT-bearing addresses map by GT indicator;
/// a route-on-SSN address (no global title) maps to a route-on-SSN+PC SUA
/// address. The one-for-one shape of the SCCP ⇄ SUA address is what makes the
/// CLDT ⇄ UDT bridge lossless for the GT / SSN / PC fields.
fn sccp_addr_to_sua(addr: &SccpAddress) -> SuaAddress {
    let ssn = addr.ssn.map(|s| s.value());
    let gt = match &addr.global_title {
        SccpGt::Gt0100 {
            translation_type,
            numbering_plan,
            nature_of_address,
            digits,
            ..
        } => Some(SuaGt::new(
            4,
            *translation_type,
            *numbering_plan,
            *nature_of_address,
            digits.clone(),
        )),
        SccpGt::Gt0011 {
            translation_type,
            numbering_plan,
            digits,
            ..
        } => Some(SuaGt::new(
            3,
            *translation_type,
            *numbering_plan,
            0,
            digits.clone(),
        )),
        SccpGt::Gt0010 {
            translation_type,
            digits,
        } => Some(SuaGt::new(2, *translation_type, 0, 0, digits.clone())),
        SccpGt::Gt0001 {
            nature_of_address,
            digits,
            ..
        } => Some(SuaGt::new(1, 0, 0, *nature_of_address, digits.clone())),
        SccpGt::NoTitle => None,
    };
    match gt {
        Some(gt) => {
            let mut out = SuaAddress::with_gt(gt, ssn);
            if let Some(pc) = addr.point_code {
                out.point_code = Some(pc as u32);
                out.include_pc = true;
            }
            out
        }
        None => SuaAddress::with_ssn_pc(
            ssn.unwrap_or(0),
            addr.point_code.map(|p| p as u32).unwrap_or(0),
        ),
    }
}

/// Translate a SUA address back into the equivalent SCCP party address (the
/// reverse of [`sccp_addr_to_sua`]). The SUA global title carries no encoding
/// scheme, so it is recomputed from digit parity per ITU-T Q.713 (odd → 1,
/// even → 2).
fn sua_addr_to_sccp(addr: &SuaAddress) -> SccpAddress {
    let ssn = addr.ssn.map(SubsystemNumber::from_u8);
    match &addr.global_title {
        Some(gt) => {
            let digits = gt.digits.clone();
            let odd = digits.chars().count() % 2 == 1;
            let es = if odd { 1 } else { 2 };
            let sccp_gt = match gt.gti {
                1 => SccpGt::Gt0001 {
                    nature_of_address: gt.nature_of_address,
                    odd_even: odd,
                    digits,
                },
                2 => SccpGt::Gt0010 {
                    translation_type: gt.translation_type,
                    digits,
                },
                3 => SccpGt::Gt0011 {
                    translation_type: gt.translation_type,
                    numbering_plan: gt.numbering_plan,
                    encoding_scheme: es,
                    digits,
                },
                _ => SccpGt::Gt0100 {
                    translation_type: gt.translation_type,
                    numbering_plan: gt.numbering_plan,
                    encoding_scheme: es,
                    nature_of_address: gt.nature_of_address,
                    digits,
                },
            };
            let mut out = SccpAddress::with_gt(sccp_gt, ssn);
            if let Some(pc) = addr.point_code {
                out.point_code = Some(pc as u16);
            }
            out
        }
        None => SccpAddress::with_ssn(
            ssn.unwrap_or(SubsystemNumber::Unknown),
            addr.point_code.map(|p| p as u16),
        ),
    }
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

    // ── SUA CLDT ⇄ SCCP-user bridge ──────────────────────────────────────────

    const NODE_PC: u32 = 1000;

    /// A GT-routed CLDT bridges to an SCCP UDT stamped with the node PC (so the
    /// router runs GTT), and re-wrapping that MSU rebuilds an equivalent CLDT.
    #[test]
    fn sua_cldt_bridges_to_sccp_and_back() {
        let source = SuaAddress::with_gt(SuaGt::e164("15550100"), Some(8));
        let dest = SuaAddress::with_gt(SuaGt::e164("15559999"), Some(6));
        let cldt =
            SuaMessage::cldt(100, 0, &source, &dest, 7, Some(15), vec![0x62, 0x40, 0x01]).unwrap();

        // Inbound: CLDT (with SS7 hop counter) → MSU carrying an SCCP XUDT. The
        // node's configured network indicator (here national = 2) is stamped on it.
        let msu = extract_sua(&cldt.encode(), NODE_PC, 2).unwrap();
        assert_eq!(msu.si, SI_SCCP);
        assert_eq!(msu.ni, 2, "the configured network indicator is stamped");
        assert_eq!(
            msu.dpc, NODE_PC,
            "GT-routed CLDT stamped with node PC for GTT"
        );
        let sccp = SccpMessage::decode(&msu.payload).unwrap();
        assert_eq!(sccp.called_party().global_title.digits(), Some("15559999"));
        assert_eq!(sccp.calling_party().global_title.digits(), Some("15550100"));
        assert_eq!(sccp.data(), &[0x62, 0x40, 0x01]);
        assert_eq!(sccp.hop_counter(), Some(15));

        // Egress: MSU → CLDT again, addresses + data + hop counter preserved.
        let back = SuaMessage::decode(&wrap_sua(&msu, 100).unwrap()).unwrap();
        assert_eq!(back.message_type, SuaType::Cldt);
        assert_eq!(
            back.destination_address().unwrap().gt_digits(),
            Some("15559999")
        );
        assert_eq!(back.source_address().unwrap().gt_digits(), Some("15550100"));
        assert_eq!(back.data(), Some(&[0x62, 0x40, 0x01][..]));
        assert_eq!(back.ss7_hop_count(), Some(15));
        assert_eq!(back.routing_context(), Some(100));
    }

    /// A CLDT without an SS7 hop counter bridges to a plain SCCP UDT.
    #[test]
    fn sua_cldt_without_hop_counter_is_udt() {
        let source = SuaAddress::with_gt(SuaGt::e164("15550100"), Some(8));
        let dest = SuaAddress::with_gt(SuaGt::e164("15559999"), Some(6));
        let cldt = SuaMessage::cldt(1, 0, &source, &dest, 0, None, vec![0xAA]).unwrap();
        let msu = extract_sua(&cldt.encode(), NODE_PC, 0).unwrap();
        assert!(matches!(
            SccpMessage::decode(&msu.payload).unwrap(),
            SccpMessage::Udt(_)
        ));
    }

    /// A route-on-SSN+PC CLDT keeps its addressed point code (transit by DPC).
    #[test]
    fn sua_ssn_pc_cldt_transits_by_dpc() {
        let source = SuaAddress::with_ssn_pc(8, 1000);
        let dest = SuaAddress::with_ssn_pc(6, 2000);
        let cldt = SuaMessage::cldt(1, 0, &source, &dest, 0, None, vec![0xAB, 0xCD]).unwrap();
        let msu = extract_sua(&cldt.encode(), NODE_PC, 0).unwrap();
        assert_eq!(
            msu.dpc, 2000,
            "route-on-PC CLDT transits to the addressed DPC"
        );
    }

    /// The connection-oriented set is not bridged.
    #[test]
    fn extract_sua_rejects_non_connectionless() {
        let aspup = SuaMessage::asp_up(None, None).encode();
        assert!(extract_sua(&aspup, NODE_PC, 0).is_err());
    }

    /// SUA cannot carry a non-SCCP user part.
    #[test]
    fn wrap_sua_rejects_non_sccp() {
        let mut msu = sample();
        msu.si = SI_ISUP;
        assert!(wrap_sua(&msu, 100).is_err());
    }
}
