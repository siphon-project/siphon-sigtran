//! The per-message pipeline: an inbound [`Msu`] becomes a routing decision and
//! is acted on (forwarded to the resolved egress, delivered locally, or dropped
//! with a logged reason).

use sccp::{
    ExtendedUnitDataService, GlobalTitle, LongUnitDataService, ReturnCause, SccpMessage,
    UnitDataService,
};

use super::framing::{self, Msu};
use super::{LocalDelivery, Registry, TaskCtx};
use crate::config::Adaptation;
use crate::isup::{IsupScreen, Screened};
use crate::metrics::{self, LoopKind, Mtp3Discard};
use crate::mtp3::route::Destination;
use crate::routing::{Inbound, RouteDecision};
use crate::sccp::gtt::GttSelector;

/// SCTP stream for M3UA management/data here (we use stream 1 for DATA and
/// stream 0 for the ASPSM/SSNM control messages, matching the peers we drive).
const M3UA_DATA_STREAM: u16 = 1;
const SUA_DATA_STREAM: u16 = 1;
const PPID_M3UA: u32 = 3;
const PPID_SUA: u32 = 4;
/// The service indicator of signalling network management (Q.704 14.2.1).
const SI_MANAGEMENT: u8 = 0;

/// Build the router [`Inbound`] from an MSU. The DPC alone routes a transit MSU
/// of any Service Indicator; only an SCCP MSU (`SI=3`) is decoded further so
/// GTT / content / local-termination can see the called party.
pub fn inbound_from_msu(msu: &Msu) -> Inbound {
    let mut inbound = Inbound {
        dpc: msu.dpc,
        ..Default::default()
    };
    if msu.si == framing::SI_SCCP {
        // Any connectionless type (UDT/UDTS/XUDT/XUDTS/LUDT/LUDTS) exposes the
        // called party the same way, so GTT sees the extended/long messages too.
        if let Ok(sccp) = SccpMessage::decode(&msu.payload) {
            let called = sccp.called_party();
            inbound.called_ssn = called.ssn.as_ref().map(|s| s.value());
            if called.global_title.digits().is_some() {
                inbound.cdpa = Some(selector_from_gt(&called.global_title));
            }
        }
    }
    inbound
}

/// Map an SCCP Global Title into the GTT selector fields the resolver matches on.
fn selector_from_gt(gt: &GlobalTitle) -> GttSelector {
    let digits = gt.digits().unwrap_or_default().to_string();
    match gt {
        GlobalTitle::Gt0100 {
            translation_type,
            numbering_plan,
            nature_of_address,
            ..
        } => GttSelector {
            digits,
            gti: Some(4),
            tt: Some(*translation_type),
            np: Some(*numbering_plan),
            nai: Some(*nature_of_address),
        },
        GlobalTitle::Gt0011 {
            translation_type,
            numbering_plan,
            ..
        } => GttSelector {
            digits,
            gti: Some(3),
            tt: Some(*translation_type),
            np: Some(*numbering_plan),
            nai: None,
        },
        GlobalTitle::Gt0010 {
            translation_type, ..
        } => GttSelector {
            digits,
            gti: Some(2),
            tt: Some(*translation_type),
            np: None,
            nai: None,
        },
        GlobalTitle::Gt0001 {
            nature_of_address, ..
        } => GttSelector {
            digits,
            gti: Some(1),
            tt: None,
            np: None,
            nai: Some(*nature_of_address),
        },
        GlobalTitle::NoTitle => GttSelector::from_digits(digits),
    }
}

/// Stamp new called-party GT digits on a connectionless SCCP message (UDT / XUDT
/// / LUDT), preserving the GT indicator / TT / NP / NAI and the SSN, for a content
/// rule's `rewrite_cdpa_gt`. Returns the re-encoded payload, or `None` if the
/// message is not a rewritable type or fails to re-encode.
fn rewrite_called_gt(payload: &[u8], digits: &str) -> Option<Vec<u8>> {
    let mut msg = SccpMessage::decode(payload).ok()?;
    let rewritten = match &mut msg {
        SccpMessage::Udt(m) => set_gt_digits(&mut m.called_party.global_title, digits),
        SccpMessage::Xudt(m) => set_gt_digits(&mut m.called_party.global_title, digits),
        SccpMessage::Ludt(m) => set_gt_digits(&mut m.called_party.global_title, digits),
        _ => false,
    };
    if !rewritten {
        return None;
    }
    msg.encode().ok()
}

/// Replace a Global Title's digits in place, keeping every other field. Returns
/// `false` for a `NoTitle` address (nothing to rewrite).
fn set_gt_digits(gt: &mut GlobalTitle, new: &str) -> bool {
    let slot = match gt {
        GlobalTitle::Gt0001 { digits, .. } => digits,
        GlobalTitle::Gt0010 { digits, .. } => digits,
        GlobalTitle::Gt0011 { digits, .. } => digits,
        GlobalTitle::Gt0100 { digits, .. } => digits,
        GlobalTitle::NoTitle => return false,
    };
    *slot = new.to_string();
    true
}

/// Route one inbound MSU and act on the decision. `inbound_assoc` is the id of
/// the association the MSU arrived on; it feeds the route-reflect loop guard.
pub async fn dispatch(msu: Msu, ctx: &TaskCtx, inbound_assoc: &str) {
    // Count every inbound MSU by Service Indicator (fixed-array atomic, no alloc).
    metrics::msu(metrics::Dir::Rx, msu.si);

    // Loop guard 1 (own-OPC): a message whose OPC is our own point code is one
    // we originated coming back to us. Drop it before it can loop.
    let node_pc = ctx.router.node_point_code(&ctx.tenant);
    if let Some(our_pc) = node_pc {
        if msu.opc == our_pc {
            metrics::record_loop(LoopKind::OwnOpc);
            eprintln!(
                "siphon-sigtran: loop dropped (own-opc): OPC {} == node PC, DPC {} SI {} in on {inbound_assoc}",
                msu.opc, msu.dpc, msu.si
            );
            return;
        }
    }

    // The AS / linkset the MSU arrived over, for the route-reflect guard.
    let inbound_src = ctx.registry.inbound_destination(inbound_assoc);

    let mut inbound = inbound_from_msu(&msu);
    // Content routing needs the decoded application layer. Decode it only when the
    // tenant actually has content rules, so a pure-transit node pays nothing.
    if msu.si == framing::SI_SCCP && ctx.router.tenant_has_content_rules(&ctx.tenant) {
        if let Ok(sccp) = SccpMessage::decode(&msu.payload) {
            use crate::content::Screening;
            match crate::content::screen(&sccp) {
                Screening::View(view) => inbound.view = Some(view),
                // Dropped by the router where the rules would have applied.
                Screening::Undecodable => inbound.content_undecodable = true,
                // One segment of a segmented message: not reassembled here, so
                // not evaluated. Counted, so it is visible that it was not.
                Screening::Segmented => metrics::content_segment_unscreened(),
                Screening::NotApplicable => {}
            }
        }
    }
    // The signalling link selection of the label picks among routes of equal
    // priority (Q.704 2.3.2 b).
    match ctx.router.route_for(&ctx.tenant, &inbound, msu.sls) {
        RouteDecision::Route { via } => {
            // ISUP screening on the SI=5 transit path (opt-in per tenant). Only an
            // SI=5 MSU consults `isup_screen`; every other Service Indicator (the
            // SCCP hot path included) pays just this compare, and a tenant with no
            // screening block returns `None` here, so transit stays unchanged.
            if msu.si == framing::SI_ISUP {
                if let Some(screen) = ctx.router.isup_screen(&ctx.tenant) {
                    if apply_isup_screen(screen, &msu, inbound_assoc) {
                        return;
                    }
                }
            }
            if is_reflection(inbound_src.as_ref(), &via) {
                loop_reflect(&via, &msu, inbound_assoc);
                // The point it came from is the one this node routes it
                // through: it is not transferred, and that point is told
                // (Q.704 13.2.2 iii, the response method).
                ctx.registry.unroutable(msu.dpc, inbound_assoc);
                return;
            }
            send_via(&via, &msu, &ctx.registry).await
        }
        RouteDecision::RouteTo {
            dpc,
            via: Some(via),
            rewrite_cdpa_gt,
            ..
        } => {
            if is_reflection(inbound_src.as_ref(), &via) {
                loop_reflect(&via, &msu, inbound_assoc);
                return;
            }
            // A GTT / content result to a concrete DPC is an SCCP relay point, so
            // apply the SCCP hop counter (the standard GTT loop breaker) before
            // relaying. It decrements XUDT/LUDT and drops + returns a violation at
            // zero.
            let payload = match hop_counter_guard(&msu, ctx, inbound_src.as_ref()).await {
                HopGuard::Forward(payload) => payload,
                HopGuard::Exhausted => return,
            };
            let mut out = msu.clone();
            out.dpc = dpc;
            out.payload = payload;
            // A content rule's `rewrite_cdpa_gt` stamps new called-party GT digits
            // on the egress SCCP before relay; a re-encode failure forwards the
            // message unchanged rather than dropping a good one.
            if let Some(gt) = &rewrite_cdpa_gt {
                match rewrite_called_gt(&out.payload, gt) {
                    Some(rewritten) => out.payload = rewritten,
                    None => eprintln!(
                        "siphon-sigtran: rewrite_cdpa_gt re-encode failed, forwarding unchanged"
                    ),
                }
            }
            send_via(&via, &out, &ctx.registry).await;
        }
        RouteDecision::RouteTo { dpc, via: None, .. } => {
            eprintln!("siphon-sigtran: no MTP3 route to translated DPC {dpc}, returning on error");
            return_undeliverable(&msu, ReturnCause::MtpFailure, ctx, inbound_src.as_ref()).await;
        }
        RouteDecision::Local => {
            // Local termination: hand the MSU (and the association it arrived on,
            // for the reply path) to the dialogue SAP over the local-delivery
            // channel.
            let _ = ctx
                .local_tx
                .send(LocalDelivery {
                    msu,
                    ingress_assoc: inbound_assoc.to_string(),
                })
                .await;
        }
        RouteDecision::CrossTenant { tenant, .. } => {
            eprintln!(
                "siphon-sigtran: cross-tenant hand-off to `{tenant}` not wired on the transport \
                 yet, returning on error"
            );
            return_undeliverable(&msu, ReturnCause::SccpFailure, ctx, inbound_src.as_ref()).await;
        }
        RouteDecision::Drop { reason } => {
            eprintln!("siphon-sigtran: dropping MSU to {}: {reason}", msu.dpc);
            // Q.704 2.4.1: "When a signalling transfer point detects that a
            // received message cannot be delivered to its destination point,
            // it sends in response a transfer-prohibited message as specified
            // in 13.2." A message for this node itself is not a transfer.
            if node_pc.is_some_and(|pc| pc != msu.dpc) {
                metrics::mtp3_discard(Mtp3Discard::NoRoute, 1);
                ctx.registry.unroutable(msu.dpc, inbound_assoc);
            }
            return_undeliverable(
                &msu,
                ReturnCause::NoTranslationForAddress,
                ctx,
                inbound_src.as_ref(),
            )
            .await;
        }
    }
}

/// Whether a resolved egress would send the MSU straight back out the same
/// AS / linkset it arrived on (route reflection).
fn is_reflection(inbound_src: Option<&Destination>, via: &Destination) -> bool {
    inbound_src == Some(via)
}

/// Count and log a dropped route-reflection loop.
fn loop_reflect(via: &Destination, msu: &Msu, inbound_assoc: &str) {
    metrics::record_loop(LoopKind::RouteReflect);
    eprintln!(
        "siphon-sigtran: loop dropped (route-reflect): egress {via} == inbound {inbound_assoc}, \
         OPC {} DPC {} SI {}",
        msu.opc, msu.dpc, msu.si
    );
}

/// Screen a transiting ISUP MSU (SI=5) against the tenant's rules. Returns `true`
/// if the message was screened (dropped, counted under
/// `sigtran_isup_screened_total`, and logged), `false` if it should transit. A
/// decode failure never crashes the path: it takes the tenant's configured
/// default action, and either outcome is logged (a malformed ISUP frame is never
/// passed or dropped silently).
fn apply_isup_screen(screen: &IsupScreen, msu: &Msu, inbound_assoc: &str) -> bool {
    let verdict = screen.screen(&msu.payload);
    if let Some(reason) = verdict.reason() {
        metrics::record_isup_screened(reason);
    }
    match verdict {
        Screened::Pass => false,
        Screened::PassUndecoded { error } => {
            eprintln!(
                "siphon-sigtran: isup screen could not decode SI=5 MSU \
                 (OPC {} DPC {} in on {inbound_assoc}): {error}; passing per default allow",
                msu.opc, msu.dpc
            );
            false
        }
        Screened::BlockRule { rule } => {
            eprintln!(
                "siphon-sigtran: isup screened (drop): rule `{rule}`, OPC {} DPC {} SI {} in on {inbound_assoc}",
                msu.opc, msu.dpc, msu.si
            );
            true
        }
        Screened::BlockDefault => {
            eprintln!(
                "siphon-sigtran: isup screened (drop): default action, OPC {} DPC {} SI {} in on {inbound_assoc}",
                msu.opc, msu.dpc, msu.si
            );
            true
        }
        Screened::BlockUndecoded { error } => {
            eprintln!(
                "siphon-sigtran: isup screened (drop): undecodable SI=5 MSU per default block \
                 (OPC {} DPC {} in on {inbound_assoc}): {error}",
                msu.opc, msu.dpc
            );
            true
        }
    }
}

/// SCCP "return message on error" message-handling value (Q.713): the originator
/// asks for a UDTS/XUDTS back when the message cannot be delivered.
const SCCP_RETURN_ON_ERROR: u8 = 0x8;

/// Outcome of the SCCP hop-counter guard on the GTT / content-translation relay.
enum HopGuard {
    /// Forward the message with this SCCP payload (hop counter decremented, or
    /// unchanged for a message that carries no hop counter).
    Forward(Vec<u8>),
    /// The hop counter was exhausted: the message was dropped and counted, and a
    /// violation return was sent if it asked to be returned on error.
    Exhausted,
}

/// Apply the SCCP hop counter at a global-title translation (Q.713 §4 / Q.714).
///
/// XUDT/LUDT carry a hop counter that a translating node decrements; when it
/// reaches zero the message is a routing loop and is discarded (and returned as
/// XUDTS/LUDTS "hop counter violation" when the return option is set). This is
/// the standard GTT loop breaker two nodes ping-ponging a global title would
/// otherwise never escape. UDT/UDTS carry no hop counter, and other Service
/// Indicators are not SCCP at all, so those loops are caught by the MTP3 own-OPC
/// and route-reflect guards instead; both forward unchanged here.
async fn hop_counter_guard(
    msu: &Msu,
    ctx: &TaskCtx,
    inbound_src: Option<&Destination>,
) -> HopGuard {
    if msu.si != framing::SI_SCCP {
        return HopGuard::Forward(msu.payload.clone());
    }
    let mut sccp = match SccpMessage::decode(&msu.payload) {
        Ok(m) => m,
        Err(_) => return HopGuard::Forward(msu.payload.clone()),
    };
    let Some(hop) = sccp.hop_counter() else {
        return HopGuard::Forward(msu.payload.clone());
    };

    let remaining = hop.saturating_sub(1);
    if remaining != 0 {
        set_hop_counter(&mut sccp, remaining);
        return match sccp.encode() {
            Ok(bytes) => HopGuard::Forward(bytes),
            // Re-encoding a message we just decoded should not fail; if it
            // somehow does, forward the original rather than drop a good message.
            Err(e) => {
                eprintln!("siphon-sigtran: hop-counter re-encode failed ({e}), forwarding as-is");
                HopGuard::Forward(msu.payload.clone())
            }
        };
    }

    // Exhausted → routing loop. Drop, count, and return a violation if asked.
    metrics::record_loop(LoopKind::HopCounter);
    eprintln!(
        "siphon-sigtran: loop dropped (hop-counter): OPC {} DPC {} exhausted at GTT",
        msu.opc, msu.dpc
    );
    if let Some(src) = inbound_src {
        let our_pc = ctx.router.node_point_code(&ctx.tenant);
        if let Some(ret) = sccp_return(msu, &sccp, ReturnCause::HopCounterViolation, our_pc) {
            send_via(src, &ret, &ctx.registry).await;
        }
    }
    HopGuard::Exhausted
}

/// Set the hop counter on the SCCP types that carry one; a no-op for UDT/UDTS.
fn set_hop_counter(msg: &mut SccpMessage, hop: u8) {
    match msg {
        SccpMessage::Xudt(m) => m.hop_counter = hop,
        SccpMessage::Xudts(m) => m.hop_counter = hop,
        SccpMessage::Ludt(m) => m.hop_counter = hop,
        SccpMessage::Ludts(m) => m.hop_counter = hop,
        SccpMessage::Udt(_) | SccpMessage::Udts(_) => {}
    }
}

/// Build an SCCP return (UDTS / XUDTS / LUDTS) for a connectionless message that
/// could not be delivered, addressed back to the originator (called / calling
/// swapped) and carrying `cause`. `our_pc` is the node's point code in the tenant
/// (the return's OPC). Returns `None` when the message did not ask to be returned
/// on error, or is itself a service message (a return is never returned). This is
/// the Q.714 "always answer an undeliverable SCCP message" seam.
fn sccp_return(
    inbound: &Msu,
    sccp: &SccpMessage,
    cause: ReturnCause,
    our_pc: Option<u32>,
) -> Option<Msu> {
    let return_on_error = match sccp {
        SccpMessage::Udt(m) => m.message_handling == SCCP_RETURN_ON_ERROR,
        SccpMessage::Xudt(m) => m.message_handling == SCCP_RETURN_ON_ERROR,
        SccpMessage::Ludt(m) => m.message_handling == SCCP_RETURN_ON_ERROR,
        SccpMessage::Udts(_) | SccpMessage::Xudts(_) | SccpMessage::Ludts(_) => false,
    };
    if !return_on_error {
        return None;
    }

    // The return goes back to the original calling party, from the called party.
    let to = sccp.calling_party().clone();
    let from = sccp.called_party().clone();
    let data = sccp.data().to_vec();
    let payload = match sccp {
        SccpMessage::Ludt(_) => SccpMessage::Ludts(LongUnitDataService::new(cause, to, from, data)),
        SccpMessage::Xudt(_) => {
            SccpMessage::Xudts(ExtendedUnitDataService::new(cause, to, from, data))
        }
        _ => SccpMessage::Udts(UnitDataService::new(cause, to, from, data)),
    }
    .encode()
    .ok()?;

    // We originate the return: OPC is our own point code, DPC is whoever sent it
    // to us; SLS / NI / MP mirror the inbound so it follows the same path back.
    let opc = our_pc.unwrap_or(inbound.dpc);
    Some(Msu {
        opc,
        dpc: inbound.opc,
        si: inbound.si,
        ni: inbound.ni,
        mp: inbound.mp,
        sls: inbound.sls,
        payload,
    })
}

/// Answer an undeliverable inbound SCCP message with an SCCP return carrying
/// `cause`, back over the association it arrived on, when the originator asked to
/// be returned on error. A no-op for non-SCCP, an undecodable payload, or a
/// message with no return option. Keeps the "always answer" invariant on the SCCP
/// drop paths (no translation, no route, cross-tenant, deferred-to-Python).
async fn return_undeliverable(
    msu: &Msu,
    cause: ReturnCause,
    ctx: &TaskCtx,
    inbound_src: Option<&Destination>,
) {
    if msu.si != framing::SI_SCCP {
        return;
    }
    let Some(src) = inbound_src else { return };
    let Ok(sccp) = SccpMessage::decode(&msu.payload) else {
        return;
    };
    let our_pc = ctx.router.node_point_code(&ctx.tenant);
    if let Some(ret) = sccp_return(msu, &sccp, cause, our_pc) {
        send_via(src, &ret, &ctx.registry).await;
    }
}

/// Forward an MSU on a resolved [`Destination`]'s egress association(s). Takes
/// the [`Registry`] directly (not the whole [`TaskCtx`]) so the origination path
/// — which routes an originated `Begin` by DPC without an inbound context — can
/// reuse the same egress selection + framing as the transfer path.
///
/// A message for a destination whose traffic is held for controlled rerouting
/// (Q.704 8.2.1 a) goes into that buffer instead, and leaves by the routing as
/// it is when T6 runs out.
pub(crate) async fn send_via(via: &Destination, msu: &Msu, registry: &Registry) {
    if registry.hold_if_rerouting(msu) {
        return;
    }
    send_now(via, msu, registry).await;
}

/// [`send_via`] for a message that is not to be held.
async fn send_now(via: &Destination, msu: &Msu, registry: &Registry) {
    // An M2PA link numbers and sends its own User Data: hand the MSU to the
    // link, which counts it when it goes out.
    if let Destination::Linkset(name) = via {
        match registry.select_link(name, msu.sls) {
            Some(slot) => send_on_link(slot, msu),
            None => no_egress(via, msu),
        }
        return;
    }
    // Signalling network management does not go to an ASP as DATA (RFC 4666
    // 1.4.3.2): what has an M3UA message of its own is sent as that.
    if msu.si == SI_MANAGEMENT {
        super::m3ua::management_for_server(via.name(), msu, registry).await;
        return;
    }
    let selected = registry.select(via, msu.sls);
    if selected.is_empty() {
        // A server whose last active ASP just left is pending: its traffic
        // waits for T(r) (RFC 4666 4.3.2).
        if !registry.queue_if_pending(via.name(), msu) {
            no_egress(via, msu);
        }
        return;
    }
    for sel in selected {
        // An Application Server is served by M3UA or SUA ASPs; the egress
        // framing follows the selected association's adaptation (M3UA DATA on
        // a point-code routing label, or a SUA CLDT wrapping the SCCP user).
        let (bytes, stream, ppid) = match sel.adaptation {
            Adaptation::M3ua => (
                framing::wrap_m3ua(msu, sel.routing_context),
                M3UA_DATA_STREAM,
                PPID_M3UA,
            ),
            Adaptation::Sua => match framing::wrap_sua(msu, sel.routing_context.unwrap_or(0)) {
                Ok(b) => (b, SUA_DATA_STREAM, PPID_SUA),
                Err(e) => {
                    eprintln!("siphon-sigtran: sua framing failed: {e}");
                    continue;
                }
            },
            Adaptation::M2pa => {
                eprintln!(
                    "siphon-sigtran: application-server egress selected an m2pa association (invalid config), dropping"
                );
                continue;
            }
        };
        if let Err(e) = sel.assoc.send(&bytes, stream, ppid).await {
            eprintln!("siphon-sigtran: egress send on {via} failed: {e}");
        } else {
            metrics::msu(metrics::Dir::Tx, msu.si);
        }
    }
}

/// A route was chosen and nothing on it carries traffic: counted and logged.
fn no_egress(via: &Destination, msu: &Msu) {
    metrics::mtp3_discard(Mtp3Discard::NoEgress, 1);
    eprintln!(
        "siphon-sigtran: no active egress for {via} (dpc {}), message dropped",
        msu.dpc
    );
}

/// Send what was held for a destination during controlled rerouting, by the
/// routing as it now is (Q.704 8.2.1 c: "starting with the content of the
/// controlled rerouting buffer"), until the buffer is found empty.
pub(crate) async fn release_destination(dpc: u32, ctx: &TaskCtx) {
    while let Some(batch) = ctx.registry.release_destination(dpc) {
        for msu in batch {
            match ctx.router.egress_for(&ctx.tenant, msu.dpc, msu.sls, None) {
                Some(via) => send_now(&via, &msu, &ctx.registry).await,
                None => {
                    metrics::mtp3_discard(Mtp3Discard::NoRoute, 1);
                    eprintln!(
                        "siphon-sigtran: dpc {} became inaccessible during rerouting, held message dropped",
                        msu.dpc
                    );
                }
            }
        }
    }
}

/// Send an MSU (SIO and SIF) that the link `from` held or was handed and will
/// not carry: by another link of its linkset, or by another route to its
/// destination (Q.704 4.3.2, 4.3.3).
pub(crate) async fn reroute(raw: Vec<u8>, ctx: &TaskCtx, from: &super::registry::AssocSlot) {
    let decoded = match mtp3::Mtp3Msu::decode(&raw, mtp3::Variant::Itu) {
        Ok(decoded) => decoded,
        Err(error) => {
            metrics::mtp3_discard(Mtp3Discard::NoAlternative, 1);
            eprintln!(
                "siphon-sigtran: a message held by `{}` cannot be read back ({error}), dropped",
                from.id
            );
            return;
        }
    };
    let msu = Msu {
        opc: decoded.opc.value(),
        dpc: decoded.dpc.value(),
        si: decoded.si.0,
        ni: decoded.ni.bits(),
        mp: decoded.mp,
        sls: decoded.sls,
        payload: decoded.data,
    };
    // Routing may still lead to `from` itself: it is passed by here, link
    // first, then its whole linkset.
    let own = ctx.registry.inbound_destination(&from.id);
    let mut via = ctx.router.egress_for(&ctx.tenant, msu.dpc, msu.sls, None);
    if via.is_some() && via == own {
        if let Some(Destination::Linkset(name)) = &own {
            let other = ctx
                .registry
                .select_link_avoiding(name, msu.sls, Some(&from.id));
            if let Some(slot) = other {
                if !ctx.registry.hold_if_rerouting(&msu) {
                    send_on_link(slot, &msu);
                }
                return;
            }
        }
        via = ctx
            .router
            .egress_for(&ctx.tenant, msu.dpc, msu.sls, own.as_ref());
    }
    match via {
        Some(via) => send_via(&via, &msu, &ctx.registry).await,
        // Q.704 5.3.3 i): "the concerned messages already stored in the
        // transmission and retransmission buffers of the unavailable
        // signalling link, as well as those received subsequently, are
        // discarded".
        None => {
            metrics::mtp3_discard(Mtp3Discard::NoAlternative, 1);
            eprintln!(
                "siphon-sigtran: no alternative to `{}` for dpc {}, message dropped",
                from.id, msu.dpc
            );
        }
    }
}

/// Hand an MSU to the M2PA link an association is, for transmission. A full
/// transmit queue is counted by the link port; anything else that keeps the MSU
/// off the link is logged here.
pub(crate) fn send_on_link(slot: &super::registry::AssocSlot, msu: &Msu) {
    let Some(link) = slot.link() else {
        eprintln!(
            "siphon-sigtran: `{}` is not an m2pa link, MSU for dpc {} dropped",
            slot.id, msu.dpc
        );
        return;
    };
    match framing::mtp3_msu(msu) {
        Ok(raw) => {
            if !link.offer(raw) {
                eprintln!(
                    "siphon-sigtran: m2pa link `{}`: transmit queue full, MSU for dpc {} dropped",
                    slot.id, msu.dpc
                );
            }
        }
        Err(e) => eprintln!("siphon-sigtran: m2pa framing failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};

    fn gt(digits: &str) -> GlobalTitle {
        GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: digits.to_string(),
        }
    }

    fn udt_msu(message_handling: u8) -> Msu {
        let mut udt = UnitData::new(
            SccpAddress::with_gt(gt("15550100"), Some(SubsystemNumber::Hlr)),
            SccpAddress::with_gt(gt("15550170"), Some(SubsystemNumber::Msc)),
            vec![0x01, 0x02, 0x03],
        );
        udt.message_handling = message_handling;
        Msu {
            opc: 4000,
            dpc: 1000,
            si: framing::SI_SCCP,
            ni: 0,
            mp: 0,
            sls: 5,
            payload: SccpMessage::Udt(udt).encode().expect("encode udt"),
        }
    }

    #[test]
    fn undeliverable_return_on_error_udt_gets_a_udts_back() {
        // A UDT that asked to be returned on error, undeliverable, gets a UDTS back
        // to the originator: our OPC, their DPC, called/calling swapped, cause set.
        let inbound = udt_msu(SCCP_RETURN_ON_ERROR);
        let sccp = SccpMessage::decode(&inbound.payload).unwrap();

        let ret = sccp_return(
            &inbound,
            &sccp,
            ReturnCause::NoTranslationForAddress,
            Some(1000),
        )
        .expect("a return is generated for a return-on-error message");
        assert_eq!(ret.opc, 1000, "return OPC is our point code");
        assert_eq!(ret.dpc, 4000, "return DPC is the originator");
        assert_eq!(
            ret.sls, 5,
            "SLS mirrors the inbound so it follows the path back"
        );

        match SccpMessage::decode(&ret.payload).unwrap() {
            SccpMessage::Udts(u) => {
                assert_eq!(u.return_cause, ReturnCause::NoTranslationForAddress);
                assert_eq!(u.called_party.global_title.digits(), Some("15550170")); // was calling
                assert_eq!(u.calling_party.global_title.digits(), Some("15550100")); // was called
                assert_eq!(u.data, vec![0x01, 0x02, 0x03]);
            }
            other => panic!("expected a UDTS return, got {other:?}"),
        }
    }

    #[test]
    fn no_return_when_the_message_did_not_ask_for_one() {
        let inbound = udt_msu(0); // no return-on-error option
        let sccp = SccpMessage::decode(&inbound.payload).unwrap();
        assert!(sccp_return(&inbound, &sccp, ReturnCause::MtpFailure, Some(1000)).is_none());
    }

    #[test]
    fn rewrite_called_gt_restamps_digits_preserving_the_rest() {
        // A content rule's rewrite_cdpa_gt restamps the called-party GT digits and
        // leaves the SSN, the calling party, and the user data untouched.
        let udt = UnitData::new(
            SccpAddress::with_gt(gt("15550100"), Some(SubsystemNumber::Hlr)),
            SccpAddress::with_gt(gt("15550170"), Some(SubsystemNumber::Msc)),
            vec![0xAA, 0xBB],
        );
        let payload = SccpMessage::Udt(udt).encode().unwrap();

        let rewritten = rewrite_called_gt(&payload, "15550199").expect("rewrite applies to a UDT");
        match SccpMessage::decode(&rewritten).unwrap() {
            SccpMessage::Udt(m) => {
                assert_eq!(m.called_party.global_title.digits(), Some("15550199"));
                assert_eq!(m.called_party.ssn.map(|s| s.value()), Some(6)); // HLR SSN kept
                assert_eq!(m.calling_party.global_title.digits(), Some("15550170"));
                assert_eq!(m.data, vec![0xAA, 0xBB]);
            }
            other => panic!("expected a UDT, got {other:?}"),
        }
    }

    // The octets in the two tests below are written out by hand from Q.713
    // 3.4.2.3: two address signals per octet, the earlier one in the low half,
    // encoding scheme 1 (odd) or 2 (even), filler 0000 after an odd count.

    /// The called party address of a UDT, as it is on the wire.
    fn called_octets(payload: &[u8]) -> &[u8] {
        let start = 2 + usize::from(payload[2]);
        let len = usize::from(payload[start]);
        &payload[start + 1..start + 1 + len]
    }

    #[test]
    fn a_rewritten_title_says_how_many_digits_it_has() {
        // rewrite_cdpa_gt puts a title of another length in place of the one that
        // came in: the odd/even indication has to follow the new digits, or the
        // next node reads the title one digit short.
        let udt = UnitData::new(
            SccpAddress::with_gt(gt("15550100123"), Some(SubsystemNumber::Hlr)),
            SccpAddress::with_gt(gt("15550170"), Some(SubsystemNumber::Msc)),
            vec![0xAA],
        );
        let payload = SccpMessage::Udt(udt).encode().unwrap();
        assert_eq!(
            called_octets(&payload),
            [0x12, 0x06, 0x00, 0x11, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21, 0x03],
            "eleven digits: scheme 1, filler 0"
        );

        let even = rewrite_called_gt(&payload, "155501001234").expect("rewrite applies");
        assert_eq!(
            called_octets(&even),
            [0x12, 0x06, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21, 0x43],
            "twelve digits: scheme 2, every half octet a digit"
        );
        let odd = rewrite_called_gt(&even, "15550100123").expect("rewrite applies");
        assert_eq!(called_octets(&odd), called_octets(&payload));
    }

    #[test]
    fn a_received_title_is_read_by_its_odd_even_indication() {
        // Global title translation matches on these digits: a filler must not
        // become a digit, and the last digit of an even title must not be lost.
        let msu = |called: &[u8]| {
            let mut payload = vec![0x09, 0x00, 0x03, 0x00, 0x00];
            payload[3] = 3 + called.len() as u8;
            payload[4] = 5 + called.len() as u8;
            payload.push(called.len() as u8);
            payload.extend_from_slice(called);
            payload.extend_from_slice(&[0x02, 0x42, 0x08, 0x01, 0xAA]);
            Msu {
                opc: 4000,
                dpc: 1000,
                si: framing::SI_SCCP,
                ni: 0,
                mp: 0,
                sls: 0,
                payload,
            }
        };
        let digits = |called: &[u8]| {
            inbound_from_msu(&msu(called))
                .cdpa
                .expect("a called global title")
                .digits
        };
        assert_eq!(
            digits(&[0x12, 0x06, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21]),
            "1555010012"
        );
        assert_eq!(
            digits(&[0x12, 0x06, 0x00, 0x11, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21, 0x03]),
            "15550100123"
        );
        assert_eq!(
            digits(&[0x12, 0x06, 0x00, 0x12, 0x04, 0x51, 0x55, 0x10, 0x00, 0x21, 0x43]),
            "155501001234"
        );
    }
}
