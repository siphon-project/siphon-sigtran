//! The per-message pipeline: an inbound [`Msu`] becomes a routing decision and
//! is acted on (forwarded to the resolved egress, delivered locally, or dropped
//! with a logged reason). Plus the M3UA SSNM handler that folds DUNA/DAVA/DAUD
//! into the router's route state.

use async_sctp::SctpAssociation;
use m3ua::{M3uaMessage, MessageType};
use mtp3::{Mtp3Event, PointCode};
use sccp::{GlobalTitle, SccpMessage};

use super::framing::{self, Msu};
use super::{LocalDelivery, TaskCtx};
use crate::metrics::{self, LoopKind};
use crate::mtp3::route::Destination;
use crate::routing::{Inbound, RouteDecision};
use crate::sccp::gtt::GttSelector;

/// SCTP stream for M3UA management/data here (we use stream 1 for DATA and
/// stream 0 for the ASPSM/SSNM control messages, matching the peers we drive).
const M3UA_DATA_STREAM: u16 = 1;
const M3UA_CTRL_STREAM: u16 = 0;
const M2PA_DATA_STREAM: u16 = 1;
const PPID_M3UA: u32 = 3;
const PPID_M2PA: u32 = 5;

/// Build the router [`Inbound`] from an MSU. The DPC alone routes a transit MSU
/// of any Service Indicator; only an SCCP MSU (`SI=3`) is decoded further so
/// GTT / content / local-termination can see the called party.
pub fn inbound_from_msu(msu: &Msu) -> Inbound {
    let mut inbound = Inbound {
        dpc: msu.dpc,
        ..Default::default()
    };
    if msu.si == framing::SI_SCCP {
        if let Ok(SccpMessage::Udt(udt)) = SccpMessage::decode(&msu.payload) {
            inbound.called_ssn = udt.called_party.ssn.as_ref().map(|s| s.value());
            if udt.called_party.global_title.digits().is_some() {
                inbound.cdpa = Some(selector_from_gt(&udt.called_party.global_title));
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

/// Route one inbound MSU and act on the decision. `inbound_assoc` is the id of
/// the association the MSU arrived on; it feeds the route-reflect loop guard.
pub async fn dispatch(msu: Msu, ctx: &TaskCtx, inbound_assoc: &str) {
    // Loop guard 1 (own-OPC): a message whose OPC is our own point code is one
    // we originated coming back to us. Drop it before it can loop.
    if let Some(our_pc) = ctx.router.node_point_code(&ctx.tenant) {
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

    let inbound = inbound_from_msu(&msu);
    match ctx.router.route_in(&ctx.tenant, &inbound) {
        RouteDecision::Route { via } => {
            if is_reflection(inbound_src.as_ref(), &via) {
                loop_reflect(&via, &msu, inbound_assoc);
                return;
            }
            send_via(&via, &msu, ctx).await
        }
        RouteDecision::RouteTo {
            dpc,
            via: Some(via),
            ..
        } => {
            if is_reflection(inbound_src.as_ref(), &via) {
                loop_reflect(&via, &msu, inbound_assoc);
                return;
            }
            // A GTT / content result to a concrete DPC. Relay to the resolved
            // egress with the new DPC. (SCCP CdPA GT / SSN rewrite from a content
            // rule is not applied on the wire yet, that rides the dialogue-SAP
            // work; the DPC-level relay is honoured here.)
            let mut out = msu.clone();
            out.dpc = dpc;
            send_via(&via, &out, ctx).await;
        }
        RouteDecision::RouteTo { dpc, via: None, .. } => {
            eprintln!("siphon-sigtran: no MTP3 route to translated DPC {dpc}, dropping");
        }
        RouteDecision::Local => {
            // Local termination: hand the MSU to the (phase-4) dialogue SAP seam.
            let _ = ctx.local_tx.send(LocalDelivery { msu }).await;
        }
        RouteDecision::CrossTenant { tenant, .. } => {
            eprintln!(
                "siphon-sigtran: cross-tenant hand-off to `{tenant}` not wired on the transport yet"
            );
        }
        RouteDecision::Python { hook } => {
            eprintln!("siphon-sigtran: content rule deferred to python hook `{hook}` (phase-3)");
        }
        RouteDecision::Drop { reason } => {
            eprintln!("siphon-sigtran: dropping MSU to {}: {reason}", msu.dpc);
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

/// Forward an MSU on a resolved [`Destination`]'s egress association(s).
async fn send_via(via: &Destination, msu: &Msu, ctx: &TaskCtx) {
    let selected = ctx.registry.select(via, msu.sls);
    if selected.is_empty() {
        eprintln!(
            "siphon-sigtran: no active egress for {via} (dpc {})",
            msu.dpc
        );
        return;
    }
    for sel in selected {
        let (bytes, stream, ppid) = match via {
            Destination::ApplicationServer(_) => (
                framing::wrap_m3ua(msu, sel.routing_context),
                M3UA_DATA_STREAM,
                PPID_M3UA,
            ),
            Destination::Linkset(_) => match framing::wrap_m2pa(msu) {
                Ok(b) => (b, M2PA_DATA_STREAM, PPID_M2PA),
                Err(e) => {
                    eprintln!("siphon-sigtran: m2pa framing failed: {e}");
                    continue;
                }
            },
        };
        if let Err(e) = sel.assoc.send(&bytes, stream, ppid).await {
            eprintln!("siphon-sigtran: egress send on {via} failed: {e}");
        }
    }
}

/// Whether an M3UA message type is an SSNM (SS7 network management) message the
/// ASP/ASPSM state machine does not itself handle.
pub fn is_ssnm(mt: MessageType) -> bool {
    matches!(
        mt,
        MessageType::Duna
            | MessageType::Dava
            | MessageType::Daud
            | MessageType::Scon
            | MessageType::Dupu
            | MessageType::Drst
    )
}

/// Handle an inbound M3UA SSNM message: translate DUNA/DAVA to MTP3
/// Pause/Resume, answer a DAUD audit from the live route state, and note SCON /
/// DUPU. `reply` is the association to answer a DAUD on.
pub async fn handle_ssnm(msg: &M3uaMessage, ctx: &TaskCtx, reply: &SctpAssociation) {
    let variant = ctx.registry.variant();
    let to_pc = |v: u32| PointCode::from_value(v, variant).ok();
    match msg.message_type {
        MessageType::Duna => {
            for pc in msg.affected_point_codes() {
                if let Some(p) = to_pc(pc) {
                    ctx.router
                        .apply_mtp3_event(&ctx.tenant, &Mtp3Event::Pause { affected: p });
                }
            }
        }
        MessageType::Dava | MessageType::Drst => {
            for pc in msg.affected_point_codes() {
                if let Some(p) = to_pc(pc) {
                    ctx.router
                        .apply_mtp3_event(&ctx.tenant, &Mtp3Event::Resume { affected: p });
                }
            }
        }
        MessageType::Daud => {
            // Audit: answer DAVA for the point codes we can currently reach and
            // DUNA for those we cannot, from the live route state.
            let rc = msg.routing_context();
            let (mut avail, mut unavail) = (Vec::new(), Vec::new());
            for pc in msg.affected_point_codes() {
                if ctx.router.is_reachable(&ctx.tenant, pc) {
                    avail.push(pc);
                } else {
                    unavail.push(pc);
                }
            }
            if !avail.is_empty() {
                let _ = reply
                    .send(
                        &M3uaMessage::dava(rc, avail).encode(),
                        M3UA_CTRL_STREAM,
                        PPID_M3UA,
                    )
                    .await;
            }
            if !unavail.is_empty() {
                let _ = reply
                    .send(
                        &M3uaMessage::duna(rc, unavail).encode(),
                        M3UA_CTRL_STREAM,
                        PPID_M3UA,
                    )
                    .await;
            }
        }
        MessageType::Scon => {
            // Congestion: fold in a level-1 status for each affected PC. (The
            // detailed congestion level parameter is not parsed here yet.)
            for pc in msg.affected_point_codes() {
                if let Some(p) = to_pc(pc) {
                    ctx.router.apply_mtp3_event(
                        &ctx.tenant,
                        &Mtp3Event::Status {
                            affected: p,
                            status: mtp3::Mtp3Status::Congested { level: 1 },
                        },
                    );
                }
            }
        }
        MessageType::Dupu => {
            eprintln!("siphon-sigtran: DUPU (destination user part unavailable) noted");
        }
        _ => {}
    }
}
