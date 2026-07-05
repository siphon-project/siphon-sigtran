//! M3UA per-association task loops (RFC 4666).
//!
//! Two directions:
//!
//! * [`run_sg`] drives the **SG side** of a `server` association: a peer ASP
//!   connects and runs the ASPSM/ASPTM handshake against us. We reply
//!   ASP-UP-ACK / ASP-ACTIVE-ACK / ASP-INACTIVE-ACK / ASP-DOWN-ACK, ack BEAT, and
//!   deliver DATA up the stack once the peer is Active. The published
//!   [`m3ua::Asp`] state machine is the engine.
//! * [`run_asp`] drives the **ASP side** of a `client` association: we initiate
//!   ASP-UP, and on ASP-UP-ACK send ASP-ACTIVE (with the AS routing context +
//!   traffic mode). On ASP-ACTIVE-ACK the AS becomes available for egress.
//!
//! Both directions handle SSNM (DUNA/DAVA/DAUD/SCON) and BEAT, and both mark
//! their slot active/inactive so [`Registry::recompute`](super::registry::Registry::recompute)
//! tracks live AS availability.
//!
//! ## Handled vs not
//!
//! Handled: ASP-UP/-ACK, ASP-DOWN/-ACK, ASP-ACTIVE/-ACK, ASP-INACTIVE/-ACK,
//! BEAT/-ACK, DATA, DUNA, DAVA, DAUD (answered), SCON (noted), DUPU (noted),
//! NTFY (logged). Not handled (out of scope this phase): Routing Key Management
//! (REG/DEREG), the M3UA ERR round-trip, and multiple ASPs multiplexed on one
//! SCTP association (one peer per association here).

use std::sync::Arc;

use async_sctp::SctpAssociation;
use m3ua::{AspAction, AspState, M3uaMessage, MessageType};
use tokio::sync::watch;

use super::forward::{self, dispatch};
use super::framing;
use super::registry::AssocSlot;
use super::TaskCtx;
use crate::config::TrafficMode;

const CTRL_STREAM: u16 = 0;
const PPID_M3UA: u32 = 3;

/// RFC 4666 §3.5.2 Traffic Mode Type value.
fn traffic_mode_value(m: TrafficMode) -> u32 {
    match m {
        TrafficMode::Override => 1,
        TrafficMode::Loadshare => 2,
        TrafficMode::Broadcast => 3,
    }
}

/// SG side: reply to a peer ASP's ASPSM/ASPTM handshake and deliver its DATA.
pub async fn run_sg(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut asp = m3ua::Asp::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = assoc.recv() => {
                let (data, info) = match r {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if info.ppid != PPID_M3UA {
                    continue;
                }
                let msg = match M3uaMessage::decode(&data) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                // SSNM is not part of the ASP state machine; handle it directly.
                if forward::is_ssnm(msg.message_type) {
                    forward::handle_ssnm(&msg, &ctx, &assoc).await;
                    continue;
                }
                let before = asp.state();
                let action = asp.handle(&msg);
                let after = asp.state();
                match action {
                    AspAction::Reply(reply) => {
                        let _ = assoc.send(&reply.encode(), CTRL_STREAM, PPID_M3UA).await;
                    }
                    AspAction::Deliver => {
                        if let Ok(msu) = framing::extract_m3ua(&data) {
                            dispatch(msu, &ctx, &slot.id).await;
                        }
                    }
                    AspAction::Ignore => {}
                }
                if before != after {
                    slot.set_active(after == AspState::Active);
                    ctx.registry.recompute(&ctx.router);
                }
            }
        }
    }
    disconnect(&slot, &ctx);
}

/// ASP side: initiate ASP-UP → ASP-ACTIVE, then carry DATA/SSNM/BEAT.
pub async fn run_asp(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    membership: Option<(u32, TrafficMode)>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    // Kick off the ASPSM handshake.
    let _ = assoc
        .send(
            &M3uaMessage::asp_up(Some(1), None).encode(),
            CTRL_STREAM,
            PPID_M3UA,
        )
        .await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = assoc.recv() => {
                let (data, info) = match r {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if info.ppid != PPID_M3UA {
                    continue;
                }
                let msg = match M3uaMessage::decode(&data) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match msg.message_type {
                    MessageType::AspUpAck => {
                        // Up: go Active for the AS we belong to (if any).
                        if let Some((rc, tm)) = membership {
                            let ac =
                                M3uaMessage::asp_active(Some(traffic_mode_value(tm)), Some(rc));
                            let _ = assoc.send(&ac.encode(), CTRL_STREAM, PPID_M3UA).await;
                        }
                    }
                    MessageType::AspActiveAck => {
                        slot.set_active(true);
                        ctx.registry.recompute(&ctx.router);
                    }
                    MessageType::AspInactiveAck | MessageType::AspDownAck => {
                        slot.set_active(false);
                        ctx.registry.recompute(&ctx.router);
                    }
                    MessageType::Heartbeat => {
                        let _ = assoc
                            .send(
                                &M3uaMessage::heartbeat_ack(None).encode(),
                                CTRL_STREAM,
                                PPID_M3UA,
                            )
                            .await;
                    }
                    MessageType::HeartbeatAck => {}
                    MessageType::Data => {
                        if slot.is_carrying() {
                            if let Ok(msu) = framing::extract_m3ua(&data) {
                                dispatch(msu, &ctx, &slot.id).await;
                            }
                        }
                    }
                    MessageType::Notify => {
                        // Status notification from the SG; no state change here.
                    }
                    mt if forward::is_ssnm(mt) => {
                        forward::handle_ssnm(&msg, &ctx, &assoc).await;
                    }
                    _ => {}
                }
            }
        }
    }
    disconnect(&slot, &ctx);
}

/// Mark the slot down and recompute availability when the association ends.
fn disconnect(slot: &Arc<AssocSlot>, ctx: &TaskCtx) {
    slot.set_active(false);
    slot.clear_sender();
    ctx.registry.recompute(&ctx.router);
}
