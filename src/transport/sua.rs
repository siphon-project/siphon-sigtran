//! SUA per-association task loops (RFC 3868).
//!
//! SUA is the SIGTRAN sibling of M3UA: the same ASPSM/ASPTM handshake brings an
//! Application Server up, but the traffic it carries is the **SCCP user** (TCAP)
//! addressed by Global Title / SSN / Point Code, not the MTP3 user on a
//! point-code routing label. Connectionless data rides in **CLDT** (and its
//! error response **CLDR**), which bridges one-for-one to an SCCP UDT/UDTS. So a
//! `sua` AS routes through the exact same GTT / content / local-termination
//! engine as SCCP-over-M3UA: the only differences from [`super::m3ua`] are the
//! payload framing (CLDT via the `sua` codec, PPID 4 not 3) and the
//! CLDT ⇄ SCCP-user bridge in [`super::framing`].
//!
//! Two directions, mirroring [`super::m3ua`]:
//!
//! * [`run_sg`] drives the **SG side** of a `server` association: a peer ASP
//!   connects and runs the ASPSM/ASPTM handshake against us. We reply
//!   ASP-UP-ACK / ASP-ACTIVE-ACK / ASP-INACTIVE-ACK / ASP-DOWN-ACK, ack BEAT, and
//!   deliver CLDT/CLDR up the stack once the peer is Active.
//! * [`run_asp`] drives the **ASP side** of a `client` association: we initiate
//!   ASP-UP, and on ASP-UP-ACK send ASP-ACTIVE (with the AS routing context +
//!   traffic mode). On ASP-ACTIVE-ACK the AS becomes available for egress.
//!
//! Both directions fold SSNM (DUNA/DAVA/DAUD/SCON/DUPU) into the router.
//!
//! ## Handled vs not
//!
//! Handled: ASP-UP/-ACK, ASP-DOWN/-ACK, ASP-ACTIVE/-ACK, ASP-INACTIVE/-ACK,
//! BEAT/-ACK, CLDT, CLDR, DUNA, DAVA, DAUD (answered), SCON (noted), DUPU
//! (noted), NTFY/ERR (logged). Not handled (out of scope this phase): the SUA
//! **connection-oriented** set (CORE/COAK/CODT/CODA/…), Routing Key Management
//! (REG/DEREG), and multiple ASPs multiplexed on one SCTP association (one peer
//! per association here).
//!
//! ## State machine
//!
//! Unlike M3UA (whose `m3ua` crate ships the `m3ua::Asp` state machine
//! [`super::m3ua`] drives), the `sua` crate is **wire-format only** and ships no
//! state machine, so the small composite ASPSM/ASPTM machine below ([`AspState`])
//! is local. SUA reuses M3UA's state model (RFC 3868 §4 defers to RFC 4666), so
//! it is a faithful, minimal transcription of the same transitions.

use std::sync::Arc;

use async_sctp::SctpAssociation;
use mtp3::{Mtp3Event, PointCode};
use sua::{MessageType, SuaMessage};
use tokio::sync::watch;

use super::forward::dispatch;
use super::framing::{self, PPID_SUA};
use super::registry::AssocSlot;
use super::TaskCtx;
use crate::config::TrafficMode;

const CTRL_STREAM: u16 = 0;

/// The composite ASPSM/ASPTM state a SUA association exposes. Local because the
/// `sua` codec ships no state machine (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AspState {
    /// ASP-Down: the SCTP association is up but no ASP-UP has completed.
    Down,
    /// ASP-Inactive: ASP-UP acked, not yet carrying traffic.
    Inactive,
    /// ASP-Active: carrying connectionless data.
    Active,
}

/// RFC 4666 §3.5.2 Traffic Mode Type value (SUA shares the parameter).
fn traffic_mode_value(m: TrafficMode) -> u32 {
    match m {
        TrafficMode::Override => 1,
        TrafficMode::Loadshare => 2,
        TrafficMode::Broadcast => 3,
    }
}

/// SG side: answer a peer ASP's ASPSM/ASPTM handshake and deliver its CLDT/CLDR.
pub async fn run_sg(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut state = AspState::Down;
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = assoc.recv() => {
                let (data, info) = match r {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if info.ppid != PPID_SUA {
                    continue;
                }
                let msg = match SuaMessage::decode(&data) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                // SSNM is not part of the ASP state machine; handle it directly.
                if is_ssnm(msg.message_type) {
                    handle_ssnm(&msg, &ctx, &assoc).await;
                    continue;
                }
                let before = state;
                match msg.message_type {
                    MessageType::AspUp => {
                        let _ = assoc
                            .send(&SuaMessage::asp_up_ack(None).encode(), CTRL_STREAM, PPID_SUA)
                            .await;
                        state = AspState::Inactive;
                    }
                    MessageType::AspActive => {
                        let ack = SuaMessage::asp_active_ack(None, msg.routing_context());
                        let _ = assoc.send(&ack.encode(), CTRL_STREAM, PPID_SUA).await;
                        state = AspState::Active;
                    }
                    MessageType::AspInactive => {
                        let ack = SuaMessage::asp_inactive_ack(msg.routing_context());
                        let _ = assoc.send(&ack.encode(), CTRL_STREAM, PPID_SUA).await;
                        state = AspState::Inactive;
                    }
                    MessageType::AspDown => {
                        let _ = assoc
                            .send(&SuaMessage::asp_down_ack(None).encode(), CTRL_STREAM, PPID_SUA)
                            .await;
                        state = AspState::Down;
                    }
                    MessageType::Heartbeat => {
                        let _ = assoc
                            .send(&SuaMessage::heartbeat_ack(None).encode(), CTRL_STREAM, PPID_SUA)
                            .await;
                    }
                    MessageType::Cldt | MessageType::Cldr => {
                        if state == AspState::Active {
                            deliver(&data, &ctx, &slot).await;
                        }
                    }
                    MessageType::Error | MessageType::Notify => {
                        // Peer management notification; no state change here.
                    }
                    _ => {}
                }
                if before != state {
                    slot.set_active(state == AspState::Active);
                    ctx.registry.recompute(&ctx.router);
                }
            }
        }
    }
    disconnect(&slot, &ctx);
}

/// ASP side: initiate ASP-UP → ASP-ACTIVE, then carry CLDT/SSNM/BEAT.
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
            &SuaMessage::asp_up(Some(1), None).encode(),
            CTRL_STREAM,
            PPID_SUA,
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
                if info.ppid != PPID_SUA {
                    continue;
                }
                let msg = match SuaMessage::decode(&data) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match msg.message_type {
                    MessageType::AspUpAck => {
                        // Up: go Active for the AS we belong to (if any).
                        if let Some((rc, tm)) = membership {
                            let ac =
                                SuaMessage::asp_active(Some(traffic_mode_value(tm)), Some(rc));
                            let _ = assoc.send(&ac.encode(), CTRL_STREAM, PPID_SUA).await;
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
                                &SuaMessage::heartbeat_ack(None).encode(),
                                CTRL_STREAM,
                                PPID_SUA,
                            )
                            .await;
                    }
                    MessageType::HeartbeatAck => {}
                    MessageType::Cldt | MessageType::Cldr => {
                        if slot.is_carrying() {
                            deliver(&data, &ctx, &slot).await;
                        }
                    }
                    MessageType::Notify => {
                        // Status notification from the SG; no state change here.
                    }
                    mt if is_ssnm(mt) => {
                        handle_ssnm(&msg, &ctx, &assoc).await;
                    }
                    _ => {}
                }
            }
        }
    }
    disconnect(&slot, &ctx);
}

/// Bridge an inbound CLDT/CLDR to an [`Msu`](super::Msu) carrying the equivalent
/// SCCP message and route it through the shared dispatch. A decode failure is
/// logged, never silently dropped.
async fn deliver(data: &[u8], ctx: &TaskCtx, slot: &Arc<AssocSlot>) {
    let node_pc = ctx.router.node_point_code(&ctx.tenant).unwrap_or(0);
    match framing::extract_sua(data, node_pc) {
        Ok(msu) => dispatch(msu, ctx, &slot.id).await,
        Err(e) => {
            eprintln!(
                "siphon-sigtran: sua CLDT/CLDR decode failed on `{}`: {e}",
                slot.id
            );
        }
    }
}

/// Whether a SUA message type is an SSNM (SS7 network management) message the
/// ASP/ASPSM state machine does not itself handle.
fn is_ssnm(mt: MessageType) -> bool {
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

/// Handle an inbound SUA SSNM message: translate DUNA/DAVA to MTP3 Pause/Resume,
/// answer a DAUD audit from the live route state, and note SCON / DUPU. `reply`
/// is the association to answer a DAUD on. Mirrors [`super::forward::handle_ssnm`]
/// (the M3UA path) on the SUA codec.
async fn handle_ssnm(msg: &SuaMessage, ctx: &TaskCtx, reply: &SctpAssociation) {
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
                        &SuaMessage::dava(rc, &avail).encode(),
                        CTRL_STREAM,
                        PPID_SUA,
                    )
                    .await;
            }
            if !unavail.is_empty() {
                let _ = reply
                    .send(
                        &SuaMessage::duna(rc, &unavail).encode(),
                        CTRL_STREAM,
                        PPID_SUA,
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
            eprintln!("siphon-sigtran: SUA DUPU (destination user part unavailable) noted");
        }
        _ => {}
    }
}

/// Mark the slot down and recompute availability when the association ends.
fn disconnect(slot: &Arc<AssocSlot>, ctx: &TaskCtx) {
    slot.set_active(false);
    slot.clear_sender();
    ctx.registry.recompute(&ctx.router);
}
