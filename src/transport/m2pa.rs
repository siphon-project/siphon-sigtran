//! M2PA per-link task loop (RFC 4165).
//!
//! A link brings itself into service with the Link Status alignment exchange
//! (Alignment → Proving → Ready), driven by the published
//! [`m2pa::M2paStateMachine`], then carries MTP3 MSUs in User Data messages.
//! Reaching In-Service marks the slot active so the owning linkset becomes an
//! available egress; losing the association marks it down.
//!
//! Link Status rides SCTP stream 0, User Data stream 1 (RFC 4165 §3.4). We drive
//! the alignment reactively: on each inbound Link Status we advance our state
//! machine and answer with the status that pushes the peer forward, so two
//! freshly-started endpoints converge on In-Service.

use std::sync::Arc;

use async_sctp::SctpAssociation;
use m2pa::{LinkState, LinkStatusMessage, M2paMessage, M2paState, M2paStateMachine};
use tokio::sync::watch;

use super::forward::dispatch;
use super::framing;
use super::registry::AssocSlot;
use super::TaskCtx;

const STATUS_STREAM: u16 = 0;
const PPID_M2PA: u32 = 5;

/// The Link Status to send in response to reaching a given alignment state, so
/// the peer advances too. `None` means "send nothing" (aligned already, or out
/// of service).
pub fn next_status(state: M2paState) -> Option<LinkState> {
    match state {
        M2paState::Aligned => Some(LinkState::ProvingNormal),
        M2paState::Proving | M2paState::AlignedReady => Some(LinkState::Ready),
        _ => None,
    }
}

async fn send_status(assoc: &SctpAssociation, state: LinkState) {
    let msg = M2paMessage::LinkStatus {
        bsn: 0xFF_FFFF,
        fsn: 0xFF_FFFF,
        message: LinkStatusMessage::new(state),
    };
    if let Ok(bytes) = msg.encode() {
        let _ = assoc.send(&bytes, STATUS_STREAM, PPID_M2PA).await;
    }
}

/// Drive one M2PA link: align to in-service, then carry MSUs.
pub async fn run_link(
    assoc: Arc<SctpAssociation>,
    slot: Arc<AssocSlot>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sm = M2paStateMachine::new();
    sm.start(); // OutOfService → NotAligned
    send_status(&assoc, LinkState::Alignment).await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = assoc.recv() => {
                let (data, info) = match r {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if info.ppid != PPID_M2PA {
                    continue;
                }
                match M2paMessage::decode(&data) {
                    Ok(M2paMessage::LinkStatus { message, .. }) => {
                        let before = sm.state();
                        let new = sm.on_link_status(message.state);
                        if let Some(next) = next_status(new) {
                            send_status(&assoc, next).await;
                        }
                        if before != new {
                            slot.set_active(new == M2paState::InService);
                            ctx.registry.recompute(&ctx.router);
                        }
                    }
                    Ok(M2paMessage::UserData { .. }) => {
                        if slot.is_carrying() {
                            if let Ok(Some(msu)) = framing::extract_m2pa(&data) {
                                dispatch(msu, &ctx, &slot.id).await;
                            }
                        }
                        // User Data before in-service is dropped (as MTP2 would).
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    slot.set_active(false);
    slot.clear_sender();
    ctx.registry.recompute(&ctx.router);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_reaches_in_service_between_two_endpoints() {
        // Model the reactive exchange between two freshly-started state machines
        // and confirm both converge on In-Service (no sockets).
        let mut a = M2paStateMachine::new();
        let mut b = M2paStateMachine::new();
        a.start();
        b.start();
        // Both open with Alignment.
        let mut a_out = vec![LinkState::Alignment];
        let mut b_out = vec![LinkState::Alignment];
        for _ in 0..8 {
            let (mut na, mut nb) = (Vec::new(), Vec::new());
            for s in b_out.drain(..) {
                if let Some(n) = next_status(a.on_link_status(s)) {
                    na.push(n);
                }
            }
            for s in a_out.drain(..) {
                if let Some(n) = next_status(b.on_link_status(s)) {
                    nb.push(n);
                }
            }
            a_out = na;
            b_out = nb;
            if a.state() == M2paState::InService && b.state() == M2paState::InService {
                break;
            }
        }
        assert_eq!(a.state(), M2paState::InService);
        assert_eq!(b.state(), M2paState::InService);
    }
}
