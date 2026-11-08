//! Lifecycle of a DNS-expanded client ASP. Each child owns its reconnect loop.
use super::{dial_association, dial_settings, dns, local_addrs, m3ua::Request, Dialled, TaskCtx};
use crate::config::Association;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
};

struct Member {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Drop for Member {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.task.abort();
    }
}

async fn remove(name: String, mut member: Member, ctx: &TaskCtx) {
    member.stop.send_replace(true);
    let _ = (&mut member.task).await;
    let (done, finished) = oneshot::channel();
    if ctx.registry.request(Request::Remove { name, done }) {
        let _ = finished.await;
    }
}

pub(super) async fn run(
    a: Association,
    resolver: Arc<dyn dns::Resolver>,
    ctx: TaskCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut members: BTreeMap<SocketAddr, Member> = BTreeMap::new();
    let mut refresh = tokio::time::interval(Duration::from_secs(a.resolve_seconds));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = refresh.tick() => {}
        }
        let answer = tokio::select! {
            _ = shutdown.changed() => break,
            answer = tokio::time::timeout(dial_settings(&a).connect_timeout, dns::resolve(resolver.as_ref(), &a.addrs, a.port)) => answer,
        };
        let addresses: BTreeSet<_> = match answer {
            Ok(Ok(addresses)) => addresses.into_iter().collect(),
            error => {
                eprintln!(
                    "siphon-sigtran: DNS refresh for `{}` failed: {error:?}",
                    a.id
                );
                continue;
            }
        };
        let removed: Vec<_> = members
            .keys()
            .filter(|addr| !addresses.contains(addr))
            .copied()
            .collect();
        for address in removed {
            if let Some(member) = members.remove(&address) {
                remove(format!("{}@{address}", a.id), member, &ctx).await;
            }
        }
        for address in addresses {
            if members.contains_key(&address) {
                continue;
            }
            let name = format!("{}@{address}", a.id);
            let (done, added) = oneshot::channel();
            if !ctx.registry.request(Request::Add {
                template: a.id.clone(),
                name,
                done,
            }) {
                break;
            }
            let Ok(Some(slot)) = added.await else {
                continue;
            };
            let local = match local_addrs(&a) {
                Ok(local) => local,
                Err(error) => {
                    eprintln!("siphon-sigtran: local addresses: {error}");
                    break;
                }
            };
            let (stop, receiver) = watch::channel(false);
            let dialled = Dialled {
                slot,
                peer: vec![address.to_string()],
                port: address.port(),
                resolver: resolver.clone(),
                local,
                settings: dial_settings(&a),
                sctp: async_sctp::SctpConfig::new().nodelay(true),
                membership: None,
            };
            let task = tokio::spawn(dial_association(dialled, ctx.clone(), receiver));
            members.insert(address, Member { stop, task });
        }
    }
    // Signal every member before waiting for any one to finish.
    for member in members.values() {
        member.stop.send_replace(true);
    }
    for (address, member) in members {
        remove(format!("{}@{address}", a.id), member, &ctx).await;
    }
}
