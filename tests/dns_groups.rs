#![allow(clippy::disallowed_methods)] // Test runtimes may block their dedicated test threads.
use siphon_sigtran::{
    config::Config,
    routing::Router,
    transport::dns::{Lookup, Resolver},
    TransportHandle,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Addresses(Mutex<Option<Vec<SocketAddr>>>);
impl Resolver for Addresses {
    fn lookup<'a>(&'a self, _: &'a str, _: u16) -> Lookup<'a> {
        let answer = self.0.lock().unwrap().clone();
        Box::pin(
            async move { answer.ok_or_else(|| std::io::Error::other("temporary DNS failure")) },
        )
    }
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition reached");
}

#[tokio::test]
async fn dns_changes_add_remove_and_preserve_members_on_lookup_failure() {
    let cfg = Config::parse("node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: peer, adaptation: m3ua, role: client, addrs: [peer.example], port: 2905, all_addresses: true, resolve_seconds: 1 }\napplication_servers:\n  - { name: first, routing_context: 1, traffic_mode: loadshare, asps: [peer] }\n  - { name: second, routing_context: 2, traffic_mode: override, asps: [peer] }\n").unwrap();
    let a: SocketAddr = "192.0.2.1:2905".parse().unwrap();
    let b: SocketAddr = "192.0.2.2:2905".parse().unwrap();
    let dns = Arc::new(Addresses(Mutex::new(Some(vec![b, a, a]))));
    let handle = TransportHandle::start_tenant_with_resolver(
        &cfg,
        "default",
        Arc::new(Router::new(&cfg)),
        dns.clone(),
    )
    .await
    .unwrap();
    let registry = handle.registry();
    let an = format!("peer@{a}");
    let bn = format!("peer@{b}");
    until(|| registry.slot(&an).is_some() && registry.slot(&bn).is_some()).await;
    let retained = registry.slot(&bn).unwrap();
    assert_eq!(retained.memberships().len(), 2);
    assert!(
        !retained.is_carrying(),
        "DNS alone never activates a member"
    );
    *dns.0.lock().unwrap() = None;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        registry.slot(&an).is_some(),
        "lookup errors preserve last successful set"
    );
    *dns.0.lock().unwrap() = Some(vec![b]);
    until(|| registry.slot(&an).is_none()).await;
    assert!(Arc::ptr_eq(&retained, &registry.slot(&bn).unwrap()));
    *dns.0.lock().unwrap() = Some(vec![]);
    until(|| registry.slot(&bn).is_none()).await;
    handle.shutdown();
}

struct FailingDns(std::sync::atomic::AtomicUsize);
impl Resolver for FailingDns {
    fn lookup<'a>(&'a self, _: &'a str, _: u16) -> Lookup<'a> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(std::io::Error::other("temporary DNS failure")) })
    }
}

#[tokio::test]
async fn ordinary_client_retries_dns_failure_without_blocking_start_and_stops_on_shutdown() {
    use std::sync::atomic::Ordering;
    let cfg = Config::parse("node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: peer, adaptation: m3ua, role: client, addrs: [peer.example], port: 2905, dial: { backoff_initial_ms: 10, backoff_max_ms: 20, backoff_jitter_percent: 0 } }\n").unwrap();
    let dns = Arc::new(FailingDns(std::sync::atomic::AtomicUsize::new(0)));
    let handle = TransportHandle::start_tenant_with_resolver(
        &cfg,
        "default",
        Arc::new(Router::new(&cfg)),
        dns.clone(),
    )
    .await
    .unwrap();
    until(|| dns.0.load(Ordering::SeqCst) >= 3).await;
    handle.shutdown();
    tokio::task::yield_now().await;
    let count = dns.0.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(dns.0.load(Ordering::SeqCst), count);
}
