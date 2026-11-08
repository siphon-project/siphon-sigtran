#![allow(clippy::disallowed_methods)] // Test runtimes may block their dedicated test threads.
use siphon_sigtran::transport::dns::{resolve, Resolver, SystemResolver};
use std::net::SocketAddr;

struct Fake;
impl Resolver for Fake {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>,
    > {
        Box::pin(async move {
            assert_eq!(host, "peer.example");
            Ok(vec![
                SocketAddr::from(([192, 0, 2, 2], port)),
                SocketAddr::from(([192, 0, 2, 1], port)),
                SocketAddr::from(([192, 0, 2, 2], port)),
            ])
        })
    }
}

#[tokio::test]
async fn names_ports_literals_and_deduplication() {
    for (name, port) in [("peer.example", 2905), ("peer.example:2906", 2906)] {
        let found = resolve(&Fake, &[name.into()], 2905).await.unwrap();
        assert_eq!(
            found,
            vec![
                SocketAddr::from(([192, 0, 2, 1], port)),
                SocketAddr::from(([192, 0, 2, 2], port))
            ]
        );
    }
    for (name, expected) in [
        ("192.0.2.1", "192.0.2.1:2905"),
        ("192.0.2.1:2906", "192.0.2.1:2906"),
        ("2001:db8::1", "[2001:db8::1]:2905"),
        ("[2001:db8::1]:2906", "[2001:db8::1]:2906"),
    ] {
        assert_eq!(
            resolve(&Fake, &[name.into()], 2905).await.unwrap(),
            vec![expected.parse::<SocketAddr>().unwrap()]
        );
    }
    assert!(!resolve(&SystemResolver, &["localhost".into()], 2905)
        .await
        .unwrap()
        .is_empty());
}
