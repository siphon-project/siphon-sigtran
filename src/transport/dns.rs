//! DNS resolution at dial time, injectable for deterministic address changes.
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
};

/// An asynchronous address lookup.
pub type Lookup<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Resolves a host with a default port. Implementations may supply test address sets.
pub trait Resolver: Send + Sync {
    /// Look up all addresses currently published for this host.
    fn lookup<'a>(&'a self, host: &'a str, port: u16) -> Lookup<'a>;
}

/// The system resolver, via Tokio's blocking resolver pool.
pub struct SystemResolver;
impl Resolver for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str, port: u16) -> Lookup<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// Resolve names, host:port pairs, IPv4 and IPv6 literals; sort and deduplicate.
/// An empty successful answer is retained so a group can withdraw all members.
pub async fn resolve(
    resolver: &dyn Resolver,
    names: &[String],
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for name in names {
        if let Ok(addr) = name.parse::<SocketAddr>() {
            addresses.push(addr);
        } else if let Ok(ip) = name
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            addresses.push(SocketAddr::new(ip, port));
        } else {
            let (host, port) = match name.rsplit_once(':') {
                Some((host, value)) => (
                    host,
                    value.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid peer port")
                    })?,
                ),
                None => (name.as_str(), port),
            };
            addresses.extend(resolver.lookup(host, port).await?);
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}
