//! Who a listening endpoint accepts.
//!
//! The kernel answers an INIT by itself: what `accept` hands over is an
//! association that is established already, from whoever asked. Whether it is
//! the peer of one of the associations configured on the endpoint is decided
//! here, from the addresses the peer presented (all of them, for a multihomed
//! peer) and its port. Nothing in this module touches a socket.
//!
//! RFC 4165 4.1.2 has it for a signalling link, and it holds for an ASP as
//! well: "Each MTP link corresponds to an SCTP association. To prevent
//! duplicate associations from being established, it is RECOMMENDED that each
//! endpoint know the IP address (or IP addresses, if multi-homing is used)
//! and port number of both endpoints."

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub use crate::metrics::Refusal;

/// Whom one association of a listening endpoint accepts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    /// Every address of the peer. Empty: whoever connects.
    pub addrs: Vec<IpAddr>,
    /// The port of the peer, when it is fixed.
    pub port: Option<u16>,
}

impl Rule {
    /// The rule of an association with no `peer_addrs`.
    pub fn anyone() -> Self {
        Self::default()
    }

    fn lists(&self, ip: IpAddr) -> bool {
        self.addrs.contains(&ip.to_canonical())
    }
}

/// Decide whose peer presented `peer`, the addresses and the port of an
/// accepted association. `Ok` is the position of the association in `rules`.
///
/// * An association without a list takes whoever comes (it is alone on its
///   endpoint: the configuration is refused otherwise).
/// * An association with a list takes a peer all of whose addresses it
///   lists. A peer with a listed and an unlisted address is refused: it
///   would be sent traffic at an address nobody vouched for.
/// * With a port configured, the port of the peer is that port.
pub fn admit(rules: &[Rule], peer: &[SocketAddr]) -> Result<usize, Refusal> {
    if peer.is_empty() {
        return Err(Refusal::Closed);
    }
    let mut partly = false;
    let mut wrong_port = false;
    for (position, rule) in rules.iter().enumerate() {
        if rule.addrs.is_empty() {
            return Ok(position);
        }
        let listed = peer.iter().filter(|a| rule.lists(a.ip())).count();
        if listed == 0 {
            continue;
        }
        if listed < peer.len() {
            partly = true;
            continue;
        }
        if rule
            .port
            .is_some_and(|port| peer.iter().any(|a| a.port() != port))
        {
            wrong_port = true;
            continue;
        }
        return Ok(position);
    }
    Err(if wrong_port {
        Refusal::PeerPort
    } else if partly {
        Refusal::UnlistedAddress
    } else {
        Refusal::UnknownPeer
    })
}

/// Limits a line of the log that a remote party can cause as often as it
/// likes: the first is written, then one per `interval`, which says how many
/// were left out. Every event is counted in a metric where it happens; this
/// is about the log only.
#[derive(Debug)]
pub struct Throttle {
    interval: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl Throttle {
    /// One line per `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
            suppressed: 0,
        }
    }

    /// An event at `now`. `Some(n)` when its line is to be written, `n` being
    /// how many lines were left out since the last one; `None` when this one
    /// is left out.
    pub fn event(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < self.interval => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(addrs: &[&str], port: Option<u16>) -> Rule {
        Rule {
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            port,
        }
    }

    fn peer(addrs: &[&str]) -> Vec<SocketAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn a_peer_is_matched_by_every_address_it_presents() {
        let hlr = rule(&["192.0.2.10", "198.51.100.10"], None);
        let msc = rule(&["192.0.2.20"], Some(2905));
        let v6 = rule(&["2001:db8::1"], None);
        let rules = [hlr, msc, v6];
        // (what the peer presents, the verdict)
        let table: [(&[&str], Result<usize, Refusal>); 13] = [
            // One address of a multihomed peer, and both.
            (&["192.0.2.10:4000"], Ok(0)),
            (&["198.51.100.10:4000"], Ok(0)),
            (&["192.0.2.10:4000", "198.51.100.10:4000"], Ok(0)),
            (&["198.51.100.10:4000", "192.0.2.10:4000"], Ok(0)),
            // An address nobody lists.
            (&["203.0.113.5:2905"], Err(Refusal::UnknownPeer)),
            (
                &["203.0.113.5:2905", "203.0.113.6:2905"],
                Err(Refusal::UnknownPeer),
            ),
            // A listed address with one that is not.
            (
                &["192.0.2.10:4000", "203.0.113.5:4000"],
                Err(Refusal::UnlistedAddress),
            ),
            // Addresses of two associations are not one peer.
            (
                &["192.0.2.10:2905", "192.0.2.20:2905"],
                Err(Refusal::UnlistedAddress),
            ),
            // The port, where one is configured.
            (&["192.0.2.20:2905"], Ok(1)),
            (&["192.0.2.20:2906"], Err(Refusal::PeerPort)),
            // IPv6, and an IPv4 address as an IPv6 socket reports it.
            (&["[2001:db8::1]:7000"], Ok(2)),
            (&["[::ffff:192.0.2.20]:2905"], Ok(1)),
            // An association that ended before it was looked at.
            (&[], Err(Refusal::Closed)),
        ];
        for (presented, verdict) in table {
            assert_eq!(admit(&rules, &peer(presented)), verdict, "{presented:?}");
        }
    }

    #[test]
    fn an_association_without_a_list_takes_whoever_comes() {
        let rules = [Rule::anyone()];
        assert_eq!(admit(&rules, &peer(&["203.0.113.5:1"])), Ok(0));
        assert_eq!(
            admit(&rules, &peer(&["203.0.113.5:1", "192.0.2.1:1"])),
            Ok(0)
        );
        // No association at all on the endpoint.
        assert_eq!(
            admit(&[], &peer(&["203.0.113.5:1"])),
            Err(Refusal::UnknownPeer)
        );
    }

    #[test]
    fn two_associations_of_one_address_are_told_apart_by_the_port() {
        let rules = [
            rule(&["192.0.2.10"], Some(3000)),
            rule(&["192.0.2.10"], Some(3001)),
        ];
        assert_eq!(admit(&rules, &peer(&["192.0.2.10:3000"])), Ok(0));
        assert_eq!(admit(&rules, &peer(&["192.0.2.10:3001"])), Ok(1));
        assert_eq!(
            admit(&rules, &peer(&["192.0.2.10:3002"])),
            Err(Refusal::PeerPort)
        );
    }

    #[test]
    fn the_log_gets_one_line_per_interval_that_says_what_it_left_out() {
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let mut throttle = Throttle::new(Duration::from_millis(1000));
        // (when, what the throttle says)
        let table = [
            (0, Some(0)),
            (1, None),
            (500, None),
            (999, None),
            (1000, Some(3)),
            (1001, None),
            (5000, Some(1)),
            (6000, Some(0)),
        ];
        for (ms, expected) in table {
            assert_eq!(throttle.event(at(ms)), expected, "at {ms} ms");
        }
    }
}
