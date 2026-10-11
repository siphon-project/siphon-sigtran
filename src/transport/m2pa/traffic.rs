//! What level 3 has one link do with the traffic handed to it, without I/O.
//!
//! A link that routing selects is in one of three states: it carries traffic
//! ([`TrafficState::Open`]), it buffers it while a changeover or a changeback
//! runs (the buffers of ITU-T Q.704 5.5 and 6.3.1, [`TrafficState::Hold`]), or
//! it passes whatever still reaches it on to the alternative links
//! ([`TrafficState::Closed`]). [`LinkTraffic`] also keeps what a failed link
//! held at level 2 until the changeover says what the far end has, so that the
//! retrieval survives the link's next alignment and its association.
//!
//! The state is owned by whichever task serves the link's queue, so messages of
//! one link are held, sent and diverted in the order they were handed over.

use std::collections::VecDeque;

use super::link::Retrievable;

/// The service indicator of a signalling link test message (Q.707 5.4).
const SI_LINK_TEST: u8 = 1;

/// What the link does with traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficState {
    /// It is not a link for traffic: what arrives is sent another way.
    Closed,
    /// It buffers.
    Hold,
    /// It sends.
    Open,
}

/// What to do with one message handed to the link.
#[derive(Debug, PartialEq, Eq)]
pub enum Offer {
    /// Send it on the link.
    Send(Vec<u8>),
    /// It was buffered.
    Held,
    /// Send it by an alternative.
    Divert(Vec<u8>),
    /// The buffer is full: the message is not carried.
    Full,
}

/// The outcome of the diversion that ends a changeover.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diverted {
    /// To be sent by the alternatives, in order: what the far end does not
    /// have of what was sent, what was never sent, what was buffered since.
    pub messages: Vec<Vec<u8>>,
    /// Of `messages`, how many were sent once already on the failed link.
    pub resent: usize,
    /// Sent before the failure and accepted by the far end.
    pub confirmed: usize,
    /// Sent before the failure, not acknowledged, and not sent again.
    pub unconfirmed: usize,
    /// Signalling link test messages among what the link held: they are about
    /// that link and go nowhere else.
    pub link_tests: usize,
}

/// The traffic side of one link at level 3.
#[derive(Debug)]
pub struct LinkTraffic {
    state: TrafficState,
    held: VecDeque<Vec<u8>>,
    kept: Option<Retrievable>,
    capacity: usize,
}

fn is_link_test(msu: &[u8]) -> bool {
    msu.first().is_some_and(|sio| sio & 0x0F == SI_LINK_TEST)
}

impl LinkTraffic {
    /// A link that carries nothing yet, with a buffer of `capacity` messages.
    pub fn new(capacity: usize) -> Self {
        Self {
            state: TrafficState::Closed,
            held: VecDeque::new(),
            kept: None,
            capacity: capacity.max(1),
        }
    }

    /// The current state.
    #[cfg(test)]
    pub fn state(&self) -> TrafficState {
        self.state
    }

    /// Messages in the buffer.
    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// A message for the link. `in_service` says whether level 2 can send now.
    pub fn offer(&mut self, msu: Vec<u8>, in_service: bool) -> Offer {
        match self.state {
            TrafficState::Open if in_service => Offer::Send(msu),
            TrafficState::Closed => Offer::Divert(msu),
            TrafficState::Open | TrafficState::Hold => {
                if self.held.len() >= self.capacity {
                    Offer::Full
                } else {
                    self.held.push_back(msu);
                    Offer::Held
                }
            }
        }
    }

    /// Buffer from now on.
    pub fn hold(&mut self) {
        self.state = TrafficState::Hold;
    }

    /// Level 2 failed, with `left` what it held. A link that carried traffic
    /// buffers from here on and keeps `left` for the changeover. Returns how
    /// many messages are lost with the failure: those of a link that carried
    /// no traffic (management messages on their way), or of a second failure
    /// before the changeover of the first was complete.
    pub fn failed(&mut self, left: Option<Retrievable>) -> usize {
        let carried = self.state != TrafficState::Closed;
        if self.state == TrafficState::Open {
            self.state = TrafficState::Hold;
        }
        let Some(left) = left else { return 0 };
        if carried && self.kept.is_none() {
            self.kept = Some(left);
            return 0;
        }
        let all = left.retrieve(None);
        all.unconfirmed
            .iter()
            .chain(all.resend.iter())
            .filter(|msu| !is_link_test(msu))
            .count()
    }

    /// The changeover is complete (Q.704 5.5): everything the link holds goes
    /// to the alternatives, and the link passes on what still arrives. `fsnc`
    /// is the last message the far end accepted, when it said.
    pub fn divert(&mut self, fsnc: Option<u32>) -> Diverted {
        let mut out = Diverted::default();
        if let Some(kept) = self.kept.take() {
            let retrieval = kept.retrieve(fsnc);
            out.confirmed = retrieval.confirmed;
            for msu in retrieval.unconfirmed {
                if is_link_test(&msu) {
                    out.link_tests += 1;
                } else {
                    out.unconfirmed += 1;
                }
            }
            for msu in retrieval.resend {
                if is_link_test(&msu) {
                    out.link_tests += 1;
                } else {
                    out.messages.push(msu);
                }
            }
            out.resent = out.messages.len();
        }
        out.messages.extend(self.held.drain(..));
        self.state = TrafficState::Closed;
        out
    }

    /// The link carries traffic (again): the buffer goes out on the link
    /// itself, in order. Returns it, and how many messages of a failure that
    /// no changeover retrieved are lost.
    pub fn open(&mut self) -> (Vec<Vec<u8>>, usize) {
        self.state = TrafficState::Open;
        let lost = self.kept.take().map_or(0, |kept| {
            let all = kept.retrieve(None);
            all.unconfirmed
                .iter()
                .chain(all.resend.iter())
                .filter(|msu| !is_link_test(msu))
                .count()
        });
        (self.held.drain(..).collect(), lost)
    }
}

#[cfg(test)]
mod tests {
    use super::super::link::{Action, Failure, Link, LinkTimers, Proving};
    use super::*;
    use std::time::Instant;

    /// An MSU of a user part (service indicator 8) or a link test (1).
    fn msu(si: u8, tag: u8) -> Vec<u8> {
        vec![0x80 | si, 0, 0, 0, 0, tag]
    }

    /// What a link in service that sent `sent` and had `acked` of them
    /// acknowledged leaves when it fails.
    fn left_by(sent: &[Vec<u8>], acked: usize) -> Retrievable {
        use ::m2pa::LinkState as Status;
        let mut link = Link::new(LinkTimers::default(), Proving::Emergency, 16);
        let mut out = Vec::new();
        let now = Instant::now();
        link.start(&mut out);
        link.on_status(Status::Alignment, 0x00FF_FFFF, now, &mut out);
        link.on_status(Status::ProvingEmergency, 0x00FF_FFFF, now, &mut out);
        link.timeout(super::super::link::Timer::T4, now, &mut out);
        link.on_status(Status::Ready, 0x00FF_FFFF, now, &mut out);
        assert!(out.contains(&Action::InService), "{out:?}");
        for m in sent {
            link.send(m.clone(), now, &mut out);
        }
        if acked > 0 {
            // An empty User Data message acknowledging the first `acked`.
            let empty = ::m2pa::UserDataMessage::empty();
            link.on_data(acked as u32 - 1, 0x00FF_FFFF, empty, now, &mut out);
        }
        link.fail(Failure::T7, &mut out);
        link.detach().expect("a failed link leaves its buffers")
    }

    #[test]
    fn a_closed_link_passes_traffic_on_and_an_open_one_sends_it() {
        let mut t = LinkTraffic::new(4);
        assert_eq!(t.offer(msu(8, 1), true), Offer::Divert(msu(8, 1)));
        let (buffered, lost) = t.open();
        assert!(buffered.is_empty() && lost == 0);
        assert_eq!(t.offer(msu(8, 2), true), Offer::Send(msu(8, 2)));
        // Open, but level 2 cannot send: buffered, not discarded.
        assert_eq!(t.offer(msu(8, 3), false), Offer::Held);
        assert_eq!(t.held(), 1);
    }

    #[test]
    fn the_buffer_is_bounded_and_keeps_the_order() {
        let mut t = LinkTraffic::new(2);
        t.hold();
        assert_eq!(t.offer(msu(8, 1), true), Offer::Held);
        assert_eq!(t.offer(msu(8, 2), true), Offer::Held);
        assert_eq!(t.offer(msu(8, 3), true), Offer::Full);
        // Q.704 6.3.2: traffic restarts on the link "starting with the
        // content of the changeback buffer".
        assert_eq!(t.open().0, [msu(8, 1), msu(8, 2)]);
        assert_eq!(t.state(), TrafficState::Open);
    }

    #[test]
    fn changeover_with_the_far_ends_number_sends_again_exactly_what_it_lacks() {
        // Five sent (FSN 0 to 4), the first acknowledged, a link test among
        // them. The far end accepted up to FSN 2.
        let sent = [msu(8, 0), msu(8, 1), msu(1, 9), msu(8, 3), msu(8, 4)];
        let mut t = LinkTraffic::new(8);
        t.open();
        assert_eq!(t.failed(Some(left_by(&sent, 1))), 0);
        assert_eq!(t.state(), TrafficState::Hold);
        // Traffic that arrives during the changeover is buffered (5.5).
        assert_eq!(t.offer(msu(8, 5), false), Offer::Held);

        let d = t.divert(Some(2));
        // "the message signal units successive to that indicated by the
        // message are those which have to be retransmitted" (5.4.3), then
        // what was buffered.
        assert_eq!(d.messages, [msu(8, 3), msu(8, 4), msu(8, 5)]);
        assert_eq!((d.resent, d.confirmed, d.unconfirmed), (2, 2, 0));
        assert_eq!(d.link_tests, 0, "the link test was accepted before FSN 2");
        assert_eq!(t.state(), TrafficState::Closed);
        assert_eq!(t.offer(msu(8, 6), false), Offer::Divert(msu(8, 6)));
    }

    #[test]
    fn changeover_without_a_number_sends_nothing_twice() {
        // Q.704 5.6.2, 5.7.2: only "traffic not yet transmitted" starts on
        // the alternative. What was sent and never acknowledged may be lost,
        // and is counted as that.
        let sent = [msu(8, 0), msu(8, 1), msu(1, 9)];
        let mut t = LinkTraffic::new(8);
        t.open();
        t.failed(Some(left_by(&sent, 1)));
        t.offer(msu(8, 5), false);
        let d = t.divert(None);
        assert_eq!(d.messages, [msu(8, 5)]);
        assert_eq!(
            (d.resent, d.confirmed, d.unconfirmed, d.link_tests),
            (0, 0, 1, 1)
        );
    }

    #[test]
    fn a_link_test_is_never_sent_on_another_link() {
        let sent = [msu(1, 9), msu(8, 1)];
        let mut t = LinkTraffic::new(8);
        t.open();
        t.failed(Some(left_by(&sent, 0)));
        // The far end has nothing: an FSNC that is this end's last
        // acknowledged number, so both are to be sent again.
        let d = t.divert(Some(0x00FF_FFFF));
        assert_eq!(d.messages, [msu(8, 1)]);
        assert_eq!((d.resent, d.link_tests), (1, 1));
    }

    #[test]
    fn what_a_link_without_traffic_held_is_lost_with_it() {
        let sent = [msu(0, 1), msu(1, 9)];
        let mut t = LinkTraffic::new(8);
        // Closed: it carried management only.
        assert_eq!(t.failed(Some(left_by(&sent, 0))), 1, "not the link test");
        assert_eq!(t.state(), TrafficState::Closed);
        assert!(t.divert(None).messages.is_empty());

        // A second failure before the changeover of the first completes
        // keeps the first one's buffers.
        let mut t = LinkTraffic::new(8);
        t.open();
        assert_eq!(t.failed(Some(left_by(&[msu(8, 1)], 0))), 0);
        assert_eq!(t.failed(Some(left_by(&[msu(8, 2), msu(8, 3)], 0))), 2);
        assert_eq!(t.divert(Some(0x00FF_FFFF)).messages, [msu(8, 1)]);
    }
}
