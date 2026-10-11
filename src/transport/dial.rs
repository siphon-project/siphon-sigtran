//! When a `client` association is dialled, and when it is dialled again.
//!
//! The state machine of one association this node opens: it is dialled when
//! the node starts, again after every attempt that failed, and again after the
//! association it had was lost. Between attempts it waits: a back-off that
//! doubles from `initial` to `max`, with a part of it taken off at random so
//! that associations which fail together are not dialled together. Nothing
//! here touches a socket or a clock: the task that owns the association feeds
//! it what happened and when, and does what it is told ([`Action`]).
//!
//! RFC 4666 4.3.3 leaves it to the implementation ("In the case of
//! SCTP-COMMUNICATION_DOWN, the SCTP client MAY try to re-establish the SCTP
//! Association. This MAY be done by the M3UA layer automatically"), and 4.3.4.6
//! asks for it after a heartbeat that went unanswered ("the signalling process
//! SHOULD attempt to re-establish communication if it is configured as the
//! client for the disconnected M3UA peer").

use std::hash::{BuildHasher, Hasher};
use std::time::{Duration, Instant};

pub use crate::metrics::DialFailure as Failure;

/// The timers of one dialled association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// How long one attempt may take before it is given up.
    pub connect_timeout: Duration,
    /// The wait after the first failure, and after an association that had
    /// been up was lost.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
    /// How much of a wait is taken off at random, in percent (0 to 100).
    pub jitter_percent: u8,
    /// While attempts keep failing for the same reason, one line of the log
    /// per this long.
    pub log_every: Duration,
}

/// How often the log says that an association is still not there.
pub const LOG_EVERY: Duration = Duration::from_secs(60);

/// Where the association is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not started.
    Idle,
    /// An attempt is running.
    Connecting,
    /// The association is established, since then.
    Up(Instant),
    /// Waiting to dial again.
    Waiting,
    /// Stopped for good.
    Stopped,
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// The node started.
    Start,
    /// The attempt succeeded.
    Connected,
    /// The attempt failed.
    Failed(Failure),
    /// The association that was up has ended.
    Lost,
    /// The wait is over.
    Elapsed,
    /// The node is shutting down.
    Stop,
}

/// What the task has to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Dial, for at most [`Settings::connect_timeout`].
    Connect,
    /// Serve the association until it ends.
    Serve,
    /// Wait this long, then say [`Input::Elapsed`].
    Wait(Duration),
    /// Write this line.
    Log(Line),
}

/// A line of the log: one per change of state, and one per
/// [`Settings::log_every`] while nothing changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    /// The association is established.
    Established {
        /// Attempts that failed since it was last established.
        failed: u32,
    },
    /// An attempt failed: the first of a run, the first for this reason, or
    /// the first in a while.
    Failing {
        /// Why this attempt failed.
        reason: Failure,
        /// Attempts that failed since the last line and have none.
        quiet: u32,
        /// The wait before the next attempt.
        next: Duration,
    },
    /// The association ended.
    Lost {
        /// How long it had been up.
        up: Duration,
        /// The wait before it is dialled again.
        next: Duration,
    },
}

/// A sequence of numbers that is good enough to spread waits apart
/// (xorshift64*, Vigna 2016). Not for anything that has to be unpredictable.
#[derive(Debug, Clone)]
pub struct Jitter(u64);

impl Jitter {
    /// A sequence from a seed. Zero is replaced: the generator has no way out
    /// of it.
    pub fn seeded(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// A sequence of its own for one association: the standard library's
    /// hasher is keyed at random per process from the operating system, and
    /// the name of the association is hashed with it, so two associations of
    /// one node and the same association of two nodes get different waits.
    pub fn for_association(id: &str) -> Self {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write(id.as_bytes());
        Self::seeded(hasher.finish())
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number from 0 to `bound` inclusive.
    fn up_to(&mut self, bound: u64) -> u64 {
        match bound.checked_add(1) {
            Some(span) => (self.next() >> 11) % span,
            None => self.next(),
        }
    }
}

/// The state machine of one dialled association.
#[derive(Debug)]
pub struct Dial {
    settings: Settings,
    state: State,
    /// Waits since the association was last up for [`Settings::max`]: the
    /// exponent of the next wait.
    waits: u32,
    /// Attempts that failed since the association was last established.
    failed: u32,
    jitter: Jitter,
    /// The reason of the last failure that was logged, and when.
    logged: Option<(Failure, Instant)>,
    /// Failures since the last line.
    quiet: u32,
    /// The wait that is running.
    waiting: Duration,
}

impl Dial {
    /// A machine in [`State::Idle`].
    pub fn new(settings: Settings, jitter: Jitter) -> Self {
        Self {
            settings,
            state: State::Idle,
            waits: 0,
            failed: 0,
            jitter,
            logged: None,
            quiet: 0,
            waiting: Duration::ZERO,
        }
    }

    /// Where the association is.
    pub fn state(&self) -> State {
        self.state
    }

    /// The wait that is running, zero in any state but [`State::Waiting`].
    pub fn backoff(&self) -> Duration {
        if self.state == State::Waiting {
            self.waiting
        } else {
            Duration::ZERO
        }
    }

    /// The timers.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The next wait: `initial` doubled once per wait before it, at most
    /// `max`, less up to `jitter_percent` of it.
    fn next_wait(&mut self) -> Duration {
        let initial = self.settings.initial.as_millis().max(1) as u64;
        let max = (self.settings.max.as_millis() as u64).max(initial);
        let doubled = match 1u64.checked_shl(self.waits) {
            Some(factor) => initial.saturating_mul(factor),
            None => u64::MAX,
        };
        let whole = doubled.min(max);
        self.waits = self.waits.saturating_add(1);
        let off = whole.saturating_mul(u64::from(self.settings.jitter_percent.min(100))) / 100;
        let wait = whole.saturating_sub(self.jitter.up_to(off)).max(1);
        self.waiting = Duration::from_millis(wait);
        self.waiting
    }

    /// Feed what happened at `now`; the actions are in the order they are to
    /// be done. An input that makes no sense in the state the machine is in
    /// changes nothing and asks for nothing.
    pub fn handle(&mut self, input: Input, now: Instant) -> Vec<Action> {
        match (self.state, input) {
            (State::Stopped, _) => Vec::new(),
            (_, Input::Stop) => {
                self.state = State::Stopped;
                Vec::new()
            }
            (State::Idle, Input::Start) | (State::Waiting, Input::Elapsed) => {
                self.state = State::Connecting;
                vec![Action::Connect]
            }
            (State::Connecting, Input::Connected) => {
                self.state = State::Up(now);
                let failed = std::mem::take(&mut self.failed);
                self.logged = None;
                self.quiet = 0;
                vec![Action::Log(Line::Established { failed }), Action::Serve]
            }
            (State::Connecting, Input::Failed(reason)) => {
                self.failed = self.failed.saturating_add(1);
                let next = self.next_wait();
                self.state = State::Waiting;
                let mut actions = Vec::new();
                let due = match self.logged {
                    Some((last, at)) => {
                        last != reason
                            || now.saturating_duration_since(at) >= self.settings.log_every
                    }
                    None => true,
                };
                if due {
                    let quiet = std::mem::take(&mut self.quiet);
                    self.logged = Some((reason, now));
                    actions.push(Action::Log(Line::Failing {
                        reason,
                        quiet,
                        next,
                    }));
                } else {
                    self.quiet = self.quiet.saturating_add(1);
                }
                actions.push(Action::Wait(next));
                actions
            }
            (State::Up(since), Input::Lost) => {
                let up = now.saturating_duration_since(since);
                // An association that held for as long as the longest wait
                // was a working one: what comes now starts over. One that
                // did not (a far end that accepts and aborts) is one more
                // failure, and the waits go on growing.
                if up >= self.settings.max {
                    self.waits = 0;
                }
                let next = self.next_wait();
                self.state = State::Waiting;
                vec![Action::Log(Line::Lost { up, next }), Action::Wait(next)]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(jitter_percent: u8) -> Settings {
        Settings {
            connect_timeout: Duration::from_millis(500),
            initial: Duration::from_millis(100),
            max: Duration::from_millis(1000),
            jitter_percent,
            log_every: Duration::from_millis(5000),
        }
    }

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    /// The whole life of an association, one row per input: when it happens
    /// (milliseconds from the start), the state after it, and the actions.
    #[test]
    fn the_association_is_dialled_until_it_is_up_and_again_after_it_is_lost() {
        use Action::*;
        use Failure::*;
        let failing = |reason, quiet, next| {
            Log(Line::Failing {
                reason,
                quiet,
                next: ms(next),
            })
        };
        let start = Instant::now();
        let table: Vec<(u64, Input, State, Vec<Action>)> = vec![
            // Nothing before the start.
            (0, Input::Elapsed, State::Idle, vec![]),
            (0, Input::Connected, State::Idle, vec![]),
            (0, Input::Start, State::Connecting, vec![Connect]),
            // The first failure is logged; the wait doubles to its cap.
            (
                1,
                Input::Failed(Refused),
                State::Waiting,
                vec![failing(Refused, 0, 100), Wait(ms(100))],
            ),
            // A second start, or the end of an association there is not.
            (2, Input::Start, State::Waiting, vec![]),
            (2, Input::Lost, State::Waiting, vec![]),
            (101, Input::Elapsed, State::Connecting, vec![Connect]),
            // The same reason again says nothing.
            (
                102,
                Input::Failed(Refused),
                State::Waiting,
                vec![Wait(ms(200))],
            ),
            (302, Input::Elapsed, State::Connecting, vec![Connect]),
            // Another reason is a line, with what was left out.
            (
                802,
                Input::Failed(Timeout),
                State::Waiting,
                vec![failing(Timeout, 1, 400), Wait(ms(400))],
            ),
            (1202, Input::Elapsed, State::Connecting, vec![Connect]),
            (
                1203,
                Input::Failed(Timeout),
                State::Waiting,
                vec![Wait(ms(800))],
            ),
            (2003, Input::Elapsed, State::Connecting, vec![Connect]),
            // The cap.
            (
                2004,
                Input::Failed(Timeout),
                State::Waiting,
                vec![Wait(ms(1000))],
            ),
            (3004, Input::Elapsed, State::Connecting, vec![Connect]),
            (
                3005,
                Input::Failed(Timeout),
                State::Waiting,
                vec![Wait(ms(1000))],
            ),
            (4005, Input::Elapsed, State::Connecting, vec![Connect]),
            (
                4006,
                Input::Failed(Timeout),
                State::Waiting,
                vec![Wait(ms(1000))],
            ),
            (5006, Input::Elapsed, State::Connecting, vec![Connect]),
            (
                5007,
                Input::Failed(Timeout),
                State::Waiting,
                vec![Wait(ms(1000))],
            ),
            (6007, Input::Elapsed, State::Connecting, vec![Connect]),
            // The same reason, `log_every` after its line: a line again.
            (
                6008,
                Input::Failed(Timeout),
                State::Waiting,
                vec![failing(Timeout, 5, 1000), Wait(ms(1000))],
            ),
            (7008, Input::Elapsed, State::Connecting, vec![Connect]),
            // Up, after nine attempts that failed.
            (
                7009,
                Input::Connected,
                State::Up(start + ms(7009)),
                vec![Log(Line::Established { failed: 9 }), Serve],
            ),
            // Nothing dials an association that is up.
            (7010, Input::Elapsed, State::Up(start + ms(7009)), vec![]),
            (
                7010,
                Input::Failed(Other),
                State::Up(start + ms(7009)),
                vec![],
            ),
            // Lost after less than `max`: the waits go on from where they
            // were (the cap).
            (
                7509,
                Input::Lost,
                State::Waiting,
                vec![
                    Log(Line::Lost {
                        up: ms(500),
                        next: ms(1000),
                    }),
                    Wait(ms(1000)),
                ],
            ),
            (8509, Input::Elapsed, State::Connecting, vec![Connect]),
            (
                8510,
                Input::Connected,
                State::Up(start + ms(8510)),
                vec![Log(Line::Established { failed: 0 }), Serve],
            ),
            // Lost after `max` or more: the waits start over.
            (
                9510,
                Input::Lost,
                State::Waiting,
                vec![
                    Log(Line::Lost {
                        up: ms(1000),
                        next: ms(100),
                    }),
                    Wait(ms(100)),
                ],
            ),
            (9610, Input::Elapsed, State::Connecting, vec![Connect]),
            // A failure right after is the first of a new run: logged, and
            // the second wait of the run.
            (
                9611,
                Input::Failed(Unreachable),
                State::Waiting,
                vec![failing(Unreachable, 0, 200), Wait(ms(200))],
            ),
            // Stopped, and nothing after that.
            (9700, Input::Stop, State::Stopped, vec![]),
            (9811, Input::Elapsed, State::Stopped, vec![]),
            (9811, Input::Start, State::Stopped, vec![]),
        ];
        let mut dial = Dial::new(settings(0), Jitter::seeded(7));
        for (row, (at, input, state, actions)) in table.into_iter().enumerate() {
            let did = dial.handle(input, start + ms(at));
            assert_eq!(did, actions, "row {row}: {input:?} at {at} ms");
            assert_eq!(dial.state(), state, "row {row}: {input:?} at {at} ms");
            let waiting = match did.last() {
                Some(Wait(wait)) => *wait,
                _ if state == State::Waiting => dial.backoff(),
                _ => Duration::ZERO,
            };
            assert_eq!(dial.backoff(), waiting, "row {row}: the gauge");
        }
    }

    #[test]
    fn a_part_of_every_wait_is_taken_off_at_random() {
        let start = Instant::now();
        // (percent, the least a wait of 100, 200, 400, 800, 1000 may be)
        let table = [
            (0u8, [100u64, 200, 400, 800, 1000]),
            (20, [80, 160, 320, 640, 800]),
            (50, [50, 100, 200, 400, 500]),
            (100, [1, 1, 1, 1, 1]),
            // More than all of it is all of it.
            (250, [1, 1, 1, 1, 1]),
        ];
        for (percent, least) in table {
            let mut seen = std::collections::BTreeSet::new();
            for seed in 1..200u64 {
                let mut dial = Dial::new(settings(percent), Jitter::seeded(seed));
                dial.handle(Input::Start, start);
                for (step, (whole, least)) in [100u64, 200, 400, 800, 1000]
                    .into_iter()
                    .zip(least)
                    .enumerate()
                {
                    let actions = dial.handle(Input::Failed(Failure::Refused), start);
                    let Some(Action::Wait(wait)) = actions.last().copied() else {
                        panic!("{percent}%: no wait in {actions:?}");
                    };
                    let wait = wait.as_millis() as u64;
                    assert!(
                        (least..=whole).contains(&wait),
                        "{percent}%, seed {seed}: {wait} is not in {least}..={whole}"
                    );
                    if step == 0 {
                        seen.insert(wait);
                    }
                    dial.handle(Input::Elapsed, start);
                }
            }
            // With any jitter at all, different seeds wait differently.
            assert_eq!(seen.len() > 1, percent > 0, "{percent}%: {seen:?}");
        }
    }

    #[test]
    fn extreme_settings_do_not_overflow() {
        let start = Instant::now();
        let mut dial = Dial::new(
            Settings {
                connect_timeout: Duration::from_millis(1),
                initial: Duration::ZERO,
                max: Duration::from_secs(u64::MAX / 1000),
                jitter_percent: 100,
                log_every: Duration::ZERO,
            },
            Jitter::seeded(0),
        );
        dial.handle(Input::Start, start);
        for _ in 0..200 {
            let actions = dial.handle(Input::Failed(Failure::Other), start);
            assert!(matches!(actions.last(), Some(Action::Wait(wait)) if !wait.is_zero()));
            dial.handle(Input::Elapsed, start);
        }
        // A `max` below `initial` is `initial`.
        let mut dial = Dial::new(
            Settings {
                initial: Duration::from_millis(300),
                max: Duration::from_millis(100),
                ..settings(0)
            },
            Jitter::seeded(1),
        );
        dial.handle(Input::Start, start);
        for _ in 0..3 {
            assert_eq!(
                dial.handle(Input::Failed(Failure::Other), start).last(),
                Some(&Action::Wait(ms(300)))
            );
            dial.handle(Input::Elapsed, start);
        }
    }

    #[test]
    fn each_association_gets_a_sequence_of_its_own() {
        let mut a = Jitter::for_association("link-a");
        let mut b = Jitter::for_association("link-b");
        let first: Vec<u64> = (0..8).map(|_| a.up_to(1_000_000)).collect();
        let second: Vec<u64> = (0..8).map(|_| b.up_to(1_000_000)).collect();
        assert_ne!(first, second);
        assert!(first.iter().all(|v| *v <= 1_000_000));
        // The bounds are kept, the largest one included.
        let mut j = Jitter::seeded(3);
        assert_eq!(j.up_to(0), 0);
        assert!((0..100).all(|_| j.up_to(3) <= 3));
        let _ = j.up_to(u64::MAX);
    }
}
