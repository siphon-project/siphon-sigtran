//! The signalling link test of ITU-T Q.707 2.2, without I/O.
//!
//! "This procedure is to be used when a signalling link is activated or restored
//! ... The signalling link becomes available only if the test is successful."
//! While the link is in service the test "is sent at regular intervals T2". A
//! test whose acknowledgement does not arrive within T1, or arrives wrong, "is
//! considered to have failed and is repeated once"; when the repeat fails too,
//! the link is put out of service and restoration is attempted.
//!
//! Q.707 leaves the action on a failed *periodic* test for further study. This
//! implementation treats it like the test at activation: two failures in a row
//! take the link out of service.
//!
//! Like [`super::link::Link`] it owns no clock: the caller reports the
//! acknowledgement (already checked against the three criteria of 2.2) and the
//! timers, and gets [`TestAction`]s back.

use std::time::Duration;

/// The two timers of Q.707 5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestTimer {
    /// T1, supervision of the acknowledgement (4 to 12 s).
    T1,
    /// T2, the interval between tests (30 to 90 s).
    T2,
}

impl TestTimer {
    /// Both timers, in index order.
    pub const ALL: [TestTimer; 2] = [Self::T1, Self::T2];

    /// A dense index, for a deadline array.
    pub fn index(self) -> usize {
        self as usize
    }
}

/// What the caller has to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestAction {
    /// Send a signalling link test message on the link.
    SendTest,
    /// Start, or restart, a timer.
    Start(TestTimer, Duration),
    /// Stop a timer.
    Stop(TestTimer),
    /// The test at activation passed: the link is available.
    Available,
    /// One attempt failed (no acknowledgement in T1, or a wrong one).
    AttemptFailed,
    /// The test failed twice: take the link out of service.
    Failed,
}

/// Where the test stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestState {
    /// The link is not in service at level 2: nothing to test.
    Idle,
    /// A test message is out; T1 runs.
    First,
    /// The repeat is out; T1 runs.
    Second,
    /// The last test passed; T2 runs until the next one.
    Passed,
}

/// The signalling link test of one link.
#[derive(Debug)]
pub struct LinkTest {
    t1: Duration,
    t2: Duration,
    state: TestState,
    /// A test has passed since the link came into service.
    available: bool,
}

impl LinkTest {
    /// A test that has not started.
    pub fn new(t1: Duration, t2: Duration) -> Self {
        Self {
            t1,
            t2,
            state: TestState::Idle,
            available: false,
        }
    }

    /// The current state.
    #[cfg(test)]
    pub fn state(&self) -> TestState {
        self.state
    }

    /// Whether the link has passed its test since it came into service.
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Whether an acknowledgement is awaited.
    pub fn is_waiting(&self) -> bool {
        matches!(self.state, TestState::First | TestState::Second)
    }

    /// The link came into service at level 2: test it.
    pub fn begin(&mut self, out: &mut Vec<TestAction>) {
        self.available = false;
        self.state = TestState::First;
        out.push(TestAction::Stop(TestTimer::T2));
        out.push(TestAction::SendTest);
        out.push(TestAction::Start(TestTimer::T1, self.t1));
    }

    /// The link left service: forget the test.
    pub fn stop(&mut self, out: &mut Vec<TestAction>) {
        if self.state != TestState::Idle {
            out.push(TestAction::Stop(TestTimer::T1));
            out.push(TestAction::Stop(TestTimer::T2));
        }
        self.state = TestState::Idle;
        self.available = false;
    }

    /// An acknowledgement arrived while one was awaited. `correct` says whether
    /// it met the criteria of Q.707 2.2 (the link it names, the point it comes
    /// from, the pattern).
    pub fn acknowledged(&mut self, correct: bool, out: &mut Vec<TestAction>) {
        if !self.is_waiting() {
            return;
        }
        if !correct {
            self.attempt_failed(out);
            return;
        }
        out.push(TestAction::Stop(TestTimer::T1));
        self.state = TestState::Passed;
        if !self.available {
            self.available = true;
            out.push(TestAction::Available);
        }
        out.push(TestAction::Start(TestTimer::T2, self.t2));
    }

    /// A timer ran out.
    pub fn timeout(&mut self, timer: TestTimer, out: &mut Vec<TestAction>) {
        match (timer, self.state) {
            (TestTimer::T1, TestState::First | TestState::Second) => self.attempt_failed(out),
            (TestTimer::T2, TestState::Passed) => {
                self.state = TestState::First;
                out.push(TestAction::SendTest);
                out.push(TestAction::Start(TestTimer::T1, self.t1));
            }
            _ => {}
        }
    }

    fn attempt_failed(&mut self, out: &mut Vec<TestAction>) {
        out.push(TestAction::AttemptFailed);
        match self.state {
            TestState::First => {
                self.state = TestState::Second;
                out.push(TestAction::SendTest);
                out.push(TestAction::Start(TestTimer::T1, self.t1));
            }
            _ => {
                out.push(TestAction::Stop(TestTimer::T1));
                self.state = TestState::Idle;
                self.available = false;
                out.push(TestAction::Failed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: Duration = Duration::from_millis(40);
    const T2: Duration = Duration::from_millis(300);

    /// What can happen to a test.
    #[derive(Debug, Clone, Copy)]
    enum Event {
        Begin,
        Stop,
        Good,
        Bad,
        T1,
        T2,
    }

    fn test_in(state: TestState) -> LinkTest {
        let mut t = LinkTest::new(T1, T2);
        let mut out = Vec::new();
        match state {
            TestState::Idle => {}
            TestState::First => t.begin(&mut out),
            TestState::Second => {
                t.begin(&mut out);
                t.timeout(TestTimer::T1, &mut out);
            }
            TestState::Passed => {
                t.begin(&mut out);
                t.acknowledged(true, &mut out);
            }
        }
        assert_eq!(t.state(), state);
        t
    }

    /// The state table of Q.707 2.2: for every state and event, the state that
    /// follows, whether a test message is sent, and whether the link is
    /// available afterwards.
    #[test]
    fn the_link_test_state_table() {
        use TestState as S;
        // (state, event, next, test messages sent, available, failed)
        let table: &[(S, Event, S, usize, bool, bool)] = &[
            (S::Idle, Event::Begin, S::First, 1, false, false),
            (S::Idle, Event::Good, S::Idle, 0, false, false),
            (S::Idle, Event::T1, S::Idle, 0, false, false),
            (S::Idle, Event::T2, S::Idle, 0, false, false),
            // First attempt.
            (S::First, Event::Good, S::Passed, 0, true, false),
            (S::First, Event::Bad, S::Second, 1, false, false),
            (S::First, Event::T1, S::Second, 1, false, false),
            (S::First, Event::T2, S::First, 0, false, false),
            (S::First, Event::Stop, S::Idle, 0, false, false),
            // The repeat: "In the case when also the repeated test fails ... the
            // link is put out of service".
            (S::Second, Event::Good, S::Passed, 0, true, false),
            (S::Second, Event::Bad, S::Idle, 0, false, true),
            (S::Second, Event::T1, S::Idle, 0, false, true),
            // Passed: the next test after T2; an acknowledgement nobody asked
            // for is not an event.
            (S::Passed, Event::T2, S::First, 1, true, false),
            (S::Passed, Event::Good, S::Passed, 0, true, false),
            (S::Passed, Event::Bad, S::Passed, 0, true, false),
            (S::Passed, Event::T1, S::Passed, 0, true, false),
            (S::Passed, Event::Stop, S::Idle, 0, false, false),
            (S::Passed, Event::Begin, S::First, 1, false, false),
        ];
        for (state, event, next, tests, available, failed) in table {
            let mut t = test_in(*state);
            let mut out = Vec::new();
            match event {
                Event::Begin => t.begin(&mut out),
                Event::Stop => t.stop(&mut out),
                Event::Good => t.acknowledged(true, &mut out),
                Event::Bad => t.acknowledged(false, &mut out),
                Event::T1 => t.timeout(TestTimer::T1, &mut out),
                Event::T2 => t.timeout(TestTimer::T2, &mut out),
            }
            let what = format!("{state:?} + {event:?}");
            assert_eq!(t.state(), *next, "{what}");
            assert_eq!(
                out.iter().filter(|a| **a == TestAction::SendTest).count(),
                *tests,
                "{what}"
            );
            assert_eq!(t.is_available(), *available, "{what}");
            assert_eq!(out.contains(&TestAction::Failed), *failed, "{what}");
        }
    }

    #[test]
    fn a_periodic_test_that_fails_twice_takes_the_link_out() {
        let mut t = test_in(TestState::Passed);
        let mut out = Vec::new();
        t.timeout(TestTimer::T2, &mut out);
        assert!(t.is_available(), "available while the periodic test runs");
        t.timeout(TestTimer::T1, &mut out);
        assert!(t.is_available());
        t.timeout(TestTimer::T1, &mut out);
        assert!(!t.is_available());
        assert!(out.contains(&TestAction::Failed));
        assert_eq!(
            out.iter()
                .filter(|a| **a == TestAction::AttemptFailed)
                .count(),
            2
        );
    }

    #[test]
    fn the_timers_follow_the_states() {
        let mut t = LinkTest::new(T1, T2);
        let mut out = Vec::new();
        t.begin(&mut out);
        assert!(out.contains(&TestAction::Start(TestTimer::T1, T1)));
        out.clear();
        t.acknowledged(true, &mut out);
        assert_eq!(
            out,
            [
                TestAction::Stop(TestTimer::T1),
                TestAction::Available,
                TestAction::Start(TestTimer::T2, T2)
            ]
        );
        out.clear();
        t.timeout(TestTimer::T2, &mut out);
        t.acknowledged(true, &mut out);
        assert!(
            !out.contains(&TestAction::Available),
            "available is said once"
        );
    }
}
