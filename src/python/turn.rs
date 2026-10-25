//! Where a script handler's turn runs.
//!
//! The dialogue engine calls a handler synchronously, from whichever thread is
//! running the turn. On the live node that is a lane's blocking thread (see
//! `TransportHandle::serve_dialogues`); in the loopback API it is the script's
//! own thread, already attached to the interpreter.
//!
//! A turn reached from a thread that is not attached never attaches there. Its
//! Python runs as siphon executor jobs: one builds the handler's arguments and
//! calls it, and an `async def` handler's coroutine goes to siphon's asyncio
//! pool, where a second job reads what it staged once it has finished. The lane thread waits for all of it released from the
//! interpreter, so neither a garbage collection's stop-the-world nor a slow
//! coroutine holds an executor worker or a tokio worker.
//!
//! A turn reached from an attached thread (a script driving the loopback node,
//! a handler calling back into it) runs in place, as it always has.

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;

use siphon::script::async_pool::AsyncPool;
use siphon::script::blocking::block_on_released;
use siphon::script::py_executor;

use super::{drive, handler_raised, hex, DlgCmd, PyDialogue, PyIncomingOp, PyPeerTurn};
use crate::dialogue::Problem;

/// What a handler is called with besides its dialogue.
pub(super) enum TurnArg {
    /// The opening operation of a dialogue opened against us.
    Begin(PyIncomingOp),
    /// The peer's turn, an expired invocation timer, or a dialogue that ended.
    Peer(PyPeerTurn),
    /// An originating dialogue's start: the dialogue alone.
    Start,
}

/// One call of a script handler, owned, so it can be handed to the thread that
/// runs it.
pub(super) struct ScriptTurn {
    pub func: Arc<Py<PyAny>>,
    pub otid: Vec<u8>,
    pub dtid: Vec<u8>,
    pub application_context: Vec<u32>,
    pub arg: TurnArg,
    /// What to reject if the handler finds a parameter of this turn mistyped.
    pub rejection: Option<(Option<i8>, Problem)>,
}

/// Call the handler for one turn and return the commands it staged.
pub(super) fn run(turn: ScriptTurn) -> Vec<DlgCmd> {
    // SAFETY: `PyGILState_Check` only reads this thread's own thread state.
    let attached = unsafe { pyo3::ffi::PyGILState_Check() } == 1;
    if attached {
        return Python::attach(|py| run_in_place(py, turn));
    }
    match tokio::runtime::Handle::try_current() {
        // The lane's blocking thread: wait released for the executor jobs.
        Ok(_) => block_on_released(dispatch(turn)),
        // A thread with no runtime to wait on (a Rust caller driving the
        // engine by hand): there is nowhere else to run it.
        Err(_) => Python::attach(|py| run_in_place(py, turn)),
    }
}

/// What the first step of a turn left to do.
enum Started<'py> {
    /// The handler returned, or raised; this is what it staged.
    Done(Vec<DlgCmd>),
    /// An `async def` handler: its coroutine, not yet run, and the dialogue
    /// handle it stages on.
    Coroutine {
        coroutine: Bound<'py, PyAny>,
        dialogue: Bound<'py, PyDialogue>,
    },
}

/// Ids and rejection of a turn, kept for reading its outcome.
struct Outcome {
    otid: Vec<u8>,
    dtid: Vec<u8>,
    rejection: Option<(Option<i8>, Problem)>,
}

impl Outcome {
    /// What a handler that returned (`Ok`) or raised (`Err`) staged.
    fn read(
        &self,
        py: Python<'_>,
        dialogue: &Bound<'_, PyDialogue>,
        returned: PyResult<()>,
    ) -> Vec<DlgCmd> {
        match returned {
            Ok(()) => dialogue.borrow().take(),
            Err(error) => handler_raised(py, &error, self.rejection, &self.otid, &self.dtid),
        }
    }
}

/// Build the arguments and call the handler.
fn start<'py>(py: Python<'py>, turn: ScriptTurn, outcome: &Outcome) -> Started<'py> {
    let ScriptTurn {
        func,
        otid,
        dtid,
        application_context,
        arg,
        ..
    } = turn;
    let dialogue = match Bound::new(py, PyDialogue::new(otid, dtid, &application_context)) {
        Ok(dialogue) => dialogue,
        Err(error) => {
            eprintln!("siphon-sigtran: building Dialogue failed: {error}");
            return Started::Done(Vec::new());
        }
    };
    let call = match arg {
        TurnArg::Begin(op) => match Bound::new(py, op) {
            Ok(op) => func.bind(py).call1((&dialogue, &op)),
            Err(error) => {
                eprintln!("siphon-sigtran: building IncomingOp failed: {error}");
                return Started::Done(Vec::new());
            }
        },
        TurnArg::Peer(peer) => match Bound::new(py, peer) {
            Ok(peer) => func.bind(py).call1((&dialogue, &peer)),
            Err(error) => {
                eprintln!("siphon-sigtran: building PeerTurn failed: {error}");
                return Started::Done(Vec::new());
            }
        },
        TurnArg::Start => func.bind(py).call1((&dialogue,)),
    };
    let returned = match call {
        Ok(returned) => returned,
        Err(error) => return Started::Done(outcome.read(py, &dialogue, Err(error))),
    };
    let is_coroutine = py
        .import("asyncio")
        .and_then(|asyncio| asyncio.call_method1("iscoroutine", (&returned,)))
        .and_then(|is| is.is_truthy());
    // Every coroutine runs on an event loop, even one that cannot suspend: a
    // handler may use the running loop (`asyncio.get_running_loop()`,
    // `create_task`) without awaiting anything.
    match is_coroutine {
        Ok(false) => Started::Done(outcome.read(py, &dialogue, Ok(()))),
        Ok(true) => Started::Coroutine {
            coroutine: returned,
            dialogue,
        },
        Err(error) => Started::Done(outcome.read(py, &dialogue, Err(error))),
    }
}

fn outcome_of(turn: &ScriptTurn) -> Outcome {
    Outcome {
        otid: turn.otid.clone(),
        dtid: turn.dtid.clone(),
        rejection: turn.rejection,
    }
}

/// The turn on this attached thread. A coroutine runs on the asyncio pool while this thread waits released; with no pool (a script
/// driving the loopback node outside siphon) it runs on a loop of its own here.
fn run_in_place(py: Python<'_>, turn: ScriptTurn) -> Vec<DlgCmd> {
    let outcome = outcome_of(&turn);
    let (coroutine, dialogue) = match start(py, turn, &outcome) {
        Started::Done(cmds) => return cmds,
        Started::Coroutine {
            coroutine,
            dialogue,
        } => (coroutine, dialogue),
    };
    let pool = AsyncPool::global();
    let multi_thread = tokio::runtime::Handle::try_current()
        .map(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        .unwrap_or(false);
    let returned = match pool {
        Some(pool) if multi_thread => match pool.submit(py, &coroutine) {
            Ok((receiver, future)) => {
                let limit = pool.coroutine_timeout();
                let settled = block_on_released(settle(receiver, limit));
                if settled.is_err() && limit_passed(&settled) {
                    let _ = future.bind(py).call_method0("cancel");
                }
                settled.map(|_| ()).map_err(Settled::into_error)
            }
            Err(error) => Err(error),
        },
        _ => drive(py, &coroutine),
    };
    outcome.read(py, &dialogue, returned)
}

/// The turn as executor jobs, awaited without the interpreter.
async fn dispatch(turn: ScriptTurn) -> Vec<DlgCmd> {
    let ids = format!("otid={} dtid={}", hex(&turn.otid), hex(&turn.dtid));
    let outcome = outcome_of(&turn);

    /// The first job's result: done, or a coroutine running on the pool.
    enum First {
        Done(Vec<DlgCmd>),
        Waiting {
            receiver: tokio::sync::oneshot::Receiver<PyResult<Py<PyAny>>>,
            future: Py<PyAny>,
            dialogue: Py<PyDialogue>,
            limit: Duration,
            outcome: Outcome,
        },
    }

    let first = py_executor::try_run(move || {
        Python::attach(|py| match start(py, turn, &outcome) {
            Started::Done(cmds) => First::Done(cmds),
            Started::Coroutine {
                coroutine,
                dialogue,
            } => match AsyncPool::global() {
                Some(pool) => match pool.submit(py, &coroutine) {
                    Ok((receiver, future)) => First::Waiting {
                        receiver,
                        future,
                        dialogue: dialogue.unbind(),
                        limit: pool.coroutine_timeout(),
                        outcome,
                    },
                    Err(error) => First::Done(outcome.read(py, &dialogue, Err(error))),
                },
                // No pool: siphon is not running, so there is no driver to
                // hand it to.
                None => {
                    let returned = drive(py, &coroutine);
                    First::Done(outcome.read(py, &dialogue, returned))
                }
            },
        })
    })
    .await;

    let (receiver, future, dialogue, limit, outcome) = match first {
        Ok(First::Done(cmds)) => return cmds,
        Ok(First::Waiting {
            receiver,
            future,
            dialogue,
            limit,
            outcome,
        }) => (receiver, future, dialogue, limit, outcome),
        Err(_) => {
            eprintln!(
                "siphon-sigtran: ERROR: dialogue {ids}: the termination handler did not run (the script executor shed or lost it)"
            );
            return Vec::new();
        }
    };

    let settled = settle(receiver, limit).await;
    let finished = py_executor::run_queued(move || {
        Python::attach(|py| {
            if limit_passed(&settled) {
                let _ = future.bind(py).call_method0("cancel");
            }
            drop(future);
            let dialogue = dialogue.into_bound(py);
            outcome.read(
                py,
                &dialogue,
                settled.map(|_| ()).map_err(Settled::into_error),
            )
        })
    })
    .await;
    finished.unwrap_or_else(|_| {
        eprintln!(
            "siphon-sigtran: ERROR: dialogue {ids}: the end of an async termination handler was not read (the script executor stopped)"
        );
        Vec::new()
    })
}

/// Why a coroutine on the pool produced no value.
enum Settled {
    /// It raised.
    Raised(PyErr),
    /// It ran past the pool's coroutine timeout and is cancelled.
    TimedOut(Duration),
    /// Its driver went away without an answer.
    Lost,
}

impl Settled {
    fn into_error(self) -> PyErr {
        match self {
            Self::Raised(error) => error,
            Self::TimedOut(limit) => pyo3::exceptions::PyTimeoutError::new_err(format!(
                "async termination handler ran past {}s and was cancelled",
                limit.as_secs_f64()
            )),
            Self::Lost => pyo3::exceptions::PyRuntimeError::new_err(
                "async termination handler's driver loop went away without an answer",
            ),
        }
    }
}

fn limit_passed(settled: &Result<Py<PyAny>, Settled>) -> bool {
    matches!(settled, Err(Settled::TimedOut(_)))
}

/// Wait for a coroutine handed to the pool, no longer than `limit`.
async fn settle(
    receiver: tokio::sync::oneshot::Receiver<PyResult<Py<PyAny>>>,
    limit: Duration,
) -> Result<Py<PyAny>, Settled> {
    match tokio::time::timeout(limit, receiver).await {
        Ok(Ok(Ok(value))) => Ok(value),
        Ok(Ok(Err(error))) => Err(Settled::Raised(error)),
        Ok(Err(_)) => Err(Settled::Lost),
        Err(_) => Err(Settled::TimedOut(limit)),
    }
}
