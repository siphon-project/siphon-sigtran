//! Where a handler's Python runs on the live path.
//!
//! The lane of `TransportHandle::serve_dialogues` hands a turn to the engine on
//! one of tokio's blocking threads, and the origination drain hands a `begin` to
//! it the same way; that is reproduced here, on a runtime whose threads are
//! named so they can be told apart. Each handler writes down the name of the
//! thread it runs on. None of them may be one of the runtime's: a thread of
//! tokio that attaches holds every garbage collection's stop-the-world open for
//! as long as it waits, so a collection loop runs on another thread throughout.
//! Every wait has a deadline, so a regression fails instead of hanging.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule};
use tokio::sync::mpsc;

use siphon::script::async_pool::AsyncPool;
use siphon::script::py_executor::{ExecutorConfig, PyExecutor};

use crate::transport::framing::{Msu, SI_SCCP};
use crate::transport::Origination;

/// The name of every thread of the test's tokio runtime, workers and blocking
/// threads alike (Linux keeps the first 15 bytes).
const TOKIO_THREADS: &str = "sigtran-tokio";

const SCRIPT: &str = r#"
import asyncio
import gc
import threading

import siphon
from siphon import gsm_map

node = siphon.configure("""
node: { point_code: 1000, variant: ITU }
associations: []
sccp:
  local_ssns: [6, 8]
""")

WHERE = []

def here(tag):
    with open(f"/proc/self/task/{threading.get_native_id()}/comm") as comm:
        WHERE.append((tag, comm.read().strip()))

STOP = threading.Event()
COLLECTIONS = [0]

def collect():
    while not STOP.is_set():
        gc.collect()
        COLLECTIONS[0] += 1

@gsm_map.on_operation("sri-sm")
def answer_at_once(dlg, op):
    here("sync")
    dlg.end()

@gsm_map.on_operation("report-sm-delivery-status")
async def answer_later(dlg, op):
    here("async-before")
    await asyncio.sleep(0.05)
    here("async-after")
    dlg.end()

@gsm_map.on_operation("mo-forward-sm")
async def originate_then_answer(dlg, op):
    here("originating-before")
    peer = await gsm_map.begin(
        gsm_map.mt_forward_sm(imsi="001010000000042", sc_addr="15550100", tpdu=b"\x04\x00"),
        called_gt="15550180", called_ssn=8, calling_gt="15550100", calling_ssn=8,
        dpc=2000, ac=gsm_map.AC.short_msg_mt_relay,
    )
    here("originating-after")
    assert peer.is_end
    dlg.end()

CANCELLED = []

@gsm_map.on_operation("purge-ms")
async def never_answers(dlg, op):
    here("stuck")
    try:
        await asyncio.sleep(60)
    except asyncio.CancelledError:
        CANCELLED.append(True)
        raise
    dlg.end()

def on_reply(dlg, peer):
    here("on-reply")

def begin_of(op, ssn):
    return bytes(node.assemble_begin(op=op, called_gt="15550100", called_ssn=ssn, calling_gt="15550180"))
"#;

/// A UDT carrying TCAP, as the transport hands it to the engine.
fn msu(payload: Vec<u8>) -> Msu {
    Msu {
        opc: 2000,
        dpc: 1000,
        si: SI_SCCP,
        ni: 0,
        mp: 0,
        sls: 0,
        payload,
    }
}

fn bytes_of(value: Bound<'_, PyAny>) -> Vec<u8> {
    value
        .cast_into::<PyBytes>()
        .expect("bytes")
        .as_bytes()
        .to_vec()
}

#[test]
fn no_handler_runs_on_a_tokio_thread_while_collections_run() {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(drive_dialogues);
        let _ = done.send(outcome);
    });
    match finished.recv_timeout(Duration::from_secs(60)) {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("the dialogues did not finish within 60 s: a turn is stuck"),
    }
}

fn drive_dialogues() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(TOKIO_THREADS)
        .enable_all()
        .build()
        .expect("runtime");
    Python::initialize();
    PyExecutor::install(
        runtime.handle().clone(),
        ExecutorConfig {
            core_threads: 2,
            max_threads: 4,
            queue_capacity: 64,
            stall_abort: None,
        },
    );
    // The coroutine timeout the stuck handler below runs into.
    AsyncPool::install(2, runtime.handle().clone(), Duration::from_secs(2));
    let (origin_tx, mut origin_rx) = mpsc::unbounded_channel::<Origination>();
    super::set_origin_tx(origin_tx);

    let globals = Python::attach(|py| {
        let siphon = PyModule::new(py, "siphon").expect("module");
        super::register(py, &siphon).expect("register");
        py.import("sys")
            .and_then(|sys| sys.getattr("modules"))
            .and_then(|modules| modules.set_item("siphon", &siphon))
            .expect("mount");
        let globals = PyDict::new(py);
        let code = std::ffi::CString::new(SCRIPT).expect("no NUL");
        if let Err(error) = py.run(code.as_c_str(), Some(&globals), None) {
            error.print(py);
            panic!("the script failed: {error}");
        }
        globals.unbind()
    });
    let engine = super::node().engine();

    // Collections on a thread of their own for the whole run.
    let collector = Python::attach(|py| {
        globals
            .bind(py)
            .get_item("collect")
            .expect("lookup")
            .expect("collect")
            .unbind()
    });
    let collecting = std::thread::spawn(move || {
        Python::attach(|py| {
            let _ = collector.bind(py).call0();
        });
    });

    let begin = |op: &str, ssn: u8| {
        Python::attach(|py| {
            let begin_of = globals.bind(py).get_item("begin_of").ok().flatten();
            bytes_of(
                begin_of
                    .expect("begin_of")
                    .call1((op, ssn))
                    .expect("assemble"),
            )
        })
    };
    let deliver = |payload: Vec<u8>| {
        let engine = Arc::clone(&engine);
        runtime.spawn_blocking(move || engine.deliver(&msu(payload), "loopback"))
    };

    // A sync handler, and an async one that suspends.
    let sync_turn = deliver(begin("sri-sm", 6));
    let async_turn = deliver(begin("report-sm-delivery-status", 6));
    // An async handler that never finishes: cancelled at the pool's timeout.
    let stuck_turn = deliver(begin("purge-ms", 6));
    // An async handler that originates a dialogue and waits for its answer.
    let originating_turn = deliver(begin("mo-forward-sm", 8));

    let origination = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(20), origin_rx.recv()).await })
        .expect("the handler originated within 20 s")
        .expect("an origination");
    let begun = {
        let engine = Arc::clone(&engine);
        runtime
            .block_on(
                runtime.spawn_blocking(move || engine.begin(origination.req, origination.handler)),
            )
            .expect("begin ran")
            .expect("the Begin was built")
    };
    let answer = Python::attach(|py| {
        let node = globals
            .bind(py)
            .get_item("node")
            .ok()
            .flatten()
            .expect("node");
        let otid = node
            .call_method1("decode", (PyBytes::new(py, &begun.1[0].payload),))
            .and_then(|decoded| decoded.getattr("otid"))
            .expect("otid");
        let gsm_map = py
            .import("siphon")
            .and_then(|m| m.getattr("gsm_map"))
            .expect("gsm_map");
        let staged = gsm_map.call_method0("mt_forward_sm_res").expect("result");
        let kwargs = PyDict::new(py);
        kwargs.set_item("dtid", otid).expect("dtid");
        kwargs.set_item("staged", staged).expect("staged");
        bytes_of(
            node.call_method("assemble_end", (), Some(&kwargs))
                .expect("assemble_end"),
        )
    });
    let answered = deliver(answer);

    // A dialogue the script originates itself, answered by the peer.
    let originated = Python::attach(|py| {
        let run = std::ffi::CString::new(
            "FRAMES = node.originate(invoke=gsm_map.mt_forward_sm(imsi='001010000000042', \
             sc_addr='15550100', tpdu=b'\\x04\\x00', more_messages_to_send=True), \
             on_reply=on_reply, called_gt='15550180', called_ssn=8, calling_gt='15550100', \
             calling_ssn=8, dpc=2000, ac=gsm_map.AC.short_msg_mt_relay)\n\
             ACK = bytes(node.assemble_continue(dtid=node.decode(FRAMES[0]).otid, \
             staged=gsm_map.mt_forward_sm_res(), invoke_id=1))\n",
        )
        .expect("no NUL");
        py.run(run.as_c_str(), Some(globals.bind(py)), None)
            .expect("originate");
        bytes_of(
            globals
                .bind(py)
                .get_item("ACK")
                .ok()
                .flatten()
                .expect("ACK"),
        )
    });
    let replied = deliver(originated);

    let deadline = Instant::now() + Duration::from_secs(30);
    for (name, turn) in [
        ("sync", sync_turn),
        ("async", async_turn),
        ("originating", originating_turn),
        ("originated answer", answered),
        ("on_reply", replied),
    ] {
        let left = deadline.saturating_duration_since(Instant::now());
        runtime
            .block_on(async { tokio::time::timeout(left, turn).await })
            .unwrap_or_else(|_| panic!("the {name} turn did not finish"))
            .unwrap_or_else(|error| panic!("the {name} turn panicked: {error}"));
    }
    // The stuck handler staged nothing, so its Begin is aborted, once the
    // coroutine has run into the timeout and been cancelled.
    let left = deadline.saturating_duration_since(Instant::now());
    let stuck_out = runtime
        .block_on(async { tokio::time::timeout(left, stuck_turn).await })
        .expect("the stuck turn finished at the coroutine timeout")
        .expect("the stuck turn did not panic");
    let stuck_kind = Python::attach(|py| {
        let node = globals
            .bind(py)
            .get_item("node")
            .ok()
            .flatten()
            .expect("node");
        node.call_method1("decode", (PyBytes::new(py, &stuck_out[0].payload),))
            .and_then(|decoded| decoded.getattr("kind"))
            .and_then(|kind| kind.extract::<String>())
            .expect("kind")
    });
    assert_eq!(stuck_kind, "abort", "the unanswered Begin is aborted");
    let cancelled_by = Instant::now() + Duration::from_secs(5);
    while !Python::attach(|py| {
        globals
            .bind(py)
            .get_item("CANCELLED")
            .ok()
            .flatten()
            .and_then(|list| list.len().ok())
            .unwrap_or(0)
            > 0
    }) {
        assert!(
            Instant::now() < cancelled_by,
            "the timed-out coroutine was cancelled"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let (seen, collections) = Python::attach(|py| {
        let globals = globals.bind(py);
        let _ = globals
            .get_item("STOP")
            .ok()
            .flatten()
            .map(|stop| stop.call_method0("set"));
        let seen: Vec<(String, String)> = globals
            .get_item("WHERE")
            .ok()
            .flatten()
            .and_then(|list| list.cast_into::<PyList>().ok())
            .and_then(|list| list.extract().ok())
            .expect("WHERE");
        let collections: Vec<u64> = globals
            .get_item("COLLECTIONS")
            .ok()
            .flatten()
            .and_then(|list| list.extract().ok())
            .expect("COLLECTIONS");
        (seen, collections[0])
    });
    let _ = collecting.join();

    eprintln!("handler steps and their threads: {seen:?}; {collections} collections");
    let tags: Vec<&str> = seen.iter().map(|(tag, _)| tag.as_str()).collect();
    for tag in [
        "sync",
        "async-before",
        "async-after",
        "originating-before",
        "originating-after",
        "on-reply",
        "stuck",
    ] {
        assert!(tags.contains(&tag), "the {tag} step ran: {seen:?}");
    }
    let on_tokio: Vec<&(String, String)> = seen
        .iter()
        .filter(|(_, thread)| thread.starts_with(TOKIO_THREADS))
        .collect();
    assert!(
        on_tokio.is_empty(),
        "handlers ran attached on tokio threads: {on_tokio:?} (all: {seen:?})"
    );
    assert!(collections > 0, "the collections ran alongside");
}
