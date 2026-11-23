//! The lane wait without a socket, for environments that cannot open SCTP.
use super::*;
use crate::dialogue::{Dialogue, IncomingOp, InvokeTimeout, OperationClass, PeerTurn};
use sccp::{SccpAddress, SubsystemNumber, UnitData};
use tcap::component::{Component, Invoke};
use tcap::types::OperationCode;
use tcap::{Begin, End, TcapMessage};

struct Waiting {
    sender: mpsc::UnboundedSender<Origination>,
    timed_out: bool,
}
impl TerminationHandler for Waiting {
    fn on_begin(&self, dlg: &mut Dialogue, op: &IncomingOp) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.sender
            .send(Origination {
                req: OutgoingBegin {
                    application_context: vec![],
                    called: address(),
                    calling: address(),
                    opc: 1000,
                    dpc: 2000,
                    ni: 0,
                    sls: 0,
                    ingress_assoc: String::new(),
                },
                handler: Arc::new(Resolving(tx)),
            })
            .unwrap();
        if rx.recv_timeout(Duration::from_secs(3)) == Ok(self.timed_out) {
            dlg.reply(op.operation_code, None);
            dlg.end().unwrap();
        }
    }
}
struct Resolving(std::sync::mpsc::Sender<bool>);
impl TerminationHandler for Resolving {
    fn rust_only_origination(&self) -> bool {
        true
    }
    fn on_start(&self, dlg: &mut Dialogue) {
        dlg.invoke_with(
            45,
            None,
            OperationClass::One,
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        dlg.send().unwrap();
    }
    fn on_continue(&self, _: &mut Dialogue, _: &PeerTurn) {
        let _ = self.0.send(false);
    }
    fn on_invoke_timeout(&self, dlg: &mut Dialogue, _: &InvokeTimeout) {
        let _ = self.0.send(true);
        dlg.abort().unwrap();
    }
}
fn address() -> SccpAddress {
    SccpAddress::with_ssn(SubsystemNumber::Hlr, Some(1000))
}
fn msu(message: TcapMessage) -> Msu {
    Msu {
        opc: 2000,
        dpc: 1000,
        ni: 0,
        si: 3,
        sls: 0,
        mp: 0,
        payload: UnitData::new(address(), address(), tcap::encode(&message).unwrap())
            .encode()
            .unwrap(),
    }
}
fn old_lane(tid: &[u8]) -> u64 {
    tid.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    }) % 32
}
async fn colliding_wait(answer: bool) {
    let (origin_tx, mut origin_rx) = mpsc::unbounded_channel::<Origination>();
    let mut engine = DialogueEngine::new(crate::config::Tcap::default());
    engine.register(
        6,
        45,
        Arc::new(Waiting {
            sender: origin_tx,
            timed_out: !answer,
        }),
    );
    let engine = Arc::new(engine);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut lanes = Vec::new();
    let mut tasks = Vec::new();
    for lane in 0..DIALOGUE_LANES + ORIGINATION_LANES {
        let (tx, mut rx) = mpsc::channel::<LaneWork>(LANE_DEPTH);
        lanes.push(tx);
        let engine = engine.clone();
        let out = out_tx.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(work) = rx.recv().await {
                let engine = engine.clone();
                let frames = handler_turn(lane, "regression", move || match work {
                    LaneWork::Deliver(delivery) => engine.deliver(&delivery.msu, ""),
                    LaneWork::Timers(tid) => engine
                        .expire(&tid, Instant::now())
                        .into_iter()
                        .map(|(_, msu)| msu)
                        .collect(),
                })
                .await
                .unwrap();
                for frame in frames {
                    let _ = out.send(frame);
                }
            }
        }));
    }
    let peer_tid = (0..256u32)
        .map(u32::to_be_bytes)
        .find(|tid| old_lane(tid) == old_lane(&0x8000_0002u32.to_be_bytes()))
        .unwrap();
    let begin = msu(TcapMessage::Begin(Begin {
        otid: peer_tid.to_vec().into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(45),
            parameter: None,
        })]),
    }));
    let lane = crate::dialogue::dialogue_lane(&begin) as usize;
    lanes[lane]
        .send(LaneWork::Deliver(LocalDelivery {
            msu: begin,
            ingress_assoc: String::new(),
        }))
        .await
        .unwrap();
    let origin = tokio::time::timeout(Duration::from_secs(1), origin_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let (tid, frames) = engine.begin(origin.req, origin.handler).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(old_lane(&tid), old_lane(&peer_tid));
    let lane = crate::dialogue::tid_lane(&tid) as usize;
    if answer {
        let end = msu(TcapMessage::End(End {
            dtid: tid.clone().into(),
            dialogue_portion: None,
            components: None,
        }));
        assert_eq!(
            crate::dialogue::dialogue_lane(&end),
            crate::dialogue::tid_lane(&tid)
        );
        lanes[lane]
            .send(LaneWork::Deliver(LocalDelivery {
                msu: end,
                ingress_assoc: String::new(),
            }))
            .await
            .unwrap();
    } else {
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(engine.claim_expired(Instant::now()), vec![tid.clone()]);
        lanes[lane].send(LaneWork::Timers(tid)).await.unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let frame = out_rx.recv().await.unwrap();
            let sccp::SccpMessage::Udt(udt) = sccp::SccpMessage::decode(&frame.payload).unwrap()
            else {
                panic!("UDT");
            };
            if let TcapMessage::End(end) = tcap::decode(&udt.data).unwrap() {
                if end.dtid.as_ref() == peer_tid {
                    break;
                }
            }
        }
    })
    .await;
    for task in tasks {
        task.abort();
    }
    assert!(
        result.is_ok(),
        "awaiting handler did not emit its End (answer={answer})"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn awaited_origination_answer_escapes_handler_lane() {
    colliding_wait(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn awaited_origination_timer_escapes_handler_lane() {
    colliding_wait(false).await;
}
