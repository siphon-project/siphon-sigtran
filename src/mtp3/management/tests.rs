//! The management of a transfer point against the text of ITU-T Q.704: each
//! table below is one procedure, each row an input in a state and what the
//! clause quoted has the node do.
//!
//! ```text
//!   A (3000): linkset a, links 0 and 1 (codes 0 and 1)
//!   B (4000): linkset b, link 2        C (5000): linkset c, link 3
//!   2000: a, then b      2200: b and c, equal      2300: c
//! ```

use super::*;
use crate::config::Config;
use ManagementMessage as M;

const A: u32 = 3000;
const B: u32 = 4000;
const C: u32 = 5000;
const LS_A: LinksetId = 0;
const LS_B: LinksetId = 1;
const LS_C: LinksetId = 2;

fn topology() -> Topology {
    let cfg = Config::parse(
        r#"
node: { point_code: 1000, variant: ITU }
associations:
  - { id: a-0, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3565, adjacent_pc: 3000 }
  - { id: a-1, adaptation: m2pa, role: client, addrs: [192.0.2.1], port: 3566, adjacent_pc: 3000 }
  - { id: b-0, adaptation: m2pa, role: client, addrs: [192.0.2.2], port: 3565, adjacent_pc: 4000 }
  - { id: c-0, adaptation: m2pa, role: client, addrs: [192.0.2.3], port: 3565, adjacent_pc: 5000 }
  - { id: gw-0, adaptation: m3ua, role: server, addrs: [192.0.2.4], port: 2905 }
application_servers:
  - { name: gateway, traffic_mode: override, routing_context: 1, asps: [gw-0] }
linksets:
  - { name: a, links: [{assoc: a-0}, {assoc: a-1}] }
  - { name: b, links: [{assoc: b-0}] }
  - { name: c, links: [{assoc: c-0}] }
mtp3_routes:
  - { dpc: 2000, linkset: a, priority: 1 }
  - { dpc: 2000, linkset: b, priority: 2 }
  - { dpc: 2200, linkset: b, priority: 1 }
  - { dpc: 2200, linkset: c, priority: 1 }
  - { dpc: 2300, linkset: c, priority: 1 }
  - { dpc: 2400, as: gateway, priority: 1 }
"#,
    )
    .unwrap();
    Topology::build(cfg.default_tenant().unwrap(), &cfg.associations)
}

fn pc(value: u32) -> PointCode {
    PointCode::from_value(value, Variant::Itu).unwrap()
}

fn from(m: &mut Management, link: LinkId, opc: u32, slc: u8, message: M) -> Vec<Action> {
    m.handle(Input::Received {
        link,
        opc,
        slc,
        message,
    })
}

/// A node past its restart with every link carrying traffic.
fn running() -> Management {
    let mut m = Management::new(topology(), Timers::default(), true);
    for link in 0..4 {
        m.handle(Input::LinkUp { link });
    }
    assert!(m.is_restarting());
    from(&mut m, 0, A, 0, M::Tra);
    from(&mut m, 2, B, 0, M::Tra);
    let actions = from(&mut m, 3, C, 0, M::Tra);
    assert!(actions.contains(&Action::Restarting(false)));
    assert!(!m.is_restarting());
    for link in 0..4 {
        assert!(m.carries(link), "link {link} carries traffic");
    }
    // T19 is over.
    for linkset in 0..3 {
        m.handle(Input::Timeout(Timer::RestartAllowed(linkset)));
    }
    // The application server behind which 2400 is comes into service.
    m.handle(Input::Server { index: 0, up: true });
    for dpc in [2000, 2200, 2300, 2400, A, B, C] {
        assert!(m.is_accessible(dpc), "{dpc} is accessible");
    }
    m
}

/// The messages among some actions: `(destination point, link code, message)`.
fn sent(actions: &[Action]) -> Vec<(u32, u8, M)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send {
                dpc, slc, message, ..
            } => Some((*dpc, *slc, *message)),
            _ => None,
        })
        .collect()
}

fn path_of(actions: &[Action], wanted: &M) -> Option<Path> {
    actions.iter().find_map(|a| match a {
        Action::Send { message, path, .. } if message == wanted => Some(*path),
        _ => None,
    })
}

fn tfp(dpc: u32) -> M {
    M::Tfp {
        destination: pc(dpc),
    }
}

fn tfa(dpc: u32) -> M {
    M::Tfa {
        destination: pc(dpc),
    }
}

fn noted(actions: &[Action], procedure: Procedure) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, Action::Note(p, _) if *p == procedure))
}

fn ignored(actions: &[Action]) -> bool {
    actions.iter().any(|a| matches!(a, Action::Ignored { .. }))
}

// ── The topology ─────────────────────────────────────────────────────────────

#[test]
fn the_topology_is_the_configuration() {
    let t = topology();
    assert_eq!(t.own_pc, 1000);
    assert_eq!(t.links.len(), 4);
    assert_eq!(
        t.linksets.iter().map(|l| l.adjacent).collect::<Vec<_>>(),
        [Some(A), Some(B), Some(C)]
    );
    assert_eq!((t.links[1].linkset, t.links[1].slc), (LS_A, 1));
    // An adjacent point is a destination by its linkset, once however many
    // links the linkset has.
    assert_eq!(
        t.routes[&A],
        [RouteSpec {
            via: Via::Linkset(LS_A),
            priority: 0
        }]
    );
    assert_eq!(t.routes[&2200].len(), 2);
    assert_eq!(t.routes[&2400][0].via, Via::Server(0));
}

// ── Clause 9: MTP restart ────────────────────────────────────────────────────

#[test]
fn the_restart_of_this_node() {
    let mut m = Management::new(topology(), Timers::default(), true);
    let t = Timers::default();

    // 9.2.1: "A signalling point starts the MTP restart procedure when its
    // first link is in service at level 2. The restarting MTP: if it has the
    // transfer function starts a timer T18; starts an overall restart timer
    // T20".
    let begun = m.handle(Input::LinkUp { link: 0 });
    assert!(begun.contains(&Action::Restarting(true)));
    assert!(begun.contains(&Action::Start(Timer::Restart, t.t18)));
    assert!(begun.contains(&Action::Start(Timer::RestartOverall, t.t20)));
    assert!(noted(&begun, Procedure::RestartBegun));
    // Nothing is sent and no link carries traffic in the first phase.
    assert!(sent(&begun).is_empty());
    assert!(!begun.iter().any(|a| matches!(a, Action::Open(_))));
    for link in 1..4 {
        let more = m.handle(Input::LinkUp { link });
        assert!(sent(&more).is_empty() && !m.carries(link));
    }

    // 9.2.2: "the routing tables within the restarting MTP are updated
    // according to the transfer-prohibited, transfer-allowed and
    // transfer-restricted messages received from the adjacent nodes."
    let marked = from(&mut m, 0, A, 0, tfp(2000));
    assert!(marked.contains(&Action::Route {
        dpc: 2000,
        linkset: LS_A,
        status: RouteStatus::Prohibited
    }));
    // 9.6.6: the other message groups are discarded during the restart.
    assert!(ignored(&from(
        &mut m,
        0,
        A,
        0,
        M::Rst {
            destination: pc(2300)
        }
    )));
    assert!(ignored(&from(&mut m, 0, A, 0, M::Xco { fsn: 1 })));

    // "T18 ... is stopped when ... enough TRA messages (and therefore routing
    // data) have been received".
    assert!(sent(&from(&mut m, 0, A, 0, M::Tra)).is_empty());
    assert!(sent(&from(&mut m, 2, B, 0, M::Tra)).is_empty());
    let ended = from(&mut m, 3, C, 0, M::Tra);
    assert!(ended.contains(&Action::Stop(Timer::Restart)));
    assert!(ended.contains(&Action::Stop(Timer::RestartOverall)));
    for link in 0..4 {
        assert!(ended.contains(&Action::Open(link)), "link {link} opens");
    }
    // The second phase. 2000 goes by b, since A prohibited it: B is told
    // (13.2.2 i), A is not. 2200 goes by b and c: both are told. 2300 goes
    // by c. Nothing is said to a point about itself.
    let messages = sent(&ended);
    let prohibited: Vec<(u32, M)> = messages
        .iter()
        .filter(|(_, _, m)| matches!(m, M::Tfp { .. }))
        .map(|(dpc, _, m)| (*dpc, *m))
        .collect();
    // 2400 is behind an application server that is not in service: 13.2.2 v).
    assert_eq!(
        prohibited,
        [
            (A, tfp(2400)),
            (B, tfp(2000)),
            (B, tfp(2200)),
            (B, tfp(2400)),
            (C, tfp(2200)),
            (C, tfp(2300)),
            (C, tfp(2400)),
        ]
    );
    // 9.2.4: "sends traffic restart allowed messages to all adjacent
    // signalling points ... In addition, timer T19 is started", after the
    // transfer-prohibited messages.
    let last_tfp = messages
        .iter()
        .rposition(|(_, _, m)| matches!(m, M::Tfp { .. }))
        .unwrap();
    let first_tra = messages.iter().position(|(_, _, m)| *m == M::Tra).unwrap();
    assert!(
        last_tfp < first_tra,
        "routing data before the restart allowed"
    );
    // "preventive TFP messages ... must have been sent before normal User
    // traffic is carried": no link opens ahead of them.
    let last_prohibited = ended
        .iter()
        .rposition(|a| {
            matches!(
                a,
                Action::Send {
                    message: M::Tfp { .. },
                    ..
                }
            )
        })
        .unwrap();
    let first_open = ended
        .iter()
        .position(|a| matches!(a, Action::Open(_)))
        .unwrap();
    assert!(last_prohibited < first_open);
    assert_eq!(
        messages
            .iter()
            .filter(|(_, _, m)| *m == M::Tra)
            .map(|(dpc, _, _)| *dpc)
            .collect::<Vec<_>>(),
        [A, B, C]
    );
    for linkset in 0..3 {
        assert!(ended.contains(&Action::Start(Timer::RestartAllowed(linkset), t.t19)));
    }
    assert!(ended.contains(&Action::Restarting(false)));
    assert!(noted(&ended, Procedure::RestartEnded));

    // 9.5.2: "If a signalling point receives a TRA message from an adjacent
    // node and an associated timer T19 is running, this TRA is discarded".
    let again = from(&mut m, 0, A, 0, M::Tra);
    assert!(ignored(&again) && sent(&again).is_empty());
}

#[test]
fn the_restart_ends_at_t18_when_an_adjacent_point_stays_silent() {
    let mut m = Management::new(topology(), Timers::default(), true);
    m.handle(Input::LinkUp { link: 0 });
    from(&mut m, 0, A, 0, M::Tra);
    assert!(m.is_restarting(), "B and C have not answered");

    // 9.2.2: "When T18 is stopped or expires, the second phase begins, which
    // includes as a major part a broadcast of non-preventive transfer
    // prohibited messages [13.2.2 v] ... taking into account signalling link
    // sets which are not available".
    let ended = m.handle(Input::Timeout(Timer::Restart));
    assert!(!m.is_restarting());
    let to_a: Vec<M> = sent(&ended)
        .into_iter()
        .filter(|(dpc, _, _)| *dpc == A)
        .map(|(_, _, m)| m)
        .collect();
    // 2000 is routed through A itself (13.2.2 i); the rest is inaccessible.
    assert_eq!(
        to_a,
        [
            tfp(2000),
            tfp(2200),
            tfp(2300),
            tfp(2400),
            tfp(B),
            tfp(C),
            M::Tra
        ]
    );
    // T20 running out later changes nothing.
    assert!(m.handle(Input::Timeout(Timer::RestartOverall)).is_empty());
}

#[test]
fn an_adjacent_point_that_restarts() {
    let mut m = running();
    let t = Timers::default();
    // The linkset to C goes down. Nothing reaches C, so it cannot be asked:
    // 5.6.2 i), the time-controlled changeover.
    let down = m.handle(Input::LinkDown { link: 3, bsnt: 7 });
    assert!(down.contains(&Action::Hold(3)));
    assert!(down.contains(&Action::Start(Timer::Changeover(3), t.t1)));
    assert!(down.contains(&Action::Accessibility {
        dpc: 2300,
        accessible: false
    }));
    // 13.2.2 ii): the broadcast, and T8.
    let messages = sent(&down);
    for adjacent in [A, B] {
        assert!(messages.contains(&(adjacent, 0, tfp(2300))));
        assert!(messages.contains(&(adjacent, 0, tfp(C))));
    }
    assert!(down.contains(&Action::Start(Timer::Prohibited(2300), t.t8)));
    let diverted = m.handle(Input::Timeout(Timer::Changeover(3)));
    assert!(diverted.contains(&Action::Divert {
        link: 3,
        fsnc: None
    }));
    assert!(noted(&diverted, Procedure::ChangeoverTimeControlled));

    // 9.3.1: "A signalling point X considers that the MTP of an inaccessible
    // adjacent signalling point Y is restarting when the first link in a
    // direct link set is in the in service state at level 2". 9.3.2: X
    // "starts a timer T21 ... sends any necessary TFP and TFR messages to Y;
    // then X sends a traffic restart allowed message to signalling point Y."
    let up = m.handle(Input::LinkUp { link: 3 });
    assert!(up.contains(&Action::Start(Timer::AdjacentRestart(LS_C), t.t21)));
    assert!(noted(&up, Procedure::AdjacentRestartBegun));
    assert_eq!(
        sent(&up),
        [(C, 0, tfp(2300)), (C, 0, M::Tra)],
        "what C must not send here, then the restart allowed"
    );
    assert_eq!(path_of(&up, &M::Tra), Some(Path::Link(3)));
    // 9.6.7: no traffic for C or through it yet.
    assert!(!m.carries(3) && !m.is_accessible(2300));

    // "When a traffic restart allowed message has been received by X from
    // signalling point Y, and a TRA message has been sent by X to Y, X stops
    // timer T21." 6.4.1: the time-controlled diversion follows, since 2200
    // is on linkset b meanwhile.
    let allowed = from(&mut m, 3, C, 0, M::Tra);
    assert!(allowed.contains(&Action::Stop(Timer::AdjacentRestart(LS_C))));
    assert!(noted(&allowed, Procedure::AdjacentRestartEnded));
    assert!(allowed.contains(&Action::Hold(3)));
    assert!(allowed.contains(&Action::Start(Timer::Changeback(3), t.t3)));
    // 9.3.2: "it broadcasts to adjacent available signalling points
    // transfer-allowed ... messages concerning Y and all signalling points
    // made accessible via Y."
    let messages = sent(&allowed);
    for adjacent in [A, B] {
        assert!(messages.contains(&(adjacent, 0, tfa(2300))));
        assert!(messages.contains(&(adjacent, 0, tfa(C))));
    }
    // 13.2.2 i): 2200 is shared with C again, so C must not send it here.
    assert!(messages.contains(&(C, 0, tfp(2200))));
    let open = m.handle(Input::Timeout(Timer::Changeback(3)));
    assert!(open.contains(&Action::Open(3)));
    assert!(noted(&open, Procedure::ChangebackTimeControlled));
}

#[test]
fn an_adjacent_point_that_never_says_restart_allowed_is_waited_for_t21() {
    let mut m = running();
    m.handle(Input::LinkDown { link: 3, bsnt: 0 });
    m.handle(Input::Timeout(Timer::Changeover(3)));
    m.handle(Input::LinkUp { link: 3 });
    assert!(!m.carries(3));
    let expired = m.handle(Input::Timeout(Timer::AdjacentRestart(LS_C)));
    assert!(noted(&expired, Procedure::AdjacentRestartExpired));
    assert!(m.carries(3) && m.is_accessible(2300));
}

#[test]
fn an_unexpected_restart_allowed_is_answered_once() {
    let mut m = running();
    let t = Timers::default();
    // 9.5.1: "If a signalling point X receives an unexpected TRA message from
    // an adjacent node Y and no associated T19 timer is running, X sends to Y
    // any necessary TFP and TFR messages if X has the transfer function, and
    // a TRA message to Y. In addition, X starts a timer T19".
    let answer = from(&mut m, 2, B, 0, M::Tra);
    assert_eq!(
        sent(&answer),
        [(B, 0, tfp(2200)), (B, 0, M::Tra)],
        "2200 is routed through B; 2000 goes by A"
    );
    assert!(answer.contains(&Action::Start(Timer::RestartAllowed(LS_B), t.t19)));
    // 9.5.2.
    assert!(sent(&from(&mut m, 2, B, 0, M::Tra)).is_empty());
    m.handle(Input::Timeout(Timer::RestartAllowed(LS_B)));
    assert_eq!(sent(&from(&mut m, 2, B, 0, M::Tra)).len(), 2);
}

// ── Clause 5: changeover ─────────────────────────────────────────────────────

/// Link 0 of linkset a failed with 41 the last number accepted; link 1 is up.
fn in_changeover() -> (Management, Vec<Action>) {
    let mut m = running();
    let actions = m.handle(Input::LinkDown { link: 0, bsnt: 41 });
    (m, actions)
}

#[test]
fn a_failed_link_orders_changeover_on_another_link() {
    let (m, actions) = in_changeover();
    let t = Timers::default();
    // 5.3.1 a), d): traffic of the link stops and its buffer is to be
    // updated. 5.4.1: "a changeover order is sent to the remote signalling
    // point". 5.4.2: it carries "the identity of the unavailable signalling
    // link" (the link code) and "the forward sequence number of the last
    // message signal unit accepted from the unavailable signalling link".
    // RFC 4165 4.2.3: with 24 bits, in an extended changeover order.
    assert!(actions.contains(&Action::Hold(0)));
    assert_eq!(sent(&actions), [(A, 0, M::Xco { fsn: 41 })]);
    // 2.3.4.2 b): "whose transmission over the signalling link defined by the
    // SLC contained in the label must be avoided".
    assert_eq!(
        path_of(&actions, &M::Xco { fsn: 41 }),
        Some(Path::Adjacent {
            linkset: LS_A,
            avoid: Some(0)
        })
    );
    assert!(actions.contains(&Action::Start(Timer::Changeover(0), t.t2)));
    // The linkset still carries traffic: nothing became inaccessible.
    assert!(!actions
        .iter()
        .any(|a| matches!(a, Action::Accessibility { .. })));
    assert!(!m.carries(0) && m.carries(1));
}

#[test]
fn changeover_completes_as_clause_5_has_it() {
    struct Row {
        clause: &'static str,
        input: Input,
        answer: Option<M>,
        fsnc: Option<u32>,
        how: Procedure,
    }
    let received = |message: M| Input::Received {
        link: 1,
        opc: A,
        slc: 0,
        message,
    };
    let rows = [
        Row {
            clause: "5.4.3: on a changeover acknowledgement the retransmission buffer is \
                     updated according to the information contained in the message",
            input: received(M::Xca { fsn: 39 }),
            answer: None,
            fsnc: Some(39),
            how: Procedure::ChangeoverAcknowledged,
        },
        Row {
            clause: "5.6.1: on an emergency changeover acknowledgement it does not perform \
                     either buffer updating or retrieval",
            input: received(M::Eca),
            answer: None,
            fsnc: None,
            how: Procedure::ChangeoverEmergency,
        },
        Row {
            clause: "5.7.3: a 7-bit number is unreasonable for a 24-bit link, no buffer \
                     updating or retrieval is performed",
            input: received(M::Coa { fsn: 39 }),
            answer: None,
            fsnc: None,
            how: Procedure::ChangeoverEmergency,
        },
        Row {
            clause: "5.7.2: no changeover message within T2, new traffic is started on the \
                     alternative signalling link(s)",
            input: Input::Timeout(Timer::Changeover(0)),
            answer: None,
            fsnc: None,
            how: Procedure::ChangeoverUnacknowledged,
        },
        Row {
            clause: "5.4.1: a changeover order is always acknowledged by a changeover \
                     acknowledgement, even when changeover has already been initiated; \
                     5.4.3: the order updates the buffer too",
            input: received(M::Xco { fsn: 40 }),
            answer: Some(M::Xca { fsn: 41 }),
            fsnc: Some(40),
            how: Procedure::ChangeoverAcknowledged,
        },
        Row {
            clause: "5.6.1: an emergency changeover order is acknowledged by a changeover \
                     acknowledgement if the local conditions are normal",
            input: received(M::Eco),
            answer: Some(M::Xca { fsn: 41 }),
            fsnc: None,
            how: Procedure::ChangeoverEmergency,
        },
    ];
    for row in rows {
        let (mut m, _) = in_changeover();
        let actions = m.handle(row.input);
        assert_eq!(
            sent(&actions).into_iter().map(|(_, _, m)| m).next(),
            row.answer,
            "{}",
            row.clause
        );
        assert!(
            actions.contains(&Action::Divert {
                link: 0,
                fsnc: row.fsnc
            }),
            "{}: {actions:?}",
            row.clause
        );
        assert!(noted(&actions, row.how), "{}", row.clause);
        assert!(actions.contains(&Action::Stop(Timer::Changeover(0))));

        // 5.7.5: "If a changeover order is received relating to a particular
        // signalling link after the completion of changeover from that
        // signalling link, an emergency changeover acknowledgement is sent in
        // response, without any further action."
        let late = from(&mut m, 1, A, 0, M::Xco { fsn: 3 });
        assert_eq!(sent(&late), [(A, 0, M::Eca)]);
        assert_eq!(late.len(), 1);
        // 5.7.4: "If a changeover acknowledgement is received without having
        // previously sent a changeover order, no action is taken."
        let stray = from(&mut m, 1, A, 0, M::Xca { fsn: 3 });
        assert!(ignored(&stray) && stray.len() == 1);
    }
}

#[test]
fn a_changeover_order_for_a_link_that_is_up_fails_it_and_is_answered() {
    for (order, answer, fsnc) in [
        (M::Xco { fsn: 17 }, M::Xca { fsn: 23 }, Some(17)),
        // A 7-bit order cannot be answered with a 24-bit number: 5.6.1, "a
        // changeover order is acknowledged by an emergency changeover
        // acknowledgement if there are local fault conditions".
        (M::Coo { fsn: 17 }, M::Eca, None),
    ] {
        let mut m = running();
        // 3.2.2: "a signalling link which is available (not blocked) is
        // recognized by level 3 as failed when a changeover order is
        // received."
        let ordered = from(&mut m, 1, A, 0, order);
        assert_eq!(ordered, [Action::Fail(0)]);
        // Level 2 says where it stopped; 5.4.1: "a changeover acknowledgement
        // is sent instead" of an order.
        let down = m.handle(Input::LinkDown { link: 0, bsnt: 23 });
        assert_eq!(sent(&down), [(A, 0, answer)]);
        assert!(down.contains(&Action::Divert { link: 0, fsnc }));
        assert!(!down
            .iter()
            .any(|a| matches!(a, Action::Start(Timer::Changeover(_), _))));
    }
}

#[test]
fn a_link_that_returns_during_its_changeover_changes_back_afterwards() {
    let (mut m, _) = in_changeover();
    assert!(m.handle(Input::LinkUp { link: 0 }).is_empty());
    let done = from(&mut m, 1, A, 0, M::Xca { fsn: 41 });
    let divert = done
        .iter()
        .position(|a| matches!(a, Action::Divert { .. }))
        .unwrap();
    let declared = done
        .iter()
        .position(|a| {
            matches!(
                a,
                Action::Send {
                    message: M::Cbd { .. },
                    ..
                }
            )
        })
        .unwrap();
    assert!(divert < declared, "changeover completes before changeback");
}

// ── Clause 6: changeback ─────────────────────────────────────────────────────

/// Link 0 changed over to link 1 and is up again.
fn in_changeback() -> (Management, Vec<Action>, u8) {
    let (mut m, _) = in_changeover();
    from(&mut m, 1, A, 0, M::Xca { fsn: 41 });
    let actions = m.handle(Input::LinkUp { link: 0 });
    let code = sent(&actions)
        .into_iter()
        .find_map(|(_, _, m)| match m {
            M::Cbd { code } => Some(code),
            _ => None,
        })
        .expect("a changeback declaration");
    (m, actions, code)
}

#[test]
fn a_restored_link_declares_changeback_on_the_link_that_carried_its_traffic() {
    let (m, actions, code) = in_changeback();
    let t = Timers::default();
    // 6.3.1: "i) transmission of the concerned traffic on the alternative
    // signalling link is stopped; such traffic is stored in a changeback
    // buffer; ii) a changeback declaration is sent to the remote signalling
    // point of the signalling link made available via the concerned
    // alternative signalling link". 6.3.3: its label carries "the identity of
    // the signalling link to which traffic will be diverted".
    assert!(actions.contains(&Action::Hold(0)));
    assert_eq!(sent(&actions), [(A, 0, M::Cbd { code })]);
    assert_eq!(path_of(&actions, &M::Cbd { code }), Some(Path::Behind(1)));
    assert!(actions.contains(&Action::Start(Timer::Changeback(0), t.t4)));
    assert!(m.carries(0), "available: its traffic is held, not diverted");
}

#[test]
fn changeback_completes_as_clause_6_has_it() {
    let t = Timers::default();
    // 6.3.2: "The concerned signalling point will restart diverted traffic
    // over the signalling link made available when it receives a changeback
    // acknowledgement".
    let (mut m, _, code) = in_changeback();
    let done = from(&mut m, 0, A, 0, M::Cba { code });
    assert!(done.contains(&Action::Open(0)));
    assert!(done.contains(&Action::Stop(Timer::Changeback(0))));
    assert!(noted(&done, Procedure::ChangebackAcknowledged));
    // 6.5.1: "If a changeback-acknowledgement is received by a signalling
    // point which has not previously sent a changeback-declaration, no action
    // is taken."
    let stray = from(&mut m, 0, A, 0, M::Cba { code });
    assert!(ignored(&stray) && stray.len() == 1);

    // An acknowledgement with another code is not the one awaited (6.3.4).
    let (mut m, _, code) = in_changeback();
    let other = from(
        &mut m,
        0,
        A,
        0,
        M::Cba {
            code: code.wrapping_add(9),
        },
    );
    assert!(ignored(&other) && !other.contains(&Action::Open(0)));

    // 6.5.3: "If no changeback-acknowledgement is received in response to a
    // changeback declaration within a time T4, the changeback-declaration is
    // repeated and a new timer T5 is started. If no
    // changeback-acknowledgement is received before the expiry of T5, the
    // maintenance functions are alerted and traffic on the link made
    // available is started."
    let repeated = m.handle(Input::Timeout(Timer::Changeback(0)));
    assert_eq!(sent(&repeated), [(A, 0, M::Cbd { code })]);
    assert_eq!(path_of(&repeated, &M::Cbd { code }), Some(Path::Behind(1)));
    assert!(repeated.contains(&Action::Start(Timer::Changeback(0), t.t5)));
    let given_up = m.handle(Input::Timeout(Timer::Changeback(0)));
    assert!(given_up.contains(&Action::Open(0)));
    assert!(noted(&given_up, Procedure::ChangebackUnacknowledged));
}

#[test]
fn a_changeback_declaration_is_always_acknowledged() {
    let mut m = running();
    // 6.5.2: "If a changeback-declaration is received after the completion of
    // the changeback procedure, a changeback-acknowledgement is sent in
    // response, without taking any further action." 6.3.4: with "the same
    // configuration" of the changeback code.
    for code in [0, 77, 255] {
        let answer = from(&mut m, 1, A, 0, M::Cbd { code });
        assert_eq!(answer.len(), 1);
        assert_eq!(sent(&answer), [(A, 0, M::Cba { code })]);
    }
}

// ── Clauses 7, 8 and 13: routes ──────────────────────────────────────────────

#[test]
fn transfer_prohibited_is_forced_rerouting() {
    let mut m = running();
    let t = Timers::default();
    // 7.2.1: "transmission of signalling traffic towards the concerned
    // destination on the link set(s) pertaining to the unavailable route is
    // immediately stopped ... the concerned signalling traffic is restarted
    // on a link set pertaining to the alternative route ... if appropriate, a
    // transfer-prohibited procedure is performed".
    let actions = from(&mut m, 0, A, 0, tfp(2000));
    assert!(actions.contains(&Action::Route {
        dpc: 2000,
        linkset: LS_A,
        status: RouteStatus::Prohibited
    }));
    assert!(noted(&actions, Procedure::ForcedRerouting));
    assert!(!actions
        .iter()
        .any(|a| matches!(a, Action::HoldDestination(_))));
    // 13.2.2 i): B is the point now routed through; 13.3.2 i): A no longer is.
    assert_eq!(sent(&actions), [(A, 0, tfa(2000)), (B, 0, tfp(2000))]);
    // 13.5.2: the route set test, "every T10 period".
    assert!(actions.contains(&Action::Start(Timer::RouteSetTest(2000, LS_A), t.t10)));
    let test = m.handle(Input::Timeout(Timer::RouteSetTest(2000, LS_A)));
    assert_eq!(
        sent(&test),
        [(
            A,
            0,
            M::Rst {
                destination: pc(2000)
            }
        )]
    );
    assert!(test.contains(&Action::Start(Timer::RouteSetTest(2000, LS_A), t.t10)));

    // 13.2.4: "a repeated transfer-prohibited message ... no actions are
    // taken", and one "relating to a non-existent route".
    assert!(from(&mut m, 0, A, 0, tfp(2000)).is_empty());
    let none = from(&mut m, 0, A, 0, tfp(2300));
    assert!(ignored(&none) && none.len() == 1);

    // 7.2.3: "If no alternative route exists ... that destination is declared
    // inaccessible, and the actions specified in 5.3.3 apply": iii) "the
    // transfer-prohibited procedure is performed".
    let last = from(&mut m, 2, B, 0, tfp(2000));
    assert!(last.contains(&Action::Accessibility {
        dpc: 2000,
        accessible: false
    }));
    let messages = sent(&last);
    assert!(messages.contains(&(A, 0, tfp(2000))) && messages.contains(&(C, 0, tfp(2000))));
    assert!(last.contains(&Action::Start(Timer::Prohibited(2000), t.t8)));
}

#[test]
fn transfer_allowed_is_controlled_rerouting() {
    let mut m = running();
    let t = Timers::default();
    from(&mut m, 0, A, 0, tfp(2000));
    // 8.2.1: "a) transmission of signalling traffic towards the concerned
    // destination on the link set belonging to the alternative route ... is
    // stopped; such traffic is stored in a controlled rerouting buffer; a
    // timer T6 is started; b) ... a transfer-prohibited procedure is
    // performed for the route made available ... and a transfer-allowed
    // procedure for the alternative one".
    let actions = from(&mut m, 0, A, 0, tfa(2000));
    assert!(actions.contains(&Action::HoldDestination(2000)));
    assert!(actions.contains(&Action::Start(Timer::Rerouting(2000), t.t6)));
    assert!(noted(&actions, Procedure::ControlledRerouting));
    assert!(actions.contains(&Action::Stop(Timer::RouteSetTest(2000, LS_A))));
    assert_eq!(sent(&actions), [(A, 0, tfp(2000)), (B, 0, tfa(2000))]);
    // The route is marked only when T6 runs out: "c) at the expiry of T6, the
    // concerned signalling traffic is restarted on an outgoing link set
    // pertaining to the signalling route made available, ... starting with
    // the content of the controlled rerouting buffer".
    assert!(!actions.iter().any(|a| matches!(a, Action::Route { .. })));
    let expired = m.handle(Input::Timeout(Timer::Rerouting(2000)));
    assert_eq!(
        expired,
        [
            Action::Route {
                dpc: 2000,
                linkset: LS_A,
                status: RouteStatus::Allowed
            },
            Action::ReleaseDestination(2000)
        ]
    );
    // 13.3.4: a repeated transfer-allowed, no actions.
    assert!(from(&mut m, 0, A, 0, tfa(2000)).is_empty());
}

#[test]
fn a_route_made_available_to_an_inaccessible_destination_opens_at_once() {
    let mut m = running();
    from(&mut m, 3, C, 0, tfp(2300));
    assert!(!m.is_accessible(2300));
    // 8.2.3: "If the destination was inaccessible ... when the route is made
    // available, then the destination is declared accessible and actions
    // specified in 6.2.3 ... apply": there is nothing to hold.
    let actions = from(&mut m, 3, C, 0, tfa(2300));
    assert!(actions.contains(&Action::Route {
        dpc: 2300,
        linkset: LS_C,
        status: RouteStatus::Allowed
    }));
    assert!(!actions
        .iter()
        .any(|a| matches!(a, Action::HoldDestination(_))));
    assert!(actions.contains(&Action::Accessibility {
        dpc: 2300,
        accessible: true
    }));
    // 13.3.2 ii): "sent to all accessible adjacent signalling points, except
    // those signalling points that receive a TFP message according to
    // 13.2.2 i)", which here is C.
    assert_eq!(sent(&actions), [(A, 0, tfa(2300)), (B, 0, tfa(2300))]);
}

#[test]
fn transfer_restricted_moves_traffic_to_an_equal_route() {
    let mut m = running();
    let t = Timers::default();
    // 13.4.3: "When a signalling point receives a transfer-restricted message
    // ... and has an alternative equal priority link set available and not
    // restricted to destination X, it performs the actions in 8.2."
    let actions = from(
        &mut m,
        2,
        B,
        0,
        M::Tfr {
            destination: pc(2200),
        },
    );
    assert!(actions.contains(&Action::HoldDestination(2200)));
    assert!(actions.contains(&Action::Start(Timer::RouteSetTest(2200, LS_B), t.t10)));
    // B is no longer routed through for 2200.
    assert_eq!(sent(&actions), [(B, 0, tfa(2200))]);
    let expired = m.handle(Input::Timeout(Timer::Rerouting(2200)));
    assert!(expired.contains(&Action::Route {
        dpc: 2200,
        linkset: LS_B,
        status: RouteStatus::Restricted
    }));
    // 13.5.2 / 15.10.3: the test for a restricted destination.
    let test = m.handle(Input::Timeout(Timer::RouteSetTest(2200, LS_B)));
    assert_eq!(
        sent(&test),
        [(
            B,
            0,
            M::Rsr {
                destination: pc(2200)
            }
        )]
    );
}

#[test]
fn a_route_set_test_is_answered_when_the_sender_is_wrong() {
    // 13.5.4: "a signalling transfer point will compare the status of the
    // destination in the received message with the actual status of the
    // destination. If they are the same, no further action is taken. If they
    // are different, one of the following messages is sent in response".
    struct Row {
        why: &'static str,
        from: (LinkId, u32),
        test: M,
        answer: Option<M>,
    }
    let rst = |dpc| M::Rst {
        destination: pc(dpc),
    };
    let rsr = |dpc| M::Rsr {
        destination: pc(dpc),
    };
    let rows = [
        Row {
            why: "2300 is reached by a link not connected to A: transfer-allowed",
            from: (0, A),
            test: rst(2300),
            answer: Some(tfa(2300)),
        },
        Row {
            why: "2300 is reached through C itself: prohibited toward C, as it believes",
            from: (3, C),
            test: rst(2300),
            answer: None,
        },
        Row {
            why: "C believes 2300 restricted through here; it is prohibited",
            from: (3, C),
            test: rsr(2300),
            answer: Some(tfp(2300)),
        },
        Row {
            why: "A believes 2300 restricted; it is allowed",
            from: (0, A),
            test: rsr(2300),
            answer: Some(tfa(2300)),
        },
        Row {
            why: "no route to 2999: prohibited, as the sender believes",
            from: (0, A),
            test: rst(2999),
            answer: None,
        },
        Row {
            why: "no route to 2999 and the sender believes it restricted",
            from: (0, A),
            test: rsr(2999),
            answer: Some(tfp(2999)),
        },
    ];
    for row in rows {
        let mut m = running();
        let actions = from(&mut m, row.from.0, row.from.1, 0, row.test);
        let answer = sent(&actions)
            .into_iter()
            .map(|(dpc, _, m)| (dpc, m))
            .next();
        assert_eq!(answer, row.answer.map(|m| (row.from.1, m)), "{}", row.why);
    }
}

#[test]
fn a_message_that_cannot_be_transferred_is_answered_once_per_t8() {
    let mut m = running();
    let t = Timers::default();
    // 13.2.2 iii): "When a message destined to signalling point X is received
    // at signalling transfer point Y and Y is unable to transfer the message,
    // and if no corresponding timer T8 is running ... the transfer-prohibited
    // message is sent to the adjacent signalling point from which the message
    // concerned was received (Response Method). In addition, timer T8 is
    // started concerning SP X."
    let first = m.handle(Input::Unroutable { dpc: 2999, link: 2 });
    assert_eq!(sent(&first), [(B, 0, tfp(2999))]);
    assert!(first.contains(&Action::Start(Timer::Prohibited(2999), t.t8)));
    // "Within T8 ... no transfer prohibited message will be sent via the
    // Response Method referring to that destination", whoever sent.
    assert!(m
        .handle(Input::Unroutable { dpc: 2999, link: 2 })
        .is_empty());
    assert!(m
        .handle(Input::Unroutable { dpc: 2999, link: 0 })
        .is_empty());
    m.handle(Input::Timeout(Timer::Prohibited(2999)));
    assert_eq!(
        sent(&m.handle(Input::Unroutable { dpc: 2999, link: 0 })),
        [(A, 0, tfp(2999))]
    );
    // A message for this node itself is not a transfer.
    assert!(m
        .handle(Input::Unroutable { dpc: 1000, link: 0 })
        .is_empty());

    // Footnote 7: the operator may choose "not to send a TFP if no routing
    // data for X exists".
    let mut quiet = Management::new(topology(), Timers::default(), false);
    for link in 0..4 {
        quiet.handle(Input::LinkUp { link });
    }
    quiet.handle(Input::Timeout(Timer::Restart));
    assert!(quiet
        .handle(Input::Unroutable { dpc: 2999, link: 2 })
        .is_empty());
    // A known destination that is inaccessible is still answered.
    quiet.handle(Input::LinkDown { link: 3, bsnt: 0 });
    quiet.handle(Input::Timeout(Timer::Prohibited(2300)));
    assert_eq!(
        sent(&quiet.handle(Input::Unroutable { dpc: 2300, link: 2 })),
        [(B, 0, tfp(2300))]
    );
}

#[test]
fn accessibility_follows_application_servers_and_pauses_too() {
    let mut m = running();
    let down = m.handle(Input::Server {
        index: 0,
        up: false,
    });
    assert!(down.contains(&Action::Accessibility {
        dpc: 2400,
        accessible: false
    }));
    // 13.2.2 ii): the broadcast.
    assert_eq!(
        sent(&down),
        [(A, 0, tfp(2400)), (B, 0, tfp(2400)), (C, 0, tfp(2400))]
    );
    let up = m.handle(Input::Server { index: 0, up: true });
    assert!(up.contains(&Action::Accessibility {
        dpc: 2400,
        accessible: true
    }));
    // 13.3.2 ii): the broadcast.
    assert_eq!(
        sent(&up),
        [(A, 0, tfa(2400)), (B, 0, tfa(2400)), (C, 0, tfa(2400))]
    );
    let paused = m.handle(Input::Paused {
        dpc: 2400,
        paused: true,
    });
    assert!(paused.contains(&Action::Accessibility {
        dpc: 2400,
        accessible: false
    }));
    assert_eq!(sent(&paused).len(), 3);
    assert!(sent(&paused).iter().all(|(_, _, m)| *m == tfp(2400)));
}

#[test]
fn messages_from_elsewhere_are_counted_not_obeyed() {
    let mut m = running();
    // Route management is between adjacent points (13.2.1: "always addressed
    // to an adjacent signalling point").
    let stranger = from(&mut m, 0, 6000, 0, tfp(2000));
    assert!(ignored(&stranger) && stranger.len() == 1);
    // A link code the linkset does not have.
    let no_link = from(&mut m, 0, A, 9, M::Xco { fsn: 1 });
    assert!(ignored(&no_link) && no_link.len() == 1);
    // 13.9.6, and the messages of clause 12.
    for message in [M::Rct, M::Css, M::Dlc { link: 3 }] {
        let actions = from(&mut m, 0, A, 0, message);
        assert!(ignored(&actions) && actions.len() == 1);
    }
    // 13.6: a transfer-controlled conveys a congestion indication.
    let congested = from(
        &mut m,
        0,
        6000,
        0,
        M::Tfc {
            destination: pc(2000),
            status: 2,
        },
    );
    assert_eq!(
        congested,
        [Action::Congestion {
            dpc: 2000,
            status: 2
        }]
    );
}

// ── Clause 10: management inhibiting ─────────────────────────────────────────

#[test]
fn a_link_is_inhibited_and_uninhibited_at_the_far_ends_request() {
    let mut m = running();
    let t = Timers::default();
    // 10.2 d): "If the signalling point Y finds that inhibiting of the
    // concerned link is permissible, it sends an inhibit acknowledgement to
    // signalling point X and marks the link remotely inhibited. If the link
    // concerned is currently carrying traffic, signalling point Y sends the
    // inhibit acknowledgement via that link and diverts subsequent traffic
    // for it, using the time controlled changeover procedure. Y then starts
    // inhibit test timer T23."
    let inhibited = from(&mut m, 1, A, 0, M::Lin);
    assert_eq!(sent(&inhibited), [(A, 0, M::Lia)]);
    assert_eq!(path_of(&inhibited, &M::Lia), Some(Path::Link(0)));
    assert!(inhibited.contains(&Action::Hold(0)));
    assert!(inhibited.contains(&Action::Start(Timer::Changeover(0), t.t1)));
    assert!(inhibited.contains(&Action::Start(Timer::InhibitTest(0), t.t23)));
    assert!(noted(&inhibited, Procedure::LinkInhibited));
    assert!(m.is_inhibited(0) && !m.carries(0));
    let diverted = m.handle(Input::Timeout(Timer::Changeover(0)));
    assert!(diverted.contains(&Action::Divert {
        link: 0,
        fsnc: None
    }));

    // 10.4 a): "An inhibit signalling link message concerning an inhibited
    // signalling link is answered with an inhibit acknowledgement message
    // without taking any further action."
    let again = from(&mut m, 1, A, 0, M::Lin);
    assert_eq!(again.len(), 1);
    assert_eq!(sent(&again), [(A, 0, M::Lia)]);

    // 10.6.2: "A remote inhibit test is performed when timer T23 expires ...
    // and the concerned link is marked remotely inhibited. In this case a
    // remote inhibit test message is sent ... and timer T23 is restarted."
    let test = m.handle(Input::Timeout(Timer::InhibitTest(0)));
    assert_eq!(sent(&test), [(A, 0, M::Lrt)]);
    assert!(test.contains(&Action::Start(Timer::InhibitTest(0), t.t23)));
    // 10.6.1 i): a local inhibit test for a link marked remotely inhibited,
    // "no action".
    assert!(from(&mut m, 0, A, 0, M::Llt).is_empty());

    // An inhibited link stays out of traffic when it fails and returns.
    m.handle(Input::LinkDown { link: 0, bsnt: 0 });
    m.handle(Input::LinkUp { link: 0 });
    assert!(!m.carries(0));

    // 10.3.1 c): "Upon receipt of the uninhibit link message, signalling
    // point Y returns an uninhibit acknowledgement message to signalling
    // point X and cancels the remote inhibit indication. If no local
    // inhibited, failed or blocked condition exists on the link, it is put in
    // the available state and changeback is initiated."
    let lifted = from(&mut m, 1, A, 0, M::Lun);
    assert!(sent(&lifted).contains(&(A, 0, M::Lua)));
    assert!(noted(&lifted, Procedure::LinkUninhibited));
    assert!(lifted.contains(&Action::Stop(Timer::InhibitTest(0))));
    assert!(sent(&lifted)
        .iter()
        .any(|(_, _, m)| matches!(m, M::Cbd { .. })));
    assert!(!m.is_inhibited(0) && m.carries(0));
    // "If a timer T23 expires and the concerned link is not remotely
    // inhibited, no further action is taken."
    assert!(m.handle(Input::Timeout(Timer::InhibitTest(0))).is_empty());
}

#[test]
fn inhibiting_the_last_link_to_a_destination_is_denied() {
    let mut m = running();
    // 10.2 c): "checks whether, in the case of an available link, inhibiting
    // will result in a destination becoming inaccessible and, if so, an
    // inhibit denied message is returned".
    let denied = from(&mut m, 3, C, 0, M::Lin);
    assert_eq!(sent(&denied), [(C, 0, M::Lid)]);
    assert!(noted(&denied, Procedure::LinkInhibitDenied));
    assert!(!m.is_inhibited(3) && m.carries(3));
}

#[test]
fn unexpected_inhibit_messages_are_answered_as_10_4_has_it() {
    struct Row {
        clause: &'static str,
        message: M,
        answer: Option<M>,
    }
    let rows = [
        Row {
            clause: "10.4 b): an uninhibit for an uninhibited link is answered with an \
                     uninhibit acknowledgement without taking any further action",
            message: M::Lun,
            answer: Some(M::Lua),
        },
        Row {
            clause: "10.4 c): a force uninhibit for an uninhibited link is answered with an \
                     uninhibit signalling link message",
            message: M::Lfu,
            answer: Some(M::Lun),
        },
        Row {
            clause: "10.4 d): an inhibit acknowledgement with no inhibit outstanding, no action",
            message: M::Lia,
            answer: None,
        },
        Row {
            clause: "10.4 e): an uninhibit acknowledgement with no uninhibit outstanding, no \
                     action",
            message: M::Lua,
            answer: None,
        },
        Row {
            clause: "an inhibit denied with no inhibit outstanding, no action",
            message: M::Lid,
            answer: None,
        },
    ];
    for row in rows {
        let mut m = running();
        let actions = from(&mut m, 1, A, 1, row.message);
        let answer = sent(&actions)
            .into_iter()
            .map(|(_, slc, m)| (slc, m))
            .next();
        assert_eq!(answer, row.answer.map(|m| (1, m)), "{}", row.clause);
        assert!(m.carries(1), "{}", row.clause);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Start(..) | Action::Hold(_))),
            "{}",
            row.clause
        );
    }
}

#[test]
fn the_inhibit_tests_repair_a_disagreement() {
    let t = Timers::default();
    // 10.6.1 ii): a local inhibit test for a link not marked remotely
    // inhibited, "the force uninhibit procedure to be invoked". 10.3.2 d):
    // "The force uninhibit signalling link message is transmitted down the
    // link to be uninhibited." e): T13, twice.
    let mut m = running();
    let forced = from(&mut m, 0, A, 0, M::Llt);
    assert_eq!(sent(&forced), [(A, 0, M::Lfu)]);
    assert_eq!(path_of(&forced, &M::Lfu), Some(Path::Link(0)));
    assert!(forced.contains(&Action::Start(Timer::ForceUninhibit(0), t.t13)));
    let repeated = m.handle(Input::Timeout(Timer::ForceUninhibit(0)));
    assert_eq!(sent(&repeated), [(A, 0, M::Lfu)]);
    let abandoned = m.handle(Input::Timeout(Timer::ForceUninhibit(0)));
    assert!(sent(&abandoned).is_empty());
    assert!(noted(&abandoned, Procedure::UninhibitAbandoned));
    // The uninhibit the force asks for ends it.
    let mut m = running();
    from(&mut m, 0, A, 0, M::Llt);
    let answered = from(&mut m, 0, A, 0, M::Lun);
    assert!(answered.contains(&Action::Stop(Timer::ForceUninhibit(0))));
    assert!(m
        .handle(Input::Timeout(Timer::ForceUninhibit(0)))
        .is_empty());

    // 10.6.2 ii): a remote inhibit test for a link this node has not
    // inhibited, "the uninhibit procedure to be invoked". 10.3.1 e): T12,
    // twice.
    let mut m = running();
    let uninhibit = from(&mut m, 0, A, 0, M::Lrt);
    assert_eq!(sent(&uninhibit), [(A, 0, M::Lun)]);
    assert!(uninhibit.contains(&Action::Start(Timer::Uninhibit(0), t.t12)));
    assert_eq!(
        sent(&m.handle(Input::Timeout(Timer::Uninhibit(0)))),
        [(A, 0, M::Lun)]
    );
    assert!(noted(
        &m.handle(Input::Timeout(Timer::Uninhibit(0))),
        Procedure::UninhibitAbandoned
    ));
    let mut m = running();
    from(&mut m, 0, A, 0, M::Lrt);
    let acknowledged = from(&mut m, 0, A, 0, M::Lua);
    assert_eq!(acknowledged, [Action::Stop(Timer::Uninhibit(0))]);
}

// ── Robustness ───────────────────────────────────────────────────────────────

#[test]
fn inputs_about_things_that_do_not_exist_do_nothing() {
    let mut m = running();
    assert!(m.handle(Input::LinkUp { link: 99 }).is_empty());
    assert!(m.handle(Input::LinkDown { link: 99, bsnt: 0 }).is_empty());
    assert!(m
        .handle(Input::Unroutable {
            dpc: 2999,
            link: 99
        })
        .is_empty());
    assert!(m
        .handle(Input::Received {
            link: 99,
            opc: A,
            slc: 0,
            message: M::Tra
        })
        .is_empty());
    for timer in [
        Timer::Changeover(99),
        Timer::Changeback(99),
        Timer::Rerouting(9999),
        Timer::RouteSetTest(2000, 99),
        Timer::Uninhibit(99),
        Timer::ForceUninhibit(99),
        Timer::InhibitTest(99),
        Timer::RestartAllowed(99),
        Timer::AdjacentRestart(99),
        // Timers that ran out after what they were for was over.
        Timer::Changeover(0),
        Timer::Changeback(0),
        Timer::Rerouting(2000),
        Timer::Restart,
    ] {
        assert!(m.handle(Input::Timeout(timer)).is_empty(), "{timer:?}");
    }
    assert!(m.handle(Input::Server { index: 9, up: true }).is_empty());
    assert!(m
        .handle(Input::Paused {
            dpc: 2999,
            paused: true
        })
        .is_empty());
}

#[test]
fn a_short_isolation_does_not_restart_and_a_long_one_does() {
    let mut m = running();
    let t = Timers::default();
    m.handle(Input::Server {
        index: 0,
        up: false,
    });
    let mut isolated = Vec::new();
    for link in 0..4 {
        isolated = m.handle(Input::LinkDown { link, bsnt: 0 });
    }
    assert!(isolated.contains(&Action::Start(Timer::Isolation, t.t1)));
    // 9.4.1: "In the case where a signalling point is isolated due to a short
    // term processor outage [lasting less than T1] ... the restart procedure
    // should not be started."
    let back = m.handle(Input::LinkUp { link: 0 });
    assert!(back.contains(&Action::Stop(Timer::Isolation)));
    assert!(!m.is_restarting());

    // "If an isolation lasts longer than T1, the restart procedure must be
    // performed."
    m.handle(Input::LinkDown { link: 0, bsnt: 0 });
    m.handle(Input::Timeout(Timer::Isolation));
    let restarted = m.handle(Input::LinkUp { link: 0 });
    assert!(restarted.contains(&Action::Restarting(true)));
}

// ── 13.4: a destination reached by restricted routes only ────────────────────

#[test]
fn a_destination_is_restricted_while_every_route_in_use_is() {
    let restricted = |actions: &[Action], dpc: u32| {
        actions.iter().find_map(|a| match a {
            Action::Restricted {
                dpc: about,
                restricted,
            } if *about == dpc => Some(*restricted),
            _ => None,
        })
    };
    let mut m = running();
    // 2300 has the one route through C: restricted there, it is restricted.
    let tfr = |dpc| M::Tfr {
        destination: pc(dpc),
    };
    let tfa = |dpc| M::Tfa {
        destination: pc(dpc),
    };
    let actions = from(&mut m, 3, C, 0, tfr(2300));
    assert_eq!(restricted(&actions, 2300), Some(true));
    assert!(m.is_accessible(2300), "it can still be reached");
    // Said once.
    assert_eq!(restricted(&from(&mut m, 3, C, 0, tfr(2300)), 2300), None);
    let actions = from(&mut m, 3, C, 0, tfa(2300));
    assert_eq!(restricted(&actions, 2300), Some(false));

    // 2200 is shared by B and C: restricted through one of them, the other
    // carries it alone and it is not restricted.
    let actions = from(&mut m, 2, B, 0, tfr(2200));
    assert_eq!(restricted(&actions, 2200), None);
    let actions = from(&mut m, 3, C, 0, tfr(2200));
    assert_eq!(restricted(&actions, 2200), Some(true));
    // The link to C fails: B's restricted route is all there is, and still
    // is. The link to B fails too: inaccessible, which says it all.
    let actions = m.handle(Input::LinkDown { link: 3, bsnt: 0 });
    assert_eq!(restricted(&actions, 2200), None);
    let actions = m.handle(Input::LinkDown { link: 2, bsnt: 0 });
    assert_eq!(restricted(&actions, 2200), None);
    assert!(actions.contains(&Action::Accessibility {
        dpc: 2200,
        accessible: false
    }));
    // A destination behind an application server is never restricted.
    assert_eq!(restricted(&from(&mut m, 0, A, 0, tfr(2400)), 2400), None);
}
