//! What a handler does with an argument or a result that does not decode, and
//! what the peer is sent for it.
//!
//! The application codecs decode strictly: a member or a list element that is
//! on the wire and cannot be read is an error, not a missing member. A handler
//! that gets such an error has been sent a mistyped parameter (Q.772 3.7.2.3,
//! 3.7.3.3, 3.7.4.5) and answers with a Reject of the component, through
//! [`PeerComponent::mistyped_parameter`] and [`Dialogue::reject`].
//!
//! The arguments and results are assembled by hand from the ASN.1 of the
//! application protocol, and the messages the engine emits are dissected by
//! Wireshark when `tshark` is installed. Every value is synthetic (test PLMN
//! 001/01, `+1-555-01xx` numbers).

#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads
use std::sync::{Arc, Mutex};

use tcap::{Component, Reject, TcapMessage};

use siphon_sigtran::dialogue::{
    CloseReason, Dialogue, PeerComponent, PeerTurn, Problem, ReturnResultProblem,
};

mod common;
use common::*;

/// What a handler read from the results of a turn: the decoded value, or the
/// decode error text.
type Seen<T> = Arc<Mutex<Vec<Result<T, String>>>>;

/// On every result of a turn: decode its parameter as `T` with `decode`; if it
/// does not decode, reject the component as mistyped. Then end the dialogue if
/// it is still open.
fn decode_results<T: Clone + Send + 'static>(
    seen: Seen<T>,
    decode: fn(&[u8]) -> Result<T, String>,
) -> impl Fn(&mut Dialogue, &PeerTurn) + Send + Sync + 'static {
    move |dlg, peer| {
        for component in &peer.components {
            let PeerComponent::Result { parameter, .. } = component else {
                continue;
            };
            let outcome = decode(parameter.as_deref().unwrap_or_default());
            if outcome.is_err() {
                if let Some((invoke_id, problem)) = component.mistyped_parameter() {
                    dlg.reject(invoke_id, problem);
                }
            }
            seen.lock().unwrap().push(outcome);
        }
        if !dlg.is_closed() {
            dlg.end().expect("end");
        }
    }
}

/// Open a dialogue toward the HLR with one class 1 invoke of `op`, and return
/// the engine, the probe and our transaction id.
fn originate(
    op: i64,
    argument: Vec<u8>,
    on_turn: impl Fn(&mut Dialogue, &PeerTurn) + Send + Sync + 'static,
) -> (
    siphon_sigtran::dialogue::DialogueEngine,
    Arc<Probe>,
    Vec<u8>,
) {
    let probe = Probe::new()
        .on_start(move |dlg| {
            dlg.invoke(op, Some(argument.clone())).expect("invoke");
            dlg.send().expect("the Begin");
        })
        .on_turn(on_turn)
        .arc();
    let engine = engine(probe.clone());
    let (tid, frames) = engine.begin(outgoing(), probe.clone()).expect("begin");
    assert_eq!(frames.len(), 1);
    (engine, probe, tid)
}

fn assert_rejected_as_mistyped_result(out: &[siphon_sigtran::transport::Msu], dtid: &str) {
    assert_eq!(out.len(), 1, "the peer is told");
    let TcapMessage::End(_) = decode(&out[0]) else {
        panic!("expected an End");
    };
    assert_eq!(
        rejects_of(&out[0]),
        vec![Reject::return_result(
            1,
            ReturnResultProblem::MISTYPED_PARAMETER
        )]
    );
    assert!(
        !components_of(&out[0])
            .iter()
            .any(|c| matches!(c, Component::Invoke(_))),
        "nothing is invoked on the strength of a result that was not read"
    );
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.end_element")
            .hex("tcap.dtid", dtid)
            .present("gsm_old.reject_element")
            .show("gsm_old.derivable", "1")
            .show("gsm_old.returnResultProblem", "2")
            .label("gsm_old.returnResultProblem", "mistypedParameter");
    }
}

// ── MAP (TS 29.002) ──────────────────────────────────────────────────────────

mod map {
    use super::*;
    use gsm_map::operations::auth::SendAuthenticationInfoRes;
    use gsm_map::operations::sri_sm::RoutingInfoForSmRes;
    use gsm_map::types::AdditionalNumber;

    const SRI_SM: i64 = 45;
    const SEND_AUTHENTICATION_INFO: i64 = 56;

    fn map_decode<T: rasn::Decode>(bytes: &[u8]) -> Result<T, String> {
        gsm_map::decode(bytes).map_err(|e| e.to_string())
    }

    /// `RoutingInfoForSM-Arg ::= SEQUENCE { msisdn [0], sm-RP-PRI [1] BOOLEAN,
    /// serviceCentreAddress [2] }` for MSISDN 15550142 and service centre
    /// 15550100.
    fn sri_sm_arg() -> Vec<u8> {
        tlv(
            0x30,
            &[
                &tlv(0x80, &[0x91, 0x51, 0x55, 0x10, 0x24])[..],
                &tlv(0x81, &[0xFF])[..],
                &tlv(0x82, &[0x91, 0x51, 0x55, 0x10, 0x00])[..],
            ]
            .concat(),
        )
    }

    /// `RoutingInfoForSM-Res ::= SEQUENCE { imsi IMSI, locationInfoWithLMSI [0]
    /// LocationInfoWithLMSI }` with `LocationInfoWithLMSI ::= SEQUENCE {
    /// networkNode-Number [1] ISDN-AddressString, ..., additional-Number [6]
    /// Additional-Number OPTIONAL }` and `Additional-Number ::= CHOICE {
    /// msc-Number [0], sgsn-Number [1] }`. IMSI 001010000000042, serving MSC
    /// 15550180, and `additional` as the content of the `[6]` member.
    fn sri_sm_res(additional: &[u8]) -> Vec<u8> {
        let location = [
            &tlv(0x81, &[0x91, 0x51, 0x55, 0x10, 0x08])[..],
            &tlv(0xA6, additional)[..],
        ]
        .concat();
        tlv(0x30, &[&RES[..], &tlv(0xA0, &location)[..]].concat())
    }

    /// `[1]`: the sgsn-Number alternative, 15550181.
    const SGSN_NUMBER: [u8; 7] = [0x81, 0x05, 0x91, 0x51, 0x55, 0x10, 0x18];
    /// `[2]`: no alternative of Additional-Number.
    const NO_SUCH_ALTERNATIVE: [u8; 7] = [0x82, 0x05, 0x91, 0x51, 0x55, 0x10, 0x18];

    #[test]
    fn a_routing_answer_with_both_serving_nodes_decodes() {
        let seen: Seen<RoutingInfoForSmRes> = Seen::default();
        let (engine, _probe, tid) = originate(
            SRI_SM,
            sri_sm_arg(),
            decode_results(seen.clone(), map_decode),
        );
        let answer = cont(
            &[0x77],
            &tid,
            &[return_result_last(
                1,
                Some((SRI_SM, &sri_sm_res(&SGSN_NUMBER))),
            )],
        );
        let out = engine.deliver(&inbound(&answer), "ingress");
        assert_eq!(out.len(), 1);
        assert!(rejects_of(&out[0]).is_empty());
        let seen = seen.lock().unwrap();
        let res = seen[0].as_ref().expect("decodes");
        assert_eq!(
            res.location_info_with_lmsi.additional_number,
            Some(AdditionalNumber::SgsnNumber(
                vec![0x91, 0x51, 0x55, 0x10, 0x18].into()
            ))
        );
    }

    /// The defect the strict decoder closes, pinned on the octets: the generic
    /// BER decoder of rasn 0.28 returned this answer as complete, with one
    /// serving node. A service centre acting on that never tries the second
    /// node.
    #[test]
    fn a_malformed_answer_is_not_returned_without_its_second_node() {
        let wire = sri_sm_res(&NO_SUCH_ALTERNATIVE);
        // rasn 0.28 returned it without the unreadable part; 0.29 refuses it.
        assert!(rasn::ber::decode::<RoutingInfoForSmRes>(&wire).is_err());
        assert!(gsm_map::decode::<RoutingInfoForSmRes>(&wire).is_err());
    }

    /// A routing answer whose additional number is malformed is an error to the
    /// handler, and the peer gets a Reject of the result: returnResultProblem,
    /// mistypedParameter (Q.773 Table 28, value 2).
    #[test]
    fn a_routing_answer_with_a_malformed_additional_number_is_rejected() {
        let seen: Seen<RoutingInfoForSmRes> = Seen::default();
        let (engine, probe, tid) = originate(
            SRI_SM,
            sri_sm_arg(),
            decode_results(seen.clone(), map_decode),
        );
        let answer = cont(
            &[0x77, 0x78],
            &tid,
            &[return_result_last(
                1,
                Some((SRI_SM, &sri_sm_res(&NO_SUCH_ALTERNATIVE))),
            )],
        );
        let out = engine.deliver(&inbound(&answer), "ingress");
        assert!(
            seen.lock().unwrap()[0].is_err(),
            "the handler is not handed an answer with a node missing"
        );
        assert_rejected_as_mistyped_result(&out, "7778");
        assert_eq!(probe.reasons(), vec![CloseReason::Ended]);
        assert_eq!(engine.open_dialogues(), 0);
    }

    /// The same answer in an End: the transaction is over, so no Reject can be
    /// sent, and the handler still gets the error instead of half an answer.
    #[test]
    fn a_malformed_routing_answer_in_an_end_is_an_error_to_the_handler() {
        let seen: Seen<RoutingInfoForSmRes> = Seen::default();
        let (engine, probe, tid) = originate(
            SRI_SM,
            sri_sm_arg(),
            decode_results(seen.clone(), map_decode),
        );
        let answer = end(
            &tid,
            &[return_result_last(
                1,
                Some((SRI_SM, &sri_sm_res(&NO_SUCH_ALTERNATIVE))),
            )],
        );
        assert!(engine.deliver(&inbound(&answer), "ingress").is_empty());
        assert!(seen.lock().unwrap()[0].is_err());
        assert_eq!(probe.reasons(), vec![CloseReason::PeerEnded]);
    }

    /// `SendAuthenticationInfoRes ::= [3] SEQUENCE { authenticationSetList
    /// CHOICE { tripletList [0] SEQUENCE OF AuthenticationTriplet, .. } }` with
    /// `AuthenticationTriplet ::= SEQUENCE { rand OCTET STRING (SIZE (16)), sres
    /// (SIZE (4)), kc (SIZE (8)) }`. One whole triplet, then `last`.
    fn sai_res(last: &[u8]) -> Vec<u8> {
        let whole = tlv(
            0x30,
            &[
                &tlv(0x04, &[0x11; 16])[..],
                &tlv(0x04, &[0x22; 4])[..],
                &tlv(0x04, &[0x33; 8])[..],
            ]
            .concat(),
        );
        tlv(0xA3, &tlv(0xA0, &[&whole[..], last].concat()))
    }

    /// A triplet without its kc.
    fn triplet_without_kc() -> Vec<u8> {
        tlv(
            0x30,
            &[&tlv(0x04, &[0x44; 16])[..], &tlv(0x04, &[0x55; 4])[..]].concat(),
        )
    }

    #[test]
    fn a_vector_list_is_not_returned_one_short() {
        let wire = sai_res(&triplet_without_kc());
        // rasn 0.28 returned it without the unreadable part; 0.29 refuses it.
        assert!(rasn::ber::decode::<SendAuthenticationInfoRes>(&wire).is_err());
        assert!(gsm_map::decode::<SendAuthenticationInfoRes>(&wire).is_err());
    }

    /// A list of authentication vectors whose last element is malformed is
    /// refused whole, and the result rejected: the handler does not get a list
    /// that is one vector short.
    #[test]
    fn an_authentication_vector_list_with_a_malformed_last_element_is_refused() {
        let seen: Seen<SendAuthenticationInfoRes> = Seen::default();
        // SendAuthenticationInfoArg ::= SEQUENCE { imsi [0], numberOfRequestedVectors }.
        let argument = tlv(
            0x30,
            &[&tlv(0x80, &RES[2..])[..], &[0x02, 0x01, 0x02][..]].concat(),
        );
        let (engine, _probe, tid) = originate(
            SEND_AUTHENTICATION_INFO,
            argument,
            decode_results(seen.clone(), map_decode),
        );
        let answer = cont(
            &[0x79],
            &tid,
            &[return_result_last(
                1,
                Some((SEND_AUTHENTICATION_INFO, &sai_res(&triplet_without_kc()))),
            )],
        );
        let out = engine.deliver(&inbound(&answer), "ingress");
        assert!(seen.lock().unwrap()[0].is_err());
        assert_rejected_as_mistyped_result(&out, "79");

        // Two whole triplets decode.
        let whole = tlv(
            0x30,
            &[
                &tlv(0x04, &[0x44; 16])[..],
                &tlv(0x04, &[0x55; 4])[..],
                &tlv(0x04, &[0x66; 8])[..],
            ]
            .concat(),
        );
        let res: SendAuthenticationInfoRes =
            gsm_map::decode(&sai_res(&whole)).expect("two whole triplets");
        assert_eq!(res.triplet_list.map(|t| t.len()), Some(2));
    }

    /// TS 29.002 17.1.4 has a receiver accept extension additions it does not
    /// know. A routing answer carrying a member this crate does not model,
    /// after the ones it does, is read, and what was skipped is reported.
    #[test]
    fn a_routing_answer_with_an_unknown_extension_member_is_accepted() {
        // A `[29]` member after `locationInfoWithLMSI`, past the extension
        // marker of RoutingInfoForSM-Res.
        let location = tlv(0x81, &[0x91, 0x51, 0x55, 0x10, 0x08]);
        let wire = tlv(
            0x30,
            &[&RES[..], &tlv(0xA0, &location)[..], &[0x9D, 0x01, 0x2A][..]].concat(),
        );
        let seen: Seen<RoutingInfoForSmRes> = Seen::default();
        let (engine, _probe, tid) = originate(
            SRI_SM,
            sri_sm_arg(),
            decode_results(seen.clone(), map_decode),
        );
        let answer = cont(
            &[0x7A],
            &tid,
            &[return_result_last(1, Some((SRI_SM, &wire)))],
        );
        let out = engine.deliver(&inbound(&answer), "ingress");
        assert!(rejects_of(&out[0]).is_empty(), "nothing is rejected");
        assert!(seen.lock().unwrap()[0].is_ok());

        let decoded =
            gsm_map::decode_with_extensions::<RoutingInfoForSmRes>(&wire).expect("decodes");
        assert_eq!(decoded.unknown_extensions.len(), 1);
    }

    /// The opening Invoke: an argument that does not decode is rejected with
    /// invokeProblem, mistypedParameter (Q.773 Table 27, value 2).
    #[test]
    fn an_invoke_whose_argument_does_not_decode_is_rejected() {
        use gsm_map::operations::sri_sm::RoutingInfoForSmArg;
        let probe = Probe::new()
            .on_begin(|dlg, op| {
                let argument = op.argument.as_deref().unwrap_or_default();
                match gsm_map::decode::<RoutingInfoForSmArg>(argument) {
                    Ok(_) => dlg.reply(op.operation_code, Some(RES.to_vec())),
                    Err(_) => {
                        let (invoke_id, problem) = op.mistyped_parameter();
                        dlg.reject(invoke_id, problem);
                    }
                }
                dlg.end().expect("end");
            })
            .arc();
        let mut engine = siphon_sigtran::dialogue::DialogueEngine::new(Default::default());
        engine.register(HLR, SRI_SM, probe);

        // The service centre address member [2] is cut short: it announces five
        // octets and the argument ends after two.
        let mut damaged = sri_sm_arg();
        damaged.truncate(damaged.len() - 3);
        damaged[1] -= 3;
        let wire = begin(
            &[0x7B],
            Some(&aarq(&AC)),
            &[invoke(9, SRI_SM, Some(&damaged))],
        );
        let out = engine.deliver(&inbound(&wire), "ingress");
        assert_eq!(out.len(), 1);
        assert_eq!(
            rejects_of(&out[0]),
            vec![Reject {
                invoke_id: Some(9),
                problem: Problem::Invoke(tcap::InvokeProblem::MISTYPED_PARAMETER),
            }]
        );
        if let Some(d) = dissect(&out[0]) {
            d.present("tcap.end_element")
                .hex("tcap.dtid", "7b")
                .show("gsm_old.derivable", "9")
                .show("gsm_old.invokeProblem", "2");
        }

        // The whole argument is answered.
        let wire = begin(
            &[0x7C],
            Some(&aarq(&AC)),
            &[invoke(9, SRI_SM, Some(&sri_sm_arg()))],
        );
        let out = engine.deliver(&inbound(&wire), "ingress");
        assert!(rejects_of(&out[0]).is_empty());
    }
}

// ── INAP CS-1 (ETS 300 374-1 / Q.1218) ───────────────────────────────────────

mod inap_cs1 {
    use super::*;
    use inap::operations::{ConnectArg, InitialDpArg, RequestReportBcsmEventArg};
    use inap::types::{BcsmEvent, EventTypeBcsm, LegId, MonitorMode};
    use siphon_sigtran::dialogue::{DialogueEngine, OperationClass};

    /// The IN SCP subsystem; Wireshark hands its TCAP components to the INAP
    /// dissector.
    const SCP: u8 = 106;
    const INITIAL_DP: i64 = 0;

    /// `cs1-ssp-to-scp`: `{ ccitt(0) identified-organization(4) etsi(0)
    /// inDomain(1) in-network(1) ac(1) cs1-ssp-to-scp(0) version1(0) }` (ETS
    /// 300 374-1 clause 6.5), as OBJECT IDENTIFIER content octets.
    const CS1_SSP_TO_SCP: [u8; 7] = [0x04, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00];

    /// Q.763 Called Party Number, international, ISDN numbering plan, for the
    /// digits 15550142: nature of address 4 with an even count, plan 1.
    const CALLED: [u8; 6] = [0x04, 0x10, 0x51, 0x55, 0x10, 0x24];

    /// `InitialDPArg ::= SEQUENCE { serviceKey [0] ServiceKey,
    /// calledPartyNumber [2] CalledPartyNumber OPTIONAL, .. }` with service key
    /// 100.
    fn initial_dp() -> Vec<u8> {
        tlv(
            0x30,
            &[&[0x80, 0x01, 0x64][..], &tlv(0x82, &CALLED)[..]].concat(),
        )
    }

    /// An SCP that reads the InitialDP strictly, arms two detection points each
    /// on its leg and connects the call, holding the dialogue open.
    fn scp() -> DialogueEngine {
        let probe = Probe::new()
            .on_begin(|dlg, op| {
                let argument = op.argument.as_deref().unwrap_or_default();
                let Ok(idp) = inap::decode::<InitialDpArg>(argument) else {
                    let (invoke_id, problem) = op.mistyped_parameter();
                    dlg.reject(invoke_id, problem);
                    dlg.end().expect("end");
                    return;
                };
                assert_eq!(i64::try_from(&idp.service_key), Ok(100));
                let mut answer =
                    BcsmEvent::new(EventTypeBcsm::OAnswer, MonitorMode::NotifyAndContinue);
                answer.leg_id = Some(LegId::sending(2));
                let mut disconnect =
                    BcsmEvent::new(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted);
                disconnect.leg_id = Some(LegId::sending(1));
                let rrbe = RequestReportBcsmEventArg::new(vec![answer, disconnect]);
                let connect = ConnectArg::new(CALLED.to_vec().into());
                // Both are class 2 operations (Q.1218): no reply is success.
                for (code, argument) in [
                    (
                        inap::op_codes::REQUEST_REPORT_BCSM_EVENT,
                        inap::encode(&rrbe),
                    ),
                    (inap::op_codes::CONNECT, inap::encode(&connect)),
                ] {
                    dlg.invoke_with(
                        code,
                        Some(argument.expect("encode")),
                        OperationClass::Two,
                        None,
                    )
                    .expect("invoke");
                }
                dlg.send().expect("send");
            })
            .arc();
        let mut engine = DialogueEngine::new(Default::default());
        engine.register(SCP, INITIAL_DP, probe);
        engine
    }

    /// A dialogue under the real cs1-ssp-to-scp context: the Begin with
    /// InitialDP reaches the handler, and the Continue it answers with carries
    /// the AARE for that context, a RequestReportBCSMEvent whose events name
    /// their legs, and a Connect. Wireshark reads all of it as INAP.
    #[test]
    fn a_dialogue_under_the_cs1_application_context_dissects_as_inap() {
        let engine = scp();
        let request = inbound_between(
            SCP,
            SCP,
            &begin(
                &[0x1A, 0x1B],
                Some(&aarq(&CS1_SSP_TO_SCP)),
                &[invoke(1, INITIAL_DP, Some(&initial_dp()))],
            ),
        );
        let out = engine.deliver(&request, "ingress");
        assert_eq!(out.len(), 1);
        let TcapMessage::Continue(c) = decode(&out[0]) else {
            panic!("expected a Continue");
        };
        assert_eq!(c.dtid.as_ref(), &[0x1A, 0x1B]);
        let Ok(Some(tcap::DialoguePdu::Aare {
            application_context_name,
            ..
        })) = c.dialogue_portion.as_ref().expect("an AARE").dialogue_pdu()
        else {
            panic!("expected an AARE");
        };
        assert_eq!(
            application_context_name.as_ref(),
            &inap::application_context::CS1_SSP_TO_SCP[..],
            "the helper names the context a peer sends"
        );

        // The RequestReportBCSMEvent on the wire, against the ASN.1 by hand:
        // legID [2] is an explicit tag around the LegID CHOICE.
        let bytes = tcap_bytes(&out[0]);
        let events = [
            // 30 { [0] oAnswer (7), [1] notifyAndContinue (1), [2] { [0] leg 2 } }
            &[0x30, 0x0B, 0x80, 0x01, 0x07, 0x81, 0x01, 0x01][..],
            &[0xA2, 0x03, 0x80, 0x01, 0x02][..],
            // 30 { [0] oDisconnect (9), [1] interrupted (0), [2] { [0] leg 1 } }
            &[0x30, 0x0B, 0x80, 0x01, 0x09, 0x81, 0x01, 0x00][..],
            &[0xA2, 0x03, 0x80, 0x01, 0x01][..],
        ]
        .concat();
        assert!(contains(&bytes, &tlv(0x30, &tlv(0xA0, &events))));

        if let Some(d) = dissect_all(&[&request, &out[0]]) {
            d.present("inap")
                // The Begin: the context, and the InitialDP.
                .show("tcap.aarq_application_context_name", "0.4.0.1.1.1.0.0")
                .present("inap.InitialDPArg_element")
                .show("inap.serviceKey", "100")
                // The Continue: the AARE, then the two invokes.
                .present("tcap.continue_element")
                .hex("tcap.dtid", "1a1b")
                .show("tcap.aare_application_context_name", "0.4.0.1.1.1.0.0")
                .show_all("inap.code.local", &["0", "23", "20"])
                .present("inap.RequestReportBCSMEventArg_element")
                .show("inap.bcsmEvents", "2")
                .show_all("inap.eventTypeBCSM", &["7", "9"])
                .show_all("inap.monitorMode", &["1", "0"])
                .show_all("inap.sendingSideID", &["02", "01"])
                .present("inap.ConnectArg_element")
                .show("inap.destinationRoutingAddress", "1")
                .show_all("inap.CalledPartyNumber", &["04:10:51:55:10:24"]);
        }
    }

    /// An InitialDP that does not decode is rejected: Reject, invokeProblem,
    /// mistypedParameter, in an End that still answers the dialogue request.
    #[test]
    fn an_initial_dp_that_does_not_decode_is_rejected() {
        let engine = scp();
        for damaged in [
            // serviceKey [0] announces four octets and holds one.
            tlv(0x30, &[0x80, 0x04, 0x64]),
            // No serviceKey, which ETS 300 374-1 makes mandatory.
            tlv(0x30, &tlv(0x82, &CALLED)),
            // A member InitialDPArg does not have ([45]).
            tlv(0x30, &[0x80, 0x01, 0x64, 0x9F, 0x2D, 0x01, 0x00]),
            // An eventTypeBCSM [28] that is not one of the enumeration (99).
            tlv(0x30, &[0x80, 0x01, 0x64, 0x9C, 0x01, 0x63]),
        ] {
            let request = inbound_between(
                SCP,
                SCP,
                &begin(
                    &[0x1C],
                    Some(&aarq(&CS1_SSP_TO_SCP)),
                    &[invoke(3, INITIAL_DP, Some(&damaged))],
                ),
            );
            let out = engine.deliver(&request, "ingress");
            assert_eq!(out.len(), 1, "{damaged:02x?}");
            let TcapMessage::End(_) = decode(&out[0]) else {
                panic!("expected an End");
            };
            assert_eq!(
                rejects_of(&out[0]),
                vec![Reject::invoke(3, tcap::InvokeProblem::MISTYPED_PARAMETER)],
                "{damaged:02x?}"
            );
            assert_eq!(engine.open_dialogues(), 0);
            if let Some(d) = dissect(&out[0]) {
                d.present("tcap.end_element")
                    .hex("tcap.dtid", "1c")
                    .show("tcap.aare_application_context_name", "0.4.0.1.1.1.0.0")
                    .present("inap.reject_element")
                    .show("inap.present", "3")
                    .show("inap.invokeProblem", "2")
                    .label("inap.invokeProblem", "mistypedArgument");
            }
        }
    }

    /// The lenient decoder (rasn 0.28) took an InitialDP with an unreadable
    /// member behind an explicit tag for one without that member.
    #[test]
    fn an_initial_dp_is_not_returned_without_the_unreadable_member() {
        // bearerCapability [27] is an explicit tag around a CHOICE { bearerCap
        // [0], tmr [1] }; [5] is no alternative of it.
        let wire = tlv(
            0x30,
            &[&[0x80, 0x01, 0x64][..], &tlv(0xBB, &[0x85, 0x01, 0x00])[..]].concat(),
        );
        // rasn 0.28 returned it without the unreadable part; 0.29 refuses it.
        assert!(rasn::ber::decode::<InitialDpArg>(&wire).is_err());
        assert!(inap::decode::<InitialDpArg>(&wire).is_err());
    }
}

// ── CAP (TS 29.078) ──────────────────────────────────────────────────────────

mod cap {
    use super::*;
    use gsm_cap::operations::{
        ApplyChargingArg, ApplyChargingReportArg, EventReportBcsmArg, InitialDpArg, ReleaseCallArg,
        RequestReportBcsmEventArg,
    };
    use gsm_cap::types::{
        BcsmEvent, CamelAChBillingChargingCharacteristicsV3, CamelCallResult, EventTypeBcsm, LegId,
        MonitorMode, SendingSideId, TimeDurationChargingV3, TimeInformation,
    };
    use siphon_sigtran::dialogue::{DialogueEngine, OperationClass};

    /// The CAP subsystem; Wireshark hands its TCAP components to the CAMEL
    /// dissector.
    const CAP: u8 = 146;
    const INITIAL_DP: i64 = 0;
    const EVENT_REPORT_BCSM: i64 = 24;
    const APPLY_CHARGING_REPORT: i64 = 36;

    /// `capssf-scfGenericAC`, CAMEL phase 3: `{ itu-t(0)
    /// identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1)
    /// cap3OE(21) ac(3) 4 }`, as OBJECT IDENTIFIER content octets.
    const GENERIC_PHASE3: [u8; 7] = [0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x04];

    /// A mobile-originated InitialDP as a gsmSSF sends it, by hand from
    /// `InitialDPArg` of TS 29.078, the members in the order the ASN.1 declares
    /// them. Test PLMN 001/01, IMSI 001010000000042, dialled 15550142.
    fn initial_dp() -> Vec<u8> {
        // LocationInformation (TS 29.002): the age (untagged INTEGER), the VLR
        // number [1], and the cell global id behind the explicit [3] of a
        // CHOICE: cellGlobalIdOrServiceAreaIdFixedLength [0], MCC 001 MNC 01
        // (`00 F1 10`), LAC 1, CI 1.
        let location = [
            &[0x02, 0x01, 0x00][..],
            &tlv(0x81, &[0x91, 0x51, 0x55, 0x10, 0x08])[..],
            &tlv(
                0xA3,
                &tlv(0x80, &[0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x01]),
            )[..],
        ]
        .concat();
        tlv(
            0x30,
            &[
                // serviceKey [0]: 100
                &[0x80, 0x01, 0x64][..],
                // callingPartyNumber [3]: Q.763, international, ISDN plan,
                // presentation allowed, network provided; 15550101
                &tlv(0x83, &[0x04, 0x13, 0x51, 0x55, 0x10, 0x10])[..],
                // callingPartysCategory [5]: ordinary subscriber
                &[0x85, 0x01, 0x0A][..],
                // bearerCapability [27], explicit: bearerCap [0], speech
                &tlv(0xBB, &tlv(0x80, &[0x80, 0x90, 0xA3]))[..],
                // eventTypeBCSM [28]: collectedInfo (2)
                &[0x9C, 0x01, 0x02][..],
                // iMSI [50]
                &tlv_high(false, 50, &RES[2..])[..],
                // subscriberState [51], explicit: assumedIdle [0] NULL
                &tlv_high(true, 51, &[0x80, 0x00])[..],
                // locationInformation [52]
                &tlv_high(true, 52, &location)[..],
                // ext-basicServiceCode [53], explicit: ext-Teleservice [3], telephony
                &tlv_high(true, 53, &[0x83, 0x01, 0x11])[..],
                // callReferenceNumber [54]
                &tlv_high(false, 54, &[0x01, 0x02, 0x03, 0x04])[..],
                // mscAddress [55]: 15550180
                &tlv_high(false, 55, &[0x91, 0x51, 0x55, 0x10, 0x08])[..],
                // calledPartyBCDNumber [56]: unknown type, ISDN plan; 15550142
                &tlv_high(false, 56, &[0x81, 0x51, 0x55, 0x10, 0x24])[..],
                // timeAndTimezone [57]: 2026-10-09 12:34:56, zone 0
                &tlv_high(false, 57, &[0x02, 0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00])[..],
            ]
            .concat(),
        )
    }

    /// EventReportBCSM for oAnswer on leg 2: `SEQUENCE { eventTypeBCSM [0] 7,
    /// eventSpecificInformationBCSM [2] { oAnswerSpecificInfo [5] {} }, legID
    /// [3] { receivingSideID [1] 02 }, miscCallInfo [4] { messageType [0]
    /// notification (1) } }`.
    fn event_report_answer() -> Vec<u8> {
        tlv(
            0x30,
            &[
                &[0x80, 0x01, 0x07][..],
                &[0xA2, 0x02, 0xA5, 0x00][..],
                &[0xA3, 0x03, 0x81, 0x01, 0x02][..],
                &[0xA4, 0x03, 0x80, 0x01, 0x01][..],
            ]
            .concat(),
        )
    }

    /// ApplyChargingReport: an OCTET STRING holding CAMEL-CallResult,
    /// `timeDurationChargingResult [0] { partyToCharge [0] { receivingSideID
    /// [1] 01 }, timeInformation [1] { timeIfNoTariffSwitch [0] 600 },
    /// legActive [2] FALSE }`: 60 seconds used, the leg released.
    fn apply_charging_report() -> Vec<u8> {
        let result = tlv(
            0xA0,
            &[
                &[0xA0, 0x03, 0x81, 0x01, 0x01][..],
                &[0xA1, 0x04, 0x80, 0x02, 0x02, 0x58][..],
                &[0x82, 0x01, 0x00][..],
            ]
            .concat(),
        );
        tlv(0x04, &result)
    }

    /// What the SCP read from the gsmSSF, for the assertions.
    #[derive(Default)]
    struct Seen {
        imsi: Option<Vec<u8>>,
        dialled: Option<Vec<u8>>,
        answered_on: Option<Vec<u8>>,
        used: Option<u32>,
    }

    /// An SCP for a prepaid call: on InitialDP it arms the answer and the
    /// disconnect of both legs, grants a call period and lets the call proceed;
    /// it notes the answer; on the charging report it releases the call.
    fn scp(seen: Arc<Mutex<Seen>>) -> DialogueEngine {
        let on_begin = seen.clone();
        let probe = Probe::new()
            .on_begin(move |dlg, op| {
                let argument = op.argument.as_deref().unwrap_or_default();
                let Ok(idp) = gsm_cap::decode::<InitialDpArg>(argument) else {
                    let (invoke_id, problem) = op.mistyped_parameter();
                    dlg.reject(invoke_id, problem);
                    dlg.end().expect("end");
                    return;
                };
                {
                    let mut seen = on_begin.lock().unwrap();
                    seen.imsi = idp.imsi.map(|i| i.to_vec());
                    seen.dialled = idp.called_party_bcd_number.map(|n| n.to_vec());
                }
                // The call may last an hour before the next message.
                dlg.set_idle_timeout(Some(std::time::Duration::from_secs(3_600)));

                let event = |event, mode, leg| {
                    let mut armed = BcsmEvent::new(event, mode);
                    armed.leg_id = Some(LegId::sending(leg));
                    armed
                };
                let rrbe = RequestReportBcsmEventArg::new(vec![
                    event(EventTypeBcsm::OAnswer, MonitorMode::NotifyAndContinue, 2),
                    event(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted, 1),
                    event(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted, 2),
                ]);
                // The dialogue runs under the phase 3 context, so the charging
                // characteristics are the phase 3 type: 60 s, release at the
                // end, a warning tone.
                assert_eq!(dlg.application_context(), [0, 4, 0, 0, 1, 21, 3, 4]);
                let mut charging = TimeDurationChargingV3::new(600);
                charging.release_if_duration_exceeded = Some(true);
                charging.tone = Some(true);
                let mut apply = ApplyChargingArg::with_characteristics(
                    &CamelAChBillingChargingCharacteristicsV3::TimeDurationCharging(charging),
                )
                .expect("encode the characteristics");
                apply.party_to_charge = Some(SendingSideId::leg(1));

                // RequestReportBCSMEvent and ApplyCharging are class 2, Continue
                // is class 4 (TS 29.078).
                for (code, argument, class) in [
                    (
                        gsm_cap::op_codes::REQUEST_REPORT_BCSM_EVENT,
                        Some(gsm_cap::encode(&rrbe).expect("encode")),
                        OperationClass::Two,
                    ),
                    (
                        gsm_cap::op_codes::APPLY_CHARGING,
                        Some(gsm_cap::encode(&apply).expect("encode")),
                        OperationClass::Two,
                    ),
                    (gsm_cap::op_codes::CONTINUE, None, OperationClass::Four),
                ] {
                    dlg.invoke_with(code, argument, class, None)
                        .expect("invoke");
                }
                dlg.send().expect("send");
            })
            .on_turn(move |dlg, peer| {
                for component in &peer.components {
                    let PeerComponent::Invoke {
                        operation_code,
                        argument,
                        ..
                    } = component
                    else {
                        continue;
                    };
                    let argument = argument.as_deref().unwrap_or_default();
                    let mut seen = seen.lock().unwrap();
                    let read = match *operation_code {
                        EVENT_REPORT_BCSM => {
                            gsm_cap::decode::<EventReportBcsmArg>(argument).map(|report| {
                                seen.answered_on = report.leg_id.map(|leg| leg.leg_type().to_vec());
                            })
                        }
                        APPLY_CHARGING_REPORT => {
                            gsm_cap::decode::<ApplyChargingReportArg>(argument)
                                .and_then(|report| report.call_result())
                                .map(|CamelCallResult::TimeDurationChargingResult(result)| {
                                    if let TimeInformation::TimeIfNoTariffSwitch(used) =
                                        result.time_information
                                    {
                                        seen.used = Some(used);
                                    }
                                    // The period is used up: release, normal call
                                    // clearing (Q.850 cause 16, coded ITU-T,
                                    // location user).
                                    let release = ReleaseCallArg(vec![0x80, 0x90].into());
                                    dlg.invoke_with(
                                        gsm_cap::op_codes::RELEASE_CALL,
                                        Some(gsm_cap::encode(&release).expect("encode")),
                                        OperationClass::Four,
                                        None,
                                    )
                                    .expect("invoke");
                                    dlg.end().expect("end");
                                })
                        }
                        _ => Ok(()),
                    };
                    if read.is_err() {
                        if let Some((invoke_id, problem)) = component.mistyped_parameter() {
                            dlg.reject(invoke_id, problem);
                            dlg.end().expect("end");
                        }
                    }
                }
            })
            .arc();
        let mut engine = DialogueEngine::new(Default::default());
        engine.register(CAP, INITIAL_DP, probe);
        engine
    }

    fn from_ssf(tcap_bytes: &[u8]) -> siphon_sigtran::transport::Msu {
        inbound_between(CAP, CAP, tcap_bytes)
    }

    /// A prepaid call from trigger to release, through the engine: a realistic
    /// InitialDP under the phase 3 generic context; a Continue carrying
    /// RequestReportBCSMEvent with legs, ApplyCharging and Continue; the answer
    /// reported; the charging report; ReleaseCall with a cause in the End.
    /// Wireshark reads every frame as CAMEL, and the fields are asserted.
    #[test]
    fn a_prepaid_call_dissects_as_camel_field_by_field() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let engine = scp(seen.clone());
        let ssf = [0x2A, 0x2B, 0x2C, 0x2D];

        let trigger = from_ssf(&begin(
            &ssf,
            Some(&aarq(&GENERIC_PHASE3)),
            &[invoke(1, INITIAL_DP, Some(&initial_dp()))],
        ));
        let instructions = engine.deliver(&trigger, "ingress");
        assert_eq!(instructions.len(), 1);
        let TcapMessage::Continue(c) = decode(&instructions[0]) else {
            panic!("expected a Continue");
        };
        let scf = c.otid.to_vec();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.imsi.as_deref(), Some(&RES[2..]));
            assert_eq!(
                seen.dialled.as_deref(),
                Some(&[0x81, 0x51, 0x55, 0x10, 0x24][..])
            );
        }

        // The call is answered ten minutes of ringing and routing later.
        assert!(engine
            .sweep(std::time::Instant::now() + std::time::Duration::from_secs(600))
            .is_empty());
        let answer = from_ssf(&cont(
            &ssf,
            &scf,
            &[invoke(2, EVENT_REPORT_BCSM, Some(&event_report_answer()))],
        ));
        assert!(
            engine.deliver(&answer, "ingress").is_empty(),
            "a notification needs no answer, and none is an abort"
        );
        assert_eq!(
            seen.lock().unwrap().answered_on.as_deref(),
            Some(&[0x02][..])
        );
        assert_eq!(engine.open_dialogues(), 1);

        let report = from_ssf(&cont(
            &ssf,
            &scf,
            &[invoke(
                3,
                APPLY_CHARGING_REPORT,
                Some(&apply_charging_report()),
            )],
        ));
        let release = engine.deliver(&report, "ingress");
        assert_eq!(release.len(), 1);
        assert!(matches!(decode(&release[0]), TcapMessage::End(_)));
        assert_eq!(seen.lock().unwrap().used, Some(600));
        assert_eq!(engine.open_dialogues(), 0);

        // The charging characteristics on the wire, against the ASN.1 by hand:
        // phase 3 has `tone [3] BOOLEAN` (`83 01 FF`), where phase 4 would
        // have the explicit `audibleIndicator [3]` (`A3 03 01 01 FF`).
        let characteristics = [
            0xA0, 0x0A, 0x80, 0x02, 0x02, 0x58, 0x81, 0x01, 0xFF, 0x83, 0x01, 0xFF,
        ];
        let apply_charging = [
            &tlv(0x80, &characteristics)[..],
            // partyToCharge [2], explicit: sendingSideID [0] leg 1
            &[0xA2, 0x03, 0x80, 0x01, 0x01][..],
        ]
        .concat();
        assert!(contains(
            &tcap_bytes(&instructions[0]),
            &tlv(0x30, &apply_charging)
        ));

        if let Some(d) = dissect_all(&[&trigger, &instructions[0], &answer, &report, &release[0]]) {
            d.present("camel")
                .show_all(
                    "camel.local",
                    // InitialDP; RequestReportBCSMEvent, ApplyCharging, Continue;
                    // EventReportBCSM; ApplyChargingReport; ReleaseCall.
                    &["0", "23", "35", "31", "24", "36", "22"],
                )
                // The Begin.
                .show("tcap.aarq_application_context_name", "0.4.0.0.1.21.3.4")
                .present("camel.InitialDPArg_element")
                .show("camel.serviceKey", "100")
                .show("camel.callingPartyNumber", "04:13:51:55:10:10")
                .show("camel.bearerCap", "80:90:a3")
                .show("camel.iMSI", "00:01:01:00:00:00:40:f2")
                .present("gsm_map.ms.assumedIdle_element")
                .show("gsm_map.ms.vlr_number", "91:51:55:10:08")
                .show(
                    "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
                    "00:f1:10:00:01:00:01",
                )
                .show("gsm_map.ext_Teleservice", "17")
                .show("camel.callReferenceNumber", "01:02:03:04")
                .show("camel.mscAddress", "91:51:55:10:08")
                .show("camel.calledPartyBCDNumber", "81:51:55:10:24")
                .show("camel.timeandtimezone.time", "20261009123456")
                // The SCP's Continue.
                .show("tcap.aare_application_context_name", "0.4.0.0.1.21.3.4")
                .present("camel.RequestReportBCSMEventArg_element")
                .show("camel.bcsmEvents", "3")
                .show_all("camel.monitorMode", &["1", "0", "0"])
                .show_all("inap.sendingSideID", &["02", "01", "02"])
                .present("camel.ApplyChargingArg_element")
                .show("camel.maxCallPeriodDuration", "600")
                .show("camel.releaseIfdurationExceeded", "True")
                .show("camel.sendingSideID", "01")
                // The gsmSSF's reports.
                .present("camel.EventReportBCSMArg_element")
                .show_all("camel.eventTypeBCSM", &["2", "7", "9", "9", "7"])
                .present("camel.oAnswerSpecificInfo_element")
                .show_all("camel.receivingSideID", &["02", "01"])
                .show("inap.messageType", "1")
                .present("camel.timeDurationChargingResult_element")
                .show("camel.timeIfNoTariffSwitch", "600")
                .show("camel.legActive", "False")
                // The End.
                .present("tcap.end_element")
                .show("camel.allCallSegments", "80:90")
                .show("camel.cause_indicator", "16");
        }
    }

    /// An InitialDP that does not decode is rejected: Reject, invokeProblem,
    /// mistypedParameter, in an End.
    #[test]
    fn an_initial_dp_that_does_not_decode_is_rejected() {
        let engine = scp(Arc::default());
        let whole = initial_dp();
        for damaged in [
            // serviceKey [0] announces four octets and holds one.
            tlv(0x30, &[0x80, 0x04, 0x64]),
            // No serviceKey.
            tlv(0x30, &[0x85, 0x01, 0x0A]),
            // subscriberState [51] holding an alternative it does not have
            // ([7]): behind an explicit tag, where the plain decoder returned
            // the InitialDP without the member.
            tlv(
                0x30,
                &[
                    &[0x80, 0x01, 0x64][..],
                    &tlv_high(true, 51, &[0x87, 0x00])[..],
                ]
                .concat(),
            ),
            // The whole argument with its last member cut off mid-value.
            {
                let mut cut = whole[..whole.len() - 3].to_vec();
                cut[1] -= 3;
                cut
            },
        ] {
            let request = from_ssf(&begin(
                &[0x2E],
                Some(&aarq(&GENERIC_PHASE3)),
                &[invoke(5, INITIAL_DP, Some(&damaged))],
            ));
            let out = engine.deliver(&request, "ingress");
            assert_eq!(out.len(), 1, "{damaged:02x?}");
            assert!(matches!(decode(&out[0]), TcapMessage::End(_)));
            assert_eq!(
                rejects_of(&out[0]),
                vec![Reject::invoke(5, tcap::InvokeProblem::MISTYPED_PARAMETER)],
                "{damaged:02x?}"
            );
            assert_eq!(engine.open_dialogues(), 0);
            if let Some(d) = dissect(&out[0]) {
                d.present("tcap.end_element")
                    .hex("tcap.dtid", "2e")
                    .present("camel.reject_element")
                    .show("camel.present", "5")
                    .show("camel.invokeProblem", "2");
            }
        }
    }

    /// A report whose argument does not decode, on the established dialogue: the
    /// Invoke is rejected and the SCP ends the dialogue.
    #[test]
    fn an_event_report_that_does_not_decode_is_rejected() {
        let engine = scp(Arc::default());
        let ssf = [0x2F];
        let out = engine.deliver(
            &from_ssf(&begin(
                &ssf,
                Some(&aarq(&GENERIC_PHASE3)),
                &[invoke(1, INITIAL_DP, Some(&initial_dp()))],
            )),
            "ingress",
        );
        let TcapMessage::Continue(c) = decode(&out[0]) else {
            panic!("expected a Continue");
        };
        // legID [3] as the earlier encoding had it, a primitive [2] holding the
        // leg octet: not an EventReportBCSMArg.
        let old_form = tlv(0x30, &[0x80, 0x01, 0x07, 0x82, 0x01, 0x02]);
        let out = engine.deliver(
            &from_ssf(&cont(
                &ssf,
                &c.otid,
                &[invoke(7, EVENT_REPORT_BCSM, Some(&old_form))],
            )),
            "ingress",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(
            rejects_of(&out[0]),
            vec![Reject::invoke(7, tcap::InvokeProblem::MISTYPED_PARAMETER)]
        );
        assert!(matches!(decode(&out[0]), TcapMessage::End(_)));
    }

    /// The lenient decoder (rasn 0.28) took an InitialDP with an unreadable
    /// member behind an explicit tag for one without that member.
    #[test]
    fn an_initial_dp_is_not_returned_without_the_unreadable_member() {
        let wire = tlv(
            0x30,
            &[
                &[0x80, 0x01, 0x64][..],
                &tlv_high(true, 51, &[0x87, 0x00])[..],
            ]
            .concat(),
        );
        // rasn 0.28 returned it without the unreadable part; 0.29 refuses it.
        assert!(rasn::ber::decode::<InitialDpArg>(&wire).is_err());
        assert!(gsm_cap::decode::<InitialDpArg>(&wire).is_err());
    }
}
