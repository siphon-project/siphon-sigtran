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
    /// BER decoder returns this answer as complete, with one serving node. A
    /// service centre acting on that never tries the second node.
    #[test]
    fn the_lenient_decoder_returns_the_malformed_answer_without_its_second_node() {
        let wire = sri_sm_res(&NO_SUCH_ALTERNATIVE);
        let lenient: RoutingInfoForSmRes =
            rasn::ber::decode(&wire).expect("the lenient decoder accepts it");
        assert_eq!(lenient.location_info_with_lmsi.additional_number, None);
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
    fn the_lenient_decoder_returns_the_vector_list_one_short() {
        let wire = sai_res(&triplet_without_kc());
        let lenient: SendAuthenticationInfoRes =
            rasn::ber::decode(&wire).expect("the lenient decoder accepts it");
        assert_eq!(lenient.triplet_list.map(|t| t.len()), Some(1));
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

    /// The lenient decoder took an InitialDP with an unreadable member behind
    /// an explicit tag for one without that member.
    #[test]
    fn the_lenient_decoder_returns_the_initial_dp_without_the_unreadable_member() {
        // bearerCapability [27] is an explicit tag around a CHOICE { bearerCap
        // [0], tmr [1] }; [5] is no alternative of it.
        let wire = tlv(
            0x30,
            &[&[0x80, 0x01, 0x64][..], &tlv(0xBB, &[0x85, 0x01, 0x00])[..]].concat(),
        );
        let lenient: InitialDpArg =
            rasn::ber::decode(&wire).expect("the lenient decoder accepts it");
        assert_eq!(lenient.bearer_capability, None);
        assert!(inap::decode::<InitialDpArg>(&wire).is_err());
    }
}
