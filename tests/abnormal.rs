//! The abnormal procedures of ITU-T Q.774 clause 3, driven through the
//! [`DialogueEngine`]: what the engine answers to a damaged or unexpected TCAP
//! message, and what it tells the handler.
//!
//! The damaged messages are assembled here octet by octet from the ASN.1 of
//! Q.773 clause 3 (the `tlv` helper only prepends a tag and a length), so they
//! do not depend on the encoder under test. Every message the engine emits in
//! response is checked twice: decoded back with the `tcap` codec, and, when
//! `tshark` is installed, dissected by Wireshark with assertions on the fields
//! it reads (message type, transaction ids, abort cause, problem code, invoke
//! id) and on the absence of malformed markers. Without `tshark` the dissection
//! half is skipped with a message; the CI wire job requires it.
//!
//! Every value is synthetic: `+1-555-01xx` global titles, decimal point codes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tcap::{AbortReason, Component, Reject, TcapMessage};

use siphon_sigtran::config::Tcap;
use siphon_sigtran::dialogue::{
    CloseReason, DialogueEngine, DialogueError, GeneralProblem, InvokeProblem, InvokeTimeout,
    OperationClass, PAbortCause, PeerAbort, PeerComponent, Problem, ReturnErrorProblem,
    ReturnResultProblem, UserAbort,
};

mod common;
use common::*;

// ── Tests: the transaction sub-layer (Q.774 3.3.4, Table 7) ──────────────────

/// Q.774 3.3.4: "if the originating transaction ID is derivable ... The
/// transaction sub-layer should form an Abort message with an appropriate
/// P-Abort cause information element and transmit it to the originating end."
/// Table 7, BEGIN / Der.: Abort.
#[test]
fn a_begin_with_trailing_octets_is_answered_with_a_p_abort() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    // A well-formed Begin, then one octet SCCP delivered as part of the user
    // data: "Length indicator value does not correspond to length of message"
    // (Q.772 Table 1, badly formatted transaction portion).
    let mut wire = begin(
        &[0x11, 0x22, 0x33, 0x44],
        None,
        &[invoke(1, OP, Some(&ARG))],
    );
    wire.push(0x00);

    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1, "a damaged Begin is answered, not dropped");
    assert_reversed(&out[0]);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(
        abort.reason,
        Some(AbortReason::PAbort(
            PAbortCause::BADLY_FORMATTED_TRANSACTION_PORTION
        ))
    );
    assert_eq!(engine.open_dialogues(), 0);

    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "11223344")
            .hex("tcap.p_abortCause", "02")
            .label("tcap.p_abortCause", "badlyFormattedTransactionPortion");
    }
}

/// Q.772 2.3.1 / Table 7, UNKNOWN / Der.: Abort, cause unrecognized message
/// type.
#[test]
fn an_unknown_message_type_with_a_derivable_otid_is_answered_with_a_p_abort() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    // [APPLICATION 3] is not a message type of Table 8/Q.773.
    let wire = tlv(0x63, &tlv(0x48, &[0x0A, 0x0B]));
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x0A, 0x0B]);
    assert_eq!(
        abort.reason,
        Some(AbortReason::PAbort(PAbortCause::UNRECOGNIZED_MESSAGE_TYPE))
    );
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "0a0b")
            .hex("tcap.p_abortCause", "00");
    }
}

/// Table 7, BEGIN / Not der.: Discard. Q.774 3.3.4: "if the originating
/// transaction ID is not derivable, the local end ... discards the message and
/// does not take any other action".
#[test]
fn a_begin_without_a_derivable_otid_is_discarded() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    // The originating transaction ID is five octets (SIZE (1..4)).
    let wire = tlv(0x62, &tlv(0x48, &[1, 2, 3, 4, 5]));
    assert!(engine.deliver(&inbound(&wire), "ingress").is_empty());
}

/// Table 7, CONTINUE / Der. / unass.: Abort. Q.772 Table 1: "a Continue
/// message has been received with an unrecognized (destination) Transaction
/// ID".
#[test]
fn a_continue_for_an_unknown_transaction_is_answered_unrecognised_transaction_id() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    let wire = cont(&[0x51, 0x52], &[0x80, 0x00, 0x00, 0x63], &[]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1, "an unknown Continue is answered, not dropped");
    assert_reversed(&out[0]);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x51, 0x52], "addressed to its OTID");
    assert_eq!(
        abort.reason,
        Some(AbortReason::PAbort(
            PAbortCause::UNRECOGNIZED_TRANSACTION_ID
        ))
    );
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "5152")
            .hex("tcap.p_abortCause", "01")
            .label("tcap.p_abortCause", "unrecognizedTransactionID");
    }
}

/// Table 7, END/ABORT with an unassigned destination transaction ID: Discard.
#[test]
fn an_end_or_abort_for_an_unknown_transaction_is_discarded() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    let end = tlv(0x64, &tlv(0x49, &[0x80, 0x00, 0x00, 0x63]));
    assert!(engine.deliver(&inbound(&end), "ingress").is_empty());
    let abort = tlv(0x67, &tlv(0x49, &[0x80, 0x00, 0x00, 0x63]));
    assert!(engine.deliver(&inbound(&abort), "ingress").is_empty());
}

// ── Tests: the engine's own aborts ───────────────────────────────────────────

/// Q.772 2.3.5: "resource limitation: Sufficient resources are not available
/// to start a transaction." The dialogue ceiling is exactly that, so it is a
/// P-Abort of the transaction sub-layer, not a dialogue-portion fault.
#[test]
fn a_begin_over_the_dialogue_ceiling_gets_a_p_abort_resource_limitation() {
    let mut engine = DialogueEngine::new(Tcap {
        max_dialogues: 1,
        ..Tcap::default()
    });
    engine.register(HLR, OP, Probe::new().on_begin(invoke_and_hold).arc());
    let first = engine.deliver(
        &inbound(&begin(&[0x01], None, &[invoke(1, OP, Some(&ARG))])),
        "ingress",
    );
    assert_eq!(first.len(), 1);
    assert_eq!(engine.open_dialogues(), 1);

    let out = engine.deliver(
        &inbound(&begin(&[0x02], None, &[invoke(1, OP, Some(&ARG))])),
        "ingress",
    );
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x02]);
    assert_eq!(
        abort.reason,
        Some(AbortReason::PAbort(PAbortCause::RESOURCE_LIMITATION))
    );
    assert_eq!(engine.open_dialogues(), 1);
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "02")
            .hex("tcap.p_abortCause", "04")
            .label("tcap.p_abortCause", "resourceLimitation");
    }
}

/// No handler serves the operation: the TC-user refuses the dialogue. Q.774
/// 3.2.2.1: "When a BEGIN message has been received ... containing a Dialogue
/// Request (AARQ) APDU, the TC-User can abort for any user defined reason ...
/// a Dialogue Abort (ABRT) APDU is generated with abort-source coded as
/// "dialogue-service-user"".
#[test]
fn a_begin_nobody_serves_gets_a_u_abort_from_the_dialogue_service_user() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    let wire = begin(
        &[0x31, 0x32, 0x33],
        Some(&aarq(&AC)),
        &[invoke(1, 99, Some(&ARG))],
    );
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x31, 0x32, 0x33]);
    assert_eq!(
        abrt_source(&abort),
        Some(0),
        "abort-source dialogue-service-user"
    );
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "313233")
            .absent("tcap.p_abortCause")
            .present("tcap.dialogueAbort_element")
            .show("tcap.abort_source", "0");
    }
}

/// Without a dialogue portion in the Begin there is no ABRT to send (Q.774
/// 3.2.2.1: "a Dialogue Abort (ABRT) APDU is formatted only for the case when
/// the AARQ/AARE APDUs were used during the dialogue establishment state"):
/// the Abort carries no reason.
#[test]
fn a_u_abort_of_a_dialogue_without_an_application_context_carries_no_reason() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    let wire = begin(&[0x31], None, &[invoke(1, 99, Some(&ARG))]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.reason, None);
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "31")
            .absent("tcap.p_abortCause")
            .absent("tcap.dialogueAbort_element");
    }
}

// ── Tests: the dialogue portion (Q.774 3.2.2.1) ──────────────────────────────

/// Q.774 3.2.2.1: for a syntactically incorrect dialogue portion "a
/// TR-U-ABORT request primitive is issued to the transaction sub-layer with an
/// ABRT APDU as user data. The abort-source field of the ABRT APDU is set to
/// "dialogue-service-provider" and the user information field is absent. ...
/// If any components are received in the message with an incorrect dialogue
/// portion, these are discarded."
#[test]
fn a_begin_with_a_malformed_dialogue_portion_gets_an_abrt_from_the_provider() {
    let seen = Probe::new().on_begin(reply_and_end).arc();
    let engine = engine(seen.clone());
    // The dialogue-as OID, then an AARQ whose application-context-name wrapper
    // [1] announces an OBJECT IDENTIFIER and holds an INTEGER.
    let aarq = tlv(0x60, &tlv(0xA1, &[0x02, 0x01, 0x05]));
    let external = tlv(
        0x28,
        &[
            &tlv(0x06, &[0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01])[..],
            &tlv(0xA0, &aarq)[..],
        ]
        .concat(),
    );
    let wire = begin(&[0x41, 0x42], Some(&external), &[invoke(1, OP, Some(&ARG))]);

    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1, "an abnormal dialogue is answered");
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x41, 0x42]);
    assert_eq!(
        abrt_source(&abort),
        Some(1),
        "abort-source dialogue-service-provider"
    );
    assert!(
        seen.begins().is_empty(),
        "the components of the message are discarded"
    );
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "4142")
            .present("tcap.dialogueAbort_element")
            .show("tcap.abort_source", "1");
    }
}

// ── Tests: the component portion (Q.774 3.2.2.2) ─────────────────────────────

/// Q.773 3.1: `result SEQUENCE { operationCode, parameter } OPTIONAL`: an
/// operation that returns nothing is answered with a ReturnResult that has no
/// result sequence at all.
#[test]
fn a_reply_without_a_parameter_is_a_return_result_without_a_result_sequence() {
    let engine = engine(
        Probe::new()
            .on_begin(|dlg, op| {
                dlg.reply(op.operation_code, None);
                dlg.end().expect("end");
            })
            .arc(),
    );
    let wire = begin(&[0x61], Some(&aarq(&AC)), &[invoke(5, OP, Some(&ARG))]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1, "the reply is sent, not swallowed");
    let TcapMessage::End(end) = decode(&out[0]) else {
        panic!("expected an End");
    };
    let comps = end.components.expect("components");
    let Component::ReturnResultLast(rr) = &comps[0] else {
        panic!("expected a ReturnResultLast, got {:?}", comps[0]);
    };
    assert_eq!(rr.invoke_id, 5);
    assert_eq!(rr.result, None);
    // a2 03 02 01 05: [2] { INTEGER 5 }, nothing after the invoke id.
    assert!(contains(
        &tcap_bytes(&out[0]),
        &[0xA2, 0x03, 0x02, 0x01, 0x05]
    ));

    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.end_element")
            .hex("tcap.dtid", "61")
            .present("gsm_old.returnResultLast_element")
            .show("gsm_old.invokeID", "5")
            .absent("gsm_old.resultretres_element");
    }
}

#[test]
fn a_reply_with_a_parameter_carries_the_operation_code_and_the_parameter() {
    let engine = engine(Probe::new().on_begin(reply_and_end).arc());
    let wire = begin(&[0x62], Some(&aarq(&AC)), &[invoke(6, OP, Some(&ARG))]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let TcapMessage::End(end) = decode(&out[0]) else {
        panic!("expected an End");
    };
    let comps = end.components.expect("components");
    let Component::ReturnResultLast(rr) = &comps[0] else {
        panic!("expected a ReturnResultLast");
    };
    let value = rr.result.as_ref().expect("result sequence");
    assert_eq!(value.operation_code, tcap::OperationCode::Local(OP));
    assert_eq!(
        value.parameter.as_ref().map(|p| p.as_bytes()),
        Some(&RES[..])
    );

    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.end_element")
            .hex("tcap.dtid", "62")
            .present("gsm_old.returnResultLast_element")
            .show("gsm_old.invokeID", "6")
            .present("gsm_old.resultretres_element")
            .show("gsm_old.localValue", &OP.to_string());
    }
}

/// A Begin that carries an APDU with no place in a Begin (here an AARE) has a
/// dialogue portion "inconsistent with the state of the underlying
/// transaction" (Q.774 3.2.2.1): the same abnormal-dialogue abort.
#[test]
fn a_begin_carrying_a_dialogue_response_is_an_abnormal_dialogue() {
    let seen = Probe::new().on_begin(reply_and_end).arc();
    let engine = engine(seen.clone());
    let wire = begin(&[0x43], Some(&aare(&AC)), &[invoke(1, OP, Some(&ARG))]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    assert_eq!(abrt_source(&abort_of(&out[0])), Some(1));
    assert!(seen.begins().is_empty());
}

/// Q.774 3.2.3: an AARQ whose version list does not hold version 1 is answered
/// with an AARE "result = reject (permanent); result-source-diagnostic =
/// dialogue-service-provider (no-common-dialogue-version)" as user abort
/// information, and "any received components are discarded".
#[test]
fn an_aarq_without_version_1_is_refused_with_no_common_dialogue_portion() {
    let seen = Probe::new().on_begin(reply_and_end).arc();
    let engine = engine(seen.clone());
    // protocol-version [0] IMPLICIT BIT STRING, 6 unused bits, bit 1 set
    // (a "version 2") and bit 0 (version1) clear: 80 02 06 40.
    let mut body = vec![0x80, 0x02, 0x06, 0x40];
    body.extend(tlv(0xA1, &tlv(0x06, &AC)));
    let wire = begin(
        &[0x44],
        Some(&dialogue_external(&tlv(0x60, &body))),
        &[invoke(1, OP, Some(&ARG))],
    );
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    let Some(AbortReason::UAbort(portion)) = &abort.reason else {
        panic!("expected user abort information");
    };
    let Ok(Some(tcap::DialoguePdu::Aare {
        application_context_name,
        result,
        result_source_diagnostic,
        ..
    })) = portion.dialogue_pdu()
    else {
        panic!("expected an AARE");
    };
    assert_eq!(application_context_name.as_ref(), &AC_ARCS[..]);
    assert_eq!(result, tcap::AssociateResult::RejectedPermanent);
    assert_eq!(
        result_source_diagnostic,
        tcap::AssociateSourceDiagnostic::PROVIDER_NO_COMMON_DIALOGUE_PORTION
    );
    assert!(seen.begins().is_empty());
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "44")
            .present("tcap.dialogueResponse_element")
            .show("tcap.result", "1")
            .show("tcap.dialogue_service_provider", "2");
    }
}

/// A Continue for one of our dialogues with a damaged transaction portion.
/// Table 7/Q.774, CONTINUE / Der. / Ass.: Abort, Return to Idle, local user
/// advised. Q.774 3.3.4 iii): "the transaction sub-layer terminates the
/// transaction at its end ... inform the TC-user of the transaction abort."
#[test]
fn a_damaged_continue_for_our_dialogue_is_aborted_and_the_handler_told() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x71, 0x72]);
    assert_eq!(engine.open_dialogues(), 1);

    let mut wire = cont(&[0x71, 0x72], &ours, &[return_result_last(1, None)]);
    wire.push(0xFF);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.dtid.as_ref(), &[0x71, 0x72]);
    assert_eq!(
        abort.reason,
        Some(AbortReason::PAbort(
            PAbortCause::BADLY_FORMATTED_TRANSACTION_PORTION
        ))
    );
    assert_eq!(engine.open_dialogues(), 0, "the local dialogue is released");
    assert!(probe.turns().is_empty(), "the damaged message is discarded");
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::ProviderAbort {
            cause: PAbortCause::BADLY_FORMATTED_TRANSACTION_PORTION,
            sent: true
        }]
    );
}

/// Table 7/Q.774, END/ABORT / Ass.: Discard, Return to Idle, local user
/// advised. No Abort goes back.
#[test]
fn a_damaged_end_for_our_dialogue_releases_it_without_an_answer() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x73]);

    // The component portion tag is there with no components: an incorrect
    // transaction portion (Q.772 Table 1).
    let mut body = tlv(0x49, &ours);
    body.extend_from_slice(&[0x6C, 0x00]);
    let out = engine.deliver(&inbound(&tlv(0x64, &body)), "ingress");
    assert!(out.is_empty(), "a damaged End is not answered");
    assert_eq!(engine.open_dialogues(), 0);
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::ProviderAbort {
            cause: PAbortCause::INCORRECT_TRANSACTION_PORTION,
            sent: false
        }]
    );
}

/// Q.774 3.2.2.1 on an established dialogue: "a TC-P-ABORT indication
/// primitive is issued to the local TC-user with the "P-Abort" parameter in
/// the primitive set to "abnormal dialogue". At the same time, a TR-U-ABORT
/// request primitive is issued ... with an ABRT APDU as user data."
#[test]
fn a_continue_with_a_malformed_dialogue_portion_aborts_our_dialogue() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x74]);

    // An EXTERNAL naming the dialogue abstract syntax around an ABRT whose
    // abort-source is missing.
    let broken = dialogue_external(&tlv(0x64, &[]));
    let wire = cont_with(
        &[0x74],
        &ours,
        Some(&broken),
        &[return_result_last(1, None)],
    );
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    assert_eq!(abrt_source(&abort_of(&out[0])), Some(1));
    assert_eq!(engine.open_dialogues(), 0);
    assert!(probe.turns().is_empty(), "its components are discarded");
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::AbnormalDialogue { sent: true }]
    );
}

// ── Tests: Reject (Q.774 3.2.2.2, Table 5) ───────────────────────────────────

/// The three general problems of Q.772 3.7.1, each as the component after a
/// good Invoke: `(the faulty component, the invoke id that can be read, the
/// general problem code)`.
fn faulty_components() -> [(Vec<u8>, Option<i8>, i64); 3] {
    [
        // [5] is not a component type of Table 19/Q.773: unrecognized
        // component (0). No invoke id is taken from an unknown component.
        (
            vec![0xA5, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x3A],
            None,
            0,
        ),
        // An Invoke that stops after its invoke id: mistyped component (1).
        (vec![0xA1, 0x03, 0x02, 0x01, 0x07], Some(7), 1),
        // An Invoke whose operation code announces five octets and holds one:
        // badly structured component (2).
        (
            vec![0xA1, 0x06, 0x02, 0x01, 0x07, 0x02, 0x05, 0x3A],
            Some(7),
            2,
        ),
    ]
}

fn assert_reject_dissects(
    msu: &siphon_sigtran::transport::Msu,
    id: Option<i8>,
    field: &str,
    code: i64,
) {
    if let Some(d) = dissect(msu) {
        d.present("gsm_old.reject_element")
            .show(field, &code.to_string());
        match id {
            Some(id) => {
                d.show("gsm_old.derivable", &id.to_string())
                    .absent("gsm_old.not_derivable_element");
            }
            None => {
                d.present("gsm_old.not_derivable_element")
                    .absent("gsm_old.derivable");
            }
        }
    }
}

/// Q.774 3.2.2.2: "Protocol errors in the component portion of a TCAP message
/// are reported using the Reject component", "When an invoke ID is available
/// in a component to be rejected, this ID is reflected in the Reject
/// component", and the stored Reject is transmitted with "the first dialogue
/// handling primitive (TC-CONTINUE request or TC-END request respectively)".
/// Here that primitive is an End.
#[test]
fn a_malformed_component_is_rejected_in_the_closing_end() {
    for (faulty, id, code) in faulty_components() {
        let probe = Probe::new().on_begin(reply_and_end).arc();
        let engine = engine(probe.clone());
        let wire = begin(
            &[0x81, 0x82],
            Some(&aarq(&AC)),
            &[invoke(1, OP, Some(&ARG)), faulty],
        );
        let out = engine.deliver(&inbound(&wire), "ingress");
        assert_eq!(out.len(), 1);

        // The component before the faulty one was processed as a normal turn.
        let begins = probe.begins();
        assert_eq!(begins.len(), 1);
        assert_eq!(begins[0].invoke_id, 1);
        assert_eq!(
            begins[0].further,
            vec![PeerComponent::LocalReject {
                invoke_id: id,
                problem: Problem::General(GeneralProblem(code)),
            }],
            "the handler is told of the local rejection"
        );

        let TcapMessage::End(end) = decode(&out[0]) else {
            panic!("expected an End");
        };
        assert_eq!(end.dtid.as_ref(), &[0x81, 0x82]);
        assert_eq!(
            rejects_of(&out[0]),
            vec![Reject::general(id, GeneralProblem(code))]
        );
        assert!(
            components_of(&out[0])
                .iter()
                .any(|c| matches!(c, Component::ReturnResultLast(rr) if rr.invoke_id == 1)),
            "the good Invoke is answered in the same End"
        );
        if let Some(d) = dissect(&out[0]) {
            d.present("tcap.end_element").hex("tcap.dtid", "8182");
        }
        assert_reject_dissects(&out[0], id, "gsm_old.generalProblem", code);
    }
}

/// The same with a Continue as the next dialogue handling primitive.
#[test]
fn a_malformed_component_is_rejected_in_the_next_continue() {
    for (faulty, id, code) in faulty_components() {
        let probe = Probe::new().on_begin(reply_and_hold).arc();
        let engine = engine(probe.clone());
        let wire = begin(
            &[0x83],
            Some(&aarq(&AC)),
            &[invoke(1, OP, Some(&ARG)), faulty],
        );
        let out = engine.deliver(&inbound(&wire), "ingress");
        assert_eq!(out.len(), 1);
        let TcapMessage::Continue(c) = decode(&out[0]) else {
            panic!("expected a Continue");
        };
        assert_eq!(c.dtid.as_ref(), &[0x83]);
        assert_eq!(
            rejects_of(&out[0]),
            vec![Reject::general(id, GeneralProblem(code))]
        );
        assert_eq!(engine.open_dialogues(), 1, "the dialogue goes on");
        if let Some(d) = dissect(&out[0]) {
            d.present("tcap.continue_element").hex("tcap.dtid", "83");
        }
        assert_reject_dissects(&out[0], id, "gsm_old.generalProblem", code);
    }
}

/// Q.774 3.2.2.2: "In the case of multiple components within a message, when
/// a malformed component is detected by the component sub-layer, subsequent
/// components in the message are discarded."
#[test]
fn components_after_a_malformed_one_are_discarded() {
    let probe = Probe::new().on_begin(reply_and_end).arc();
    let engine = engine(probe.clone());
    let wire = begin(
        &[0x84],
        None,
        &[
            invoke(1, OP, Some(&ARG)),
            vec![0xA1, 0x03, 0x02, 0x01, 0x07],
            invoke(3, OP, Some(&ARG)),
        ],
    );
    engine.deliver(&inbound(&wire), "ingress");
    let begins = probe.begins();
    assert_eq!(begins[0].invoke_id, 1);
    assert_eq!(begins[0].further.len(), 1, "invoke 3 is not delivered");
    assert!(matches!(
        begins[0].further[0],
        PeerComponent::LocalReject { .. }
    ));
}

/// A Begin whose only component cannot be read has nothing to dispatch on, and
/// the component sub-layer still has a Reject to send. The engine ends the
/// dialogue (Q.774 3.2.2.2, option b: "to end the dialogue using the basic
/// scenario"), which carries the Reject and, since an AARQ came, the AARE.
#[test]
fn a_begin_whose_only_component_is_malformed_is_ended_with_the_reject() {
    let probe = Probe::new().on_begin(reply_and_end).arc();
    let engine = engine(probe.clone());
    let wire = begin(
        &[0x85],
        Some(&aarq(&AC)),
        &[vec![0xA1, 0x03, 0x02, 0x01, 0x02]],
    );
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let TcapMessage::End(end) = decode(&out[0]) else {
        panic!("expected an End");
    };
    assert!(end.dialogue_portion.is_some(), "the AARE answers the AARQ");
    assert_eq!(
        rejects_of(&out[0]),
        vec![Reject::general(Some(2), GeneralProblem::MISTYPED_COMPONENT)]
    );
    assert!(probe.begins().is_empty());
    assert_eq!(engine.open_dialogues(), 0);
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.end_element")
            .hex("tcap.dtid", "85")
            .present("tcap.dialogueResponse_element");
    }
    assert_reject_dissects(&out[0], Some(2), "gsm_old.generalProblem", 1);
}

/// A malformed component on an established dialogue: the components before it
/// are a normal turn, the Reject is stored and leaves with the handler's next
/// Continue.
#[test]
fn a_malformed_component_in_a_continue_is_rejected_with_the_next_leg() {
    let probe = Probe::new()
        .on_begin(invoke_and_hold)
        .on_turn(|dlg, _| {
            dlg.invoke(OP, Some(ARG.to_vec())).expect("invoke");
            dlg.send().expect("send");
        })
        .arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x86]);

    let wire = cont(
        &[0x86],
        &ours,
        &[
            return_result_last(1, Some((OP, &RES))),
            vec![0xA1, 0x03, 0x02, 0x01, 0x09],
        ],
    );
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let turns = probe.turns();
    assert_eq!(turns.len(), 1);
    assert!(matches!(
        turns[0].components[0],
        PeerComponent::Result { invoke_id: 1, .. }
    ));
    assert_eq!(
        turns[0].components[1],
        PeerComponent::LocalReject {
            invoke_id: Some(9),
            problem: Problem::General(GeneralProblem::MISTYPED_COMPONENT),
        }
    );
    assert!(matches!(decode(&out[0]), TcapMessage::Continue(_)));
    assert_eq!(
        rejects_of(&out[0]),
        vec![Reject::general(Some(9), GeneralProblem::MISTYPED_COMPONENT)]
    );
}

/// Q.774 Table 5, note: "Some users may choose not to issue the dialogue
/// primitive ... In these cases no action is taken at the remote end." A
/// handler that says nothing keeps the Reject stored; it leaves with whatever
/// the handler sends next.
#[test]
fn a_stored_reject_waits_for_the_next_dialogue_primitive() {
    let probe = Probe::new()
        .on_begin(invoke_and_hold)
        .on_turn(|dlg, peer| {
            // Silent on the damaged turn, ends on the clean one.
            if !peer
                .components
                .iter()
                .any(|c| matches!(c, PeerComponent::LocalReject { .. }))
            {
                dlg.end().expect("end");
            }
        })
        .arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x87]);

    let damaged = cont(&[0x87], &ours, &[vec![0xA1, 0x03, 0x02, 0x01, 0x09]]);
    assert!(engine.deliver(&inbound(&damaged), "ingress").is_empty());
    assert_eq!(
        engine.open_dialogues(),
        1,
        "silence keeps the dialogue open"
    );

    let clean = cont(&[0x87], &ours, &[return_result_last(1, Some((OP, &RES)))]);
    let out = engine.deliver(&inbound(&clean), "ingress");
    assert_eq!(out.len(), 1);
    assert!(matches!(decode(&out[0]), TcapMessage::End(_)));
    assert_eq!(
        rejects_of(&out[0]),
        vec![Reject::general(Some(9), GeneralProblem::MISTYPED_COMPONENT)]
    );
}

/// A malformed component in an End: the transaction is gone, so the Reject
/// cannot be sent; the handler still gets the good components and the
/// indication.
#[test]
fn a_malformed_component_in_an_end_is_reported_to_the_handler_only() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x88]);

    let wire = end(
        &ours,
        &[
            return_result_last(1, Some((OP, &RES))),
            vec![0xA1, 0x03, 0x02, 0x01, 0x09],
        ],
    );
    assert!(engine.deliver(&inbound(&wire), "ingress").is_empty());
    let turns = probe.turns();
    assert!(turns[0].is_end);
    assert_eq!(turns[0].components.len(), 2);
    assert!(matches!(
        turns[0].components[1],
        PeerComponent::LocalReject { .. }
    ));
    assert_eq!(probe.reasons(), vec![CloseReason::PeerEnded]);
}

/// Q.774 3.2.2.2: "If the incorrect component is itself a Reject component,
/// the component is discarded and the local TC-user is advised of the syntax
/// error in the received Reject component." No Reject answers a Reject.
#[test]
fn a_malformed_reject_is_not_answered_with_a_reject() {
    let probe = Probe::new()
        .on_begin(invoke_and_hold)
        .on_turn(|dlg, _| dlg.end().expect("end"))
        .arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x89]);

    // A Reject with an invoke id and no problem.
    let wire = cont(&[0x89], &ours, &[vec![0xA4, 0x03, 0x02, 0x01, 0x01]]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    assert!(rejects_of(&out[0]).is_empty());
    assert!(matches!(
        probe.turns()[0].components[0],
        PeerComponent::LocalReject {
            invoke_id: Some(1),
            ..
        }
    ));
}

/// A Reject from the peer reaches the handler as what it is: the invoke id,
/// which may be absent, and the typed problem. It also ends the operation it
/// names.
#[test]
fn a_reject_from_the_peer_reaches_the_handler_typed() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0x8A]);

    // invokeProblem [1] mistypedParameter (2) for our invoke 1, and a general
    // problem with an invoke id the peer could not derive.
    let wire = cont(&[0x8A], &ours, &[reject(Some(1), 1, 2), reject(None, 0, 2)]);
    assert!(engine.deliver(&inbound(&wire), "ingress").is_empty());
    assert_eq!(
        probe.turns()[0].components,
        vec![
            PeerComponent::Reject {
                invoke_id: Some(1),
                problem: Problem::Invoke(InvokeProblem::MISTYPED_PARAMETER),
            },
            PeerComponent::Reject {
                invoke_id: None,
                problem: Problem::General(GeneralProblem::BADLY_STRUCTURED_COMPONENT),
            },
        ]
    );

    // Invoke 1 is idle again: a late result for it is no longer expected.
    let late = cont(&[0x8A], &ours, &[return_result_last(1, None)]);
    engine.deliver(&inbound(&late), "ingress");
    assert_eq!(
        probe.turns()[1].components,
        vec![PeerComponent::LocalReject {
            invoke_id: Some(1),
            problem: Problem::ReturnResult(ReturnResultProblem::UNRECOGNIZED_INVOKE_ID),
        }]
    );
}

/// The Rejects the component sub-layer builds for a well-formed component that
/// does not fit the state of its operation (Q.774 Table 5), each carried in a
/// Continue and in an End, and the one a handler issues itself.
#[test]
fn a_reject_of_each_problem_class_leaves_in_a_continue_and_in_an_end() {
    // (how our invoke is staged, what the peer answers, the Reject expected,
    // the Wireshark field and value)
    type Case = (OperationClass, Vec<u8>, Reject, &'static str, i64);
    let cases: Vec<Case> = vec![
        // A result for an invoke id that names no operation of ours.
        (
            OperationClass::One,
            return_result_last(55, None),
            Reject::return_result(55, ReturnResultProblem::UNRECOGNIZED_INVOKE_ID),
            "gsm_old.returnResultProblem",
            0,
        ),
        // Table 5: "Return result (L/NL), Operation Class 2/4: Initiate Reject".
        (
            OperationClass::Two,
            return_result_last(1, None),
            Reject::return_result(1, ReturnResultProblem::RETURN_RESULT_UNEXPECTED),
            "gsm_old.returnResultProblem",
            1,
        ),
        // An error for an invoke id that names no operation of ours.
        (
            OperationClass::One,
            return_error(56, 34),
            Reject::return_error(56, ReturnErrorProblem::UNRECOGNIZED_INVOKE_ID),
            "gsm_old.returnErrorProblem",
            0,
        ),
        // Table 5: "Return error, Operation Class 3/4: Initiate Reject".
        (
            OperationClass::Three,
            return_error(1, 34),
            Reject::return_error(1, ReturnErrorProblem::RETURN_ERROR_UNEXPECTED),
            "gsm_old.returnErrorProblem",
            1,
        ),
        // Q.772 3.7.2.6: a linked id that is not an active invoke of ours.
        (
            OperationClass::One,
            linked_invoke(4, 77, OP),
            Reject::invoke(4, InvokeProblem::UNRECOGNIZED_LINKED_ID),
            "gsm_old.invokeProblem",
            5,
        ),
    ];
    for (class, answer, expected, field, code) in cases {
        for closing in [false, true] {
            let probe = Probe::new()
                .on_begin(move |dlg, _| {
                    dlg.invoke_with(OP, Some(ARG.to_vec()), class, None)
                        .expect("invoke");
                    dlg.send().expect("send");
                })
                .on_turn(move |dlg, _| {
                    if closing {
                        dlg.end().expect("end");
                    } else {
                        dlg.send().expect("send");
                    }
                })
                .arc();
            let engine = engine(probe.clone());
            let ours = open(&engine, &[0x90]);
            let out = engine.deliver(
                &inbound(&cont(&[0x90], &ours, std::slice::from_ref(&answer))),
                "ingress",
            );
            assert_eq!(out.len(), 1);
            assert_eq!(
                matches!(decode(&out[0]), TcapMessage::End(_)),
                closing,
                "{expected:?}"
            );
            assert_eq!(rejects_of(&out[0]), vec![expected]);
            assert_eq!(
                probe.turns()[0].components,
                vec![PeerComponent::LocalReject {
                    invoke_id: expected.invoke_id,
                    problem: expected.problem,
                }],
                "the component is not delivered as a result"
            );
            if let Some(d) = dissect(&out[0]) {
                d.present(if closing {
                    "tcap.end_element"
                } else {
                    "tcap.continue_element"
                })
                .hex("tcap.dtid", "90");
            }
            assert_reject_dissects(&out[0], expected.invoke_id, field, code);
        }
    }
}

/// A handler rejects a component itself (TC-U-REJECT), here an Invoke whose
/// argument it could not read: Q.772 3.7.2.3, "mistyped parameter".
#[test]
fn a_handler_can_reject_an_invoke_with_mistyped_parameter() {
    for closing in [false, true] {
        let probe = Probe::new()
            .on_begin(move |dlg, op| {
                dlg.reject(
                    Some(op.invoke_id),
                    Problem::Invoke(InvokeProblem::MISTYPED_PARAMETER),
                );
                if closing {
                    dlg.end().expect("end");
                } else {
                    dlg.send().expect("send");
                }
            })
            .arc();
        let engine = engine(probe);
        let wire = begin(&[0x91], Some(&aarq(&AC)), &[invoke(12, OP, Some(&ARG))]);
        let out = engine.deliver(&inbound(&wire), "ingress");
        assert_eq!(out.len(), 1);
        assert_eq!(
            rejects_of(&out[0]),
            vec![Reject::invoke(12, InvokeProblem::MISTYPED_PARAMETER)]
        );
        assert_reject_dissects(&out[0], Some(12), "gsm_old.invokeProblem", 2);
    }
}

// ── Tests: several components in a Begin ─────────────────────────────────────

/// Q.774 3.2.1.2: a TR-BEGIN indication is "followed by component handling
/// primitives associated with each of the components received". Every
/// component of the Begin reaches the handler, not only the first Invoke.
#[test]
fn every_component_of_a_begin_reaches_the_handler() {
    let probe = Probe::new()
        .on_begin(|dlg, op| {
            dlg.reply(op.operation_code, Some(RES.to_vec()));
            for further in &op.further {
                if let PeerComponent::Invoke {
                    invoke_id,
                    operation_code,
                    ..
                } = further
                {
                    dlg.reply_to(*invoke_id, *operation_code, Some(RES.to_vec()));
                }
            }
            dlg.end().expect("end");
        })
        .arc();
    let engine = engine(probe.clone());
    let wire = begin(
        &[0xA1],
        Some(&aarq(&AC)),
        &[invoke(1, OP, Some(&ARG)), invoke(2, OP, Some(&ARG))],
    );
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let begins = probe.begins();
    assert_eq!(begins[0].invoke_id, 1);
    assert_eq!(
        begins[0].further,
        vec![PeerComponent::Invoke {
            invoke_id: 2,
            operation_code: OP,
            argument: Some(ARG.to_vec()),
        }]
    );
    let answered: Vec<i8> = components_of(&out[0])
        .iter()
        .filter_map(|c| match c {
            Component::ReturnResultLast(rr) => Some(rr.invoke_id),
            _ => None,
        })
        .collect();
    assert_eq!(answered, vec![1, 2]);
    if let Some(d) = dissect(&out[0]) {
        d.present("tcap.end_element")
            .show_all("gsm_old.invokeID", &["1", "2"]);
    }
}

// ── Tests: operation classes and timers (Q.774 3.2.1.1.3) ────────────────────

fn timers(invoke_timer_ms: u64, dialogue_timer_ms: u64) -> Tcap {
    Tcap {
        invoke_timer_ms,
        dialogue_timer_ms,
        max_dialogues: 100,
    }
}

fn later(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

/// Q.774 3.2.1.1.3: "if a class 1 operation times out, this indicates an
/// abnormal situation. The component sub-layer will release the invoke ID and
/// inform the application. It is now up to the application to decide whether
/// to abort the transaction or to report an error to the peer application."
/// The default handler aborts, and that is a TC-user abort.
#[test]
fn a_class_1_timeout_is_reported_and_the_default_handler_aborts_as_the_tc_user() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine_with(timers(50, 600_000), probe.clone());
    open(&engine, &[0xB1]);

    let out = engine.sweep(later(1_000));
    assert_eq!(
        probe.timeouts(),
        vec![InvokeTimeout {
            invoke_id: 1,
            operation_code: OP,
            class: OperationClass::One
        }]
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "ingress");
    let abort = abort_of(&out[0].1);
    assert_eq!(abort.dtid.as_ref(), &[0xB1]);
    assert_eq!(abort.p_abort_cause(), None, "not a P-Abort");
    assert_eq!(abrt_source(&abort), Some(0), "dialogue-service-user");
    assert_eq!(engine.open_dialogues(), 0);
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::InvokeTimeout {
            invoke_id: 1,
            operation_code: OP
        }]
    );
    if let Some(d) = dissect(&out[0].1) {
        d.present("tcap.abort_element")
            .hex("tcap.dtid", "b1")
            .absent("tcap.p_abortCause")
            .show("tcap.abort_source", "0");
    }
}

/// A handler may decide otherwise for class 1: report an error and go on.
#[test]
fn a_handler_can_keep_the_dialogue_after_a_class_1_timeout() {
    let probe = Probe::new()
        .on_begin(invoke_and_hold)
        .on_timeout(|_, _| {})
        .arc();
    let engine = engine_with(timers(50, 600_000), probe.clone());
    open(&engine, &[0xB2]);
    assert!(engine.sweep(later(1_000)).is_empty());
    assert_eq!(probe.timeouts().len(), 1);
    assert_eq!(engine.open_dialogues(), 1);
    assert!(probe.reasons().is_empty());
    // The timer does not fire twice.
    assert!(engine.sweep(later(2_000)).is_empty());
    assert_eq!(probe.timeouts().len(), 1);
}

/// "This notification ... gives the definite outcome of a class 2 or 3
/// operation for which no result has been received (normal situation)": the
/// dialogue is not aborted.
#[test]
fn a_class_2_or_3_timeout_is_the_normal_outcome_and_aborts_nothing() {
    for class in [OperationClass::Two, OperationClass::Three] {
        let probe = Probe::new()
            .on_begin(move |dlg, _| {
                dlg.invoke_with(OP, Some(ARG.to_vec()), class, None)
                    .expect("invoke");
                dlg.send().expect("send");
            })
            .arc();
        let engine = engine_with(timers(50, 600_000), probe.clone());
        open(&engine, &[0xB3]);
        assert!(engine.sweep(later(1_000)).is_empty(), "nothing is sent");
        assert_eq!(
            probe.timeouts(),
            vec![InvokeTimeout {
                invoke_id: 1,
                operation_code: OP,
                class
            }]
        );
        assert_eq!(engine.open_dialogues(), 1, "the dialogue lives on");
        assert!(probe.reasons().is_empty());
    }
}

/// "notification to the TC-user by means of a TC-L-CANCEL indication (in the
/// case of a class 1, 2 or 3 operation)": a class 4 operation returns to idle
/// without one.
#[test]
fn a_class_4_timeout_is_silent() {
    let probe = Probe::new()
        .on_begin(|dlg, _| {
            dlg.invoke_with(OP, Some(ARG.to_vec()), OperationClass::Four, None)
                .expect("invoke");
            dlg.send().expect("send");
        })
        .arc();
    let engine = engine_with(timers(50, 600_000), probe.clone());
    let ours = open(&engine, &[0xB4]);
    assert!(engine.sweep(later(1_000)).is_empty());
    assert!(probe.timeouts().is_empty());
    assert_eq!(engine.open_dialogues(), 1);

    // The invoke id is idle again: a late result is rejected.
    let out = engine.deliver(
        &inbound(&cont(&[0xB4], &ours, &[return_result_last(1, None)])),
        "ingress",
    );
    assert!(out.is_empty());
    assert!(matches!(
        probe.turns()[0].components[0],
        PeerComponent::LocalReject { .. }
    ));
}

/// A result that arrives in time stops the timer.
#[test]
fn a_result_in_time_stops_the_invocation_timer() {
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine_with(timers(50, 600_000), probe.clone());
    let ours = open(&engine, &[0xB5]);
    engine.deliver(
        &inbound(&cont(
            &[0xB5],
            &ours,
            &[return_result_last(1, Some((OP, &RES)))],
        )),
        "ingress",
    );
    assert!(engine.sweep(later(1_000)).is_empty());
    assert!(probe.timeouts().is_empty());
    assert_eq!(engine.open_dialogues(), 1);
}

/// A timeout given with the invoke overrides the configured one ("The
/// TC-INVOKE request primitive indicates a timer value").
#[test]
fn an_invoke_can_carry_its_own_timer() {
    let probe = Probe::new()
        .on_begin(|dlg, _| {
            dlg.invoke_with(
                OP,
                Some(ARG.to_vec()),
                OperationClass::One,
                Some(Duration::from_secs(3_600)),
            )
            .expect("invoke");
            dlg.send().expect("send");
        })
        .arc();
    let engine = engine_with(timers(50, 86_400_000), probe.clone());
    open(&engine, &[0xB6]);
    assert!(engine.sweep(later(60_000)).is_empty());
    assert!(probe.timeouts().is_empty());
    assert_eq!(engine.sweep(later(3_700_000)).len(), 1);
}

/// The peer reports an event on a waiting dialogue and the handler has nothing
/// to say: the dialogue stays open. (It used to be aborted.)
#[test]
fn a_handler_that_says_nothing_to_a_continue_keeps_the_dialogue_open() {
    let probe = Probe::new().on_begin(reply_and_hold).arc();
    let engine = engine(probe.clone());
    let ours = open(&engine, &[0xB7]);
    let out = engine.deliver(
        &inbound(&cont(&[0xB7], &ours, &[invoke(2, OP, Some(&ARG))])),
        "ingress",
    );
    assert!(out.is_empty(), "no abort");
    assert_eq!(engine.open_dialogues(), 1);
    assert_eq!(probe.turns().len(), 1);
    assert!(probe.reasons().is_empty());
}

/// Q.774 3.3.4, case 1 ("No reaction to transaction"): "covered by a local,
/// implementation-dependent, mechanism which results in aborting the
/// transaction locally". The idle timeout releases the dialogue, tells the
/// handler, and sends the peer a TC-user abort in case it is still there.
#[test]
fn an_idle_dialogue_is_aborted_as_the_tc_user_and_the_handler_told() {
    let probe = Probe::new().on_begin(reply_and_hold).arc();
    let engine = engine_with(timers(600_000, 50), probe.clone());
    open(&engine, &[0xB8]);
    let out = engine.sweep(later(1_000));
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0].1);
    assert_eq!(abort.dtid.as_ref(), &[0xB8]);
    assert_eq!(abort.p_abort_cause(), None);
    assert_eq!(abrt_source(&abort), Some(0));
    assert_eq!(engine.open_dialogues(), 0);
    assert_eq!(probe.reasons(), vec![CloseReason::IdleTimeout]);
}

/// A dialogue that legitimately waits (a call in progress) sets its own idle
/// timeout, or none.
#[test]
fn a_dialogue_can_set_or_disable_its_idle_timeout() {
    for (timeout, survives) in [
        (Some(Duration::from_secs(7_200)), true),
        (None, true),
        (Some(Duration::from_millis(10)), false),
    ] {
        let probe = Probe::new()
            .on_begin(move |dlg, op| {
                dlg.set_idle_timeout(timeout);
                reply_and_hold(dlg, op);
            })
            .arc();
        let engine = engine_with(timers(600_000, 30_000), probe.clone());
        open(&engine, &[0xB9]);
        let out = engine.sweep(later(3_600_000));
        assert_eq!(out.is_empty(), survives, "{timeout:?}");
        assert_eq!(engine.open_dialogues(), usize::from(survives));
    }
}

/// `dialogue_timer_ms: 0` turns the idle timeout off for every dialogue.
#[test]
fn a_zero_dialogue_timer_disables_the_idle_timeout() {
    let probe = Probe::new().on_begin(reply_and_hold).arc();
    let engine = engine_with(timers(600_000, 0), probe);
    open(&engine, &[0xBA]);
    assert!(engine.sweep(later(86_400_000)).is_empty());
    assert_eq!(engine.open_dialogues(), 1);
}

/// A handler that answers nothing to a Begin leaves the peer with a
/// transaction nobody confirms: the engine aborts it as the TC-user, and the
/// handler is told.
#[test]
fn a_handler_that_answers_nothing_to_a_begin_is_aborted_as_the_tc_user() {
    let probe = Probe::new().arc();
    let engine = engine(probe.clone());
    let wire = begin(&[0xBB], Some(&aarq(&AC)), &[invoke(1, OP, Some(&ARG))]);
    let out = engine.deliver(&inbound(&wire), "ingress");
    assert_eq!(out.len(), 1);
    let abort = abort_of(&out[0]);
    assert_eq!(abort.p_abort_cause(), None);
    assert_eq!(abrt_source(&abort), Some(0));
    assert_eq!(probe.reasons(), vec![CloseReason::NoAnswer]);
}

// ── Tests: the end of a dialogue reaches the handler once ────────────────────

/// What an Abort from the peer carried reaches the handler: a P-Abort with its
/// cause, or one of the kinds of U-Abort.
#[test]
fn a_peer_abort_tells_the_handler_whether_it_was_a_p_abort_or_a_u_abort() {
    type Build = Box<dyn Fn(&[u8]) -> Vec<u8>>;
    let cases: Vec<(Build, PeerAbort)> = vec![
        (
            Box::new(|dtid| p_abort(dtid, 4)),
            PeerAbort::Provider(PAbortCause::RESOURCE_LIMITATION),
        ),
        (
            Box::new(|dtid| p_abort(dtid, 1)),
            PeerAbort::Provider(PAbortCause::UNRECOGNIZED_TRANSACTION_ID),
        ),
        (
            Box::new(|dtid| u_abort(dtid, None)),
            PeerAbort::User(UserAbort::NoInformation),
        ),
        (
            Box::new(|dtid| u_abort(dtid, Some(&abrt(0)))),
            PeerAbort::User(UserAbort::DialogueServiceUser),
        ),
        (
            Box::new(|dtid| u_abort(dtid, Some(&abrt(1)))),
            PeerAbort::AbnormalDialogue,
        ),
        (
            // User information in a user-defined abstract syntax (1.3.9999.1).
            Box::new(|dtid| {
                let mut body = tlv(0x06, &[0x2B, 0xCE, 0x0F, 0x01]);
                body.extend(tlv(0xA0, &[0x04, 0x01, 0x2A]));
                u_abort(dtid, Some(&tlv(0x28, &body)))
            }),
            PeerAbort::User(UserAbort::UserDefined),
        ),
    ];
    for (build, expected) in cases {
        let probe = Probe::new().on_begin(invoke_and_hold).arc();
        let engine = engine(probe.clone());
        let ours = open(&engine, &[0xC1]);
        let out = engine.deliver(&inbound(&build(&ours)), "ingress");
        assert!(out.is_empty(), "an Abort is not answered");
        assert_eq!(engine.open_dialogues(), 0);
        assert_eq!(probe.reasons(), vec![CloseReason::PeerAbort(expected)]);
        assert_eq!(
            expected.is_provider(),
            !matches!(expected, PeerAbort::User(_))
        );
    }
}

/// The abort counters split P-Abort from U-Abort with a closed set of label
/// values: a cause value Q.773 does not name counts as "other".
#[test]
fn abort_metrics_distinguish_p_abort_from_u_abort_without_open_ended_labels() {
    use siphon_sigtran::metrics::{self, AbortCause, Dir};
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let engine = engine(probe.clone());

    let other = metrics::tcap_aborts(Dir::Rx, AbortCause::OtherPAbort);
    let ours = open(&engine, &[0xC2]);
    engine.deliver(&inbound(&p_abort(&ours, 77)), "ingress");
    // The counters are process-wide and the tests run in parallel, so these
    // are lower bounds.
    assert!(metrics::tcap_aborts(Dir::Rx, AbortCause::OtherPAbort) > other);
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::PeerAbort(PeerAbort::Provider(PAbortCause(77)))]
    );

    let user = metrics::tcap_aborts(Dir::Rx, AbortCause::AbrtUser);
    let ours = open(&engine, &[0xC3]);
    engine.deliver(&inbound(&u_abort(&ours, Some(&abrt(0)))), "ingress");
    assert!(metrics::tcap_aborts(Dir::Rx, AbortCause::AbrtUser) > user);

    let sent = metrics::tcap_aborts(Dir::Tx, AbortCause::UnrecognizedTransactionId);
    engine.deliver(
        &inbound(&cont(&[0x01], &[0x80, 0, 0, 0x7F], &[])),
        "ingress",
    );
    assert!(metrics::tcap_aborts(Dir::Tx, AbortCause::UnrecognizedTransactionId) > sent);

    let text = metrics::render();
    assert!(text.contains("sigtran_tcap_abort_total{dir=\"rx\",kind=\"p-abort\",cause=\"other\"}"));
    assert!(!text.contains("cause=\"77\""));
}

/// However a dialogue ends, `on_closed` is called exactly once.
#[test]
fn every_way_a_dialogue_ends_tells_the_handler_exactly_once() {
    // The handler ends it.
    let probe = Probe::new().on_begin(reply_and_end).arc();
    let e = engine(probe.clone());
    e.deliver(
        &inbound(&begin(&[0xD1], None, &[invoke(1, OP, Some(&ARG))])),
        "i",
    );
    assert_eq!(probe.reasons(), vec![CloseReason::Ended]);

    // The handler aborts it.
    let probe = Probe::new()
        .on_begin(|dlg, _| dlg.abort().expect("abort"))
        .arc();
    let e = engine(probe.clone());
    e.deliver(
        &inbound(&begin(&[0xD2], None, &[invoke(1, OP, Some(&ARG))])),
        "i",
    );
    assert_eq!(probe.reasons(), vec![CloseReason::Aborted]);

    // The peer ends it; a second End for the same id changes nothing.
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let e = engine(probe.clone());
    let ours = open(&e, &[0xD3]);
    e.deliver(&inbound(&end(&ours, &[return_result_last(1, None)])), "i");
    e.deliver(&inbound(&end(&ours, &[])), "i");
    e.deliver(&inbound(&p_abort(&ours, 1)), "i");
    assert_eq!(probe.reasons(), vec![CloseReason::PeerEnded]);

    // The peer aborts it; the timers have nothing left to say.
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let e = engine_with(timers(50, 50), probe.clone());
    let ours = open(&e, &[0xD4]);
    e.deliver(&inbound(&u_abort(&ours, None)), "i");
    assert!(e.sweep(later(10_000)).is_empty());
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::PeerAbort(PeerAbort::User(
            UserAbort::NoInformation
        ))]
    );

    // Both timers are due in the same sweep: one end, not two.
    let probe = Probe::new().on_begin(invoke_and_hold).arc();
    let e = engine_with(timers(50, 50), probe.clone());
    open(&e, &[0xD5]);
    assert_eq!(e.sweep(later(10_000)).len(), 1);
    assert!(e.sweep(later(20_000)).is_empty());
    assert_eq!(probe.reasons().len(), 1);
}

// ── Tests: nothing fails silently on the send path ───────────────────────────

/// A staged component the encoder refuses makes the flush fail, and the
/// handler gets the error. The peer is not left waiting either: with nothing
/// sent in answer to its Begin, the engine aborts.
#[test]
fn an_encode_failure_is_returned_to_the_handler_and_counted() {
    use siphon_sigtran::metrics;
    let seen: Arc<Mutex<Option<DialogueError>>> = Arc::new(Mutex::new(None));
    let slot = seen.clone();
    let probe = Probe::new()
        .on_begin(move |dlg, op| {
            // Two elements where Q.773 has one ("ANY DEFINED BY
            // operationCode").
            dlg.reply(
                op.operation_code,
                Some(vec![0x04, 0x01, 0x01, 0x04, 0x01, 0x02]),
            );
            *slot.lock().unwrap() = dlg.end().err();
            assert!(!dlg.is_closed(), "a failed End closes nothing");
        })
        .arc();
    let engine = engine(probe.clone());
    let before = metrics::tcap_send_errors();
    let out = engine.deliver(
        &inbound(&begin(&[0xE1], None, &[invoke(1, OP, Some(&ARG))])),
        "ingress",
    );
    assert!(
        matches!(*seen.lock().unwrap(), Some(DialogueError::Encode(_))),
        "the handler is told: {:?}",
        seen.lock().unwrap()
    );
    assert!(metrics::tcap_send_errors() > before);
    assert_eq!(out.len(), 1, "the peer gets an abort, not silence");
    assert!(matches!(decode(&out[0]), TcapMessage::Abort(_)));
    assert_eq!(probe.reasons(), vec![CloseReason::NoAnswer]);
}

/// An originated dialogue whose Begin cannot be encoded is an error to the
/// caller of `begin`, and no dialogue is left behind.
#[test]
fn a_begin_that_cannot_be_encoded_is_an_error_to_the_caller() {
    let probe = Probe::new()
        .on_start(|dlg| {
            dlg.invoke(OP, Some(vec![0x04, 0x05, 0x01]))
                .expect("invoke");
            assert!(dlg.send().is_err());
        })
        .arc();
    let engine = engine(probe.clone());
    let result = engine.begin(outgoing(), probe.clone());
    assert!(
        matches!(result, Err(DialogueError::Encode(_))),
        "{result:?}"
    );
    assert_eq!(engine.open_dialogues(), 0);
    assert_eq!(probe.reasons(), vec![CloseReason::NotSent]);
}

/// A handler that opens a dialogue and sends no Begin gets an error too.
#[test]
fn a_begin_that_sends_nothing_is_an_error_to_the_caller() {
    let probe = Probe::new().arc();
    let engine = engine(probe.clone());
    assert!(matches!(
        engine.begin(outgoing(), probe.clone()),
        Err(DialogueError::NothingSent)
    ));
    assert_eq!(engine.open_dialogues(), 0);
}

/// Before the peer answered our Begin there is no destination transaction id:
/// a Continue or an End is an error, and an abort is local (Q.774 3.2.2.1:
/// "the result of the TC/TR-U-ABORT request primitive is purely local").
#[test]
fn an_originated_dialogue_the_peer_never_answered_times_out_locally() {
    let probe = Probe::new()
        .on_start(|dlg| {
            dlg.invoke(OP, Some(ARG.to_vec())).expect("invoke");
            dlg.send().expect("the Begin");
            assert_eq!(dlg.send(), Err(DialogueError::NoPeerTransaction));
        })
        .arc();
    let engine = engine_with(timers(50, 600_000), probe.clone());
    let (tid, frames) = engine.begin(outgoing(), probe.clone()).expect("begin");
    assert_eq!(frames.len(), 1);
    let TcapMessage::Begin(b) = decode(&frames[0]) else {
        panic!("expected a Begin");
    };
    assert_eq!(b.otid.as_ref(), &tid[..]);
    assert_eq!(engine.open_dialogues(), 1);

    // The class 1 invoke times out; the default abort has nobody to go to.
    let out = engine.sweep(later(1_000));
    assert!(
        out.is_empty(),
        "nothing can be addressed to an unknown peer id"
    );
    assert_eq!(engine.open_dialogues(), 0);
    assert_eq!(
        probe.reasons(),
        vec![CloseReason::InvokeTimeout {
            invoke_id: 1,
            operation_code: OP
        }]
    );
}

/// The originating side: the peer's first Continue is correlated on our
/// transaction id, and its result delivered.
#[test]
fn an_originated_dialogue_gets_its_result() {
    let probe = Probe::new()
        .on_start(|dlg| {
            dlg.invoke(OP, Some(ARG.to_vec())).expect("invoke");
            dlg.send().expect("the Begin");
        })
        .arc();
    let engine = engine(probe.clone());
    let (tid, _) = engine.begin(outgoing(), probe.clone()).expect("begin");
    let wire = end(&tid, &[return_result_last(1, Some((OP, &RES)))]);
    assert!(engine.deliver(&inbound(&wire), "ingress").is_empty());
    assert_eq!(
        probe.turns()[0].components,
        vec![PeerComponent::Result {
            invoke_id: 1,
            operation_code: Some(OP),
            parameter: Some(RES.to_vec()),
        }]
    );
    assert_eq!(probe.reasons(), vec![CloseReason::PeerEnded]);
}
