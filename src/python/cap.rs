//! Typed, read-only views of what a gsmSSF sends a gsmSCF script: the members of
//! a CAP InitialDP, an EventReportBCSM, an ApplyChargingReport, and the CAMEL
//! phase of the dialogue they arrive in.
//!
//! The decoding is the `gsm_cap` codec's, strict: a member on the wire that
//! cannot be read is an error, not an absent member. This module only projects
//! the decoded types onto what a script reads (digits for the TBCD strings, an
//! integer for a one-octet value, the octets for everything that has a format
//! of its own), and turns a value that is not what its type says into the same
//! `MistypedParameter` a failed decode raises.
//!
//! The getters themselves sit on the classes in the parent module, because
//! `pyo3` wants the methods of a class in one block; each of them is one call
//! into here.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use gsm_cap::operations::{ApplyChargingReportArg, EventReportBcsmArg, InitialDpArg};
use gsm_cap::types::{
    CamelCallResult, CellGlobalIdOrServiceAreaIdOrLai, EventSpecificInformationBcsm,
    ExtBasicServiceCode, LocationInformation, MessageType, NotReachableReason, SubscriberState,
    TimeInformation,
};

use super::{mistyped, PeerComp, PyIncomingOp};
use crate::dialogue::{InvokeProblem, Problem};

// ── The CAMEL phase of an application context ────────────────────────────────

/// The CAMEL phase a CAP application context belongs to, 1 to 4, or `None` for
/// a context that is not one of CAP's (GSM 09.78 for phases 1 and 2, TS 29.078
/// clauses 6.1.2.1, 6.2.2.1, 7.2.1 and 8.2.1 for phases 3 and 4).
pub(super) fn camel_phase(application_context: &[u32]) -> Option<u8> {
    use gsm_cap::application_context as c;
    let phases: [(u8, &[[u32; 8]]); 4] = [
        (1, &[c::CAP_V1_GSMSSF_TO_GSMSCF]),
        (
            2,
            &[
                c::CAP_V2_GSMSSF_TO_GSMSCF,
                c::CAP_V2_ASSIST_GSMSSF_TO_GSMSCF,
                c::CAP_V2_GSMSRF_TO_GSMSCF,
            ],
        ),
        (
            3,
            &[
                c::CAP_V3_GSMSSF_SCF_GENERIC,
                c::CAP_V3_GSMSSF_SCF_ASSIST_HANDOFF,
                c::CAP_V3_GSMSRF_GSMSCF,
                c::CAP_V3_GPRSSSF_GSMSCF,
                c::CAP_V3_GSMSCF_GPRSSSF,
                c::CAP_V3_SMS,
            ],
        ),
        (
            4,
            &[
                c::CAP_V4_GSMSSF_SCF_GENERIC,
                c::CAP_V4_GSMSSF_SCF_ASSIST_HANDOFF,
                c::CAP_V4_SCF_GSMSSF_GENERIC,
                c::CAP_V4_GSMSRF_GSMSCF,
                c::CAP_V4_SMS,
            ],
        ),
    ];
    phases
        .iter()
        .find(|(_, contexts)| {
            contexts
                .iter()
                .any(|known| known[..] == *application_context)
        })
        .map(|(phase, _)| *phase)
}

// ── Values inside the OCTET STRINGs ──────────────────────────────────────────

/// The digits of a TBCD-STRING (TS 29.002: "two digits per octet, each digit
/// encoded 0000 to 1001 (0 to 9) ... 1111 used as filler when there is an odd
/// number of digits"), for the strings that hold decimal digits only: an IMSI,
/// the digits of an ISDN-AddressString. A filler anywhere but in the last
/// digit position, and any of `*`, `#`, `a`, `b`, `c`, is not such a string.
fn decimal_tbcd(octets: &[u8]) -> Result<String, String> {
    let mut digits = String::with_capacity(octets.len() * 2);
    for (index, octet) in octets.iter().enumerate() {
        let last = index + 1 == octets.len();
        for (nibble, may_be_filler) in [(octet & 0x0F, false), (octet >> 4, last)] {
            match nibble {
                0..=9 => digits.push(char::from(b'0' + nibble)),
                0x0F if may_be_filler => {}
                _ => return Err(format!("{nibble:#x} is not a decimal digit")),
            }
        }
    }
    Ok(digits)
}

/// An IMSI as its digits. `IMSI ::= TBCD-STRING (SIZE (3..8))`.
fn imsi_digits(what: &str, imsi: &[u8]) -> PyResult<String> {
    if !(3..=8).contains(&imsi.len()) {
        return Err(mistyped(what, "an IMSI is 3 to 8 octets"));
    }
    decimal_tbcd(imsi).map_err(|e| mistyped(what, e))
}

/// The digits of an ISDN-AddressString: one octet of nature of address and
/// numbering plan, then the digits as a TBCD-STRING.
fn address_digits(what: &str, address: &[u8]) -> PyResult<String> {
    let (_nature_and_plan, digits) = address
        .split_first()
        .ok_or_else(|| mistyped(what, "an address string is at least one octet"))?;
    decimal_tbcd(digits).map_err(|e| mistyped(what, e))
}

/// A value its type gives exactly one octet (`OCTET STRING (SIZE(1))`).
fn one_octet(what: &str, octets: &[u8]) -> Result<u8, String> {
    match octets {
        [octet] => Ok(*octet),
        _ => Err(format!("{what} is {} octets, not one", octets.len())),
    }
}

fn bytes<'py>(py: Python<'py>, octets: Option<&[u8]>) -> Option<Bound<'py, PyBytes>> {
    octets.map(|o| PyBytes::new(py, o))
}

// ── InitialDP ────────────────────────────────────────────────────────────────

/// What an [`IncomingOp`](PyIncomingOp) getter reads from a CAP InitialDP:
/// `None` for another operation, `MistypedParameter` when the argument does not
/// decode, otherwise what `read` makes of it.
fn initial_dp<T>(
    op: &PyIncomingOp,
    read: impl FnOnce(InitialDpArg) -> PyResult<Option<T>>,
) -> PyResult<Option<T>> {
    match op.cap_initial_dp()? {
        Some(idp) => read(idp),
        None => Ok(None),
    }
}

pub(super) fn imsi(op: &PyIncomingOp) -> PyResult<Option<String>> {
    initial_dp(op, |idp| {
        idp.imsi
            .map(|imsi| imsi_digits("the InitialDP iMSI", &imsi))
            .transpose()
    })
}

pub(super) fn calling_party_number<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    initial_dp(op, |idp| Ok(bytes(py, idp.calling_party_number.as_deref())))
}

pub(super) fn calling_partys_category(op: &PyIncomingOp) -> PyResult<Option<u8>> {
    initial_dp(op, |idp| {
        idp.calling_partys_category
            .map(|category| {
                one_octet("callingPartysCategory", &category)
                    .map_err(|e| mistyped("the InitialDP", e))
            })
            .transpose()
    })
}

pub(super) fn event_type_bcsm(op: &PyIncomingOp) -> PyResult<Option<i64>> {
    initial_dp(op, |idp| Ok(idp.event_type_bcsm.map(|e| e as i64)))
}

pub(super) fn subscriber_state(op: &PyIncomingOp) -> PyResult<Option<&'static str>> {
    initial_dp(op, |idp| {
        Ok(idp.subscriber_state.map(|state| match state {
            SubscriberState::AssumedIdle(()) => "assumed-idle",
            SubscriberState::CamelBusy(()) => "camel-busy",
            SubscriberState::NetDetNotReachable(_) => "net-det-not-reachable",
            SubscriberState::NotProvidedFromVlr(()) => "not-provided-from-vlr",
        }))
    })
}

pub(super) fn not_reachable_reason(op: &PyIncomingOp) -> PyResult<Option<&'static str>> {
    initial_dp(op, |idp| {
        Ok(match idp.subscriber_state {
            Some(SubscriberState::NetDetNotReachable(reason)) => Some(match reason {
                NotReachableReason::MsPurged => "ms-purged",
                NotReachableReason::ImsiDetached => "imsi-detached",
                NotReachableReason::RestrictedArea => "restricted-area",
                NotReachableReason::NotRegistered => "not-registered",
            }),
            _ => None,
        })
    })
}

pub(super) fn location_information(op: &PyIncomingOp) -> PyResult<Option<PyLocationInformation>> {
    initial_dp(op, |idp| {
        Ok(idp.location_information.map(PyLocationInformation))
    })
}

pub(super) fn ext_basic_service_code<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<(&'static str, Bound<'py, PyBytes>)>> {
    initial_dp(op, |idp| {
        Ok(idp.ext_basic_service_code.map(|code| match code {
            ExtBasicServiceCode::ExtBearerService(c) => ("bearer-service", PyBytes::new(py, &c)),
            ExtBasicServiceCode::ExtTeleservice(c) => ("teleservice", PyBytes::new(py, &c)),
        }))
    })
}

pub(super) fn call_reference_number<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    initial_dp(op, |idp| {
        Ok(bytes(py, idp.call_reference_number.as_deref()))
    })
}

pub(super) fn msc_address(op: &PyIncomingOp) -> PyResult<Option<String>> {
    initial_dp(op, |idp| {
        idp.msc_address
            .map(|address| address_digits("the InitialDP mscAddress", &address))
            .transpose()
    })
}

pub(super) fn time_and_timezone<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    initial_dp(op, |idp| Ok(bytes(py, idp.time_and_timezone.as_deref())))
}

pub(super) fn call_forwarding_ss_pending(op: &PyIncomingOp) -> PyResult<bool> {
    initial_dp(op, |idp| Ok(idp.call_forwarding_ss_pending.map(|()| true)))
        .map(|pending| pending.unwrap_or(false))
}

pub(super) fn original_called_party_id<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    initial_dp(op, |idp| {
        Ok(bytes(py, idp.original_called_party_id.as_deref()))
    })
}

pub(super) fn redirecting_party_id<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    initial_dp(op, |idp| Ok(bytes(py, idp.redirecting_party_id.as_deref())))
}

pub(super) fn redirection_information<'py>(
    py: Python<'py>,
    op: &PyIncomingOp,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    initial_dp(op, |idp| {
        Ok(bytes(py, idp.redirection_information.as_deref()))
    })
}

pub(super) fn gmsc_address(op: &PyIncomingOp) -> PyResult<Option<String>> {
    initial_dp(op, |idp| {
        idp.initial_dp_arg_extension
            .and_then(|extension| extension.gmsc_address)
            .map(|address| address_digits("the InitialDP gmscAddress", &address))
            .transpose()
    })
}

/// The `locationInformation` of a CAP InitialDP (TS 29.002
/// `LocationInformation`): where the VLR last saw the subscriber.
#[pyclass(name = "LocationInformation", module = "siphon", frozen)]
pub struct PyLocationInformation(LocationInformation);

#[pymethods]
impl PyLocationInformation {
    /// `ageOfLocationInformation`: minutes since the network last had contact
    /// with the mobile station; 0 while it is in contact.
    #[getter]
    fn age_of_location(&self) -> Option<u16> {
        self.0.age_of_location_information
    }

    /// `vlr-number`, as its digits. Raises `MistypedParameter` when the
    /// address holds something that is no decimal digit.
    #[getter]
    fn vlr_number(&self) -> PyResult<Option<String>> {
        self.0
            .vlr_number
            .as_deref()
            .map(|address| address_digits("the vlr-number of the location information", address))
            .transpose()
    }

    /// `msc-Number`, as its digits. As `vlr_number`.
    #[getter]
    fn msc_number(&self) -> PyResult<Option<String>> {
        self.0
            .msc_number
            .as_deref()
            .map(|address| address_digits("the msc-Number of the location information", address))
            .transpose()
    }

    /// `locationNumber`, the octets of a Q.763 location number.
    #[getter]
    fn location_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        bytes(py, self.0.location_number.as_deref())
    }

    /// The cell global identity or, when `sai_present`, the service area
    /// identity: seven octets, MCC and MNC (3), location area code (2), cell
    /// identity or service area code (2). `None` when the location is given as
    /// a location area only, or not at all.
    #[getter]
    fn cell_global_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.0.cell_global_id_or_service_area_id_or_lai {
            Some(CellGlobalIdOrServiceAreaIdOrLai::CellGlobalIdOrServiceAreaIdFixedLength(
                cell,
            )) => Some(PyBytes::new(py, cell)),
            _ => None,
        }
    }

    /// The location area identity: five octets, MCC and MNC (3), location area
    /// code (2). It is what the argument carries as `laiFixedLength`, or the
    /// first five octets of the cell global identity, which are the same
    /// thing.
    #[getter]
    fn location_area_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        use CellGlobalIdOrServiceAreaIdOrLai as Area;
        match &self.0.cell_global_id_or_service_area_id_or_lai {
            Some(Area::LaiFixedLength(area)) => Some(PyBytes::new(py, area)),
            Some(Area::CellGlobalIdOrServiceAreaIdFixedLength(cell)) => {
                cell.get(..5).map(|area| PyBytes::new(py, area))
            }
            None => None,
        }
    }

    /// `geographicalInformation`, the octets (TS 23.032 shape description).
    #[getter]
    fn geographical_information<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        bytes(py, self.0.geographical_information.as_deref())
    }

    /// `sai-Present`: `cell_global_id` holds a service area identity.
    #[getter]
    fn sai_present(&self) -> bool {
        self.0.sai_present.is_some()
    }

    /// `currentLocationRetrieved`: the location was obtained by paging the
    /// subscriber for this request.
    #[getter]
    fn current_location_retrieved(&self) -> bool {
        self.0.current_location_retrieved.is_some()
    }

    fn __repr__(&self) -> String {
        format!(
            "LocationInformation(age_of_location={:?})",
            self.0.age_of_location_information
        )
    }
}

// ── The reports that follow, one component each ──────────────────────────────

/// A component's parameter does not decode: the `MistypedParameter` to raise,
/// carrying the invoke id of that component as `invoke_id`. A turn can hold
/// several components (a charging report and the disconnect it belongs to
/// arrive together), and the Reject has to name the one that was not read.
fn mistyped_component(
    py: Python<'_>,
    component: &PeerComp,
    what: &str,
    error: impl std::fmt::Display,
) -> PyErr {
    let raised = mistyped(what, error);
    if let Some(invoke_id) = component.invoke_id {
        // An exception without the attribute is still the right exception; the
        // Reject then names the first component of the turn, as it did.
        let _ = raised.value(py).setattr("invoke_id", invoke_id);
    }
    raised
}

/// The Invoke a `MistypedParameter` names, when a view of one component raised
/// it: what to reject in place of the first component of the turn.
pub(super) fn rejected_invoke(py: Python<'_>, error: &PyErr) -> Option<(Option<i8>, Problem)> {
    let invoke_id: i8 = error.value(py).getattr("invoke_id").ok()?.extract().ok()?;
    Some((
        Some(invoke_id),
        Problem::Invoke(InvokeProblem::MISTYPED_PARAMETER),
    ))
}

/// The argument of `component` when it is an Invoke of `operation_code`.
/// `None` for anything else; an Invoke of the operation without an argument is
/// mistyped, since both reports have a mandatory one.
fn argument_of<'a>(
    py: Python<'_>,
    component: &'a PeerComp,
    operation_code: i64,
    what: &str,
) -> PyResult<Option<&'a [u8]>> {
    if component.kind != "invoke" || component.operation_code != Some(operation_code) {
        return Ok(None);
    }
    component
        .parameter
        .as_deref()
        .map(Some)
        .ok_or_else(|| mistyped_component(py, component, what, "the Invoke carries no argument"))
}

/// The leg a `ReceivingSideID` names. `LegType ::= OCTET STRING (SIZE(1))`.
fn leg_number(leg: &gsm_cap::types::ReceivingSideId) -> Result<u8, String> {
    one_octet("the leg", leg.leg_type())
}

/// `component.event_report_bcsm`.
pub(super) fn event_report_bcsm(
    py: Python<'_>,
    component: &PeerComp,
) -> PyResult<Option<PyEventReportBcsm>> {
    let what = "the CAP EventReportBCSM argument";
    let Some(argument) = argument_of(py, component, gsm_cap::op_codes::EVENT_REPORT_BCSM, what)?
    else {
        return Ok(None);
    };
    let report: EventReportBcsmArg =
        gsm_cap::decode(argument).map_err(|e| mistyped_component(py, component, what, e))?;
    let leg = report
        .leg_id
        .as_ref()
        .map(leg_number)
        .transpose()
        .map_err(|e| mistyped_component(py, component, what, e))?;
    Ok(Some(PyEventReportBcsm { report, leg }))
}

/// A decoded CAP EventReportBCSM (TS 29.078 `EventReportBCSMArg`): the
/// detection point the gsmSSF reports, on which leg, whether the call waits for
/// an instruction, and what the gsmSSF knows about the event.
#[pyclass(name = "EventReportBcsm", module = "siphon", frozen)]
pub struct PyEventReportBcsm {
    report: EventReportBcsmArg,
    leg: Option<u8>,
}

impl PyEventReportBcsm {
    fn info(&self) -> Option<&EventSpecificInformationBcsm> {
        self.report.event_specific_information_bcsm.as_ref()
    }

    /// The cause of the alternatives that carry one and nothing else.
    fn cause_of(
        &self,
        wanted: impl Fn(&EventSpecificInformationBcsm) -> Option<&gsm_cap::types::CauseSpecificInfo>,
    ) -> Option<&[u8]> {
        self.info().and_then(wanted)?.cause.as_deref()
    }

    fn answer(&self) -> Option<&gsm_cap::types::AnswerSpecificInfo> {
        use EventSpecificInformationBcsm as Info;
        match self.info()? {
            Info::OAnswerSpecificInfo(answer) | Info::TAnswerSpecificInfo(answer) => Some(answer),
            _ => None,
        }
    }
}

#[pymethods]
impl PyEventReportBcsm {
    /// `eventTypeBCSM`: 7 oAnswer, 9 oDisconnect, 15 tAnswer, ... The numbers
    /// are the ones `gsm_cap.request_report_bcsm_event` arms.
    #[getter]
    fn event_type(&self) -> i64 {
        self.report.event_type_bcsm as i64
    }

    /// `legID`: the leg the event happened on, 1 (the calling side) or 2, as
    /// the gsmSSF names it (`receivingSideID`). `None` when the report has none.
    #[getter]
    fn leg(&self) -> Option<u8> {
        self.leg
    }

    /// `miscCallInfo.messageType`: `request` when the detection point was
    /// armed as interrupted and the call waits for an instruction,
    /// `notification` when it goes on. A report without `miscCallInfo` is a
    /// request (`DEFAULT {messageType request}`).
    #[getter]
    fn message_type(&self) -> &'static str {
        if self.is_request() {
            "request"
        } else {
            "notification"
        }
    }

    /// Whether the call is suspended at the detection point until the script
    /// sends an instruction.
    #[getter]
    fn is_request(&self) -> bool {
        !matches!(
            &self.report.misc_call_info,
            Some(info) if info.message_type == MessageType::Notification
        )
    }

    /// Which alternative of `eventSpecificInformationBCSM` the report carries,
    /// by its kebab-case name (`o-answer`, `t-disconnect`, ...), or `None`.
    #[getter]
    fn specific_info(&self) -> Option<&'static str> {
        use EventSpecificInformationBcsm as Info;
        Some(match self.info()? {
            Info::RouteSelectFailureSpecificInfo(_) => "route-select-failure",
            Info::OCalledPartyBusySpecificInfo(_) => "o-called-party-busy",
            Info::ONoAnswerSpecificInfo(_) => "o-no-answer",
            Info::OAnswerSpecificInfo(_) => "o-answer",
            Info::OMidCallSpecificInfo(_) => "o-mid-call",
            Info::ODisconnectSpecificInfo(_) => "o-disconnect",
            Info::TBusySpecificInfo(_) => "t-busy",
            Info::TNoAnswerSpecificInfo(_) => "t-no-answer",
            Info::TAnswerSpecificInfo(_) => "t-answer",
            Info::TMidCallSpecificInfo(_) => "t-mid-call",
            Info::TDisconnectSpecificInfo(_) => "t-disconnect",
            Info::OTermSeizedSpecificInfo(_) => "o-term-seized",
            Info::CallAcceptedSpecificInfo(_) => "call-accepted",
            Info::OAbandonSpecificInfo(_) => "o-abandon",
            Info::OChangeOfPositionSpecificInfo(_) => "o-change-of-position",
            Info::TChangeOfPositionSpecificInfo(_) => "t-change-of-position",
            Info::DpSpecificInfoAlt(_) => "dp-specific-info-alt",
        })
    }

    /// `releaseCause` of a disconnect (oDisconnect, tDisconnect): the octets
    /// of a Q.850 cause as ISUP carries it.
    #[getter]
    fn release_cause<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        use EventSpecificInformationBcsm as Info;
        bytes(
            py,
            self.cause_of(|info| match info {
                Info::ODisconnectSpecificInfo(c) | Info::TDisconnectSpecificInfo(c) => Some(c),
                _ => None,
            }),
        )
    }

    /// `busyCause` of oCalledPartyBusy or tBusy. As `release_cause`.
    #[getter]
    fn busy_cause<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        use EventSpecificInformationBcsm as Info;
        let cause = match self.info() {
            Some(Info::TBusySpecificInfo(busy)) => busy.busy_cause.as_deref(),
            _ => self.cause_of(|info| match info {
                Info::OCalledPartyBusySpecificInfo(c) => Some(c),
                _ => None,
            }),
        };
        bytes(py, cause)
    }

    /// `failureCause` of routeSelectFailure. As `release_cause`.
    #[getter]
    fn failure_cause<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        use EventSpecificInformationBcsm as Info;
        bytes(
            py,
            self.cause_of(|info| match info {
                Info::RouteSelectFailureSpecificInfo(c) => Some(c),
                _ => None,
            }),
        )
    }

    /// `destinationAddress` of an answer (oAnswer, tAnswer): the octets of a
    /// Q.763 called party number.
    #[getter]
    fn destination_address<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        bytes(py, self.answer()?.destination_address.as_deref())
    }

    /// `or-Call` of an answer: the call was optimally routed.
    #[getter]
    fn or_call(&self) -> bool {
        self.answer().is_some_and(|a| a.or_call.is_some())
    }

    /// `forwardedCall` of an answer: the call was forwarded before it was
    /// answered.
    #[getter]
    fn forwarded_call(&self) -> bool {
        self.answer().is_some_and(|a| a.forwarded_call.is_some())
    }

    /// `chargeIndicator` of an answer, one octet (Q.763 backward call
    /// indicators, charge indicator).
    #[getter]
    fn charge_indicator<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        bytes(py, self.answer()?.charge_indicator.as_deref())
    }

    /// `callForwarded` of tBusy or tNoAnswer: conditional call forwarding
    /// takes the call from here.
    #[getter]
    fn call_forwarded(&self) -> bool {
        use EventSpecificInformationBcsm as Info;
        match self.info() {
            Some(Info::TBusySpecificInfo(busy)) => busy.call_forwarded.is_some(),
            Some(Info::TNoAnswerSpecificInfo(no_answer)) => no_answer.call_forwarded.is_some(),
            _ => false,
        }
    }

    /// `routeNotPermitted` of tBusy or oAbandon.
    #[getter]
    fn route_not_permitted(&self) -> bool {
        use EventSpecificInformationBcsm as Info;
        match self.info() {
            Some(Info::TBusySpecificInfo(busy)) => busy.route_not_permitted.is_some(),
            Some(Info::OAbandonSpecificInfo(abandon)) => abandon.route_not_permitted.is_some(),
            _ => false,
        }
    }

    /// `forwardingDestinationNumber` of tBusy or tNoAnswer: the octets of a
    /// Q.763 called party number.
    #[getter]
    fn forwarding_destination_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        use EventSpecificInformationBcsm as Info;
        let number = match self.info()? {
            Info::TBusySpecificInfo(busy) => busy.forwarding_destination_number.as_deref(),
            Info::TNoAnswerSpecificInfo(no_answer) => {
                no_answer.forwarding_destination_number.as_deref()
            }
            _ => None,
        };
        bytes(py, number)
    }

    fn __repr__(&self) -> String {
        format!(
            "EventReportBcsm(event_type={}, leg={:?}, message_type={})",
            self.event_type(),
            self.leg,
            self.message_type()
        )
    }
}

/// `component.apply_charging_report`.
pub(super) fn apply_charging_report(
    py: Python<'_>,
    component: &PeerComp,
) -> PyResult<Option<PyApplyChargingReport>> {
    let what = "the CAP ApplyChargingReport argument";
    let operation_code = gsm_cap::op_codes::APPLY_CHARGING_REPORT;
    let Some(argument) = argument_of(py, component, operation_code, what)? else {
        return Ok(None);
    };
    // The argument is an OCTET STRING, and what it holds is the BER encoding
    // of a CAMEL-CallResult: both have to decode.
    let CamelCallResult::TimeDurationChargingResult(result) =
        gsm_cap::decode::<ApplyChargingReportArg>(argument)
            .and_then(|report| report.call_result())
            .map_err(|e| mistyped_component(py, component, what, e))?;
    let party_to_charge = leg_number(&result.party_to_charge)
        .map_err(|e| mistyped_component(py, component, what, e))?;
    Ok(Some(PyApplyChargingReport {
        party_to_charge,
        time_information: result.time_information,
        leg_active: result.leg_active.unwrap_or(true),
        call_leg_released_at_tcp_expiry: result.call_leg_released_at_tcp_expiry.is_some(),
    }))
}

/// A decoded CAP ApplyChargingReport: the `timeDurationChargingResult` of the
/// CAMEL-CallResult its argument holds (TS 29.078 clause 5.1).
#[pyclass(name = "ApplyChargingReport", module = "siphon", frozen)]
pub struct PyApplyChargingReport {
    party_to_charge: u8,
    time_information: TimeInformation,
    leg_active: bool,
    call_leg_released_at_tcp_expiry: bool,
}

#[pymethods]
impl PyApplyChargingReport {
    /// `partyToCharge`: the leg the report is for, as its number. It is the
    /// one the ApplyCharging named.
    #[getter]
    fn party_to_charge(&self) -> u8 {
        self.party_to_charge
    }

    /// `timeIfNoTariffSwitch`: the time used in units of 100 ms, counted from
    /// the answer and not from the last report. `None` once a tariff switch
    /// has happened.
    #[getter]
    fn time_if_no_tariff_switch(&self) -> Option<u32> {
        match self.time_information {
            TimeInformation::TimeIfNoTariffSwitch(used) => Some(used),
            TimeInformation::TimeIfTariffSwitch(_) => None,
        }
    }

    /// `timeIfTariffSwitch.timeSinceTariffSwitch`, in units of 100 ms. `None`
    /// while no tariff switch has happened.
    #[getter]
    fn time_since_tariff_switch(&self) -> Option<u32> {
        match &self.time_information {
            TimeInformation::TimeIfTariffSwitch(times) => Some(times.time_since_tariff_switch),
            TimeInformation::TimeIfNoTariffSwitch(_) => None,
        }
    }

    /// `timeIfTariffSwitch.tariffSwitchInterval`, in units of 100 ms: the time
    /// used before the switch.
    #[getter]
    fn tariff_switch_interval(&self) -> Option<u32> {
        match &self.time_information {
            TimeInformation::TimeIfTariffSwitch(times) => times.tariff_switch_interval,
            TimeInformation::TimeIfNoTariffSwitch(_) => None,
        }
    }

    /// `legActive` (`DEFAULT TRUE`): false means the leg is gone and this is
    /// the last figure for it.
    #[getter]
    fn leg_active(&self) -> bool {
        self.leg_active
    }

    /// The same member under the name CAMEL phases 2 and 3 give it,
    /// `callActive`.
    #[getter]
    fn call_active(&self) -> bool {
        self.leg_active
    }

    /// `callLegReleasedAtTcpExpiry`: the gsmSSF released the leg because the
    /// granted period ran out.
    #[getter]
    fn call_leg_released_at_tcp_expiry(&self) -> bool {
        self.call_leg_released_at_tcp_expiry
    }

    fn __repr__(&self) -> String {
        format!(
            "ApplyChargingReport(party_to_charge={}, leg_active={})",
            self.party_to_charge, self.leg_active
        )
    }
}

/// Add the view classes to the module the namespaces are mounted on.
pub(super) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyLocationInformation>()?;
    module.add_class::<PyEventReportBcsm>()?;
    module.add_class::<PyApplyChargingReport>()
}

#[cfg(test)]
mod tests {
    //! Every argument below is written by hand from the ASN.1 of 3GPP TS 29.078
    //! V18.0.0 (clause 6.1.1 for the arguments, clause 5.1 for the data types)
    //! and, for the imported MAP types, TS 29.002 V18.0.0. Nothing here is
    //! produced by the codec under test. Test PLMN 001/01, `+1-555-01xx`
    //! numbers.

    use pyo3::prelude::*;

    use super::super::{MistypedParameter, PeerComp, PyComponent, PyDialogue, PyIncomingOp};

    /// One BER element with a short or one-octet long length.
    fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        match content.len() {
            n if n < 128 => out.push(n as u8),
            n => out.extend_from_slice(&[0x81, n as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    fn sequence(members: &[&[u8]]) -> Vec<u8> {
        tlv(&[0x30], &members.concat())
    }

    /// IMSI 001010000000001 as TBCD: `00 01 01 00 00 00 00 F1`.
    const IMSI: [u8; 8] = [0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xF1];
    /// `91`: international number, ISDN numbering plan; then 15550180 in TBCD.
    const MSC: [u8; 5] = [0x91, 0x51, 0x55, 0x10, 0x08];
    /// Q.763 calling party number: international, ISDN plan, presentation
    /// allowed, network provided; 15550101.
    const CALLING: [u8; 6] = [0x04, 0x13, 0x51, 0x55, 0x10, 0x10];
    /// MCC 001, MNC 01, LAC 1, cell identity 1.
    const CELL: [u8; 7] = [0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x01];

    /// A mobile-originated InitialDP, the members in the order `InitialDPArg`
    /// declares them. Tags above 30 take the high tag number form: `[50]`
    /// primitive is `9F 32`, `[52]` constructed `BF 34`.
    fn mobile_originated() -> Vec<u8> {
        // LocationInformation (TS 29.002): the untagged age, vlr-number [1],
        // and behind the explicit [3] of a CHOICE the
        // cellGlobalIdOrServiceAreaIdFixedLength [0].
        let location = [
            &[0x02, 0x01, 0x00][..],
            &tlv(&[0x81], &MSC),
            &tlv(&[0xA3], &tlv(&[0x80], &CELL)),
        ]
        .concat();
        sequence(&[
            &[0x80, 0x01, 0x64],                         // serviceKey [0] 100
            &tlv(&[0x83], &CALLING),                     // callingPartyNumber [3]
            &[0x85, 0x01, 0x0A],                         // callingPartysCategory [5]
            &[0xBB, 0x05, 0x80, 0x03, 0x80, 0x90, 0xA3], // bearerCapability [27] { bearerCap [0] }
            &[0x9C, 0x01, 0x02],                         // eventTypeBCSM [28] collectedInfo
            &tlv(&[0x9F, 0x32], &IMSI),                  // iMSI [50]
            &[0xBF, 0x33, 0x02, 0x80, 0x00],             // subscriberState [51] { assumedIdle [0] }
            &tlv(&[0xBF, 0x34], &location),              // locationInformation [52]
            &[0xBF, 0x35, 0x03, 0x83, 0x01, 0x11], // ext-basicServiceCode [53] { ext-Teleservice [3] }
            &[0x9F, 0x36, 0x04, 0x01, 0x02, 0x03, 0x04], // callReferenceNumber [54]
            &tlv(&[0x9F, 0x37], &MSC),             // mscAddress [55]
            &[0x9F, 0x38, 0x02, 0x81, 0x78],       // calledPartyBCDNumber [56] 87
            // timeAndTimezone [57]: 2026-10-11 08:15:30, zone 0
            &[
                0x9F, 0x39, 0x08, 0x02, 0x62, 0x01, 0x11, 0x80, 0x51, 0x03, 0x00,
            ],
        ])
    }

    /// A terminating InitialDP of a forwarded call, as a GMSC sends it.
    fn mobile_terminated() -> Vec<u8> {
        sequence(&[
            &[0x80, 0x01, 0x65],                               // serviceKey [0] 101
            &[0x82, 0x06, 0x04, 0x10, 0x51, 0x55, 0x10, 0x20], // calledPartyNumber [2] 15550102
            &tlv(&[0x83], &CALLING),                           // callingPartyNumber [3]
            &[0x8C, 0x06, 0x04, 0x10, 0x51, 0x55, 0x10, 0x30], // originalCalledPartyID [12] 15550103
            &[0x9C, 0x01, 0x0C], // eventTypeBCSM [28] termAttemptAuthorized
            &[0x9D, 0x06, 0x04, 0x10, 0x51, 0x55, 0x10, 0x40], // redirectingPartyID [29] 15550104
            &[0x9E, 0x02, 0x03, 0x21], // redirectionInformation [30]
            &tlv(&[0x9F, 0x32], &IMSI), // iMSI [50]
            // subscriberState [51] { netDetNotReachable ENUMERATED imsiDetached }
            &[0xBF, 0x33, 0x03, 0x0A, 0x01, 0x01],
            &[0x9F, 0x3A, 0x00], // callForwardingSS-Pending [58]
            // initialDPArgExtension [59] { gmscAddress [0] 15550190 }
            &[0xBF, 0x3B, 0x07, 0x80, 0x05, 0x91, 0x51, 0x55, 0x10, 0x09],
        ])
    }

    fn opening(operation_code: i64, argument: &[u8]) -> PyIncomingOp {
        PyIncomingOp {
            operation_code,
            invoke_id: 1,
            calling_gt: None,
            called_gt: None,
            argument: Some(argument.to_vec()),
            further: Vec::new(),
        }
    }

    fn initial_dp<'py>(py: Python<'py>, argument: &[u8]) -> Bound<'py, PyAny> {
        Bound::new(py, opening(gsm_cap::op_codes::INITIAL_DP, argument))
            .expect("IncomingOp")
            .into_any()
    }

    fn invoke<'py>(py: Python<'py>, operation_code: i64, argument: &[u8]) -> Bound<'py, PyAny> {
        let component = PeerComp {
            kind: "invoke",
            operation_code: Some(operation_code),
            invoke_id: Some(7),
            parameter: Some(argument.to_vec()),
            error_code: None,
            problem: None,
        };
        Bound::new(py, PyComponent(component))
            .expect("Component")
            .into_any()
    }

    fn event_report<'py>(py: Python<'py>, argument: &[u8]) -> Bound<'py, PyAny> {
        invoke(py, gsm_cap::op_codes::EVENT_REPORT_BCSM, argument)
            .getattr("event_report_bcsm")
            .expect("the report decodes")
    }

    fn charging_report<'py>(py: Python<'py>, argument: &[u8]) -> Bound<'py, PyAny> {
        invoke(py, gsm_cap::op_codes::APPLY_CHARGING_REPORT, argument)
            .getattr("apply_charging_report")
            .expect("the report decodes")
    }

    /// Read attribute `name` of `object` as `T`.
    fn read<T>(object: &Bound<'_, PyAny>, name: &str) -> T
    where
        for<'a, 'py> T: FromPyObject<'a, 'py>,
    {
        let value = object
            .getattr(name)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        value
            .extract()
            .unwrap_or_else(|_| panic!("{name} is {value:?}"))
    }

    fn octets(object: &Bound<'_, PyAny>, name: &str) -> Option<Vec<u8>> {
        read(object, name)
    }

    fn assert_mistyped(py: Python<'_>, object: &Bound<'_, PyAny>, name: &str) -> PyErr {
        let error = match object.getattr(name) {
            Ok(value) => panic!("{name} read as {value:?}"),
            Err(error) => error,
        };
        assert!(
            error.is_instance_of::<MistypedParameter>(py),
            "{name} raised {error}"
        );
        error
    }

    // ── InitialDP ────────────────────────────────────────────────────────────

    #[test]
    fn initial_dp_names_the_subscriber() {
        Python::attach(|py| {
            let idp = initial_dp(py, &mobile_originated());
            assert_eq!(read::<Option<i64>>(&idp, "service_key"), Some(100));
            assert_eq!(
                read::<Option<String>>(&idp, "imsi").as_deref(),
                Some("001010000000001")
            );
            assert_eq!(
                octets(&idp, "calling_party_number").as_deref(),
                Some(&CALLING[..])
            );
            assert_eq!(
                read::<Option<u8>>(&idp, "calling_partys_category"),
                Some(10)
            );
            assert_eq!(
                octets(&idp, "called_party_bcd_number").as_deref(),
                Some(&[0x81, 0x78][..])
            );
            assert_eq!(octets(&idp, "called_party_number"), None);
        });
    }

    #[test]
    fn initial_dp_names_the_point_in_the_call() {
        Python::attach(|py| {
            let idp = initial_dp(py, &mobile_originated());
            assert_eq!(read::<Option<i64>>(&idp, "event_type_bcsm"), Some(2));
            assert_eq!(
                read::<Option<String>>(&idp, "subscriber_state").as_deref(),
                Some("assumed-idle")
            );
            assert_eq!(read::<Option<String>>(&idp, "not_reachable_reason"), None);
            assert_eq!(
                read::<Option<(String, Vec<u8>)>>(&idp, "ext_basic_service_code"),
                Some(("teleservice".to_string(), vec![0x11]))
            );
            assert!(!read::<bool>(&idp, "call_forwarding_ss_pending"));
        });
    }

    #[test]
    fn initial_dp_identifies_the_call_for_the_charging_record() {
        Python::attach(|py| {
            let idp = initial_dp(py, &mobile_originated());
            assert_eq!(
                octets(&idp, "call_reference_number").as_deref(),
                Some(&[0x01, 0x02, 0x03, 0x04][..])
            );
            assert_eq!(
                read::<Option<String>>(&idp, "msc_address").as_deref(),
                Some("15550180")
            );
            assert_eq!(
                octets(&idp, "time_and_timezone").as_deref(),
                Some(&[0x02, 0x62, 0x01, 0x11, 0x80, 0x51, 0x03, 0x00][..])
            );
        });
    }

    #[test]
    fn initial_dp_location_is_a_view_of_its_own() {
        Python::attach(|py| {
            let idp = initial_dp(py, &mobile_originated());
            let location = idp.getattr("location_information").expect("location");
            assert_eq!(read::<Option<u16>>(&location, "age_of_location"), Some(0));
            assert_eq!(
                read::<Option<String>>(&location, "vlr_number").as_deref(),
                Some("15550180")
            );
            assert_eq!(
                octets(&location, "cell_global_id").as_deref(),
                Some(&CELL[..])
            );
            // The location area is the first five octets of the cell identity.
            assert_eq!(
                octets(&location, "location_area_id").as_deref(),
                Some(&CELL[..5])
            );
            assert_eq!(read::<Option<String>>(&location, "msc_number"), None);
            assert_eq!(octets(&location, "location_number"), None);
            assert!(!read::<bool>(&location, "sai_present"));
            assert!(!read::<bool>(&location, "current_location_retrieved"));
        });
    }

    #[test]
    fn initial_dp_location_may_be_a_location_area_only() {
        Python::attach(|py| {
            // locationInformation [52] { [3] { laiFixedLength [1] }, sai-Present
            // is absent, currentLocationRetrieved [8] NULL }.
            let lai = [0x00, 0xF1, 0x10, 0x00, 0x02];
            let location = [&tlv(&[0xA3], &tlv(&[0x81], &lai))[..], &[0x88, 0x00]].concat();
            let argument = sequence(&[&[0x80, 0x01, 0x64], &tlv(&[0xBF, 0x34], &location)]);
            let idp = initial_dp(py, &argument);
            let location = idp.getattr("location_information").expect("location");
            assert_eq!(octets(&location, "cell_global_id"), None);
            assert_eq!(
                octets(&location, "location_area_id").as_deref(),
                Some(&lai[..])
            );
            assert_eq!(read::<Option<u16>>(&location, "age_of_location"), None);
            assert!(read::<bool>(&location, "current_location_retrieved"));
        });
    }

    #[test]
    fn initial_dp_of_a_terminating_call_names_who_was_called_first() {
        Python::attach(|py| {
            let idp = initial_dp(py, &mobile_terminated());
            assert_eq!(read::<Option<i64>>(&idp, "event_type_bcsm"), Some(12));
            assert_eq!(
                octets(&idp, "called_party_number").as_deref(),
                Some(&[0x04, 0x10, 0x51, 0x55, 0x10, 0x20][..])
            );
            assert_eq!(
                octets(&idp, "original_called_party_id").as_deref(),
                Some(&[0x04, 0x10, 0x51, 0x55, 0x10, 0x30][..])
            );
            assert_eq!(
                octets(&idp, "redirecting_party_id").as_deref(),
                Some(&[0x04, 0x10, 0x51, 0x55, 0x10, 0x40][..])
            );
            assert_eq!(
                octets(&idp, "redirection_information").as_deref(),
                Some(&[0x03, 0x21][..])
            );
            assert_eq!(
                read::<Option<String>>(&idp, "gmsc_address").as_deref(),
                Some("15550190")
            );
            assert!(read::<bool>(&idp, "call_forwarding_ss_pending"));
            assert_eq!(
                read::<Option<String>>(&idp, "subscriber_state").as_deref(),
                Some("net-det-not-reachable")
            );
            assert_eq!(
                read::<Option<String>>(&idp, "not_reachable_reason").as_deref(),
                Some("imsi-detached")
            );
        });
    }

    #[test]
    fn initial_dp_members_that_are_absent_read_as_none() {
        Python::attach(|py| {
            let idp = initial_dp(py, &sequence(&[&[0x80, 0x01, 0x64]]));
            for name in [
                "imsi",
                "calling_party_number",
                "calling_partys_category",
                "event_type_bcsm",
                "subscriber_state",
                "not_reachable_reason",
                "location_information",
                "ext_basic_service_code",
                "call_reference_number",
                "msc_address",
                "time_and_timezone",
                "original_called_party_id",
                "redirecting_party_id",
                "redirection_information",
                "gmsc_address",
            ] {
                assert!(idp.getattr(name).expect(name).is_none(), "{name}");
            }
            assert!(!read::<bool>(&idp, "call_forwarding_ss_pending"));
        });
    }

    #[test]
    fn another_operation_has_no_initial_dp_members() {
        Python::attach(|py| {
            let other = Bound::new(py, opening(gsm_map::op_codes::PURGE_MS, &[0x30, 0x00]))
                .expect("IncomingOp")
                .into_any();
            for name in ["imsi", "event_type_bcsm", "location_information"] {
                assert!(other.getattr(name).expect(name).is_none(), "{name}");
            }
            assert!(!read::<bool>(&other, "call_forwarding_ss_pending"));
        });
    }

    #[test]
    fn a_damaged_initial_dp_is_a_mistyped_parameter_on_every_member() {
        Python::attach(|py| {
            let whole = mobile_originated();
            let mut cut = whole[..whole.len() - 3].to_vec();
            cut[1] -= 3;
            for damaged in [
                // serviceKey [0] announces four octets and holds one.
                vec![0x30, 0x03, 0x80, 0x04, 0x64],
                // subscriberState [51] holding an alternative it does not have.
                sequence(&[&[0x80, 0x01, 0x64], &[0xBF, 0x33, 0x02, 0x87, 0x00]]),
                // locationInformation [52] with the cell identity as a
                // primitive [3], where the ASN.1 has an explicit tag.
                sequence(&[
                    &[0x80, 0x01, 0x64],
                    &tlv(&[0xBF, 0x34], &tlv(&[0x83], &CELL)),
                ]),
                // The last member cut off mid-value.
                cut,
            ] {
                let idp = initial_dp(py, &damaged);
                for name in [
                    "imsi",
                    "event_type_bcsm",
                    "location_information",
                    "msc_address",
                    "call_forwarding_ss_pending",
                ] {
                    assert_mistyped(py, &idp, name);
                }
            }
        });
    }

    #[test]
    fn a_member_whose_content_is_not_what_its_type_says_is_mistyped() {
        Python::attach(|py| {
            // An IMSI with a nibble that is no digit (`A`) before its end, a
            // calling party's category of two octets, and an mscAddress whose
            // filler is not at the end.
            let argument = sequence(&[
                &[0x80, 0x01, 0x64],
                &[0x85, 0x02, 0x0A, 0x0A],
                &[0x9F, 0x32, 0x03, 0x00, 0xA1, 0x01],
                &[0x9F, 0x37, 0x03, 0x91, 0xF1, 0x55],
            ]);
            let idp = initial_dp(py, &argument);
            for name in ["imsi", "calling_partys_category", "msc_address"] {
                assert_mistyped(py, &idp, name);
            }
            // The members that are what they say still read.
            assert_eq!(read::<Option<i64>>(&idp, "service_key"), Some(100));
        });
    }

    // ── EventReportBCSM ──────────────────────────────────────────────────────

    #[test]
    fn an_answer_report_is_a_notification_on_the_called_leg() {
        Python::attach(|py| {
            // 30 11 { eventTypeBCSM [0] oAnswer, eventSpecificInformationBCSM
            // [2] { oAnswerSpecificInfo [5] {} }, legID [3] { receivingSideID
            // [1] 02 }, miscCallInfo [4] { messageType [0] notification } }
            let report = event_report(
                py,
                &sequence(&[
                    &[0x80, 0x01, 0x07],
                    &[0xA2, 0x02, 0xA5, 0x00],
                    &[0xA3, 0x03, 0x81, 0x01, 0x02],
                    &[0xA4, 0x03, 0x80, 0x01, 0x01],
                ]),
            );
            assert_eq!(read::<i64>(&report, "event_type"), 7);
            assert_eq!(read::<Option<u8>>(&report, "leg"), Some(2));
            assert_eq!(read::<String>(&report, "message_type"), "notification");
            assert!(!read::<bool>(&report, "is_request"));
            assert_eq!(
                read::<Option<String>>(&report, "specific_info").as_deref(),
                Some("o-answer")
            );
            assert_eq!(octets(&report, "destination_address"), None);
            assert!(!read::<bool>(&report, "forwarded_call"));
            assert_eq!(octets(&report, "release_cause"), None);
        });
    }

    #[test]
    fn an_answer_report_carries_where_the_call_was_answered() {
        Python::attach(|py| {
            // tAnswerSpecificInfo [10] { destinationAddress [50], or-Call [51],
            // forwardedCall [52], chargeIndicator [53] }
            let info = tlv(
                &[0xAA],
                &[
                    &[0x9F, 0x32, 0x06, 0x04, 0x10, 0x51, 0x55, 0x10, 0x20][..],
                    &[0x9F, 0x33, 0x00],
                    &[0x9F, 0x34, 0x00],
                    &[0x9F, 0x35, 0x01, 0x02],
                ]
                .concat(),
            );
            let report = event_report(py, &sequence(&[&[0x80, 0x01, 0x0F], &tlv(&[0xA2], &info)]));
            assert_eq!(read::<i64>(&report, "event_type"), 15);
            assert_eq!(
                read::<Option<String>>(&report, "specific_info").as_deref(),
                Some("t-answer")
            );
            assert_eq!(
                octets(&report, "destination_address").as_deref(),
                Some(&[0x04, 0x10, 0x51, 0x55, 0x10, 0x20][..])
            );
            assert!(read::<bool>(&report, "or_call"));
            assert!(read::<bool>(&report, "forwarded_call"));
            assert_eq!(
                octets(&report, "charge_indicator").as_deref(),
                Some(&[0x02][..])
            );
            // No legID and no miscCallInfo: the default is a request.
            assert_eq!(read::<Option<u8>>(&report, "leg"), None);
            assert!(read::<bool>(&report, "is_request"));
            assert_eq!(read::<String>(&report, "message_type"), "request");
        });
    }

    #[test]
    fn a_disconnect_report_carries_the_release_cause() {
        Python::attach(|py| {
            // oDisconnectSpecificInfo [7] { releaseCause [0] 80 90 }, leg 1, a
            // request by default; and the terminating form, [12], on leg 2.
            for (event, info_tag, leg, name) in [
                (0x09, 0xA7, 0x01, "o-disconnect"),
                (0x11, 0xAC, 0x02, "t-disconnect"),
            ] {
                let report = event_report(
                    py,
                    &sequence(&[
                        &[0x80, 0x01, event],
                        &[0xA2, 0x06, info_tag, 0x04, 0x80, 0x02, 0x80, 0x90],
                        &[0xA3, 0x03, 0x81, 0x01, leg],
                        &[0xA4, 0x03, 0x80, 0x01, 0x00],
                    ]),
                );
                assert_eq!(read::<i64>(&report, "event_type"), i64::from(event));
                assert_eq!(read::<Option<u8>>(&report, "leg"), Some(leg));
                assert!(read::<bool>(&report, "is_request"));
                assert_eq!(
                    read::<Option<String>>(&report, "specific_info").as_deref(),
                    Some(name)
                );
                assert_eq!(
                    octets(&report, "release_cause").as_deref(),
                    Some(&[0x80, 0x90][..])
                );
                assert_eq!(octets(&report, "busy_cause"), None);
                assert_eq!(octets(&report, "failure_cause"), None);
            }
        });
    }

    #[test]
    fn busy_no_answer_and_route_select_failure_carry_their_causes() {
        Python::attach(|py| {
            // oCalledPartyBusySpecificInfo [3] { busyCause [0] user busy }
            let busy = event_report(
                py,
                &sequence(&[
                    &[0x80, 0x01, 0x05],
                    &[0xA2, 0x06, 0xA3, 0x04, 0x80, 0x02, 0x80, 0x91],
                    &[0xA3, 0x03, 0x81, 0x01, 0x02],
                ]),
            );
            assert_eq!(
                read::<Option<String>>(&busy, "specific_info").as_deref(),
                Some("o-called-party-busy")
            );
            assert_eq!(
                octets(&busy, "busy_cause").as_deref(),
                Some(&[0x80, 0x91][..])
            );

            // tBusySpecificInfo [8] { busyCause [0], callForwarded [50],
            // routeNotPermitted [51], forwardingDestinationNumber [52] }
            let info = tlv(
                &[0xA8],
                &[
                    &[0x80, 0x02, 0x80, 0x91][..],
                    &[0x9F, 0x32, 0x00],
                    &[0x9F, 0x33, 0x00],
                    &[0x9F, 0x34, 0x06, 0x04, 0x10, 0x51, 0x55, 0x10, 0x50],
                ]
                .concat(),
            );
            let t_busy = event_report(py, &sequence(&[&[0x80, 0x01, 0x0D], &tlv(&[0xA2], &info)]));
            assert_eq!(
                read::<Option<String>>(&t_busy, "specific_info").as_deref(),
                Some("t-busy")
            );
            assert_eq!(
                octets(&t_busy, "busy_cause").as_deref(),
                Some(&[0x80, 0x91][..])
            );
            assert!(read::<bool>(&t_busy, "call_forwarded"));
            assert!(read::<bool>(&t_busy, "route_not_permitted"));
            assert_eq!(
                octets(&t_busy, "forwarding_destination_number").as_deref(),
                Some(&[0x04, 0x10, 0x51, 0x55, 0x10, 0x50][..])
            );

            // oNoAnswerSpecificInfo [4] {}: nothing defined.
            let no_answer = event_report(
                py,
                &sequence(&[&[0x80, 0x01, 0x06], &[0xA2, 0x02, 0xA4, 0x00]]),
            );
            assert_eq!(
                read::<Option<String>>(&no_answer, "specific_info").as_deref(),
                Some("o-no-answer")
            );
            assert_eq!(octets(&no_answer, "busy_cause"), None);

            // tNoAnswerSpecificInfo [9] { callForwarded [50] }
            let t_no_answer = event_report(
                py,
                &sequence(&[
                    &[0x80, 0x01, 0x0E],
                    &[0xA2, 0x05, 0xA9, 0x03, 0x9F, 0x32, 0x00],
                ]),
            );
            assert_eq!(
                read::<Option<String>>(&t_no_answer, "specific_info").as_deref(),
                Some("t-no-answer")
            );
            assert!(read::<bool>(&t_no_answer, "call_forwarded"));
            assert!(!read::<bool>(&t_no_answer, "route_not_permitted"));

            // routeSelectFailureSpecificInfo [2] { failureCause [0] no circuit
            // available (34) }
            let failure = event_report(
                py,
                &sequence(&[
                    &[0x80, 0x01, 0x04],
                    &[0xA2, 0x06, 0xA2, 0x04, 0x80, 0x02, 0x80, 0xA2],
                ]),
            );
            assert_eq!(
                read::<Option<String>>(&failure, "specific_info").as_deref(),
                Some("route-select-failure")
            );
            assert_eq!(
                octets(&failure, "failure_cause").as_deref(),
                Some(&[0x80, 0xA2][..])
            );
        });
    }

    #[test]
    fn an_abandon_report_says_whether_the_route_was_refused() {
        Python::attach(|py| {
            // oAbandonSpecificInfo [21] { routeNotPermitted [50] NULL }
            let report = event_report(
                py,
                &sequence(&[
                    &[0x80, 0x01, 0x0A],
                    &[0xA2, 0x05, 0xB5, 0x03, 0x9F, 0x32, 0x00],
                    &[0xA3, 0x03, 0x81, 0x01, 0x01],
                ]),
            );
            assert_eq!(read::<i64>(&report, "event_type"), 10);
            assert_eq!(
                read::<Option<String>>(&report, "specific_info").as_deref(),
                Some("o-abandon")
            );
            assert!(read::<bool>(&report, "route_not_permitted"));

            // An event with no specific information at all.
            let bare = event_report(py, &sequence(&[&[0x80, 0x01, 0x0A]]));
            assert_eq!(read::<Option<String>>(&bare, "specific_info"), None);
            assert!(!read::<bool>(&bare, "route_not_permitted"));
        });
    }

    #[test]
    fn only_an_invoke_of_the_operation_has_the_view() {
        Python::attach(|py| {
            let report = sequence(&[&[0x80, 0x01, 0x07]]);
            let other = invoke(py, gsm_cap::op_codes::APPLY_CHARGING_REPORT, &report);
            assert!(other.getattr("event_report_bcsm").expect("None").is_none());
            let event = invoke(py, gsm_cap::op_codes::EVENT_REPORT_BCSM, &report);
            assert!(event
                .getattr("apply_charging_report")
                .expect("None")
                .is_none());
            let result = PeerComp {
                kind: "result",
                operation_code: Some(gsm_cap::op_codes::EVENT_REPORT_BCSM),
                invoke_id: Some(7),
                parameter: Some(report),
                error_code: None,
                problem: None,
            };
            let result = Bound::new(py, PyComponent(result)).expect("Component");
            assert!(result.getattr("event_report_bcsm").expect("None").is_none());
        });
    }

    #[test]
    fn a_damaged_event_report_is_a_mistyped_parameter_that_names_its_invoke() {
        Python::attach(|py| {
            for damaged in [
                // legID as a primitive [2] holding the leg octet.
                sequence(&[&[0x80, 0x01, 0x07], &[0x82, 0x01, 0x02]]),
                // An alternative the event-specific information does not have.
                sequence(&[&[0x80, 0x01, 0x07], &[0xA2, 0x02, 0xBE, 0x00]]),
                // No eventTypeBCSM.
                sequence(&[&[0xA3, 0x03, 0x81, 0x01, 0x02]]),
                // A leg of two octets: LegType is `OCTET STRING (SIZE(1))`.
                sequence(&[&[0x80, 0x01, 0x07], &[0xA3, 0x04, 0x81, 0x02, 0x00, 0x02]]),
                // An event type the enumeration does not have.
                sequence(&[&[0x80, 0x01, 0x63]]),
                // One octet after the argument.
                [&sequence(&[&[0x80, 0x01, 0x07]])[..], &[0x00]].concat(),
            ] {
                let component = invoke(py, gsm_cap::op_codes::EVENT_REPORT_BCSM, &damaged);
                let error = assert_mistyped(py, &component, "event_report_bcsm");
                // The Reject has to name this Invoke, not the first of its turn.
                assert_eq!(read::<i64>(error.value(py).as_any(), "invoke_id"), 7);
            }
            // An Invoke of the operation with no argument at all.
            let bare = PeerComp {
                kind: "invoke",
                operation_code: Some(gsm_cap::op_codes::EVENT_REPORT_BCSM),
                invoke_id: Some(7),
                parameter: None,
                error_code: None,
                problem: None,
            };
            let bare = Bound::new(py, PyComponent(bare))
                .expect("Component")
                .into_any();
            assert_mistyped(py, &bare, "event_report_bcsm");
        });
    }

    // ── ApplyChargingReport ──────────────────────────────────────────────────

    #[test]
    fn a_charging_report_gives_the_time_used_and_whether_the_leg_is_up() {
        Python::attach(|py| {
            // 04 10 { timeDurationChargingResult [0] { partyToCharge [0] {
            // receivingSideID [1] 01 }, timeInformation [1] {
            // timeIfNoTariffSwitch [0] 600 }, legActive [2] FALSE } }
            let report = charging_report(
                py,
                &[
                    0x04, 0x10, 0xA0, 0x0E, 0xA0, 0x03, 0x81, 0x01, 0x01, 0xA1, 0x04, 0x80, 0x02,
                    0x02, 0x58, 0x82, 0x01, 0x00,
                ],
            );
            assert_eq!(read::<u8>(&report, "party_to_charge"), 1);
            assert_eq!(
                read::<Option<u32>>(&report, "time_if_no_tariff_switch"),
                Some(600)
            );
            assert_eq!(
                read::<Option<u32>>(&report, "time_since_tariff_switch"),
                None
            );
            assert_eq!(read::<Option<u32>>(&report, "tariff_switch_interval"), None);
            assert!(!read::<bool>(&report, "leg_active"));
            assert!(!read::<bool>(&report, "call_active"));
            assert!(!read::<bool>(&report, "call_leg_released_at_tcp_expiry"));
        });
    }

    #[test]
    fn a_charging_report_after_a_tariff_switch_gives_both_times() {
        Python::attach(|py| {
            // timeInformation [1] { timeIfTariffSwitch [1] {
            // timeSinceTariffSwitch [0] 300, tariffSwitchInterval [1] 600 } };
            // legActive absent (DEFAULT TRUE); callLegReleasedAtTcpExpiry [3].
            let result = tlv(
                &[0xA0],
                &[
                    &[0xA0, 0x03, 0x81, 0x01, 0x02][..],
                    &[
                        0xA1, 0x0A, 0xA1, 0x08, 0x80, 0x02, 0x01, 0x2C, 0x81, 0x02, 0x02, 0x58,
                    ],
                    &[0x83, 0x00],
                ]
                .concat(),
            );
            let report = charging_report(py, &tlv(&[0x04], &result));
            assert_eq!(read::<u8>(&report, "party_to_charge"), 2);
            assert_eq!(
                read::<Option<u32>>(&report, "time_if_no_tariff_switch"),
                None
            );
            assert_eq!(
                read::<Option<u32>>(&report, "time_since_tariff_switch"),
                Some(300)
            );
            assert_eq!(
                read::<Option<u32>>(&report, "tariff_switch_interval"),
                Some(600)
            );
            assert!(read::<bool>(&report, "leg_active"));
            assert!(read::<bool>(&report, "call_active"));
            assert!(read::<bool>(&report, "call_leg_released_at_tcp_expiry"));
        });
    }

    #[test]
    fn a_damaged_charging_report_is_a_mistyped_parameter_that_names_its_invoke() {
        Python::attach(|py| {
            for damaged in [
                // A SEQUENCE where the argument is an OCTET STRING.
                vec![0x30, 0x03, 0x80, 0x01, 0x01],
                // The OCTET STRING holds something that is no CAMEL-CallResult.
                vec![0x04, 0x02, 0xA1, 0x00],
                // No partyToCharge.
                vec![0x04, 0x08, 0xA0, 0x06, 0xA1, 0x04, 0x80, 0x02, 0x02, 0x58],
                // partyToCharge without its explicit tag.
                vec![
                    0x04, 0x0B, 0xA0, 0x09, 0x80, 0x01, 0x01, 0xA1, 0x04, 0x80, 0x02, 0x02, 0x58,
                ],
                // An empty OCTET STRING.
                vec![0x04, 0x00],
            ] {
                let component = invoke(py, gsm_cap::op_codes::APPLY_CHARGING_REPORT, &damaged);
                let error = assert_mistyped(py, &component, "apply_charging_report");
                assert_eq!(read::<i64>(error.value(py).as_any(), "invoke_id"), 7);
            }
        });
    }

    // ── The dialogue ─────────────────────────────────────────────────────────

    #[test]
    fn a_dialogue_says_which_camel_phase_it_runs_under() {
        Python::attach(|py| {
            for (context, phase) in [
                (&[0, 4, 0, 0, 1, 0, 50, 0][..], Some(1)),
                (&[0, 4, 0, 0, 1, 0, 50, 1], Some(2)),
                (&[0, 4, 0, 0, 1, 0, 51, 1], Some(2)),
                (&[0, 4, 0, 0, 1, 21, 3, 4], Some(3)),
                (&[0, 4, 0, 0, 1, 21, 3, 61], Some(3)),
                (&[0, 4, 0, 0, 1, 20, 3, 14], Some(3)),
                (&[0, 4, 0, 0, 1, 23, 3, 4], Some(4)),
                (&[0, 4, 0, 0, 1, 22, 3, 14], Some(4)),
                // A MAP context is no CAMEL phase.
                (&[0, 4, 0, 0, 1, 0, 25, 3], None),
            ] {
                let dialogue =
                    Bound::new(py, PyDialogue::new(vec![1], vec![2], context)).expect("Dialogue");
                assert_eq!(
                    read::<Option<Vec<u32>>>(dialogue.as_any(), "application_context").as_deref(),
                    Some(context)
                );
                assert_eq!(
                    read::<Option<u8>>(dialogue.as_any(), "camel_phase"),
                    phase,
                    "{context:?}"
                );
            }
            let bare = Bound::new(py, PyDialogue::new(vec![1], vec![2], &[])).expect("Dialogue");
            assert!(bare.getattr("application_context").expect("None").is_none());
            assert_eq!(read::<Option<u8>>(bare.as_any(), "camel_phase"), None);
        });
    }
}
