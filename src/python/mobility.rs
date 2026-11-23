//! MAP mobility management, subscriber data management and call handling
//! for the HLR role (TS 29.002 clauses 8, 10 and 7.6): the arguments an HLR
//! terminates (updateLocation, updateGprsLocation, sendAuthenticationInfo,
//! purgeMS, sendRoutingInfo) read into objects, and the operations and
//! results it sends built from Python values (insertSubscriberData,
//! cancelLocation, provideRoamingNumber, the sendRoutingInfo and
//! updateGprsLocation results).
//!
//! Every decode is `gsm_map::decode`: a member that cannot be read, or octets
//! after the argument, raise `MistypedParameter`; a member a later release
//! added after the extension marker is skipped (TS 29.002 17.1.4).

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyModule};
use rasn::types::{BitString, Integer, OctetString};

use gsm_map::operations::auth::SendAuthenticationInfoArg;
use gsm_map::operations::call_handling::{
    CamelRoutingInfo, ExtendedRoutingInfo, GmscCamelSubscriptionInfo, InterrogationType,
    ProvideRoamingNumberArg, ProvideRoamingNumberRes, RoutingInfo, SendRoutingInfoArg,
    SendRoutingInfoRes,
};
use gsm_map::operations::camel_subscription::{
    DefaultCallHandling, OBcsmCamelTdpData, OBcsmTriggerDetectionPoint, OCsi, TBcsmCamelTdpData,
    TBcsmTriggerDetectionPoint, TCsi, VlrCamelSubscriptionInfo,
};
use gsm_map::operations::gprs_location::{UpdateGprsLocationArg, UpdateGprsLocationRes};
use gsm_map::operations::gprs_subscription::{Ambr, GprsSubscriptionData, PdpContext};
use gsm_map::operations::location::{
    CancelLocationArg, CancellationType, Identity, PurgeMsArg, UpdateLocationArg,
};
use gsm_map::operations::subscriber_data::{
    op_codes as subscriber_data_codes, InsertSubscriberDataArg, NetworkAccessMode, OdbData,
    SubscriberStatus,
};

use super::cap::{address_digits, imsi_digits};
use super::{
    err, imsi_arg, isdn_addr, mistyped, staged_map_invoke, staged_map_res, MapAcHandle,
    PyIncomingOp, PyPeerTurn, StagedInvoke, StagedResult,
};

// ── Reading the arguments an HLR terminates ──────────────────────────────────

/// The argument of the opening Invoke when it is operation `code`, None for
/// another operation.
fn argument_of<'a>(op: &'a PyIncomingOp, code: i64, what: &str) -> PyResult<Option<&'a [u8]>> {
    if op.operation_code != code {
        return Ok(None);
    }
    op.argument
        .as_deref()
        .map(Some)
        .ok_or_else(|| mistyped(what, "the Invoke carries no argument"))
}

fn decoded<T: rasn::Decode>(bytes: &[u8], what: &str) -> PyResult<T> {
    gsm_map::decode(bytes).map_err(|e| mistyped(what, e))
}

fn integer(value: &Integer, what: &str) -> PyResult<i64> {
    i64::try_from(value).map_err(|_| mistyped(what, "it does not fit an integer"))
}

fn optional_bytes(py: Python<'_>, value: Option<&[u8]>) -> Option<Py<PyBytes>> {
    value.map(|octets| PyBytes::new(py, octets).unbind())
}

/// An updateLocation argument (TS 29.002 clause 8.1.2), as a VLR sent it.
#[pyclass(name = "UpdateLocation", module = "siphon", frozen, get_all)]
pub struct PyUpdateLocation {
    /// The IMSI, as its digits.
    imsi: String,
    /// The MSC number and the VLR number, as their digits.
    msc_number: String,
    vlr_number: String,
    /// The LMSI the VLR allocated, or None.
    lmsi: Option<Py<PyBytes>>,
    /// The VLR has the subscriber data already and asks for none to be
    /// inserted (clause 8.1.2.2).
    skip_subscriber_data_update: bool,
}

pub(super) fn update_location(
    py: Python<'_>,
    op: &PyIncomingOp,
) -> PyResult<Option<PyUpdateLocation>> {
    let what = "the updateLocation argument";
    let Some(bytes) = argument_of(op, gsm_map::op_codes::UPDATE_LOCATION, what)? else {
        return Ok(None);
    };
    let arg: UpdateLocationArg = decoded(bytes, what)?;
    Ok(Some(PyUpdateLocation {
        imsi: imsi_digits("the updateLocation imsi", &arg.imsi)?,
        msc_number: address_digits("the updateLocation msc-Number", &arg.msc_number)?,
        vlr_number: address_digits("the updateLocation vlr-Number", &arg.vlr_number)?,
        lmsi: optional_bytes(py, arg.lmsi.as_deref()),
        skip_subscriber_data_update: arg.skip_subscriber_data_update.is_some(),
    }))
}

/// An updateGprsLocation argument (TS 29.002 clause 8.1.7), as an SGSN sent
/// it.
#[pyclass(name = "UpdateGprsLocation", module = "siphon", frozen, get_all)]
pub struct PyUpdateGprsLocation {
    imsi: String,
    /// The SGSN number, as its digits: the global title of the SGSN.
    sgsn_number: String,
    /// The GSN-Address octets as received (the address type and length octet,
    /// then the address).
    sgsn_address: Py<PyBytes>,
    skip_subscriber_data_update: bool,
}

pub(super) fn update_gprs_location(
    py: Python<'_>,
    op: &PyIncomingOp,
) -> PyResult<Option<PyUpdateGprsLocation>> {
    let what = "the updateGprsLocation argument";
    let Some(bytes) = argument_of(op, gsm_map::op_codes::UPDATE_GPRS_LOCATION, what)? else {
        return Ok(None);
    };
    let arg: UpdateGprsLocationArg = decoded(bytes, what)?;
    Ok(Some(PyUpdateGprsLocation {
        imsi: imsi_digits("the updateGprsLocation imsi", &arg.imsi)?,
        sgsn_number: address_digits("the updateGprsLocation sgsn-Number", &arg.sgsn_number)?,
        sgsn_address: PyBytes::new(py, &arg.sgsn_address).unbind(),
        skip_subscriber_data_update: arg.skip_subscriber_data_update.is_some(),
    }))
}

/// A sendAuthenticationInfo argument (TS 29.002 clause 8.5.2), the version 3
/// form.
#[pyclass(name = "SendAuthenticationInfo", module = "siphon", frozen, get_all)]
pub struct PySendAuthenticationInfo {
    imsi: String,
    /// How many vectors were asked for (1 to 5).
    number_of_requested_vectors: i64,
    /// `vlr` (0), `sgsn` (1), `s-cscf` (2), `bsf` (3) ... as the number of
    /// RequestingNodeType, or None when the requester did not say.
    requesting_node_type: Option<i64>,
    /// `(rand, auts)` when the USIM rejected the sequence number: the
    /// re-synchronisation the HLR has to perform first (TS 33.102 clause
    /// 6.3.5), else None.
    re_synchronisation: Option<(Py<PyBytes>, Py<PyBytes>)>,
    immediate_response_preferred: bool,
}

pub(super) fn send_authentication_info(
    py: Python<'_>,
    op: &PyIncomingOp,
) -> PyResult<Option<PySendAuthenticationInfo>> {
    let what = "the sendAuthenticationInfo argument";
    let Some(bytes) = argument_of(op, gsm_map::op_codes::SEND_AUTHENTICATION_INFO, what)? else {
        return Ok(None);
    };
    // Version 2 of infoRetrieval carries the IMSI alone (an OCTET STRING, not
    // a SEQUENCE) and is answered with a bare list of triplets. Neither form
    // is modelled: refused by name rather than as an unreadable SEQUENCE.
    if bytes.first() == Some(&0x04) {
        return Err(mistyped(
            what,
            "it is the version 2 form (an IMSI alone), which is not served",
        ));
    }
    let arg: SendAuthenticationInfoArg = decoded(bytes, what)?;
    Ok(Some(PySendAuthenticationInfo {
        imsi: imsi_digits("the sendAuthenticationInfo imsi", &arg.imsi)?,
        number_of_requested_vectors: integer(
            &arg.number_of_requested_vectors,
            "the sendAuthenticationInfo numberOfRequestedVectors",
        )?,
        requesting_node_type: arg
            .requesting_node_type
            .as_ref()
            .map(|value| integer(value, "the sendAuthenticationInfo requestingNodeType"))
            .transpose()?,
        re_synchronisation: arg.re_synchronisation_info.map(|info| {
            (
                PyBytes::new(py, &info.rand).unbind(),
                PyBytes::new(py, &info.auts).unbind(),
            )
        }),
        immediate_response_preferred: arg.immediate_response_preferred.is_some(),
    }))
}

/// A purgeMS argument (TS 29.002 clause 8.1.6).
#[pyclass(name = "PurgeMs", module = "siphon", frozen, get_all)]
pub struct PyPurgeMs {
    imsi: String,
    /// The number of the purging VLR or SGSN, as its digits; one of the two.
    vlr_number: Option<String>,
    sgsn_number: Option<String>,
}

pub(super) fn purge_ms(op: &PyIncomingOp) -> PyResult<Option<PyPurgeMs>> {
    let what = "the purgeMS argument";
    let Some(bytes) = argument_of(op, gsm_map::op_codes::PURGE_MS, what)? else {
        return Ok(None);
    };
    let arg: PurgeMsArg = decoded(bytes, what)?;
    Ok(Some(PyPurgeMs {
        imsi: imsi_digits("the purgeMS imsi", &arg.imsi)?,
        vlr_number: arg
            .vlr_number
            .as_deref()
            .map(|number| address_digits("the purgeMS vlr-Number", number))
            .transpose()?,
        sgsn_number: arg
            .sgsn_number
            .as_deref()
            .map(|number| address_digits("the purgeMS sgsn-Number", number))
            .transpose()?,
    }))
}

/// A sendRoutingInfo argument (TS 29.002 clause 10.1.1), as a GMSC sent it.
#[pyclass(name = "SendRoutingInfo", module = "siphon", frozen, get_all)]
pub struct PySendRoutingInfo {
    /// The called MSISDN, as its digits.
    msisdn: String,
    /// `basic-call` or `forwarding`.
    interrogation_type: Option<&'static str>,
    /// The GMSC (or gsmSCF) address, as its digits.
    gmsc_address: String,
    call_reference_number: Option<Py<PyBytes>>,
    /// The GMSC asks for the T-CSI to be left out (the second interrogation
    /// after the gsmSCF answered the first, TS 23.078 clause 4.5.3).
    suppress_t_csi: bool,
    /// The CAMEL phases the GMSC supports (1 to 4), empty without camelInfo.
    supported_camel_phases: Vec<i64>,
    /// An optimal routing interrogation (TS 23.079).
    or_interrogation: bool,
}

pub(super) fn send_routing_info(
    py: Python<'_>,
    op: &PyIncomingOp,
) -> PyResult<Option<PySendRoutingInfo>> {
    let what = "the sendRoutingInfo argument";
    let Some(bytes) = argument_of(op, gsm_map::op_codes::SEND_ROUTING_INFO, what)? else {
        return Ok(None);
    };
    let arg: SendRoutingInfoArg = decoded(bytes, what)?;
    let camel = arg
        .camel_info_typed()
        .transpose()
        .map_err(|e| mistyped("the sendRoutingInfo camelInfo", e))?;
    let phases = camel
        .as_ref()
        .map(|info| {
            (0..4u8)
                .filter(|bit| {
                    info.supported_camel_phases
                        .get(usize::from(*bit))
                        .is_some_and(|set| *set)
                })
                .map(|bit| i64::from(bit) + 1)
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(PySendRoutingInfo {
        msisdn: address_digits("the sendRoutingInfo msisdn", &arg.msisdn)?,
        interrogation_type: arg.interrogation_type.map(|kind| match kind {
            InterrogationType::BasicCall => "basic-call",
            InterrogationType::Forwarding => "forwarding",
        }),
        gmsc_address: address_digits(
            "the sendRoutingInfo gmsc-OrGsmSCF-Address",
            &arg.gmsc_or_gsm_scf_address,
        )?,
        call_reference_number: optional_bytes(py, arg.call_reference_number.as_deref()),
        suppress_t_csi: camel
            .as_ref()
            .is_some_and(|info| info.suppress_t_csi.is_some()),
        supported_camel_phases: phases,
        or_interrogation: arg.or_interrogation.is_some(),
    }))
}

/// The roaming number of a provideRoamingNumber result (TS 29.002 clause
/// 10.2.2), as its digits: what a VLR answered the PRN this node sent with.
/// None when the turn carries no result of that operation.
pub(super) fn roaming_number(turn: &PyPeerTurn) -> PyResult<Option<String>> {
    let what = "the provideRoamingNumber result";
    let Some(result) = turn.comps.iter().find(|c| {
        c.kind == "result" && c.operation_code == Some(gsm_map::op_codes::PROVIDE_ROAMING_NUMBER)
    }) else {
        return Ok(None);
    };
    let bytes = result
        .parameter
        .as_deref()
        .ok_or_else(|| mistyped(what, "the result carries no parameter"))?;
    let res: ProvideRoamingNumberRes = decoded(bytes, what)?;
    address_digits(
        "the provideRoamingNumber roamingNumber",
        &res.roaming_number,
    )
    .map(Some)
}

// ── Building what an HLR sends ───────────────────────────────────────────────

/// A required item of a dict argument.
fn item<'py>(dict: &Bound<'py, PyDict>, key: &str, what: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| err(format!("{what} has no {key:?}")))
}

/// An optional item; None and an absent key are the same.
fn optional_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(dict.get_item(key)?.filter(|value| !value.is_none()))
}

fn default_call_handling(name: &str) -> PyResult<DefaultCallHandling> {
    match name {
        "continue" => Ok(DefaultCallHandling::ContinueCall),
        "release" => Ok(DefaultCallHandling::ReleaseCall),
        other => Err(err(format!(
            "default_call_handling {other:?} is not continue or release"
        ))),
    }
}

/// One CAMEL trigger as `{"trigger", "service_key", "gsmscf",
/// "default_call_handling"}`, the shared part of the O- and T-BCSM TDP data.
struct Trigger {
    detection_point: String,
    service_key: Integer,
    gsm_scf: OctetString,
    default: DefaultCallHandling,
}

fn triggers(list: &Bound<'_, PyAny>, what: &str) -> PyResult<Vec<Trigger>> {
    let mut out = Vec::new();
    for entry in list.try_iter()? {
        let entry = entry?;
        let dict = entry
            .cast::<PyDict>()
            .map_err(|_| err(format!("each {what} trigger is a dict")))?;
        let detection_point: String = item(dict, "trigger", what)?.extract()?;
        let service_key: i64 = item(dict, "service_key", what)?.extract()?;
        if !(0..=i64::from(i32::MAX)).contains(&service_key) {
            return Err(err(format!(
                "{what} service_key {service_key} is outside 0..2147483647"
            )));
        }
        let gsm_scf = isdn_addr(&item(dict, "gsmscf", what)?)?;
        let default = match optional_item(dict, "default_call_handling")? {
            Some(value) => default_call_handling(&value.extract::<String>()?)?,
            None => DefaultCallHandling::ContinueCall,
        };
        out.push(Trigger {
            detection_point,
            service_key: Integer::from(service_key),
            gsm_scf: gsm_scf.into(),
            default,
        });
    }
    if out.is_empty() || out.len() > 10 {
        // maxNumOfCamelTDPData.
        return Err(err(format!("{what} takes 1 to 10 triggers")));
    }
    Ok(out)
}

/// An O-CSI from triggers at `collected-info` or `route-select-failure`.
fn o_csi(list: &Bound<'_, PyAny>, camel_phase: Option<i64>) -> PyResult<OCsi> {
    let data = triggers(list, "o_csi")?
        .into_iter()
        .map(|trigger| {
            let point = match trigger.detection_point.as_str() {
                "collected-info" => OBcsmTriggerDetectionPoint::CollectedInfo,
                "route-select-failure" => OBcsmTriggerDetectionPoint::RouteSelectFailure,
                other => {
                    return Err(err(format!(
                        "o_csi trigger {other:?} is not collected-info or route-select-failure"
                    )))
                }
            };
            Ok(OBcsmCamelTdpData::new(
                point,
                trigger.service_key,
                trigger.gsm_scf,
                trigger.default,
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let mut csi = OCsi::new(data);
    csi.camel_capability_handling = camel_phase.map(Integer::from);
    Ok(csi)
}

/// A T-CSI (or VT-CSI) from triggers at `term-attempt-authorized`, `t-busy`
/// or `t-no-answer`.
fn t_csi(list: &Bound<'_, PyAny>, camel_phase: Option<i64>, what: &str) -> PyResult<TCsi> {
    let data = triggers(list, what)?
        .into_iter()
        .map(|trigger| {
            let point = match trigger.detection_point.as_str() {
                "term-attempt-authorized" => TBcsmTriggerDetectionPoint::TermAttemptAuthorized,
                "t-busy" => TBcsmTriggerDetectionPoint::TBusy,
                "t-no-answer" => TBcsmTriggerDetectionPoint::TNoAnswer,
                other => {
                    return Err(err(format!(
                        "{what} trigger {other:?} is not term-attempt-authorized, t-busy or \
                         t-no-answer"
                    )))
                }
            };
            Ok(TBcsmCamelTdpData::new(
                point,
                trigger.service_key,
                trigger.gsm_scf,
                trigger.default,
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let mut csi = TCsi::new(data);
    csi.camel_capability_handling = camel_phase.map(Integer::from);
    Ok(csi)
}

fn camel_phase_arg(camel_phase: Option<i64>) -> PyResult<Option<i64>> {
    match camel_phase {
        Some(phase) if !(1..=4).contains(&phase) => {
            Err(err(format!("camel_phase {phase} is not 1 to 4")))
        }
        other => Ok(other),
    }
}

/// The bits of ODB-General-Data by name (TS 29.002, MAP-MS-DataTypes).
const ODB_GENERAL: [(&str, usize); 29] = [
    ("all-og-calls-barred", 0),
    ("international-og-calls-barred", 1),
    ("international-og-calls-not-to-hplmn-country-barred", 2),
    ("premium-rate-information-og-calls-barred", 3),
    ("premium-rate-entertainment-og-calls-barred", 4),
    ("ss-access-barred", 5),
    ("interzonal-og-calls-barred", 6),
    ("interzonal-og-calls-not-to-hplmn-country-barred", 7),
    (
        "interzonal-og-calls-and-international-og-calls-not-to-hplmn-country-barred",
        8,
    ),
    ("all-ect-barred", 9),
    ("chargeable-ect-barred", 10),
    ("international-ect-barred", 11),
    ("interzonal-ect-barred", 12),
    ("doubly-chargeable-ect-barred", 13),
    ("multiple-ect-barred", 14),
    ("all-packet-oriented-services-barred", 15),
    ("roamer-access-to-hplmn-ap-barred", 16),
    ("roamer-access-to-vplmn-ap-barred", 17),
    ("roaming-outside-plmn-og-calls-barred", 18),
    ("all-ic-calls-barred", 19),
    ("roaming-outside-plmn-ic-calls-barred", 20),
    ("roaming-outside-plmn-icountry-ic-calls-barred", 21),
    ("roaming-outside-plmn-barred", 22),
    ("roaming-outside-plmn-country-barred", 23),
    ("registration-all-cf-barred", 24),
    ("registration-cf-not-to-hplmn-barred", 25),
    ("registration-interzonal-cf-barred", 26),
    ("registration-interzonal-cf-not-to-hplmn-barred", 27),
    ("registration-international-cf-barred", 28),
];

/// ODB-Data from the names of the general barrings to set. The bit string
/// is 32 bits, within its SIZE (15..32).
fn odb_data(names: &[String]) -> PyResult<OdbData> {
    let mut bits = BitString::repeat(false, 32);
    for name in names {
        let (_, bit) = ODB_GENERAL
            .iter()
            .find(|(known, _)| known == name)
            .ok_or_else(|| err(format!("{name:?} is not an operator determined barring")))?;
        bits.set(*bit, true);
    }
    Ok(OdbData::new(bits))
}

/// An APN in the label form of TS 23.003 clause 9.1: each label preceded by
/// its length.
fn apn_labels(name: &str) -> PyResult<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 1);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(err(format!(
                "APN {name:?} has a label that is empty, over 63 octets or not ASCII"
            )));
        }
        out.push(u8::try_from(label.len()).map_err(err)?);
        out.extend_from_slice(label.as_bytes());
    }
    if out.len() > 100 {
        return Err(err(format!("APN {name:?} is over 100 octets")));
    }
    Ok(out)
}

/// An optional octet string item whose length its ASN.1 type bounds
/// (TS 29.002 MAP-MS-DataTypes).
fn octets_item(
    dict: &Bound<'_, PyDict>,
    key: &str,
    sizes: std::ops::RangeInclusive<usize>,
) -> PyResult<Option<OctetString>> {
    optional_item(dict, key)?
        .map(|value| {
            let octets = value.extract::<Vec<u8>>()?;
            if !sizes.contains(&octets.len()) {
                return Err(err(format!(
                    "gprs {key} is {} octets, not {} to {}",
                    octets.len(),
                    sizes.start(),
                    sizes.end()
                )));
            }
            Ok(OctetString::from(octets))
        })
        .transpose()
}

/// One PDP-Context (TS 29.002) from a dict: `context_id`, `apn`,
/// `qos_subscribed` (the three octets of TS 24.008 clause 10.5.6.5, octets 3
/// to 5), and optionally `pdp_type` (two octets, default IPv4 f1 21),
/// `pdp_address`, `ext_qos_subscribed`, `ext2_qos_subscribed`,
/// `ext3_qos_subscribed`, `ext4_qos_subscribed`, `ext_pdp_type`,
/// `charging_characteristics`, `vplmn_address_allowed` and `ambr` (uplink,
/// downlink in bits per second, TS 29.002 Bandwidth).
fn pdp_context(entry: &Bound<'_, PyAny>) -> PyResult<PdpContext> {
    let what = "a gprs context";
    let dict = entry
        .cast::<PyDict>()
        .map_err(|_| err("each gprs context is a dict"))?;
    let context_id: i64 = item(dict, "context_id", what)?.extract()?;
    if !(1..=50).contains(&context_id) {
        return Err(err(format!("gprs context_id {context_id} is not 1 to 50")));
    }
    let apn: String = item(dict, "apn", what)?.extract()?;
    let qos: Vec<u8> = item(dict, "qos_subscribed", what)?.extract()?;
    if qos.len() != 3 {
        return Err(err("gprs qos_subscribed is three octets"));
    }
    let pdp_type = octets_item(dict, "pdp_type", 2..=2)?
        .unwrap_or_else(|| OctetString::from(vec![0xf1, 0x21]));
    let mut context = PdpContext::new(
        Integer::from(context_id),
        pdp_type,
        OctetString::from(qos),
        OctetString::from(apn_labels(&apn)?),
    );
    context.pdp_address = octets_item(dict, "pdp_address", 1..=16)?;
    context.ext_qos_subscribed = octets_item(dict, "ext_qos_subscribed", 1..=9)?;
    context.ext2_qos_subscribed = octets_item(dict, "ext2_qos_subscribed", 1..=3)?;
    context.ext3_qos_subscribed = octets_item(dict, "ext3_qos_subscribed", 1..=2)?;
    context.ext4_qos_subscribed = octets_item(dict, "ext4_qos_subscribed", 1..=1)?;
    context.ext_pdp_type = octets_item(dict, "ext_pdp_type", 2..=2)?;
    context.pdp_charging_characteristics = octets_item(dict, "charging_characteristics", 2..=2)?;
    if let Some(allowed) = optional_item(dict, "vplmn_address_allowed")? {
        context.vplmn_address_allowed = allowed.extract::<bool>()?.then_some(());
    }
    if let Some(ambr) = optional_item(dict, "ambr")? {
        let (uplink, downlink): (i64, i64) = ambr.extract()?;
        context.ambr = Some(Ambr::new(Integer::from(uplink), Integer::from(downlink)));
    }
    Ok(context)
}

/// The arguments of [`insert_subscriber_data`] beyond the two the original
/// builder took.
pub(super) struct SubscriberData<'py> {
    pub category: Option<u8>,
    pub subscriber_status: Option<String>,
    pub teleservices: Option<Vec<u8>>,
    pub bearer_services: Option<Vec<u8>>,
    pub odb: Option<Vec<String>>,
    pub o_csi: Option<Bound<'py, PyAny>>,
    pub vt_csi: Option<Bound<'py, PyAny>>,
    pub camel_phase: Option<i64>,
    pub gprs: Option<Bound<'py, PyAny>>,
    pub network_access_mode: Option<String>,
}

/// An insertSubscriberData invoke (TS 29.002 clause 8.8.1).
pub(super) fn insert_subscriber_data(
    imsi: Option<Bound<'_, PyAny>>,
    msisdn: Option<Bound<'_, PyAny>>,
    data: SubscriberData<'_>,
) -> PyResult<StagedInvoke> {
    let mut arg = InsertSubscriberDataArg {
        imsi: imsi.as_ref().map(imsi_arg).transpose()?.map(Into::into),
        msisdn: msisdn.as_ref().map(isdn_addr).transpose()?.map(Into::into),
        ..InsertSubscriberDataArg::default()
    };
    arg.category = data
        .category
        .map(|category| OctetString::from(vec![category]));
    arg.subscriber_status = data
        .subscriber_status
        .as_deref()
        .map(|status| match status {
            "service-granted" => Ok(SubscriberStatus::ServiceGranted),
            "operator-determined-barring" => Ok(SubscriberStatus::OperatorDeterminedBarring),
            other => Err(err(format!(
                "subscriber_status {other:?} is not service-granted or operator-determined-barring"
            ))),
        })
        .transpose()?;
    // Ext-TeleserviceCode and Ext-BearerServiceCode: the one-octet code of
    // TS 29.002 MAP-TS-Code / MAP-BS-Code.
    let codes =
        |list: Option<Vec<u8>>, limit: usize, what: &str| -> PyResult<Option<Vec<OctetString>>> {
            list.map(|codes| {
                if codes.is_empty() || codes.len() > limit {
                    return Err(err(format!("{what} takes 1 to {limit} codes")));
                }
                Ok(codes
                    .into_iter()
                    .map(|code| OctetString::from(vec![code]))
                    .collect())
            })
            .transpose()
        };
    arg.teleservice_list = codes(data.teleservices, 20, "teleservices")?;
    arg.bearer_service_list = codes(data.bearer_services, 50, "bearer_services")?;
    arg.odb_data = data.odb.as_deref().map(odb_data).transpose()?;
    let camel_phase = camel_phase_arg(data.camel_phase)?;
    if data.o_csi.is_some() || data.vt_csi.is_some() {
        let mut camel = VlrCamelSubscriptionInfo {
            o_csi: data
                .o_csi
                .as_ref()
                .map(|list| o_csi(list, camel_phase))
                .transpose()?,
            ..VlrCamelSubscriptionInfo::default()
        };
        if let Some(list) = &data.vt_csi {
            camel
                .set_vt_csi(&t_csi(list, camel_phase, "vt_csi")?)
                .map_err(err)?;
        }
        arg.set_vlr_camel_subscription_info(&camel).map_err(err)?;
    }
    if let Some(list) = &data.gprs {
        let contexts = list
            .try_iter()?
            .map(|entry| pdp_context(&entry?))
            .collect::<PyResult<Vec<_>>>()?;
        if contexts.is_empty() || contexts.len() > 50 {
            return Err(err("gprs takes 1 to 50 contexts"));
        }
        let mut subscription = GprsSubscriptionData::new(contexts);
        subscription.complete_data_list_included = Some(());
        arg.set_gprs_subscription_data(&subscription).map_err(err)?;
    }
    arg.network_access_mode = data
        .network_access_mode
        .as_deref()
        .map(|mode| match mode {
            "packet-and-circuit" => Ok(NetworkAccessMode::PacketAndCircuit),
            "only-circuit" => Ok(NetworkAccessMode::OnlyCircuit),
            "only-packet" => Ok(NetworkAccessMode::OnlyPacket),
            other => Err(err(format!(
                "network_access_mode {other:?} is not packet-and-circuit, only-circuit or \
                 only-packet"
            ))),
        })
        .transpose()?;
    staged_map_invoke(subscriber_data_codes::INSERT_SUBSCRIBER_DATA, &arg)
}

/// An updateGprsLocation result carrying the HLR number (clause 8.1.7).
pub(super) fn update_gprs_location_res(hlr_number: &Bound<'_, PyAny>) -> PyResult<StagedResult> {
    let res = UpdateGprsLocationRes::new(isdn_addr(hlr_number)?.into());
    staged_map_res(gsm_map::op_codes::UPDATE_GPRS_LOCATION, &res)
}

/// A cancelLocation invoke (clause 8.1.3) naming the subscriber by IMSI.
pub(super) fn cancel_location(
    imsi: &Bound<'_, PyAny>,
    cancellation_type: &str,
) -> PyResult<StagedInvoke> {
    let kind = match cancellation_type {
        "update-procedure" => CancellationType::UpdateProcedure,
        "subscription-withdraw" => CancellationType::SubscriptionWithdraw,
        "initial-attach-procedure" => CancellationType::InitialAttachProcedure,
        other => {
            return Err(err(format!(
                "cancellation_type {other:?} is not update-procedure, subscription-withdraw or \
                 initial-attach-procedure"
            )))
        }
    };
    let mut arg = CancelLocationArg::new(Identity::Imsi(imsi_arg(imsi)?.into()));
    arg.cancellation_type = Some(kind);
    staged_map_invoke(gsm_map::op_codes::CANCEL_LOCATION, &arg)
}

/// A provideRoamingNumber invoke (clause 10.2.1) to the VLR serving the
/// subscriber.
pub(super) fn provide_roaming_number(
    imsi: &Bound<'_, PyAny>,
    msc_number: &Bound<'_, PyAny>,
    msisdn: Option<Bound<'_, PyAny>>,
    gmsc_address: Option<Bound<'_, PyAny>>,
    call_reference_number: Option<Vec<u8>>,
) -> PyResult<StagedInvoke> {
    let mut arg =
        ProvideRoamingNumberArg::new(imsi_arg(imsi)?.into(), isdn_addr(msc_number)?.into());
    arg.msisdn = msisdn.as_ref().map(isdn_addr).transpose()?.map(Into::into);
    arg.gmsc_address = gmsc_address
        .as_ref()
        .map(isdn_addr)
        .transpose()?
        .map(Into::into);
    arg.call_reference_number = call_reference_number.map(OctetString::from);
    staged_map_invoke(gsm_map::op_codes::PROVIDE_ROAMING_NUMBER, &arg)
}

/// A sendRoutingInfo result (clause 10.1.2): the roaming number a VLR gave,
/// or the T-CSI for the GMSC to query the gsmSCF with (camelRoutingInfo), one
/// of the two.
pub(super) fn send_routing_info_res(
    imsi: Option<Bound<'_, PyAny>>,
    roaming_number: Option<Bound<'_, PyAny>>,
    t_csi_triggers: Option<Bound<'_, PyAny>>,
    camel_phase: Option<i64>,
    vmsc_address: Option<Bound<'_, PyAny>>,
) -> PyResult<StagedResult> {
    let routing = match (roaming_number, t_csi_triggers) {
        (Some(_), Some(_)) => {
            return Err(err(
                "a sendRoutingInfo result carries a roaming number or a T-CSI, not both",
            ))
        }
        (Some(number), None) => {
            ExtendedRoutingInfo::RoutingInfo(RoutingInfo::RoamingNumber(isdn_addr(&number)?.into()))
        }
        (None, Some(list)) => ExtendedRoutingInfo::CamelRoutingInfo(CamelRoutingInfo {
            gmsc_camel_subscription_info: GmscCamelSubscriptionInfo {
                t_csi: Some(t_csi(&list, camel_phase_arg(camel_phase)?, "t_csi")?),
                ..GmscCamelSubscriptionInfo::default()
            },
            ..CamelRoutingInfo::default()
        }),
        (None, None) => {
            return Err(err(
                "a sendRoutingInfo result needs roaming_number or t_csi",
            ))
        }
    };
    let mut res = SendRoutingInfoRes {
        imsi: imsi.as_ref().map(imsi_arg).transpose()?.map(Into::into),
        vmsc_address: vmsc_address
            .as_ref()
            .map(isdn_addr)
            .transpose()?
            .map(Into::into),
        ..SendRoutingInfoRes::default()
    };
    res.set_extended_routing_info(&routing).map_err(err)?;
    staged_map_res(gsm_map::op_codes::SEND_ROUTING_INFO, &res)
}

// ── Application contexts ─────────────────────────────────────────────────────

/// The version 3 application context `context` builds, as a handle for
/// `gsm_map.begin(..., ac=...)`.
pub(super) fn context_v3(context: fn(u32) -> rasn::types::ObjectIdentifier) -> MapAcHandle {
    MapAcHandle {
        arcs: super::oid_arcs(context(gsm_map::application_context::V3)),
    }
}

pub(super) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyUpdateLocation>()?;
    module.add_class::<PyUpdateGprsLocation>()?;
    module.add_class::<PySendAuthenticationInfo>()?;
    module.add_class::<PyPurgeMs>()?;
    module.add_class::<PySendRoutingInfo>()
}

#[cfg(test)]
mod tests {
    //! The argument below is written by hand from the ASN.1 of TS 29.002
    //! (MAP-CH-DataTypes): ProvideRoamingNumberRes ::= SEQUENCE {
    //! roamingNumber ISDN-AddressString, ... }.
    use super::*;
    use crate::python::{PeerComp, TurnEvent};

    fn turn(kind: &'static str, operation_code: i64, parameter: Option<Vec<u8>>) -> PyPeerTurn {
        PyPeerTurn {
            is_end: true,
            comps: vec![PeerComp {
                kind,
                operation_code: Some(operation_code),
                invoke_id: Some(1),
                parameter,
                error_code: None,
                problem: None,
            }],
            event: TurnEvent::default(),
            rejection: None,
        }
    }

    #[test]
    fn the_roaming_number_of_a_provide_roaming_number_result_is_read() {
        // 30 07 | 04 05 91 51 55 50 10: international E.164 15550501.
        let res = vec![0x30, 0x07, 0x04, 0x05, 0x91, 0x51, 0x55, 0x50, 0x10];
        let answered = turn(
            "result",
            gsm_map::op_codes::PROVIDE_ROAMING_NUMBER,
            Some(res),
        );
        assert_eq!(
            roaming_number(&answered).unwrap().as_deref(),
            Some("15550501")
        );
    }

    #[test]
    fn another_result_has_no_roaming_number() {
        let other = turn(
            "result",
            gsm_map::op_codes::UPDATE_LOCATION,
            Some(vec![0x30, 0x00]),
        );
        assert_eq!(roaming_number(&other).unwrap(), None);
        let error = turn("error", gsm_map::op_codes::PROVIDE_ROAMING_NUMBER, None);
        assert_eq!(roaming_number(&error).unwrap(), None);
    }

    #[test]
    fn a_result_that_does_not_decode_is_mistyped() {
        let broken = turn(
            "result",
            gsm_map::op_codes::PROVIDE_ROAMING_NUMBER,
            Some(vec![0x30, 0x03, 0x04, 0x05, 0x91]),
        );
        assert!(roaming_number(&broken).is_err());
    }

    #[test]
    fn an_apn_is_written_as_labels() {
        assert_eq!(apn_labels("ims").unwrap(), b"\x03ims");
        assert_eq!(
            apn_labels("internet.mnc001.mcc001.gprs").unwrap(),
            b"\x08internet\x06mnc001\x06mcc001\x04gprs"
        );
        for bad in ["", "a..b", ".ims", &"x".repeat(64)] {
            assert!(apn_labels(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_originated_operation_runs_on_the_timer_it_was_given() {
        use crate::dialogue::{DialogueEngine, OutgoingBegin, TerminationHandler};
        use std::time::{Duration, Instant};
        // The node's timer is 10 s; the operation asks for 200 ms.
        let engine = DialogueEngine::new(crate::config::Tcap::default());
        let (answer_tx, mut answer_rx) = tokio::sync::oneshot::channel();
        let invoke = cancel_location_for_test();
        let handler: std::sync::Arc<dyn TerminationHandler> =
            std::sync::Arc::new(crate::python::OriginationHandler {
                op: invoke.op,
                arg: invoke
                    .arg
                    .resolve(
                        &context_v3(gsm_map::application_context::location_cancellation_context)
                            .arcs,
                    )
                    .unwrap(),
                class: invoke.class,
                timeout: Some(Duration::from_millis(200)),
                responder: std::sync::Mutex::new(Some(answer_tx)),
            });
        let start = Instant::now();
        engine
            .begin(
                OutgoingBegin {
                    application_context: context_v3(
                        gsm_map::application_context::location_cancellation_context,
                    )
                    .arcs,
                    called: crate::python::gt_address("15550201", Some(7)),
                    calling: crate::python::gt_address("15550100", Some(6)),
                    opc: 1000,
                    dpc: 2000,
                    ni: 0,
                    sls: 0,
                    ingress_assoc: String::new(),
                },
                handler,
            )
            .unwrap();
        engine.sweep(start + Duration::from_millis(150));
        assert!(answer_rx.try_recv().is_err(), "nothing before the timer");
        engine.sweep(start + Duration::from_millis(260));
        let outcome = answer_rx.try_recv().expect("resolved at the timer");
        assert!(
            outcome.is_err(),
            "an unanswered class 1 operation is a failure"
        );
    }

    fn cancel_location_for_test() -> StagedInvoke {
        Python::initialize();
        Python::attach(|py| {
            cancel_location(
                &pyo3::types::PyString::new(py, "001010000000001").into_any(),
                "update-procedure",
            )
        })
        .unwrap()
    }
}
