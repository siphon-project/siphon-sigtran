//! The siphon addon face: a PyO3 surface that exposes the **same** SIGTRAN
//! routing brain and MAP/CAP dialogue engine the crate ships, as a scriptable
//! siphon node. It is a siphon addon, not a standalone package. No wheel, no
//! PyPI. It builds and is tested against siphon-sip, the way the sibling addons
//! `siphon-smpp` and `siphon-http` are.
//!
//! Compiled only with `--features python`; the default crate build pulls neither
//! pyo3 nor siphon. Two seams a composing siphon binary calls at startup: it
//! reads its `extensions.sigtran` config and calls [`configure_from`] to build
//! the process-wide node, and it calls [`register`] to mount the `ss7` /
//! `gsm_map` / `gsm_cap` / `inap` namespaces (plus the shared types) onto the `siphon` package module, so scripts import them with
//! `from siphon import ss7, gsm_map, gsm_cap, inap`.
//!
//! # The model
//!
//! One process-wide [`node`] holds the routing tables (a [`Router`], live via
//! `ss7.routes` / `ss7.gtt` / `ss7.content`) and the [`DialogueEngine`]. The
//! binary configures it ([`configure_from`]); the script then programs it.
//! [`configure`] is the in-process seam that rebuilds the node from a
//! `sigtran.yaml` for loopback tests (it returns a [`Node`] round-trip handle),
//! not a live-script entrypoint.
//!
//! * **Routing** stays in Rust at line rate. A script programs the routing tables
//!   live at load (`ss7.routes` / `ss7.gtt` / `ss7.content`); static content rules
//!   route, rewrite the called-party GT, or screen on the decoded MAP/CAP layer.
//! * **Termination** registers a Python handler for one or more MAP/CAP/INAP
//!   operations, named by their kebab-case operation names on a single
//!   per-namespace decorator (`@gsm_map.on_operation("mo-forward-sm")`,
//!   `@gsm_cap.on_operation("initial-dp")`, `@inap.on_operation("initial-dp")`),
//!   the same `on_<message>("<name>")` shape the sibling addons use
//!   (`@proxy.on_request`, `@smpp.on_pdu`). When a dialogue terminates, the
//!   handler drives a [`PyDialogue`] handle (`invoke` / `reply` / `send` /
//!   `end`). An `async def` handler runs to completion on an asyncio loop,
//!   mirroring how a handler runs on siphon's runtime.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyModule, PyModuleMethods, PyString, PyTuple};

use rasn::types::{OctetString, Oid};
use sccp::{GlobalTitle, SccpAddress, SccpMessage, SubsystemNumber, UnitData};
use tcap::dialogue::{DialoguePdu, DialoguePortion};
use tcap::{
    Begin, Component, Continue as TcapContinue, ErrorCode, Invoke, OperationCode, ReturnResult,
    ReturnResultValue, TcapMessage,
};

use tokio::sync::{mpsc, oneshot};

use siphon::script::ScriptHandle;

use crate::config::{from_yaml, Config, ContentRule, GttRule, DEFAULT_TENANT};
use crate::content::{ContentEngine, Operation};
use crate::dialogue::{
    CloseReason, Dialogue as CoreDialogue, DialogueClosed, DialogueEngine,
    IncomingOp as CoreIncomingOp, InvokeTimeout, OperationClass, OutgoingBegin, PeerAbort,
    PeerComponent, PeerTurn, Problem, TerminationHandler, UserAbort,
};
use crate::mtp3::route::Destination;
use crate::routing::Router;
use crate::transport::framing::{Msu, SI_SCCP};
use crate::transport::{Origination, TransportHandle};

mod cap;

// ── Error ────────────────────────────────────────────────────────────────────
create_exception!(
    siphon_sigtran,
    SigtranError,
    PyException,
    "siphon-sigtran configuration / SS7 protocol error."
);

create_exception!(
    siphon_sigtran,
    MistypedParameter,
    SigtranError,
    "The argument of an Invoke, or the parameter of a result or an error, does not \
     decode as the type its operation defines. A handler that lets it propagate \
     has the component rejected (Reject, mistyped parameter) and the dialogue \
     ended; one that catches it decides itself, with `dlg.reject(...)`."
);

/// A parameter that does not decode as the type its operation defines.
fn mistyped(what: &str, error: impl std::fmt::Display) -> PyErr {
    MistypedParameter::new_err(format!("{what} does not decode: {error}"))
}

fn err(msg: impl std::fmt::Display) -> PyErr {
    SigtranError::new_err(msg.to_string())
}

// ── Address arguments (digit string or raw bytes) ────────────────────────────
// The MAP/CAP builders take addresses as a digit string, encoded here with the
// published codecs (the same convention as `ss7.gt`), or as already-encoded
// bytes passed straight through (e.g. a value decoded off the wire).

/// An ISDN-AddressString / AddressString: a digit string encoded as an
/// international E.164 number, or raw bytes.
fn isdn_addr(v: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(s) = v.cast::<PyString>() {
        gsm_map::address::international_e164(&s.extract::<String>()?).map_err(err)
    } else {
        v.extract::<Vec<u8>>()
    }
}

/// An IMSI: a digit string (TBCD-encoded), or raw bytes.
fn imsi_arg(v: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(s) = v.cast::<PyString>() {
        gsm_map::address::imsi(&s.extract::<String>()?).map_err(err)
    } else {
        v.extract::<Vec<u8>>()
    }
}

/// A Q.763 Called Party Number: a digit string encoded as an international E.164
/// number, or raw bytes.
fn called_party(v: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(s) = v.cast::<PyString>() {
        inap::address::international_e164(&s.extract::<String>()?).map_err(err)
    } else {
        v.extract::<Vec<u8>>()
    }
}

/// Encode a MAP result struct to BER and stage it as a `ReturnResultLast` for
/// `dlg.reply(...)`, carrying the operation code.
fn staged_map_res<T: rasn::Encode>(op: i64, res: &T) -> PyResult<StagedResult> {
    let param = gsm_map::encode(res).map_err(err)?;
    Ok(StagedResult {
        op,
        param: Some(param),
    })
}

/// Encode a MAP argument struct to BER and stage it as an `Invoke` for
/// `dlg.invoke(...)`, carrying the operation code.
fn staged_map_invoke<T: rasn::Encode>(op: i64, arg: &T) -> PyResult<StagedInvoke> {
    let bytes = gsm_map::encode(arg).map_err(err)?;
    // Every MAP operation this namespace builds reports both its result and its
    // errors (TS 29.002 clause 7 and following: class 1).
    Ok(StagedInvoke::new(op, Some(bytes), OperationClass::One))
}

/// A UMTS/EPS authentication quintuplet as `(rand, xres, ck, ik, autn)` bytes.
type Quintuplet = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
/// A GSM authentication triplet as `(rand, sres, kc)` bytes.
type Triplet = (Vec<u8>, Vec<u8>, Vec<u8>);

// ── Node state ───────────────────────────────────────────────────────────────

/// Everything a scriptable node owns: the routing tables and the termination
/// engine. Interior-mutable so the `ss7` / `gsm_map` / `gsm_cap` / `inap`
/// namespace singletons can all drive one node.
struct NodeState {
    router: Mutex<Router>,
    engine: Mutex<DialogueEngine>,
    tenant: String,
    /// The subsystems we own; a termination decorator registers on each.
    local_ssns: Vec<u8>,
}

impl NodeState {
    fn from_config(cfg: &Config) -> Self {
        let local_ssns = cfg
            .default_tenant()
            .map(|t| t.sccp.local_ssns.clone())
            .unwrap_or_default();
        NodeState {
            router: Mutex::new(Router::new(cfg)),
            engine: Mutex::new(DialogueEngine::new(cfg.tcap.clone())),
            tenant: DEFAULT_TENANT.to_string(),
            local_ssns,
        }
    }

    /// A minimal empty node (PC 1, ITU, no tables) so the namespaces work before
    /// `configure`. A script that needs real routing calls `configure` first.
    fn default_node() -> Self {
        let cfg = Config::parse("node: { point_code: 1, variant: ITU }\nassociations: []")
            .expect("the built-in empty config parses");
        Self::from_config(&cfg)
    }
}

/// The process-wide node. `configure` swaps it; the namespaces read the current
/// one on each call.
static NODE: OnceLock<Mutex<Arc<NodeState>>> = OnceLock::new();

fn node() -> Arc<NodeState> {
    NODE.get_or_init(|| Mutex::new(Arc::new(NodeState::default_node())))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn set_node(state: Arc<NodeState>) {
    let cell = NODE.get_or_init(|| Mutex::new(Arc::new(NodeState::default_node())));
    *cell.lock().unwrap_or_else(|e| e.into_inner()) = state;
}

fn lock_router(n: &NodeState) -> std::sync::MutexGuard<'_, Router> {
    n.router.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Config source coercion ───────────────────────────────────────────────────

/// Build a `Config` from a Python source: a path to a `sigtran.yaml`, an inline
/// YAML string, or a dict mirroring the file schema.
fn config_from_source(source: &Bound<'_, PyAny>) -> PyResult<Config> {
    if let Ok(s) = source.extract::<String>() {
        // A filesystem path takes precedence; otherwise treat the string as
        // inline YAML.
        if std::path::Path::new(&s).is_file() {
            return Config::load(&s).map_err(err);
        }
        return Config::parse(&s).map_err(err);
    }
    // A dict (or any object): render it as YAML and parse that, so a dict and
    // a file go through the one schema and the one parser.
    let mut text = String::new();
    py_to_yaml(source, &mut text)?;
    Config::parse(&text).map_err(err)
}

/// Render a Python value (dict / list / scalar) as YAML flow text (the JSON
/// subset of YAML) so the typed config deserialiser validates it: one schema,
/// no hand-mapping. A Python `str` is always written double-quoted, so it stays
/// a string whatever it spells (`"001"`, `"true"`, `"1e3"`).
fn py_to_yaml(obj: &Bound<'_, PyAny>, out: &mut String) -> PyResult<()> {
    use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
    use std::fmt::Write as _;

    if obj.is_none() {
        out.push_str("null");
    } else if let Ok(b) = obj.cast::<PyBool>() {
        out.push_str(if b.is_true() { "true" } else { "false" });
    } else if let Ok(s) = obj.cast::<PyString>() {
        push_yaml_str(&s.extract::<String>()?, out);
    } else if let Ok(i) = obj.cast::<PyInt>() {
        let _ = write!(out, "{}", i.extract::<i64>()?);
    } else if let Ok(f) = obj.cast::<PyFloat>() {
        let f = f.extract::<f64>()?;
        if f.is_nan() {
            out.push_str(".nan");
        } else if f.is_infinite() {
            out.push_str(if f > 0.0 { ".inf" } else { "-.inf" });
        } else {
            // `{:?}` keeps a fractional part (`2905.0`), so a float stays a float.
            let _ = write!(out, "{f:?}");
        }
    } else if let Ok(list) = obj.cast::<PyList>() {
        out.push('[');
        for (index, item) in list.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            py_to_yaml(&item, out)?;
        }
        out.push(']');
    } else if let Ok(dict) = obj.cast::<PyDict>() {
        out.push('{');
        for (index, (k, v)) in dict.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            push_yaml_str(&k.str()?.extract::<String>()?, out);
            out.push_str(": ");
            py_to_yaml(&v, out)?;
        }
        out.push('}');
    } else {
        return Err(err(format!(
            "cannot convert {} to a config value",
            obj.get_type().name()?
        )));
    }
    Ok(())
}

/// Write `s` as a YAML double-quoted scalar: `"` and `\` escaped, and every
/// character YAML does not allow raw (C0/C1 controls, DEL, the BOM, the line
/// and paragraph separators, all in the BMP) as a `\uXXXX` escape.
fn push_yaml_str(s: &str, out: &mut String) {
    use std::fmt::Write as _;

    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || matches!(c, '\u{feff}' | '\u{2028}' | '\u{2029}') => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ── Global titles / addresses ────────────────────────────────────────────────

/// An SCCP address a script builds with `ss7.gt(digits, ssn=…)` and hands to an
/// originating helper as a destination.
#[pyclass(name = "Address", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct Address {
    inner: SccpAddress,
}

#[pymethods]
impl Address {
    /// The global-title digits, if the address routes on GT.
    #[getter]
    fn digits(&self) -> Option<String> {
        self.inner.global_title.digits().map(str::to_string)
    }

    /// The subsystem number, if set.
    #[getter]
    fn ssn(&self) -> Option<u8> {
        self.inner.ssn.map(|s| s.value())
    }

    fn __repr__(&self) -> String {
        format!(
            "Address(gt={:?}, ssn={:?})",
            self.inner.global_title.digits(),
            self.inner.ssn.map(|s| s.value())
        )
    }
}

/// Build an E.164 GTI-4 SCCP address from decimal digits (`ss7.gt`).
fn gt_address(digits: &str, ssn: Option<u8>) -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    };
    SccpAddress::with_gt(gt, ssn.map(SubsystemNumber::from_u8))
}

// ── Staged components ────────────────────────────────────────────────────────

/// A staged `Invoke` produced by an originating helper (`gsm_map.mt_forward_sm`,
/// `gsm_cap.connect`, …), consumed by `dlg.invoke(...)`.
#[pyclass(name = "Invoke", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct StagedInvoke {
    op: i64,
    arg: InvokeArg,
    /// The operation class (Q.774 Table 2), known to the builder: it decides
    /// which replies are valid and what the expiry of the invocation timer
    /// means.
    class: OperationClass,
}

impl StagedInvoke {
    fn new(op: i64, arg: Option<Vec<u8>>, class: OperationClass) -> Self {
        let arg = arg.map_or(InvokeArg::None, InvokeArg::Encoded);
        Self { op, arg, class }
    }

    /// An invoke whose argument is encoded when the dialogue it is sent in is
    /// known.
    fn per_context(op: i64, arg: ContextualArg, class: OperationClass) -> Self {
        Self {
            op,
            arg: InvokeArg::PerContext(arg),
            class,
        }
    }
}

/// The argument of a staged invoke.
#[derive(Clone)]
enum InvokeArg {
    /// The operation has no argument.
    None,
    /// The BER encoding of the argument.
    Encoded(Vec<u8>),
    /// An argument whose encoding depends on the application context of the
    /// dialogue: it is encoded when the invoke is staged on one.
    PerContext(ContextualArg),
}

impl InvokeArg {
    /// The encoded argument for a dialogue under application context `ac`.
    fn resolve(&self, ac: &[u32]) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::None => Ok(None),
            Self::Encoded(bytes) => Ok(Some(bytes.clone())),
            Self::PerContext(arg) => arg.encode(ac).map(Some),
        }
    }
}

/// An invoke argument that is not the same on the wire under every application
/// context.
#[derive(Clone)]
enum ContextualArg {
    /// CAP ApplyCharging with time-duration charging. TS 29.078 changed member
    /// `[3]` of the `timeDurationCharging` inside
    /// CAMEL-AChBillingChargingCharacteristics between phase 3 (`tone [3]
    /// BOOLEAN`) and phase 4 (`audibleIndicator [3]`, an explicit CHOICE): the
    /// two are different octets, and a gsmSSF reads the one of the phase its
    /// dialogue runs under.
    CapApplyCharging {
        max_call_period_duration: u32,
        release_if_duration_exceeded: Option<bool>,
        tariff_switch_interval: Option<u32>,
        tone: Option<bool>,
        party_to_charge: Option<u8>,
    },
}

/// The CAMEL phase of a CAP application context, for the phases whose types
/// `gsm_cap` models: 3 or 4.
fn cap_phase(ac: &[u32]) -> Option<u8> {
    use gsm_cap::application_context as c;
    let phase3 = [
        c::CAP_V3_GSMSSF_SCF_GENERIC,
        c::CAP_V3_GSMSSF_SCF_ASSIST_HANDOFF,
        c::CAP_V3_GSMSRF_GSMSCF,
    ];
    let phase4 = [
        c::CAP_V4_GSMSSF_SCF_GENERIC,
        c::CAP_V4_GSMSSF_SCF_ASSIST_HANDOFF,
        c::CAP_V4_SCF_GSMSSF_GENERIC,
        c::CAP_V4_GSMSRF_GSMSCF,
    ];
    if phase3.iter().any(|known| known[..] == *ac) {
        Some(3)
    } else if phase4.iter().any(|known| known[..] == *ac) {
        Some(4)
    } else {
        None
    }
}

impl ContextualArg {
    fn encode(&self, ac: &[u32]) -> Result<Vec<u8>, String> {
        match self {
            Self::CapApplyCharging { .. } => {
                let phase = cap_phase(ac).ok_or_else(|| {
                    format!(
                        "apply_charging: the dialogue's application context {ac:?} is not a CAP \
                         phase 3 or phase 4 call-control context, so the charging characteristics \
                         cannot be chosen for it; pass phase= or charging_characteristics="
                    )
                })?;
                self.encode_for_phase(phase)
            }
        }
    }

    /// The encoding for an explicit CAMEL phase, 3 or 4.
    fn encode_for_phase(&self, phase: u8) -> Result<Vec<u8>, String> {
        use gsm_cap::operations::ApplyChargingArg;
        use gsm_cap::types::{
            AudibleIndicator, CamelAChBillingChargingCharacteristics as V4,
            CamelAChBillingChargingCharacteristicsV3 as V3, SendingSideId, TimeDurationCharging,
            TimeDurationChargingV3,
        };
        let Self::CapApplyCharging {
            max_call_period_duration,
            release_if_duration_exceeded,
            tariff_switch_interval,
            tone,
            party_to_charge,
        } = self;
        let arg = match phase {
            3 => {
                let mut charging = TimeDurationChargingV3::new(*max_call_period_duration);
                charging.release_if_duration_exceeded = *release_if_duration_exceeded;
                charging.tariff_switch_interval = *tariff_switch_interval;
                charging.tone = *tone;
                ApplyChargingArg::with_characteristics(&V3::TimeDurationCharging(charging))
            }
            4 => {
                let mut charging = TimeDurationCharging::new(*max_call_period_duration);
                charging.release_if_duration_exceeded = *release_if_duration_exceeded;
                charging.tariff_switch_interval = *tariff_switch_interval;
                charging.audible_indicator = tone.map(AudibleIndicator::Tone);
                ApplyChargingArg::with_characteristics(&V4::TimeDurationCharging(charging))
            }
            other => return Err(format!("apply_charging: CAMEL phase {other} is not 3 or 4")),
        };
        let mut arg = arg.map_err(|e| e.to_string())?;
        arg.party_to_charge = party_to_charge.map(SendingSideId::leg);
        gsm_cap::encode(&arg).map_err(|e| e.to_string())
    }
}

#[pymethods]
impl StagedInvoke {
    /// The local operation code.
    #[getter]
    fn operation_code(&self) -> i64 {
        self.op
    }

    /// The operation class, 1 to 4 (Q.774 Table 2): 1 reports success and
    /// failure, 2 failure only, 3 success only, 4 nothing.
    #[getter]
    fn operation_class(&self) -> u8 {
        self.class.number()
    }

    fn __repr__(&self) -> String {
        format!(
            "Invoke(operation_code={}, operation_class={})",
            self.op,
            self.class.number()
        )
    }
}

/// A staged `ReturnResult` produced by a result helper
/// (`gsm_map.mo_forward_sm_res`, …), consumed by `dlg.reply(...)`.
#[pyclass(name = "Result", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct StagedResult {
    op: i64,
    param: Option<Vec<u8>>,
}

// ── The decoded incoming operation handed to a termination handler ───────────

/// The decoded opening operation a termination handler receives as its second
/// argument (`arg` / `idp`). The raw BER argument is always available; common
/// MAP/CAP fields are decoded where recognised.
#[pyclass(name = "IncomingOp", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct PyIncomingOp {
    #[pyo3(get)]
    operation_code: i64,
    #[pyo3(get)]
    invoke_id: i64,
    #[pyo3(get)]
    calling_gt: Option<String>,
    #[pyo3(get)]
    called_gt: Option<String>,
    argument: Option<Vec<u8>>,
    further: Vec<PeerComp>,
}

#[pymethods]
impl PyIncomingOp {
    /// Every other component of the Begin, in the order received, as
    /// [`Component`](PyComponent) objects: further Invokes, or a
    /// `local-reject` for a component this node could not read. Empty for the
    /// usual Begin with a single Invoke.
    #[getter]
    fn further(&self) -> Vec<PyComponent> {
        self.further.iter().cloned().map(PyComponent).collect()
    }

    /// The raw BER argument bytes, if the Invoke carried a parameter.
    #[getter]
    fn argument<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.argument.as_ref().map(|a| PyBytes::new(py, a))
    }

    /// The originating SMS address (`SM-RP-OA`) of a MO/MT-ForwardSM. `None`
    /// for another operation, or when the argument says there is none. Raises
    /// `MistypedParameter` when the argument does not decode.
    #[getter]
    fn sm_rp_oa<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.decode_mo_field(py, MoField::Oa)
    }

    /// The destination SMS address (`SM-RP-DA`) of a MO/MT-ForwardSM. As
    /// `sm_rp_oa`.
    #[getter]
    fn sm_rp_da<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.decode_mo_field(py, MoField::Da)
    }

    /// The SMS TPDU (`SM-RP-UI`) of a MO/MT-ForwardSM. As `sm_rp_oa`.
    #[getter]
    fn sm_rp_ui<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.decode_mo_field(py, MoField::Ui)
    }

    /// The `calledPartyNumber` of a CAMEL initialDP: the dialled number of a
    /// forwarded or terminating call. `None` when the argument carries none
    /// (a mobile-originated call carries `called_party_bcd_number` instead), or
    /// for another operation. Raises `MistypedParameter` when the argument
    /// does not decode as a CAP InitialDPArg.
    #[getter]
    fn called_party_number<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self
            .cap_initial_dp()?
            .and_then(|idp| idp.called_party_number)
            .map(|n| PyBytes::new(py, n.as_ref())))
    }

    /// The `calledPartyBCDNumber` of a CAMEL initialDP: what the subscriber
    /// dialled on a mobile-originated call (type of number, numbering plan,
    /// then TBCD digits). As `called_party_number`.
    #[getter]
    fn called_party_bcd_number<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self
            .cap_initial_dp()?
            .and_then(|idp| idp.called_party_bcd_number)
            .map(|n| PyBytes::new(py, n.as_ref())))
    }

    /// The `serviceKey` of a CAMEL initialDP. As `called_party_number`.
    #[getter]
    fn service_key(&self) -> PyResult<Option<i64>> {
        let Some(idp) = self.cap_initial_dp()? else {
            return Ok(None);
        };
        i64::try_from(&idp.service_key)
            .map(Some)
            .map_err(|_| mistyped("the InitialDP serviceKey", "it does not fit an integer"))
    }

    // The rest of a CAMEL initialDP. Each getter is `None` for another
    // operation or an absent member, and raises `MistypedParameter` when the
    // argument does not decode, as the three above do.

    /// The `iMSI` of a CAMEL initialDP, as its digits.
    #[getter]
    fn imsi(&self) -> PyResult<Option<String>> {
        cap::imsi(self)
    }

    /// The `callingPartyNumber` of a CAMEL initialDP: the octets of a Q.763
    /// calling party number.
    #[getter]
    fn calling_party_number<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        cap::calling_party_number(py, self)
    }

    /// The `callingPartysCategory` of a CAMEL initialDP (Q.763): 10 is an
    /// ordinary subscriber.
    #[getter]
    fn calling_partys_category(&self) -> PyResult<Option<u8>> {
        cap::calling_partys_category(self)
    }

    /// The `eventTypeBCSM` of a CAMEL initialDP, the detection point that
    /// triggered: 2 collectedInfo (an originating call), 12
    /// termAttemptAuthorized (a terminating one), ...
    #[getter]
    fn event_type_bcsm(&self) -> PyResult<Option<i64>> {
        cap::event_type_bcsm(self)
    }

    /// The `subscriberState` of a CAMEL initialDP: `assumed-idle`,
    /// `camel-busy`, `net-det-not-reachable` or `not-provided-from-vlr`.
    #[getter]
    fn subscriber_state(&self) -> PyResult<Option<&'static str>> {
        cap::subscriber_state(self)
    }

    /// Why the subscriber is `net-det-not-reachable`: `ms-purged`,
    /// `imsi-detached`, `restricted-area` or `not-registered`.
    #[getter]
    fn not_reachable_reason(&self) -> PyResult<Option<&'static str>> {
        cap::not_reachable_reason(self)
    }

    /// The `locationInformation` of a CAMEL initialDP, as a
    /// [`LocationInformation`](cap::PyLocationInformation).
    #[getter]
    fn location_information(&self) -> PyResult<Option<cap::PyLocationInformation>> {
        cap::location_information(self)
    }

    /// The `ext-basicServiceCode` of a CAMEL initialDP as `(kind, octets)`,
    /// `kind` being `bearer-service` or `teleservice`.
    #[getter]
    fn ext_basic_service_code<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<(&'static str, Bound<'py, PyBytes>)>> {
        cap::ext_basic_service_code(py, self)
    }

    /// The `callReferenceNumber` of a CAMEL initialDP. With `msc_address` it
    /// identifies the call.
    #[getter]
    fn call_reference_number<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        cap::call_reference_number(py, self)
    }

    /// The `mscAddress` of a CAMEL initialDP, as its digits.
    #[getter]
    fn msc_address(&self) -> PyResult<Option<String>> {
        cap::msc_address(self)
    }

    /// The `timeAndTimezone` of a CAMEL initialDP: eight octets, the date and
    /// time in BCD with swapped nibbles, then the time zone.
    #[getter]
    fn time_and_timezone<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        cap::time_and_timezone(py, self)
    }

    /// Whether a CAMEL initialDP carries `callForwardingSS-Pending`: the call
    /// is about to be forwarded by a supplementary service.
    #[getter]
    fn call_forwarding_ss_pending(&self) -> PyResult<bool> {
        cap::call_forwarding_ss_pending(self)
    }

    /// The `originalCalledPartyID` of a CAMEL initialDP for a forwarded call:
    /// the octets of a Q.763 original called number.
    #[getter]
    fn original_called_party_id<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        cap::original_called_party_id(py, self)
    }

    /// The `redirectingPartyID` of a CAMEL initialDP for a forwarded call: the
    /// octets of a Q.763 redirecting number.
    #[getter]
    fn redirecting_party_id<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        cap::redirecting_party_id(py, self)
    }

    /// The `redirectionInformation` of a CAMEL initialDP: two octets (Q.763).
    #[getter]
    fn redirection_information<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        cap::redirection_information(py, self)
    }

    /// The `gmscAddress` of a CAMEL initialDP for a terminating or forwarded
    /// call (in `initialDPArgExtension`), as its digits.
    #[getter]
    fn gmsc_address(&self) -> PyResult<Option<String>> {
        cap::gmsc_address(self)
    }

    /// The `serviceKey` of an INAP CS-1 initialDP: the IN service logic the SSF
    /// triggered on (an `@inap.on_operation("initial-dp")` handler keys its
    /// service selection on it). `None` for another operation. Raises
    /// `MistypedParameter` when the argument does not decode as an INAP
    /// InitialDPArg, or the key does not fit an integer.
    #[getter]
    fn inap_service_key(&self) -> PyResult<Option<i64>> {
        let Some(idp) = self.inap_initial_dp()? else {
            return Ok(None);
        };
        i64::try_from(&idp.service_key)
            .map(Some)
            .map_err(|_| mistyped("the InitialDP serviceKey", "it does not fit an integer"))
    }

    /// The `calledPartyNumber` of an INAP CS-1 initialDP (the fixed-network
    /// dialled digits, distinct from the CAMEL initialDP the
    /// [`called_party_number`](Self::called_party_number) getter decodes).
    /// `None` when the argument carries none, or for another operation; raises
    /// `MistypedParameter` when the argument does not decode.
    #[getter]
    fn inap_called_party_number<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self
            .inap_initial_dp()?
            .and_then(|idp| idp.called_party_number)
            .map(|n| PyBytes::new(py, n.as_ref())))
    }

    /// The `callingPartyNumber` of an INAP CS-1 initialDP. As
    /// `inap_called_party_number`.
    #[getter]
    fn inap_calling_party_number<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self
            .inap_initial_dp()?
            .and_then(|idp| idp.calling_party_number)
            .map(|n| PyBytes::new(py, n.as_ref())))
    }

    /// Always false: an opening-leg view. A held-open handler that is re-entered
    /// on a follow-up leg receives a [`PeerTurn`](PyPeerTurn) instead, whose
    /// `is_peer_turn` is true, so one handler can tell the two legs apart.
    #[getter]
    fn is_peer_turn(&self) -> bool {
        false
    }

    fn __repr__(&self) -> String {
        format!(
            "IncomingOp(operation_code={}, invoke_id={}, calling_gt={:?}, called_gt={:?})",
            self.operation_code, self.invoke_id, self.calling_gt, self.called_gt
        )
    }
}

// ── The decoded peer turn handed to a follow-up-leg handler ──────────────────

/// One decoded component of a peer's turn.
#[derive(Clone)]
struct PeerComp {
    kind: &'static str,
    operation_code: Option<i64>,
    /// `None` only for a Reject whose invoke id could not be derived.
    invoke_id: Option<i64>,
    parameter: Option<Vec<u8>>,
    error_code: Option<i64>,
    problem: Option<Problem>,
}

impl PeerComp {
    fn from_core(c: &PeerComponent) -> Self {
        let blank = PeerComp {
            kind: "",
            operation_code: None,
            invoke_id: None,
            parameter: None,
            error_code: None,
            problem: None,
        };
        match c {
            PeerComponent::Invoke {
                invoke_id,
                operation_code,
                argument,
            } => PeerComp {
                kind: "invoke",
                operation_code: Some(*operation_code),
                invoke_id: Some(i64::from(*invoke_id)),
                parameter: argument.clone(),
                ..blank
            },
            PeerComponent::Result {
                invoke_id,
                operation_code,
                parameter,
            } => PeerComp {
                kind: "result",
                operation_code: *operation_code,
                invoke_id: Some(i64::from(*invoke_id)),
                parameter: parameter.clone(),
                ..blank
            },
            PeerComponent::Error {
                invoke_id,
                error_code,
            } => PeerComp {
                kind: "error",
                invoke_id: Some(i64::from(*invoke_id)),
                error_code: Some(*error_code),
                ..blank
            },
            PeerComponent::Reject { invoke_id, problem } => PeerComp {
                kind: "reject",
                invoke_id: invoke_id.map(i64::from),
                problem: Some(*problem),
                ..blank
            },
            PeerComponent::LocalReject { invoke_id, problem } => PeerComp {
                kind: "local-reject",
                invoke_id: invoke_id.map(i64::from),
                problem: Some(*problem),
                ..blank
            },
        }
    }
}

/// The class of a Reject problem as the Python layer names it, and its code.
fn problem_parts(problem: &Problem) -> (&'static str, i64, Option<&'static str>) {
    match problem {
        Problem::General(p) => ("general", p.value(), p.name()),
        Problem::Invoke(p) => ("invoke", p.value(), p.name()),
        Problem::ReturnResult(p) => ("return-result", p.value(), p.name()),
        Problem::ReturnError(p) => ("return-error", p.value(), p.name()),
    }
}

/// Build a Reject problem from the Python-facing class name and code.
fn problem_from_parts(class: &str, code: i64) -> PyResult<Problem> {
    Ok(match class {
        "general" => Problem::General(code.into()),
        "invoke" => Problem::Invoke(code.into()),
        "return-result" => Problem::ReturnResult(code.into()),
        "return-error" => Problem::ReturnError(code.into()),
        other => {
            return Err(err(format!(
                "unknown reject problem class `{other}` \
                 (general / invoke / return-result / return-error)"
            )))
        }
    })
}

/// One component of a peer's turn, as `turn.components` / `op.further` list it.
#[pyclass(name = "Component", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct PyComponent(PeerComp);

#[pymethods]
impl PyComponent {
    /// `invoke`, `result`, `error`, `reject` (the peer rejected one of our
    /// components) or `local-reject` (this node rejected one of the peer's: the
    /// Reject leaves with the next `send()` / `end()`).
    #[getter]
    fn kind(&self) -> &'static str {
        self.0.kind
    }

    /// The invoke id. `None` only for a reject whose invoke id could not be
    /// derived.
    #[getter]
    fn invoke_id(&self) -> Option<i64> {
        self.0.invoke_id
    }

    /// The operation code of an invoke, or the one a result echoes.
    #[getter]
    fn operation_code(&self) -> Option<i64> {
        self.0.operation_code
    }

    /// The raw BER argument of an invoke or parameter of a result.
    #[getter]
    fn parameter<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.parameter.as_ref().map(|p| PyBytes::new(py, p))
    }

    /// A CAMEL EventReportBCSM, decoded, when this component is an Invoke of
    /// it (operation 24); `None` for any other component. Raises
    /// `MistypedParameter` when the argument does not decode.
    #[getter]
    fn event_report_bcsm(&self, py: Python<'_>) -> PyResult<Option<cap::PyEventReportBcsm>> {
        cap::event_report_bcsm(py, &self.0)
    }

    /// A CAMEL ApplyChargingReport, decoded, when this component is an Invoke
    /// of it (operation 36). As `event_report_bcsm`.
    #[getter]
    fn apply_charging_report(
        &self,
        py: Python<'_>,
    ) -> PyResult<Option<cap::PyApplyChargingReport>> {
        cap::apply_charging_report(py, &self.0)
    }

    /// The error code of an error.
    #[getter]
    fn error_code(&self) -> Option<i64> {
        self.0.error_code
    }

    /// The problem class of a reject: `general`, `invoke`, `return-result` or
    /// `return-error`.
    #[getter]
    fn problem_class(&self) -> Option<&'static str> {
        self.0.problem.as_ref().map(|p| problem_parts(p).0)
    }

    /// The problem code of a reject within its class (Q.773 Tables 26 to 29).
    #[getter]
    fn problem_code(&self) -> Option<i64> {
        self.0.problem.as_ref().map(|p| problem_parts(p).1)
    }

    /// The name Q.773 gives the problem (`mistypedParameter`, ...), or `None`
    /// for a code it does not name.
    #[getter]
    fn problem_name(&self) -> Option<&'static str> {
        self.0.problem.as_ref().and_then(|p| problem_parts(p).2)
    }

    fn __repr__(&self) -> String {
        match &self.0.problem {
            Some(p) => {
                let (class, code, _) = problem_parts(p);
                format!(
                    "Component(kind={}, invoke_id={:?}, problem={class}:{code})",
                    self.0.kind, self.0.invoke_id
                )
            }
            None => format!(
                "Component(kind={}, invoke_id={:?}, operation_code={:?})",
                self.0.kind, self.0.invoke_id, self.0.operation_code
            ),
        }
    }
}

/// How a dialogue ended abnormally, or which invocation timer expired, when a
/// [`PeerTurn`](PyPeerTurn) carries that instead of components.
#[derive(Clone, Default)]
struct TurnEvent {
    /// `peer-abort`, `provider-abort`, `abnormal-dialogue`, `invoke-timeout`,
    /// `idle-timeout`, `no-answer` or `not-sent`.
    closed: Option<&'static str>,
    /// `p-abort` or `u-abort`, for an Abort (received or sent).
    abort_kind: Option<&'static str>,
    /// The P-Abort cause value, for a P-Abort.
    p_abort_cause: Option<i64>,
    /// A fixed label for what the abort carried.
    abort_cause: Option<&'static str>,
    /// The invoke whose timer expired: `(invoke_id, operation_code, class)`.
    timeout: Option<(i64, i64, u8)>,
}

fn p_abort_label(value: i64) -> &'static str {
    crate::metrics::AbortCause::from_p_abort(value).label()
}

impl TurnEvent {
    /// The event for an abnormal end, or `None` for an end the script already
    /// knows of (it ended or aborted the dialogue itself, or was handed the
    /// peer's End as a turn).
    fn from_closed(reason: &CloseReason) -> Option<Self> {
        let mut e = TurnEvent::default();
        match reason {
            CloseReason::PeerAbort(abort) => {
                e.closed = Some("peer-abort");
                match abort {
                    PeerAbort::Provider(cause) => {
                        e.abort_kind = Some("p-abort");
                        e.p_abort_cause = Some(cause.value());
                        e.abort_cause = Some(p_abort_label(cause.value()));
                    }
                    PeerAbort::AbnormalDialogue => {
                        e.abort_kind = Some("u-abort");
                        e.abort_cause = Some("abnormal-dialogue");
                    }
                    PeerAbort::NoCommonDialoguePortion => {
                        e.abort_kind = Some("u-abort");
                        e.abort_cause = Some("no-common-dialogue-portion");
                    }
                    PeerAbort::User(user) => {
                        e.abort_kind = Some("u-abort");
                        e.abort_cause = Some(match user {
                            UserAbort::NoInformation => "none",
                            UserAbort::DialogueServiceUser => "dialogue-service-user",
                            UserAbort::ApplicationContextNotSupported => {
                                "application-context-not-supported"
                            }
                            UserAbort::DialogueRefused => "dialogue-refused",
                            UserAbort::UserDefined => "user-defined",
                        });
                    }
                }
            }
            CloseReason::ProviderAbort { cause, sent } => {
                e.closed = Some("provider-abort");
                e.abort_kind = sent.then_some("p-abort");
                e.p_abort_cause = Some(cause.value());
                e.abort_cause = Some(p_abort_label(cause.value()));
            }
            CloseReason::AbnormalDialogue { sent } => {
                e.closed = Some("abnormal-dialogue");
                e.abort_kind = sent.then_some("u-abort");
                e.abort_cause = Some("abnormal-dialogue");
            }
            CloseReason::InvokeTimeout {
                invoke_id,
                operation_code,
            } => {
                e.closed = Some("invoke-timeout");
                e.abort_kind = Some("u-abort");
                e.timeout = Some((i64::from(*invoke_id), *operation_code, 1));
            }
            CloseReason::IdleTimeout => {
                e.closed = Some("idle-timeout");
                e.abort_kind = Some("u-abort");
            }
            CloseReason::NoAnswer => {
                e.closed = Some("no-answer");
                e.abort_kind = Some("u-abort");
            }
            CloseReason::NotSent => e.closed = Some("not-sent"),
            CloseReason::Ended | CloseReason::PeerEnded | CloseReason::Aborted => return None,
        }
        Some(e)
    }

    fn from_timeout(t: &InvokeTimeout) -> Self {
        TurnEvent {
            timeout: Some((i64::from(t.invoke_id), t.operation_code, t.class.number())),
            ..TurnEvent::default()
        }
    }

    fn describe(&self) -> String {
        let mut text = self.closed.unwrap_or("invoke timer expired").to_string();
        if let Some(kind) = self.abort_kind {
            text.push_str(&format!(" ({kind}"));
            if let Some(cause) = self.abort_cause {
                text.push_str(&format!(", {cause}"));
            }
            text.push(')');
        }
        text
    }
}

/// The decoded peer view a termination handler receives on a follow-up leg of a
/// held-open dialogue (the peer's `Continue` or `End`). It carries the peer's
/// operation code and the decoded result / invoke / error, so a script can, for
/// example, observe an insertSubscriberData `returnResultLast` and then finish
/// the updateLocation with its own result. The opening leg gets an
/// [`IncomingOp`](PyIncomingOp) instead; branch on `is_peer_turn`.
///
/// The same object tells the handler of two things that are not a message from
/// the peer: an invocation timer that expired (`is_timeout`), and a dialogue
/// that ended without the script ending it (`closed`: the peer aborted, a
/// damaged message arrived, the dialogue sat idle).
#[pyclass(name = "PeerTurn", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct PyPeerTurn {
    is_end: bool,
    comps: Vec<PeerComp>,
    event: TurnEvent,
    /// What to reject if the script finds a parameter of this turn mistyped:
    /// its first component that has one.
    rejection: Option<(Option<i8>, Problem)>,
}

impl PyPeerTurn {
    fn from_peer(peer: &PeerTurn) -> Self {
        PyPeerTurn {
            is_end: peer.is_end,
            comps: peer.components.iter().map(PeerComp::from_core).collect(),
            event: TurnEvent::default(),
            rejection: peer
                .components
                .iter()
                .find_map(PeerComponent::mistyped_parameter),
        }
    }

    fn from_event(event: TurnEvent) -> Self {
        PyPeerTurn {
            // A dialogue that ended is closed to the script either way.
            is_end: event.closed.is_some(),
            comps: Vec::new(),
            event,
            rejection: None,
        }
    }

    fn first(&self) -> Option<&PeerComp> {
        self.comps.first()
    }

    fn first_of(&self, kind: &str) -> Option<&PeerComp> {
        self.comps.iter().find(|c| c.kind == kind)
    }

    fn first_reject(&self) -> Option<&PeerComp> {
        self.first_of("reject")
            .or_else(|| self.first_of("local-reject"))
    }
}

#[pymethods]
impl PyPeerTurn {
    /// Always true: distinguishes a follow-up-leg view from the opening
    /// [`IncomingOp`](PyIncomingOp) a handler gets on the first leg.
    #[getter]
    fn is_peer_turn(&self) -> bool {
        true
    }

    /// Whether the dialogue is over: this turn arrived in a TCAP `End` (the peer
    /// closed the dialogue), or reports that it ended (`closed`).
    #[getter]
    fn is_end(&self) -> bool {
        self.is_end
    }

    /// Every component of the turn, in the order received.
    #[getter]
    fn components(&self) -> Vec<PyComponent> {
        self.comps.iter().cloned().map(PyComponent).collect()
    }

    /// The operation code of the first component: a `returnResultLast` echoes the
    /// operation it answers, an `Invoke` carries its own. `None` if absent.
    #[getter]
    fn operation_code(&self) -> Option<i64> {
        self.first()
            .and_then(|c| c.operation_code)
            .or(self.event.timeout.map(|t| t.1))
    }

    /// The invoke id of the first component, if any (for `is_timeout`, the
    /// invoke whose timer expired).
    #[getter]
    fn invoke_id(&self) -> Option<i64> {
        self.first()
            .and_then(|c| c.invoke_id)
            .or(self.event.timeout.map(|t| t.0))
    }

    /// Whether the peer answered one of our invokes with a `returnResultLast`.
    #[getter]
    fn is_result(&self) -> bool {
        self.first_of("result").is_some()
    }

    /// Whether the peer sent us an `Invoke` inside the open dialogue.
    #[getter]
    fn is_invoke(&self) -> bool {
        self.first_of("invoke").is_some()
    }

    /// Whether the peer rejected one of our invokes with a `returnError`.
    #[getter]
    fn is_error(&self) -> bool {
        self.first_of("error").is_some()
    }

    /// The MAP/CAP error code, if the peer sent a `returnError`.
    #[getter]
    fn error_code(&self) -> Option<i64> {
        self.first_of("error").and_then(|c| c.error_code)
    }

    /// Whether the turn carries a Reject: one the peer sent for a component of
    /// ours, or one this node raised for a component of the peer's (see
    /// `reject_is_local`). A Reject is a protocol error, not a MAP/CAP error:
    /// `is_error` stays false.
    #[getter]
    fn is_reject(&self) -> bool {
        self.first_reject().is_some()
    }

    /// Whether the first Reject was raised here, for a component of the peer's
    /// that could not be read or did not fit the dialogue. It is sent to the
    /// peer with the next `send()` / `end()`.
    #[getter]
    fn reject_is_local(&self) -> bool {
        self.first_reject()
            .is_some_and(|c| c.kind == "local-reject")
    }

    /// The invoke id the first Reject names, or `None` when there is no Reject
    /// or its invoke id could not be derived.
    #[getter]
    fn reject_invoke_id(&self) -> Option<i64> {
        self.first_reject().and_then(|c| c.invoke_id)
    }

    /// The problem class of the first Reject: `general`, `invoke`,
    /// `return-result` or `return-error`.
    #[getter]
    fn reject_problem_class(&self) -> Option<&'static str> {
        self.first_reject()
            .and_then(|c| c.problem.as_ref())
            .map(|p| problem_parts(p).0)
    }

    /// The problem code of the first Reject within its class.
    #[getter]
    fn reject_problem_code(&self) -> Option<i64> {
        self.first_reject()
            .and_then(|c| c.problem.as_ref())
            .map(|p| problem_parts(p).1)
    }

    /// The name Q.773 gives the first Reject's problem, if it names it.
    #[getter]
    fn reject_problem_name(&self) -> Option<&'static str> {
        self.first_reject()
            .and_then(|c| c.problem.as_ref())
            .and_then(|p| problem_parts(p).2)
    }

    /// Whether this reports an invocation timer that expired, not a message.
    /// `invoke_id` and `operation_code` name the invoke and `operation_class`
    /// its class: for class 1 no reply came (stage an answer to keep the
    /// dialogue, or it is aborted), for class 2 the operation succeeded, for
    /// class 3 it failed.
    #[getter]
    fn is_timeout(&self) -> bool {
        self.event.timeout.is_some() && self.event.closed.is_none()
    }

    /// The operation class (1 to 4) of the invoke whose timer expired.
    #[getter]
    fn operation_class(&self) -> Option<u8> {
        self.event.timeout.map(|t| t.2)
    }

    /// Why the dialogue ended, when it ended without the script ending it and
    /// without an `End` from the peer: `peer-abort`, `provider-abort` (a damaged
    /// message for this dialogue), `abnormal-dialogue`, `invoke-timeout`,
    /// `idle-timeout`, `no-answer` or `not-sent`. `None` for a turn from the
    /// peer. Nothing can be sent on the dialogue any more.
    #[getter]
    fn closed(&self) -> Option<&'static str> {
        self.event.closed
    }

    /// Whether the dialogue was aborted (by the peer or by this node).
    #[getter]
    fn is_abort(&self) -> bool {
        self.event.closed.is_some()
    }

    /// `p-abort` when a transaction sub-layer aborted, `u-abort` when a TC-user
    /// or a component sub-layer did, `None` when no Abort message was involved.
    #[getter]
    fn abort_kind(&self) -> Option<&'static str> {
        self.event.abort_kind
    }

    /// The P-Abort cause value (Q.773 Table 12: 0 unrecognized message type, 1
    /// unrecognized transaction ID, 2 badly formatted transaction portion, 3
    /// incorrect transaction portion, 4 resource limitation).
    #[getter]
    fn p_abort_cause(&self) -> Option<i64> {
        self.event.p_abort_cause
    }

    /// What the abort carried, as a fixed label: a P-Abort cause name, or for a
    /// U-Abort `none`, `dialogue-service-user`, `abnormal-dialogue`,
    /// `no-common-dialogue-portion`, `application-context-not-supported`,
    /// `dialogue-refused` or `user-defined`.
    #[getter]
    fn abort_cause(&self) -> Option<&'static str> {
        self.event.abort_cause
    }

    /// The raw BER result parameter of the first `returnResultLast`, if present.
    #[getter]
    fn result<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.first_of("result")
            .and_then(|c| c.parameter.as_ref())
            .map(|p| PyBytes::new(py, p))
    }

    /// The raw BER argument of the first `Invoke` the peer sent, if present.
    #[getter]
    fn argument<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.first_of("invoke")
            .and_then(|c| c.parameter.as_ref())
            .map(|p| PyBytes::new(py, p))
    }

    fn __repr__(&self) -> String {
        match (&self.event.closed, self.event.timeout) {
            (Some(_), _) => format!("PeerTurn(closed={})", self.event.describe()),
            (None, Some((id, op, class))) => format!(
                "PeerTurn(is_timeout=True, invoke_id={id}, operation_code={op}, \
                 operation_class={class})"
            ),
            _ => format!(
                "PeerTurn(is_end={}, components={})",
                self.is_end,
                self.comps.len()
            ),
        }
    }
}

enum MoField {
    Oa,
    Da,
    Ui,
}

impl PyIncomingOp {
    /// The argument as a CAP InitialDPArg (TS 29.078), when the operation is
    /// initialDP. The decode is `gsm_cap::decode`: a member on the wire that
    /// cannot be read, a member the type does not have, and octets after the
    /// argument are errors.
    fn cap_initial_dp(&self) -> PyResult<Option<gsm_cap::operations::InitialDpArg>> {
        if self.operation_code != gsm_cap::op_codes::INITIAL_DP {
            return Ok(None);
        }
        let what = "the CAP InitialDP argument";
        let bytes = self
            .argument
            .as_ref()
            .ok_or_else(|| mistyped(what, "the Invoke carries no argument"))?;
        gsm_cap::decode(bytes)
            .map(Some)
            .map_err(|e| mistyped(what, e))
    }

    /// The argument as an INAP CS-1 InitialDPArg (ETS 300 374-1 / Q.1218), when
    /// the operation is initialDP. The decode is `inap::decode`: a member or a
    /// list element on the wire that cannot be read, a member the type does not
    /// have, and octets after the argument are errors, where the argument used
    /// to read as "no such field".
    fn inap_initial_dp(&self) -> PyResult<Option<inap::operations::InitialDpArg>> {
        if self.operation_code != inap::op_codes::INITIAL_DP {
            return Ok(None);
        }
        let what = "the INAP InitialDP argument";
        let bytes = self
            .argument
            .as_ref()
            .ok_or_else(|| mistyped(what, "the Invoke carries no argument"))?;
        inap::decode(bytes).map(Some).map_err(|e| mistyped(what, e))
    }

    /// One field of a MO-ForwardSM (46) or MT-ForwardSM (44) argument. `None`
    /// for any other operation. The decode is `gsm_map::decode`: an argument
    /// with a member that cannot be read, or with octets after it, is a
    /// mistyped parameter and raises, where it used to read as "no such field";
    /// a member a later release added after the extension marker is skipped
    /// (TS 29.002 17.1.4).
    fn decode_mo_field<'py>(
        &self,
        py: Python<'py>,
        field: MoField,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        use gsm_map::operations::{mo_forward_sm::MoForwardSmArg, mt_forward_sm::MtForwardSmArg};
        use gsm_map::{SmRpDa, SmRpOa};

        let mt = match self.operation_code {
            c if c == gsm_map::op_codes::MO_FORWARD_SM => false,
            c if c == gsm_map::op_codes::MT_FORWARD_SM => true,
            _ => return Ok(None),
        };
        let what = if mt {
            "the mt-forwardSM argument"
        } else {
            "the mo-forwardSM argument"
        };
        let bytes = self
            .argument
            .as_ref()
            .ok_or_else(|| mistyped(what, "the Invoke carries no argument"))?;
        let (da, oa, ui): (SmRpDa, SmRpOa, OctetString) = if mt {
            let a: MtForwardSmArg = gsm_map::decode(bytes).map_err(|e| mistyped(what, e))?;
            (a.sm_rp_da, a.sm_rp_oa, a.sm_rp_ui)
        } else {
            let a: MoForwardSmArg = gsm_map::decode(bytes).map_err(|e| mistyped(what, e))?;
            (a.sm_rp_da, a.sm_rp_oa, a.sm_rp_ui)
        };

        Ok(match field {
            MoField::Ui => Some(PyBytes::new(py, ui.as_ref())),
            MoField::Da => match da {
                SmRpDa::Imsi(b) | SmRpDa::Lmsi(b) | SmRpDa::ServiceCentreAddressDa(b) => {
                    Some(PyBytes::new(py, b.as_ref()))
                }
                SmRpDa::NoSmRpDa(()) => None,
            },
            MoField::Oa => match oa {
                SmRpOa::MsIsdn(b) | SmRpOa::ServiceCentreAddressOa(b) => {
                    Some(PyBytes::new(py, b.as_ref()))
                }
                SmRpOa::NoSmRpOa(()) => None,
            },
        })
    }
}

// ── The dialogue handle (command buffer) ─────────────────────────────────────

#[derive(Clone)]
enum DlgCmd {
    Invoke {
        op: i64,
        arg: InvokeArg,
        class: OperationClass,
        timeout: Option<Duration>,
    },
    Reply {
        op: i64,
        result: Option<Vec<u8>>,
    },
    ReplyTo {
        id: i8,
        op: i64,
        result: Option<Vec<u8>>,
    },
    Error {
        id: i8,
        code: i64,
    },
    Reject {
        id: Option<i8>,
        problem: Problem,
    },
    IdleTimeout(Option<Duration>),
    Send,
    End,
    Abort,
}

/// An invoke id from Python: `InvokeIdType ::= INTEGER (-128..127)` (Q.773).
fn invoke_id_arg(invoke_id: i64) -> PyResult<i8> {
    i8::try_from(invoke_id).map_err(|_| err(format!("invoke id {invoke_id} is outside -128..127")))
}

/// A timeout in seconds from Python.
fn seconds_arg(seconds: f64, what: &str) -> PyResult<Duration> {
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| err(format!("{what} must be a non-negative number of seconds")))
}

/// The live dialogue handle a termination handler drives. It records the
/// components the handler stages (`invoke` / `reply` / `error` / `reject`) and
/// the flush points (`send` / `end` / `abort`); the engine replays them onto the
/// real Rust dialogue to build the wire TCAP. This keeps the handler's view
/// simple and the wire encoding in Rust.
#[pyclass(name = "Dialogue", module = "siphon")]
pub struct PyDialogue {
    cmds: Mutex<Vec<DlgCmd>>,
    otid: Vec<u8>,
    dtid: Vec<u8>,
    /// The application context of the dialogue; empty when it has none, and
    /// on the turn that reports a dialogue that is already gone.
    application_context: Vec<u32>,
}

#[pymethods]
impl PyDialogue {
    /// Stage an `Invoke` (from an originating helper), e.g.
    /// `dlg.invoke(gsm_map.mt_forward_sm(...))`.
    ///
    /// The helper knows the class of its operation (`invoke.operation_class`);
    /// `operation_class=` overrides it (1 to 4) for an operation staged by
    /// hand. `timeout=` is the invocation timer in seconds; the default is the
    /// node's `tcap.invoke_timer_ms`. When the timer of a class 1 invoke expires
    /// with no reply the handler is called with a `PeerTurn` whose `is_timeout`
    /// is true; for class 2 and 3 the expiry is the outcome of the operation,
    /// reported the same way, and the dialogue goes on.
    #[pyo3(signature = (invoke, *, operation_class=None, timeout=None))]
    fn invoke(
        &self,
        invoke: &StagedInvoke,
        operation_class: Option<u8>,
        timeout: Option<f64>,
    ) -> PyResult<()> {
        let class = match operation_class {
            None => invoke.class,
            Some(n) => OperationClass::from_number(n)
                .ok_or_else(|| err(format!("operation class {n} is not 1, 2, 3 or 4")))?,
        };
        let timeout = timeout
            .map(|t| seconds_arg(t, "invoke timeout"))
            .transpose()?;
        self.push(DlgCmd::Invoke {
            op: invoke.op,
            arg: invoke.arg.clone(),
            class,
            timeout,
        });
        Ok(())
    }

    /// Stage a `ReturnResultLast` answering the opening invoke.
    fn reply(&self, result: &StagedResult) {
        self.push(DlgCmd::Reply {
            op: result.op,
            result: result.param.clone(),
        });
    }

    /// Stage a `ReturnResultLast` answering a specific invoke id.
    fn reply_to(&self, invoke_id: i64, result: &StagedResult) -> PyResult<()> {
        self.push(DlgCmd::ReplyTo {
            id: invoke_id_arg(invoke_id)?,
            op: result.op,
            result: result.param.clone(),
        });
        Ok(())
    }

    /// Stage a `ReturnError` answering a specific invoke id.
    fn error(&self, invoke_id: i64, error_code: i64) -> PyResult<()> {
        self.push(DlgCmd::Error {
            id: invoke_id_arg(invoke_id)?,
            code: error_code,
        });
        Ok(())
    }

    /// Stage a `Reject` of a component the peer sent: a protocol error in it,
    /// as opposed to an operation that failed (`error`). `invoke_id` is the id
    /// of the rejected component (`None` if it has none that can be named),
    /// `problem_class` one of `general` / `invoke` / `return-result` /
    /// `return-error`, and `problem_code` the code within that class (Q.773
    /// Tables 26 to 29). The usual one for a handler is an Invoke whose argument
    /// does not decode: `dlg.reject(op.invoke_id, "invoke", 2)`, mistyped
    /// parameter.
    #[pyo3(signature = (invoke_id, problem_class, problem_code))]
    fn reject(
        &self,
        invoke_id: Option<i64>,
        problem_class: &str,
        problem_code: i64,
    ) -> PyResult<()> {
        self.push(DlgCmd::Reject {
            id: invoke_id.map(invoke_id_arg).transpose()?,
            problem: problem_from_parts(problem_class, problem_code)?,
        });
        Ok(())
    }

    /// Set how long this dialogue may go without a message in either direction
    /// before the node aborts it, in seconds, overriding `tcap.dialogue_timer_ms`.
    /// A dialogue that waits for the next event of a call sets what the call can
    /// last; `None` waits until the peer ends it.
    #[pyo3(signature = (seconds))]
    fn set_idle_timeout(&self, seconds: Option<f64>) -> PyResult<()> {
        let timeout = seconds
            .map(|t| seconds_arg(t, "idle timeout"))
            .transpose()?;
        self.push(DlgCmd::IdleTimeout(timeout));
        Ok(())
    }

    /// Flush the staged components as a `Continue` (the dialogue stays open).
    fn send(&self) {
        self.push(DlgCmd::Send);
    }

    /// Flush the staged components as an `End`, closing the dialogue.
    fn end(&self) {
        self.push(DlgCmd::End);
    }

    /// Abort the dialogue as its user (a U-Abort; with an ABRT APDU,
    /// abort-source dialogue-service-user, when the dialogue has an application
    /// context).
    fn abort(&self) {
        self.push(DlgCmd::Abort);
    }

    /// Our originating transaction id.
    #[getter]
    fn otid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.otid)
    }

    /// The peer's transaction id.
    #[getter]
    fn dtid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.dtid)
    }

    /// The application context of the dialogue as the arcs of its object
    /// identifier, `(0, 4, 0, 0, 1, 21, 3, 4)`. `None` for a dialogue without
    /// one, and on the turn that tells the script a dialogue is gone.
    #[getter]
    fn application_context<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        if self.application_context.is_empty() {
            return Ok(None);
        }
        PyTuple::new(py, &self.application_context).map(Some)
    }

    /// The CAMEL phase the dialogue runs under, 1 to 4, read off its
    /// application context. `None` when that is not a CAP context.
    #[getter]
    fn camel_phase(&self) -> Option<u8> {
        cap::camel_phase(&self.application_context)
    }

    fn __repr__(&self) -> String {
        format!(
            "Dialogue(otid={}, dtid={})",
            hex(&self.otid),
            hex(&self.dtid)
        )
    }
}

impl PyDialogue {
    fn new(otid: Vec<u8>, dtid: Vec<u8>, application_context: &[u32]) -> Self {
        PyDialogue {
            cmds: Mutex::new(Vec::new()),
            otid,
            dtid,
            application_context: application_context.to_vec(),
        }
    }

    fn push(&self, cmd: DlgCmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(cmd);
    }

    fn take(&self) -> Vec<DlgCmd> {
        std::mem::take(&mut self.cmds.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Replay a Python dialogue's recorded commands onto the real Rust dialogue.
///
/// The script has returned by the time its commands run, so a command the
/// dialogue refuses cannot be raised into it. It is logged at error level with
/// the dialogue's transaction ids (a flush that cannot be encoded is logged by
/// the engine itself, which also counts it), and returned so the caller can
/// surface it where there is somebody to surface it to.
///
/// The replay stops at the first command that fails, and what was staged and
/// not yet flushed is dropped: the commands of one turn are one answer, and an
/// answer with a component missing (a call let through without the charging
/// instruction that could not be built) is worse than none. A dialogue left
/// with nothing sent in answer to a Begin is aborted by the engine, so the peer
/// is not left waiting.
fn replay(dlg: &mut CoreDialogue, cmds: Vec<DlgCmd>) -> Result<(), crate::dialogue::DialogueError> {
    for cmd in cmds {
        let (what, outcome) = match cmd {
            DlgCmd::Invoke {
                op,
                arg,
                class,
                timeout,
            } => (
                "invoke",
                // An argument that depends on the application context is
                // encoded here, where the dialogue is known.
                arg.resolve(dlg.application_context())
                    .map_err(crate::dialogue::DialogueError::Argument)
                    .and_then(|arg| dlg.invoke_with(op, arg, class, timeout))
                    .map(|_| ()),
            ),
            DlgCmd::Reply { op, result } => {
                dlg.reply(op, result);
                ("reply", Ok(()))
            }
            DlgCmd::ReplyTo { id, op, result } => {
                dlg.reply_to(id, op, result);
                ("reply_to", Ok(()))
            }
            DlgCmd::Error { id, code } => {
                dlg.error(id, code);
                ("error", Ok(()))
            }
            DlgCmd::Reject { id, problem } => {
                dlg.reject(id, problem);
                ("reject", Ok(()))
            }
            DlgCmd::IdleTimeout(timeout) => {
                dlg.set_idle_timeout(timeout);
                ("set_idle_timeout", Ok(()))
            }
            DlgCmd::Send => ("send", dlg.send()),
            DlgCmd::End => ("end", dlg.end()),
            DlgCmd::Abort => ("abort", dlg.abort()),
        };
        if let Err(e) = outcome {
            eprintln!(
                "siphon-sigtran: ERROR: dialogue otid={} dtid={}: {what}() failed: {e}",
                hex(dlg.otid()),
                hex(dlg.dtid())
            );
            dlg.discard_staged();
            return Err(e);
        }
    }
    Ok(())
}

// ── The Python termination handler bridge ────────────────────────────────────

/// A [`TerminationHandler`] backed by a Python callable. On each leg it builds a
/// [`PyDialogue`] + [`PyIncomingOp`], calls the handler (driving an `async def`
/// to completion on an asyncio loop), and replays the staged commands onto the
/// real dialogue.
struct PyHandler {
    func: Py<PyAny>,
}

/// Which leg of the dialogue is re-entering the handler, and the decoded view to
/// hand it: the opening operation (`Begin`), nothing (an originating `on_start`),
/// or the peer's follow-up turn (`Continue` / `End`).
enum Leg<'a> {
    Begin(&'a CoreIncomingOp),
    Start,
    Continue(&'a PeerTurn),
    /// An invocation timer expired, or the dialogue ended abnormally.
    Event(TurnEvent),
}

impl PyHandler {
    /// Call the script for one leg on a live dialogue and replay what it staged.
    /// Returns whether the script staged anything.
    fn run(&self, dlg: &mut CoreDialogue, leg: Leg<'_>) -> bool {
        let cmds = self.call(dlg.otid(), dlg.dtid(), dlg.application_context(), leg);
        let staged = !cmds.is_empty();
        let _ = replay(dlg, cmds);
        staged
    }

    /// Call the script for one leg and return the commands it staged.
    fn call(&self, otid: &[u8], dtid: &[u8], ac: &[u32], leg: Leg<'_>) -> Vec<DlgCmd> {
        // What to reject if the script finds the parameter of this leg mistyped.
        let rejection = match &leg {
            Leg::Begin(op) => Some(op.mistyped_parameter()),
            Leg::Continue(peer) => peer
                .components
                .iter()
                .find_map(PeerComponent::mistyped_parameter),
            Leg::Start | Leg::Event(_) => None,
        };
        Python::attach(|py| {
            let pydlg = match Bound::new(py, PyDialogue::new(otid.to_vec(), dtid.to_vec(), ac)) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("siphon-sigtran: building Dialogue failed: {e}");
                    return Vec::new();
                }
            };

            let call = match leg {
                Leg::Begin(o) => {
                    let arg = PyIncomingOp {
                        operation_code: o.operation_code,
                        invoke_id: i64::from(o.invoke_id),
                        calling_gt: o.calling_gt.clone(),
                        called_gt: o.called_gt.clone(),
                        argument: o.argument.clone(),
                        further: o.further.iter().map(PeerComp::from_core).collect(),
                    };
                    match Bound::new(py, arg) {
                        Ok(a) => self.func.bind(py).call1((&pydlg, &a)),
                        Err(e) => {
                            eprintln!("siphon-sigtran: building IncomingOp failed: {e}");
                            return Vec::new();
                        }
                    }
                }
                Leg::Continue(peer) => match Bound::new(py, PyPeerTurn::from_peer(peer)) {
                    Ok(t) => self.func.bind(py).call1((&pydlg, &t)),
                    Err(e) => {
                        eprintln!("siphon-sigtran: building PeerTurn failed: {e}");
                        return Vec::new();
                    }
                },
                Leg::Event(event) => match Bound::new(py, PyPeerTurn::from_event(event)) {
                    Ok(t) => self.func.bind(py).call1((&pydlg, &t)),
                    Err(e) => {
                        eprintln!("siphon-sigtran: building PeerTurn failed: {e}");
                        return Vec::new();
                    }
                },
                Leg::Start => self.func.bind(py).call1((&pydlg,)),
            };

            let raised = match call {
                Ok(result) => drive(py, &result).err(),
                Err(e) => Some(e),
            };
            match raised {
                None => {
                    let cmds = pydlg.borrow().take();
                    cmds
                }
                Some(e) => handler_raised(py, &e, rejection, otid, dtid),
            }
        })
    }
}

/// A handler raised. Whatever it staged before is discarded: half an answer is
/// not sent. An uncaught `MistypedParameter` is the handler saying the peer's
/// component is a protocol error, and is answered as one: a Reject, mistyped
/// parameter, in an End (Q.774 3.2.2.2: the Reject leaves with the next dialogue
/// handling primitive, here a basic end). Anything else is the script's own
/// failure: nothing is staged, and a Begin left unanswered is aborted by the
/// engine.
fn handler_raised(
    py: Python<'_>,
    error: &PyErr,
    rejection: Option<(Option<i8>, Problem)>,
    otid: &[u8],
    dtid: &[u8],
) -> Vec<DlgCmd> {
    let ids = format!("otid={} dtid={}", hex(otid), hex(dtid));
    // A view of one component names the Invoke it could not read; without
    // that, the component to reject is the first of the turn.
    match cap::rejected_invoke(py, error).or(rejection) {
        Some((id, problem)) if error.is_instance_of::<MistypedParameter>(py) => {
            eprintln!("siphon-sigtran: dialogue {ids}: rejecting the component: {error}");
            vec![DlgCmd::Reject { id, problem }, DlgCmd::End]
        }
        _ => {
            eprintln!("siphon-sigtran: ERROR: dialogue {ids}: termination handler raised: {error}");
            Vec::new()
        }
    }
}

/// The handler's part in an invocation timeout, shared by the script-backed
/// handlers: tell the script, and when it has nothing to say to a class 1
/// expiry, abort. Q.774 3.2.1.1.3: "It is now up to the application to decide
/// whether to abort the transaction or to report an error to the peer
/// application"; a script decides by staging something (an error, an End, a
/// Continue), and one that does not know of timeouts gets the abort.
fn after_timeout(dlg: &mut CoreDialogue, timeout: &InvokeTimeout, script_acted: bool) {
    if !script_acted && timeout.class == OperationClass::One && !dlg.is_closed() {
        let _ = dlg.abort();
    }
}

impl TerminationHandler for PyHandler {
    fn on_begin(&self, dialogue: &mut CoreDialogue, op: &CoreIncomingOp) {
        self.run(dialogue, Leg::Begin(op));
    }

    fn on_start(&self, dialogue: &mut CoreDialogue) {
        self.run(dialogue, Leg::Start);
    }

    fn on_continue(&self, dialogue: &mut CoreDialogue, peer: &PeerTurn) {
        self.run(dialogue, Leg::Continue(peer));
    }

    fn on_invoke_timeout(&self, dialogue: &mut CoreDialogue, timeout: &InvokeTimeout) {
        let acted = self.run(dialogue, Leg::Event(TurnEvent::from_timeout(timeout)));
        after_timeout(dialogue, timeout, acted);
    }

    fn on_closed(&self, closed: &DialogueClosed) {
        // An end the script brought about or was handed as a turn is not told
        // twice. Whatever it stages on a dialogue that is over is discarded.
        if let Some(event) = TurnEvent::from_closed(&closed.reason) {
            let _ = self.call(&closed.otid, &closed.dtid, &[], Leg::Event(event));
        }
    }
}

// ── Origination (a dialogue the node initiates) ──────────────────────────────

/// The process-wide origination seam: the sender half of the transport's
/// [`Origination`] channel, populated by [`task`] once the transport is up. A
/// script's `begin(...)` helper pushes onto it; before the node is up it is
/// absent, so `begin` fails fast with a clear error rather than hanging.
static ORIGIN_TX: OnceLock<mpsc::UnboundedSender<Origination>> = OnceLock::new();

/// Record the transport's origination sender so `begin(...)` can reach it. Called
/// once by [`task`] after the transport starts; a second call is ignored.
fn set_origin_tx(tx: mpsc::UnboundedSender<Origination>) {
    let _ = ORIGIN_TX.set(tx);
}

/// A [`TerminationHandler`] for an **originated** dialogue. `on_start` stages the
/// pre-built opening `Invoke` (flushed as the `Begin`); `on_continue` hands the
/// peer's first response back to the awaiting `begin(...)` caller through a
/// oneshot and lets the dialogue close. `on_begin` stays defaulted (an initiator
/// is never a responder).
struct OriginationHandler {
    op: i64,
    arg: Option<Vec<u8>>,
    class: OperationClass,
    responder: Mutex<Option<oneshot::Sender<Result<PeerTurn, String>>>>,
}

impl OriginationHandler {
    fn resolve(&self, outcome: Result<PeerTurn, String>) {
        if let Some(tx) = self
            .responder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = tx.send(outcome);
        }
    }
}

impl TerminationHandler for OriginationHandler {
    fn on_start(&self, dialogue: &mut CoreDialogue) {
        // A failure is logged by the engine with the dialogue's identifiers and
        // comes back to the awaiting caller through `on_closed`.
        if dialogue
            .invoke_with(self.op, self.arg.clone(), self.class, None)
            .is_ok()
        {
            let _ = dialogue.send();
        }
    }

    fn on_continue(&self, dialogue: &mut CoreDialogue, peer: &PeerTurn) {
        self.resolve(Ok(peer.clone()));
        // v1 origination is single request/response: we've handed the caller the
        // peer's first turn. If the peer left the dialogue open (a Continue, not an
        // End), close it cleanly with an End so it never lingers or draws a
        // provider Abort it did not earn.
        if !peer.is_end && !dialogue.is_closed() {
            let _ = dialogue.end();
        }
    }

    fn on_invoke_timeout(&self, dialogue: &mut CoreDialogue, timeout: &InvokeTimeout) {
        // The awaiting caller asked one question. For a class 2 operation
        // silence until the timer is its success and there is no reply to wait
        // for; for class 1 (and 3) no reply is a failure.
        if timeout.class == OperationClass::Two {
            self.resolve(Ok(PeerTurn {
                is_end: false,
                components: Vec::new(),
            }));
        }
        let _ = dialogue.abort();
    }

    fn on_closed(&self, closed: &DialogueClosed) {
        // Whatever ended the dialogue before an answer came, the caller is
        // told why instead of waiting on a reply that will not come.
        let why = match TurnEvent::from_closed(&closed.reason) {
            Some(event) => event.describe(),
            None => "closed with no response".to_string(),
        };
        self.resolve(Err(format!("originated dialogue ended: {why}")));
    }
}

/// Call a Python leg callback `func(dialogue, peer_turn)` and replay the commands
/// it stages onto the real dialogue. The follow-up-leg counterpart of
/// [`PyHandler::run`], shared by the script-driven [`OriginationScriptHandler`].
fn call_python_leg(func: &Py<PyAny>, dlg: &mut CoreDialogue, turn: PyPeerTurn) -> bool {
    let cmds = call_python_turn(
        func,
        dlg.otid(),
        dlg.dtid(),
        dlg.application_context(),
        turn,
    );
    let staged = !cmds.is_empty();
    let _ = replay(dlg, cmds);
    staged
}

/// Call `func(dialogue, turn)` and return the commands it staged.
fn call_python_turn(
    func: &Py<PyAny>,
    otid: &[u8],
    dtid: &[u8],
    ac: &[u32],
    turn: PyPeerTurn,
) -> Vec<DlgCmd> {
    let rejection = turn.rejection;
    Python::attach(|py| {
        let pydlg = match Bound::new(py, PyDialogue::new(otid.to_vec(), dtid.to_vec(), ac)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("siphon-sigtran: building Dialogue failed: {e}");
                return Vec::new();
            }
        };
        let turn = match Bound::new(py, turn) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("siphon-sigtran: building PeerTurn failed: {e}");
                return Vec::new();
            }
        };
        let raised = match func.bind(py).call1((&pydlg, &turn)) {
            Ok(result) => drive(py, &result).err(),
            Err(e) => Some(e),
        };
        match raised {
            None => {
                let cmds = pydlg.borrow().take();
                cmds
            }
            Some(e) => handler_raised(py, &e, rejection, otid, dtid),
        }
    })
}

/// A [`TerminationHandler`] for a **script-driven multi-leg origination**
/// ([`Node::originate`]): `on_start` stages the opening `Invoke` and flushes the
/// `Begin`; each follow-up leg calls the Python `on_reply(dialogue, peer)`
/// callback, which stages the next segment (`dlg.invoke(...); dlg.send()`) or
/// lets the dialogue close.
struct OriginationScriptHandler {
    op: i64,
    arg: Option<Vec<u8>>,
    class: OperationClass,
    on_reply: Py<PyAny>,
}

impl TerminationHandler for OriginationScriptHandler {
    fn on_start(&self, dlg: &mut CoreDialogue) {
        if dlg
            .invoke_with(self.op, self.arg.clone(), self.class, None)
            .is_ok()
        {
            let _ = dlg.send();
        }
    }

    fn on_continue(&self, dlg: &mut CoreDialogue, peer: &PeerTurn) {
        call_python_leg(&self.on_reply, dlg, PyPeerTurn::from_peer(peer));
    }

    fn on_invoke_timeout(&self, dlg: &mut CoreDialogue, timeout: &InvokeTimeout) {
        let turn = PyPeerTurn::from_event(TurnEvent::from_timeout(timeout));
        let acted = call_python_leg(&self.on_reply, dlg, turn);
        after_timeout(dlg, timeout, acted);
    }

    fn on_closed(&self, closed: &DialogueClosed) {
        if let Some(event) = TurnEvent::from_closed(&closed.reason) {
            let turn = PyPeerTurn::from_event(event);
            let _ = call_python_turn(&self.on_reply, &closed.otid, &closed.dtid, &[], turn);
        }
    }
}

/// Open a dialogue the node initiates and return an awaitable that resolves to
/// the peer's first response ([`PyPeerTurn`]). Shared by the `gsm_map` /
/// `gsm_cap` / `inap` `begin(...)` helpers: the operation to invoke is carried by
/// the staged `invoke`, so the machinery is protocol-agnostic. The calling party
/// defaults to our own point code / network indicator and the `called_gt`
/// digits; the peer's response arrives inbound and correlates on the transaction
/// id the engine allocated.
#[allow(clippy::too_many_arguments)]
fn origination_begin<'py>(
    py: Python<'py>,
    invoke: &StagedInvoke,
    called_gt: &str,
    called_ssn: u8,
    calling_gt: &str,
    calling_ssn: u8,
    dpc: u32,
    ac: &MapAcHandle,
    opc: Option<u32>,
    sls: u8,
) -> PyResult<Bound<'py, PyAny>> {
    let tx = ORIGIN_TX
        .get()
        .ok_or_else(|| err("sigtran node not started: no transport to originate over"))?
        .clone();

    let n = node();
    let (opc_default, ni) = {
        let router = lock_router(&n);
        (
            router.node_point_code(&n.tenant).unwrap_or(0),
            router.node_network_indicator(&n.tenant),
        )
    };
    // OPC defaults to our own point code; the calling party is always the
    // script-supplied node address (never the callee's — a peer that
    // return-routes on the calling-party GT must reach us, not the HLR).
    let opc = opc.unwrap_or(opc_default);
    let calling = gt_address(calling_gt, Some(calling_ssn));
    let called = gt_address(called_gt, Some(called_ssn));

    let (resp_tx, resp_rx) = oneshot::channel();
    let handler: Arc<dyn TerminationHandler> = Arc::new(OriginationHandler {
        op: invoke.op,
        arg: invoke.arg.resolve(&ac.arcs).map_err(err)?,
        class: invoke.class,
        responder: Mutex::new(Some(resp_tx)),
    });
    let req = OutgoingBegin {
        application_context: ac.arcs.clone(),
        called,
        calling,
        opc,
        dpc,
        ni,
        sls,
        ingress_assoc: String::new(),
    };

    tx.send(Origination { req, handler })
        .map_err(|_| err("sigtran node stopped: origination channel closed"))?;

    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let peer = resp_rx
            .await
            .map_err(|_| err("originated dialogue closed with no response"))?
            .map_err(err)?;
        Ok(PyPeerTurn::from_peer(&peer))
    })
}

/// Drive a possibly-async result to completion. A plain return value is done; a
/// coroutine is run on a fresh asyncio event loop (mirroring how an `async def`
/// handler runs on siphon's runtime).
fn drive(py: Python<'_>, result: &Bound<'_, PyAny>) -> PyResult<()> {
    let asyncio = py.import("asyncio")?;
    if !asyncio
        .call_method1("iscoroutine", (result,))?
        .is_truthy()?
    {
        return Ok(());
    }
    let event_loop = asyncio.call_method0("new_event_loop")?;
    let outcome = event_loop.call_method1("run_until_complete", (result,));
    let _ = event_loop.call_method0("close");
    outcome.map(|_| ())
}

// ── The `ss7` namespace ──────────────────────────────────────────────────────

/// The `ss7` routing namespace singleton.
#[pyclass(name = "Ss7", module = "siphon")]
pub struct Ss7;

#[pymethods]
impl Ss7 {
    /// The MTP3 route table (`ss7.routes.add(...)` / `.cache(...)`).
    #[getter]
    fn routes(&self) -> Routes {
        Routes
    }

    /// The SCCP GTT table (`ss7.gtt.add(...)`).
    #[getter]
    fn gtt(&self) -> Gtt {
        Gtt
    }

    /// The content-routing surface (`ss7.content.add_rule(...)` /
    /// `.address_table(...)` / `.on(name)`).
    #[getter]
    fn content(&self) -> Content {
        Content
    }

    /// The routing domains (tenants) present.
    #[getter]
    fn tenants(&self) -> Vec<String> {
        let n = node();
        let ids: Vec<String> = lock_router(&n).tenancy().ids().cloned().collect();
        ids
    }

    /// Build an SCCP address from global-title digits (`ss7.gt("15550100", ssn=8)`).
    #[pyo3(signature = (digits, *, ssn=None))]
    fn gt(&self, digits: &str, ssn: Option<u8>) -> Address {
        Address {
            inner: gt_address(digits, ssn),
        }
    }

    /// The node's Prometheus text exposition (`ss7.metrics()`). It lives on this
    /// namespace and not on the `siphon` module, where `metrics` is the host's.
    fn metrics(&self) -> String {
        crate::metrics::render()
    }

    fn __repr__(&self) -> String {
        "ss7".to_string()
    }
}

/// `ss7.routes`, the live MTP3 route table.
#[pyclass(name = "Routes", module = "siphon")]
pub struct Routes;

#[pymethods]
impl Routes {
    /// Add (or extend) a route to a DPC. Name exactly one of `as_` (an M3UA
    /// Application Server) or `linkset` (an M2PA linkset). `priority` follows the
    /// config rule (1 = primary, higher = alternate).
    #[pyo3(signature = (*, dpc, as_=None, linkset=None, priority=1))]
    fn add(
        &self,
        dpc: u32,
        as_: Option<String>,
        linkset: Option<String>,
        priority: u8,
    ) -> PyResult<()> {
        let dest = match (as_, linkset) {
            (Some(a), None) => Destination::ApplicationServer(a),
            (None, Some(l)) => Destination::Linkset(l),
            (Some(_), Some(_)) => {
                return Err(err("ss7.routes.add: pass exactly one of as_ / linkset"))
            }
            (None, None) => return Err(err("ss7.routes.add: pass one of as_ / linkset")),
        };
        let n = node();
        let mut router = lock_router(&n);
        let tenant = n.tenant.clone();
        let rt = router
            .tenancy_mut()
            .get_mut(&tenant)
            .ok_or_else(|| err("no default tenant"))?;
        rt.routes.add(dpc, dest, priority);
        Ok(())
    }

    /// Cache a dip result: a GTT prefix rule so subsequent MSUs for `gt` route to
    /// `dpc`/`ssn` in Rust without re-running the hook. `ttl` is accepted for API
    /// stability; the cached rule persists until reprogrammed.
    #[pyo3(signature = (gt, *, dpc, ssn, ttl=None))]
    fn cache(&self, gt: &str, dpc: u32, ssn: u8, ttl: Option<u64>) -> PyResult<()> {
        let _ = ttl;
        Gtt.add_prefix(gt, dpc, ssn)
    }

    fn __repr__(&self) -> String {
        "ss7.routes".to_string()
    }
}

/// `ss7.gtt`, the live SCCP GTT table.
#[pyclass(name = "Gtt", module = "siphon")]
pub struct Gtt;

#[pymethods]
impl Gtt {
    /// Prepend a GTT rule (`match` → `to`). Both are dicts mirroring the config
    /// `gtt:` rule schema: `match={"gt_prefix": "1555", ...}`,
    /// `to={"dpc": 2000, "ssn": 6}` (or `{"group": "..."}` / `{"local": true}`).
    #[pyo3(signature = (*, r#match, to))]
    fn add(&self, r#match: &Bound<'_, PyAny>, to: &Bound<'_, PyAny>) -> PyResult<()> {
        let mut yaml = String::from("{match: ");
        py_to_yaml(r#match, &mut yaml)?;
        yaml.push_str(", to: ");
        py_to_yaml(to, &mut yaml)?;
        yaml.push('}');
        let rule: GttRule = from_yaml(&yaml).map_err(err)?;
        self.push_rule(rule)
    }

    fn __repr__(&self) -> String {
        "ss7.gtt".to_string()
    }
}

impl Gtt {
    fn add_prefix(&self, gt: &str, dpc: u32, ssn: u8) -> PyResult<()> {
        let mut yaml = String::from("{match: {gt_prefix: ");
        push_yaml_str(gt, &mut yaml);
        yaml.push_str(&format!("}}, to: {{dpc: {dpc}, ssn: {ssn}}}}}"));
        let rule: GttRule = from_yaml(&yaml).map_err(err)?;
        self.push_rule(rule)
    }

    fn push_rule(&self, rule: GttRule) -> PyResult<()> {
        let n = node();
        let mut router = lock_router(&n);
        let tenant = n.tenant.clone();
        let rt = router
            .tenancy_mut()
            .get_mut(&tenant)
            .ok_or_else(|| err("no default tenant"))?;
        rt.gtt.add_rule(rule);
        Ok(())
    }
}

/// `ss7.content`, the live content-routing surface.
#[pyclass(name = "Content", module = "siphon")]
pub struct Content;

#[pymethods]
impl Content {
    /// Prepend a content rule. `match` / `action` are dicts mirroring the config
    /// `content_routing.rules[]` schema.
    #[pyo3(signature = (*, name, r#match, action))]
    fn add_rule(
        &self,
        name: &str,
        r#match: &Bound<'_, PyAny>,
        action: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let mut yaml = String::from("{name: ");
        push_yaml_str(name, &mut yaml);
        yaml.push_str(", match: ");
        py_to_yaml(r#match, &mut yaml)?;
        yaml.push_str(", action: ");
        py_to_yaml(action, &mut yaml)?;
        yaml.push('}');
        let rule: ContentRule = from_yaml(&yaml).map_err(err)?;
        with_content(|c| c.add_rule(&rule))
    }

    /// Reference a named address table (`ss7.content.address_table("home-subs")`);
    /// call `.add(gt)` on it to program a served-subscriber GT live.
    fn address_table(&self, name: &str) -> AddressTable {
        AddressTable {
            name: name.to_string(),
        }
    }

    fn __repr__(&self) -> String {
        "ss7.content".to_string()
    }
}

/// `ss7.content.address_table(name)`, a named GT digit table.
#[pyclass(name = "AddressTable", module = "siphon")]
pub struct AddressTable {
    name: String,
}

#[pymethods]
impl AddressTable {
    /// Add a global-title digit string to this table live.
    fn add(&self, addr: &str) -> PyResult<()> {
        let name = self.name.clone();
        let addr = addr.to_string();
        with_content(move |c| c.address_table_add(&name, addr))
    }

    fn __repr__(&self) -> String {
        format!("AddressTable({})", self.name)
    }
}

/// Run a closure against the default tenant's content engine, creating an empty
/// one if the tenant had no `content_routing` block.
fn with_content(f: impl FnOnce(&mut ContentEngine)) -> PyResult<()> {
    let n = node();
    let mut router = lock_router(&n);
    let tenant = n.tenant.clone();
    let rt = router
        .tenancy_mut()
        .get_mut(&tenant)
        .ok_or_else(|| err("no default tenant"))?;
    f(rt.content.get_or_insert_with(ContentEngine::empty));
    Ok(())
}

// ── The `gsm_map` / `gsm_cap` namespaces ─────────────────────────────────────

/// The `gsm_map` (MAP, TS 29.002) namespace singleton.
#[pyclass(name = "GsmMap", module = "siphon")]
pub struct GsmMap;

#[pymethods]
impl GsmMap {
    /// The MAP application-context helpers (`gsm_map.AC.short_msg_mt_relay`).
    #[getter]
    #[allow(non_snake_case)]
    fn AC(&self) -> MapAc {
        MapAc
    }

    /// Terminate one or more MAP operations, named by their kebab-case operation
    /// names. The same `on_<message>("<name>")` shape the sibling addons use
    /// (`@proxy.on_request`, `@smpp.on_pdu`):
    ///
    /// ```python,ignore
    /// @gsm_map.on_operation("mo-forward-sm")               # one operation
    /// @gsm_map.on_operation("mo-forward-sm|mt-forward-sm") # several, pipe-separated
    /// @gsm_map.on_operation                                # bare: every MAP operation
    /// ```
    ///
    /// Known names: `mo-forward-sm`, `mt-forward-sm`, `sri-sm`,
    /// `report-sm-delivery-status`, `ready-for-sm`, `update-location`,
    /// `cancel-location`, `purge-ms`, `send-auth-info`, `provide-subscriber-info`.
    /// An unknown name raises `SigtranError` at decoration time.
    #[pyo3(signature = (arg=None))]
    fn on_operation<'py>(
        &self,
        py: Python<'py>,
        arg: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        on_operation_impl(py, arg, map_op_table())
    }

    /// Open a MAP dialogue the node initiates (an SMSC MT delivery, an SMS-GMSC
    /// SRI-SM). Stages `invoke` — an [`Invoke`](StagedInvoke) from a builder such
    /// as `gsm_map.mt_forward_sm(...)` — as the opening operation of a `Begin`
    /// toward `called_gt`/`called_ssn` at point code `dpc` under application
    /// context `ac`, and `await`s the peer's first response as a
    /// [`PeerTurn`](PyPeerTurn). The calling party defaults to our own point code
    /// and network indicator with the `called_gt` digits unless overridden.
    #[pyo3(signature = (invoke, *, called_gt, called_ssn, calling_gt, calling_ssn, dpc, ac, opc=None, sls=0))]
    #[allow(clippy::too_many_arguments)]
    fn begin<'py>(
        &self,
        py: Python<'py>,
        invoke: &StagedInvoke,
        called_gt: &str,
        called_ssn: u8,
        calling_gt: &str,
        calling_ssn: u8,
        dpc: u32,
        ac: PyRef<'_, MapAcHandle>,
        opc: Option<u32>,
        sls: u8,
    ) -> PyResult<Bound<'py, PyAny>> {
        origination_begin(
            py,
            invoke,
            called_gt,
            called_ssn,
            calling_gt,
            calling_ssn,
            dpc,
            &ac,
            opc,
            sls,
        )
    }

    /// Build a MO-ForwardSM result to reply with (`dlg.reply(...)`).
    fn mo_forward_sm_res(&self) -> StagedResult {
        StagedResult {
            op: Operation::MoForwardSm.op_code(),
            param: None,
        }
    }

    /// Build an MT-ForwardSM result to reply with.
    fn mt_forward_sm_res(&self) -> StagedResult {
        StagedResult {
            op: Operation::MtForwardSm.op_code(),
            param: None,
        }
    }

    /// Build a SendRoutingInfoForSM (SRI-SM) result, the HLR's answer to an
    /// SMS-GMSC: the recipient's `imsi` and the serving `network_node_number`
    /// (the MSC/SGSN to deliver to). `lmsi` is the optional VLR-assigned local id.
    #[pyo3(signature = (*, imsi, network_node_number, lmsi=None))]
    fn send_routing_info_for_sm_res(
        &self,
        imsi: &Bound<'_, PyAny>,
        network_node_number: &Bound<'_, PyAny>,
        lmsi: Option<Vec<u8>>,
    ) -> PyResult<StagedResult> {
        use gsm_map::operations::sri_sm::RoutingInfoForSmRes;
        use gsm_map::types::LocationInfoWithLmsi;
        let mut location = LocationInfoWithLmsi::new(isdn_addr(network_node_number)?.into());
        location.lmsi = lmsi.map(Into::into);
        let res = RoutingInfoForSmRes::new(imsi_arg(imsi)?.into(), location);
        staged_map_res(gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM, &res)
    }

    /// Build an updateLocation result carrying the `hlr_number`: the successful
    /// close of a location update, sent once the VLR has taken the subscriber data.
    #[pyo3(signature = (*, hlr_number))]
    fn update_location_res(&self, hlr_number: &Bound<'_, PyAny>) -> PyResult<StagedResult> {
        use gsm_map::operations::location::UpdateLocationRes;
        let res = UpdateLocationRes::new(isdn_addr(hlr_number)?.into());
        staged_map_res(gsm_map::op_codes::UPDATE_LOCATION, &res)
    }

    /// Build a sendAuthenticationInfo result carrying authentication vectors.
    /// Pass `quintuplets` (UMTS/EPS AKA, each `(rand, xres, ck, ik, autn)`) or
    /// `triplets` (GSM, each `(rand, sres, kc)`); omit both for an empty set.
    #[pyo3(signature = (*, quintuplets=None, triplets=None))]
    fn send_authentication_info_res(
        &self,
        quintuplets: Option<Vec<Quintuplet>>,
        triplets: Option<Vec<Triplet>>,
    ) -> PyResult<StagedResult> {
        use gsm_map::operations::auth::{
            AuthenticationQuintuplet, AuthenticationSetList, AuthenticationTriplet,
            SendAuthenticationInfoRes,
        };
        let mut res = SendAuthenticationInfoRes::default();
        match (quintuplets, triplets) {
            (Some(q), _) => res.set_authentication_set_list(AuthenticationSetList::QuintupletList(
                q.into_iter()
                    .map(|(rand, xres, ck, ik, autn)| AuthenticationQuintuplet {
                        rand: rand.into(),
                        xres: xres.into(),
                        ck: ck.into(),
                        ik: ik.into(),
                        autn: autn.into(),
                    })
                    .collect(),
            )),
            (None, Some(t)) => res.set_authentication_set_list(AuthenticationSetList::TripletList(
                t.into_iter()
                    .map(|(rand, sres, kc)| AuthenticationTriplet {
                        rand: rand.into(),
                        sres: sres.into(),
                        kc: kc.into(),
                    })
                    .collect(),
            )),
            (None, None) => {}
        }
        staged_map_res(gsm_map::op_codes::SEND_AUTHENTICATION_INFO, &res)
    }

    /// Build an insertSubscriberData result: the VLR accepting the pushed data.
    fn insert_subscriber_data_res(&self) -> PyResult<StagedResult> {
        use gsm_map::operations::subscriber_data::{op_codes, InsertSubscriberDataRes};
        let res = InsertSubscriberDataRes::default();
        staged_map_res(op_codes::INSERT_SUBSCRIBER_DATA, &res)
    }

    /// Build a cancelLocation result: the VLR confirming it dropped the record.
    fn cancel_location_res(&self) -> PyResult<StagedResult> {
        use gsm_map::operations::location::CancelLocationRes;
        staged_map_res(
            gsm_map::op_codes::CANCEL_LOCATION,
            &CancelLocationRes::default(),
        )
    }

    /// Build a purgeMS result. `freeze_tmsi` / `freeze_p_tmsi` ask the VLR/SGSN
    /// to hold the (P-)TMSI back from reuse for a while.
    #[pyo3(signature = (*, freeze_tmsi=false, freeze_p_tmsi=false))]
    fn purge_ms_res(&self, freeze_tmsi: bool, freeze_p_tmsi: bool) -> PyResult<StagedResult> {
        use gsm_map::operations::location::PurgeMsRes;
        let res = PurgeMsRes {
            freeze_tmsi: freeze_tmsi.then_some(()),
            freeze_p_tmsi: freeze_p_tmsi.then_some(()),
            ..PurgeMsRes::default()
        };
        staged_map_res(gsm_map::op_codes::PURGE_MS, &res)
    }

    /// Build a readyForSM result: the HLR acknowledging the alert.
    fn ready_for_sm_res(&self) -> PyResult<StagedResult> {
        use gsm_map::operations::ready_for_sm::ReadyForSmRes;
        staged_map_res(gsm_map::op_codes::READY_FOR_SM, &ReadyForSmRes::default())
    }

    /// Stage an insertSubscriberData invoke: the HLR pushes subscriber data to
    /// the VLR inside a held-open updateLocation. `imsi` / `msisdn` are the TBCD
    /// address bytes.
    #[pyo3(signature = (*, imsi=None, msisdn=None))]
    fn insert_subscriber_data(
        &self,
        imsi: Option<Bound<'_, PyAny>>,
        msisdn: Option<Bound<'_, PyAny>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_map::operations::subscriber_data::{op_codes, InsertSubscriberDataArg};
        let arg = InsertSubscriberDataArg {
            imsi: imsi.as_ref().map(imsi_arg).transpose()?.map(Into::into),
            msisdn: msisdn.as_ref().map(isdn_addr).transpose()?.map(Into::into),
            ..InsertSubscriberDataArg::default()
        };
        staged_map_invoke(op_codes::INSERT_SUBSCRIBER_DATA, &arg)
    }

    /// Stage an MO-ForwardSM invoke: relay a mobile-originated `tpdu` from
    /// `msisdn` to the service centre `sc_addr` (an IWMSC handing MO SMS on to
    /// the SMSC). `imsi` is the optional originating IMSI.
    #[pyo3(signature = (*, sc_addr, msisdn, tpdu, imsi=None))]
    fn mo_forward_sm(
        &self,
        sc_addr: &Bound<'_, PyAny>,
        msisdn: &Bound<'_, PyAny>,
        tpdu: Vec<u8>,
        imsi: Option<Bound<'_, PyAny>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
        use gsm_map::{SmRpDa, SmRpOa};
        let mut arg = MoForwardSmArg::new(
            SmRpDa::ServiceCentreAddressDa(isdn_addr(sc_addr)?.into()),
            SmRpOa::MsIsdn(isdn_addr(msisdn)?.into()),
            tpdu.into(),
        );
        arg.imsi = imsi.as_ref().map(imsi_arg).transpose()?.map(Into::into);
        staged_map_invoke(gsm_map::op_codes::MO_FORWARD_SM, &arg)
    }

    /// Stage an MT-ForwardSM invoke: deliver `tpdu` to `imsi` from `sc_addr`,
    /// with `more_messages_to_send` set on all but the last segment.
    #[pyo3(signature = (*, imsi, sc_addr, tpdu, more_messages_to_send=false))]
    fn mt_forward_sm(
        &self,
        imsi: &Bound<'_, PyAny>,
        sc_addr: &Bound<'_, PyAny>,
        tpdu: Vec<u8>,
        more_messages_to_send: bool,
    ) -> PyResult<StagedInvoke> {
        use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
        use gsm_map::{SmRpDa, SmRpOa};
        let mut arg = MtForwardSmArg::new(
            SmRpDa::Imsi(imsi_arg(imsi)?.into()),
            SmRpOa::ServiceCentreAddressOa(isdn_addr(sc_addr)?.into()),
            tpdu.into(),
        );
        arg.more_messages_to_send = more_messages_to_send.then_some(());
        let bytes = gsm_map::encode(&arg).map_err(err)?;
        Ok(StagedInvoke::new(
            Operation::MtForwardSm.op_code(),
            Some(bytes),
            OperationClass::One,
        ))
    }

    fn __repr__(&self) -> String {
        "gsm_map".to_string()
    }
}

/// `gsm_map.AC`, MAP application-context helpers.
#[pyclass(name = "MapAc", module = "siphon")]
pub struct MapAc;

#[pymethods]
impl MapAc {
    /// shortMsgMT-Relay (MT-ForwardSM), version 3.
    #[getter]
    fn short_msg_mt_relay(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: oid_arcs(gsm_map::application_context::short_msg_mt_relay_context(
                gsm_map::application_context::V3,
            )),
        }
    }

    /// shortMsgGateway (SendRoutingInfoForSM), version 3.
    #[getter]
    fn short_msg_gateway(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: oid_arcs(gsm_map::application_context::short_msg_gateway_context(
                gsm_map::application_context::V3,
            )),
        }
    }

    /// shortMsgMO-Relay (MO-ForwardSM), version 3.
    #[getter]
    fn short_msg_mo_relay(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: oid_arcs(gsm_map::application_context::short_msg_mo_relay_context(
                gsm_map::application_context::V3,
            )),
        }
    }
}

/// `gsm_cap.AC`, CAMEL CAP application-context helpers.
#[pyclass(name = "CapAc", module = "siphon")]
pub struct CapAc;

#[pymethods]
impl CapAc {
    /// The gsmSSF-to-gsmSCF generic (call-control) application context of
    /// CAMEL phase 3, `capssf-scfGenericAC` (`0.4.0.0.1.21.3.4`).
    #[getter]
    fn gsm_ssf_scf(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: gsm_cap::application_context::CAP_V3_GSMSSF_SCF_GENERIC.to_vec(),
        }
    }

    /// The same context of CAMEL phase 4 (`0.4.0.0.1.23.3.4`).
    #[getter]
    fn gsm_ssf_scf_phase4(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: gsm_cap::application_context::CAP_V4_GSMSSF_SCF_GENERIC.to_vec(),
        }
    }
}

/// An application-context OID handle (its arcs), e.g. for `node.assemble_begin`.
#[pyclass(name = "AppContext", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct MapAcHandle {
    #[pyo3(get)]
    arcs: Vec<u32>,
}

#[pymethods]
impl MapAcHandle {
    fn __repr__(&self) -> String {
        format!("AppContext({:?})", self.arcs)
    }
}

fn oid_arcs(oid: rasn::types::ObjectIdentifier) -> Vec<u32> {
    oid.iter().copied().collect()
}

/// The `gsm_cap` (CAMEL CAP, TS 29.078) namespace singleton.
#[pyclass(name = "GsmCap", module = "siphon")]
pub struct GsmCap;

#[pymethods]
impl GsmCap {
    /// The CAMEL CAP application-context helpers (`gsm_cap.AC.gsm_ssf_scf`).
    #[getter]
    #[allow(non_snake_case)]
    fn AC(&self) -> CapAc {
        CapAc
    }

    /// Terminate one or more CAMEL CAP operations, named by their kebab-case
    /// operation names, the same shape as `@gsm_map.on_operation`:
    ///
    /// ```python,ignore
    /// @gsm_cap.on_operation("initial-dp")        # a CAMEL initialDP
    /// @gsm_cap.on_operation("event-report-bcsm") # a gsmSSF EventReportBCSM
    /// ```
    ///
    /// Known names: `initial-dp`, `event-report-bcsm`. An unknown name raises
    /// `SigtranError` at decoration time.
    #[pyo3(signature = (arg=None))]
    fn on_operation<'py>(
        &self,
        py: Python<'py>,
        arg: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        on_operation_impl(py, arg, cap_op_table())
    }

    /// Open a CAP dialogue the node initiates (an SCP arming a call). Stages
    /// `invoke` as the opening operation of a `Begin` toward `called_gt` /
    /// `called_ssn` at point code `dpc` under application context `ac`, and
    /// `await`s the peer's first response as a [`PeerTurn`](PyPeerTurn). Same shape
    /// as `gsm_map.begin(...)`; the operation is carried by the staged invoke.
    #[pyo3(signature = (invoke, *, called_gt, called_ssn, calling_gt, calling_ssn, dpc, ac, opc=None, sls=0))]
    #[allow(clippy::too_many_arguments)]
    fn begin<'py>(
        &self,
        py: Python<'py>,
        invoke: &StagedInvoke,
        called_gt: &str,
        called_ssn: u8,
        calling_gt: &str,
        calling_ssn: u8,
        dpc: u32,
        ac: PyRef<'_, MapAcHandle>,
        opc: Option<u32>,
        sls: u8,
    ) -> PyResult<Bound<'py, PyAny>> {
        origination_begin(
            py,
            invoke,
            called_gt,
            called_ssn,
            calling_gt,
            calling_ssn,
            dpc,
            &ac,
            opc,
            sls,
        )
    }

    /// Stage a CAP Connect invoke: reroute the call to
    /// `destination_routing_address`, a list holding the one called-party number
    /// TS 29.078 allows (`SEQUENCE SIZE (1) OF CalledPartyNumber`), as a digit
    /// string or raw bytes. `original_called_party_id`, when given, preserves
    /// the originally dialled number across the reroute.
    #[pyo3(signature = (*, destination_routing_address, original_called_party_id=None))]
    fn connect(
        &self,
        destination_routing_address: Vec<Bound<'_, PyAny>>,
        original_called_party_id: Option<Bound<'_, PyAny>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ConnectArg;
        let [destination] = destination_routing_address.as_slice() else {
            return Err(err(
                "connect: destination_routing_address holds exactly one number in CAP",
            ));
        };
        let mut arg = ConnectArg::new(called_party(destination)?.into());
        arg.original_called_party_id = original_called_party_id
            .as_ref()
            .map(called_party)
            .transpose()?
            .map(Into::into);
        let bytes = gsm_cap::encode(&arg).map_err(err)?;
        Ok(StagedInvoke::new(
            gsm_cap::op_codes::CONNECT,
            Some(bytes),
            OperationClass::Two,
        ))
    }

    /// Stage a CAP ReleaseCall invoke: tear the call down with a Q.850 `cause`.
    #[pyo3(signature = (*, cause))]
    fn release_call(&self, cause: Vec<u8>) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ReleaseCallArg;
        // The CAP releaseCall argument is a bare `Cause` OCTET STRING, not a
        // SEQUENCE.
        let arg = ReleaseCallArg(cause.into());
        let bytes = gsm_cap::encode(&arg).map_err(err)?;
        Ok(StagedInvoke::new(
            gsm_cap::op_codes::RELEASE_CALL,
            Some(bytes),
            OperationClass::Four,
        ))
    }

    /// Stage a CAP RequestReportBCSMEvent invoke: arm the gsmSSF to report the
    /// given BCSM detection points. `events` is a list of `(event_type_bcsm,
    /// monitor_mode)` integer pairs (TS 29.078), e.g. `(7, 0)` = oAnswer
    /// interrupted. A third element names the leg the event is armed on:
    /// `(9, 1, 1)` = oDisconnect notifyAndContinue on leg 1. It goes out as
    /// `legID [2] { sendingSideID [0] }`. A disconnect event is armed per leg.
    #[pyo3(signature = (events))]
    fn request_report_bcsm_event(&self, events: Vec<Bound<'_, PyAny>>) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::RequestReportBcsmEventArg;
        use gsm_cap::types::{BcsmEvent, LegId};
        let bcsm_events = events
            .iter()
            .map(|event| {
                let (et, mm, leg) = bcsm_event_arg(event)?;
                let mut armed = BcsmEvent::new(event_type_bcsm(et)?, monitor_mode(mm)?);
                armed.leg_id = leg.map(LegId::sending);
                Ok(armed)
            })
            .collect::<PyResult<Vec<_>>>()?;
        let bytes = gsm_cap::encode(&RequestReportBcsmEventArg::new(bcsm_events)).map_err(err)?;
        Ok(StagedInvoke::new(
            gsm_cap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            Some(bytes),
            OperationClass::Two,
        ))
    }

    /// Stage a CAP ApplyCharging invoke: give the gsmSSF a call period to
    /// meter. `max_call_period_duration` is in units of 100 ms (TS 29.078);
    /// `release_if_duration_exceeded` has the gsmSSF release the call when it
    /// runs out, `tone` play a warning tone before that, and
    /// `tariff_switch_interval` (seconds) announces a tariff switch.
    /// `party_to_charge` is the leg to meter, as its number.
    ///
    /// The charging characteristics are not the same octets in CAMEL phase 3
    /// and phase 4, so they are encoded when the invoke is staged on a
    /// dialogue, from its application context. `phase=` (3 or 4) fixes the
    /// phase instead. `charging_characteristics=` hands over an already
    /// encoded CAMEL-AChBillingChargingCharacteristics value in place of the
    /// typed keywords.
    #[pyo3(signature = (*, max_call_period_duration=None, release_if_duration_exceeded=None, tariff_switch_interval=None, tone=None, party_to_charge=None, phase=None, charging_characteristics=None))]
    #[allow(clippy::too_many_arguments)]
    fn apply_charging(
        &self,
        max_call_period_duration: Option<u32>,
        release_if_duration_exceeded: Option<bool>,
        tariff_switch_interval: Option<u32>,
        tone: Option<bool>,
        party_to_charge: Option<u8>,
        phase: Option<u8>,
        charging_characteristics: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ApplyChargingArg;
        use gsm_cap::types::SendingSideId;
        let op = gsm_cap::op_codes::APPLY_CHARGING;
        match (max_call_period_duration, charging_characteristics) {
            (None, Some(encoded)) => {
                let mut arg = ApplyChargingArg::new(encoded.into());
                arg.party_to_charge = party_to_charge.map(SendingSideId::leg);
                let bytes = gsm_cap::encode(&arg).map_err(err)?;
                Ok(StagedInvoke::new(op, Some(bytes), OperationClass::Two))
            }
            (Some(max_call_period_duration), None) => {
                let arg = ContextualArg::CapApplyCharging {
                    max_call_period_duration,
                    release_if_duration_exceeded,
                    tariff_switch_interval,
                    tone,
                    party_to_charge,
                };
                match phase {
                    Some(phase) => {
                        let bytes = arg.encode_for_phase(phase).map_err(err)?;
                        Ok(StagedInvoke::new(op, Some(bytes), OperationClass::Two))
                    }
                    None => Ok(StagedInvoke::per_context(op, arg, OperationClass::Two)),
                }
            }
            _ => Err(err(
                "apply_charging: give max_call_period_duration or charging_characteristics",
            )),
        }
    }

    /// Stage a CAP Continue invoke: let the gsmSSF resume normal call processing
    /// at the detection point. It carries no argument.
    fn continue_(&self) -> StagedInvoke {
        StagedInvoke::new(gsm_cap::op_codes::CONTINUE, None, OperationClass::Four)
    }

    /// Stage a CAP ConnectToResource invoke (TS 29.078 11.10): connect the call
    /// to a gsmSRF at `ip_routing_address` (an E.164 digit string, encoded as an
    /// international CalledPartyNumber, or the octets of one), or, with none
    /// given, to the gsmSRF co-located with the gsmSSF. The gsmSSF then relays
    /// the PlayAnnouncement / PromptAndCollectUserInformation that follow.
    #[pyo3(signature = (*, ip_routing_address=None))]
    fn connect_to_resource(
        &self,
        ip_routing_address: Option<Bound<'_, PyAny>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ConnectToResourceArg;
        use gsm_cap::types::ResourceAddress;
        let address = match ip_routing_address {
            Some(number) => ResourceAddress::IpRoutingAddress(called_party(&number)?.into()),
            None => ResourceAddress::None(()),
        };
        staged_cap_invoke(
            gsm_cap::op_codes::CONNECT_TO_RESOURCE,
            &ConnectToResourceArg::new(address),
            OperationClass::Two,
        )
    }

    /// Stage a CAP PlayAnnouncement invoke (TS 29.078 11.23). What to send is a
    /// typed choice: an elementary announcement id (`message_id=`), a tone
    /// (`tone_id=`, `tone_duration=` seconds), or the BER of a CAP
    /// `InformationToSend` value (decoded and refused if it is not one).
    /// `request_announcement_complete=True` has the gsmSRF answer with a
    /// SpecializedResourceReport (operation 49) when it is done.
    #[pyo3(signature = (*, message_id=None, tone_id=None, tone_duration=None, information_to_send=None, disconnect_from_ip_forbidden=None, request_announcement_complete=None))]
    fn play_announcement(
        &self,
        message_id: Option<u32>,
        tone_id: Option<u32>,
        tone_duration: Option<u32>,
        information_to_send: Option<Vec<u8>>,
        disconnect_from_ip_forbidden: Option<bool>,
        request_announcement_complete: Option<bool>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::PlayAnnouncementArg;
        let info = cap_information_to_send(message_id, tone_id, tone_duration, information_to_send)?
            .ok_or_else(|| {
                err("play_announcement: give message_id, tone_id or information_to_send")
            })?;
        let mut arg = PlayAnnouncementArg::new(info);
        arg.disconnect_from_ip_forbidden = disconnect_from_ip_forbidden;
        arg.request_announcement_complete_notification = request_announcement_complete;
        staged_cap_invoke(
            gsm_cap::op_codes::PLAY_ANNOUNCEMENT,
            &arg,
            OperationClass::Two,
        )
    }

    /// Stage a CAP PromptAndCollectUserInformation invoke (TS 29.078 11.25):
    /// collect digits from the user, optionally after a prompt given as for
    /// `play_announcement`. Say what to collect with `maximum_digits=` (and
    /// `minimum_digits=`), or with `collected_info=`, the BER of a CAP
    /// `CollectedInfo` value. The digits come back in the result.
    #[pyo3(signature = (*, maximum_digits=None, minimum_digits=None, collected_info=None, disconnect_from_ip_forbidden=None, message_id=None, tone_id=None, tone_duration=None, information_to_send=None))]
    #[allow(clippy::too_many_arguments)]
    fn prompt_and_collect_user_information(
        &self,
        maximum_digits: Option<u8>,
        minimum_digits: Option<u8>,
        collected_info: Option<Vec<u8>>,
        disconnect_from_ip_forbidden: Option<bool>,
        message_id: Option<u32>,
        tone_id: Option<u32>,
        tone_duration: Option<u32>,
        information_to_send: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::PromptAndCollectUserInformationArg;
        use gsm_cap::types::{CollectedDigits, CollectedInfo};
        let what = match (maximum_digits, collected_info) {
            (Some(max), None) => {
                let mut digits = CollectedDigits::new(max);
                digits.minimum_nb_of_digits = minimum_digits;
                CollectedInfo::CollectedDigits(digits)
            }
            (None, Some(bytes)) => gsm_cap::decode::<CollectedInfo>(&bytes)
                .map_err(|e| err(format!("collected_info is not a CollectedInfo: {e}")))?,
            _ => {
                return Err(err(
                    "prompt_and_collect_user_information: give maximum_digits or collected_info",
                ))
            }
        };
        let mut arg = PromptAndCollectUserInformationArg::new(what);
        arg.disconnect_from_ip_forbidden = disconnect_from_ip_forbidden;
        arg.information_to_send =
            cap_information_to_send(message_id, tone_id, tone_duration, information_to_send)?;
        staged_cap_invoke(
            gsm_cap::op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
            &arg,
            OperationClass::One,
        )
    }

    /// Stage a CAP DisconnectForwardConnection invoke (TS 29.078 11.13): take
    /// the call off the gsmSRF after an announcement, before the instruction
    /// that goes on with it (Continue, Connect, ReleaseCall). It carries no
    /// argument.
    fn disconnect_forward_connection(&self) -> StagedInvoke {
        StagedInvoke::new(DISCONNECT_FORWARD_CONNECTION, None, OperationClass::Two)
    }

    /// Stage a CAP FurnishChargingInformation invoke (TS 29.078 11.19): free
    /// format data (1 to 160 octets) for the call record the MSC writes, for
    /// leg `party_to_charge` (default leg 1), replacing what an earlier one
    /// gave, or after it with `append=True`.
    #[pyo3(signature = (*, free_format_data, party_to_charge=None, append=None))]
    fn furnish_charging_information(
        &self,
        free_format_data: Vec<u8>,
        party_to_charge: Option<u8>,
        append: Option<bool>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::FurnishChargingInformationArg;
        use gsm_cap::types::{
            AppendFreeFormatData, CamelFciBillingChargingCharacteristics, FciBccCamelSequence1,
            SendingSideId,
        };
        if free_format_data.is_empty() || free_format_data.len() > 160 {
            return Err(err(format!(
                "furnish_charging_information: free_format_data is 1 to 160 octets, not {}",
                free_format_data.len()
            )));
        }
        let characteristics =
            CamelFciBillingChargingCharacteristics::FciBccCamelSequence1(FciBccCamelSequence1 {
                free_format_data: free_format_data.into(),
                party_to_charge: party_to_charge.map(SendingSideId::leg),
                append_free_format_data: append.map(|append| {
                    if append {
                        AppendFreeFormatData::Append
                    } else {
                        AppendFreeFormatData::Overwrite
                    }
                }),
            });
        let arg =
            FurnishChargingInformationArg::from_characteristics(&characteristics).map_err(err)?;
        staged_cap_invoke(
            gsm_cap::op_codes::FURNISH_CHARGING_INFORMATION,
            &arg,
            OperationClass::Two,
        )
    }

    /// Stage a CAP Cancel invoke (TS 29.078 11.8): cancel the announcement of
    /// the PlayAnnouncement / PromptAndCollectUserInformation invoke
    /// `invoke_id`, or, with `all_requests=True`, every outstanding request of
    /// the dialogue.
    #[pyo3(signature = (*, invoke_id=None, all_requests=false))]
    fn cancel(&self, invoke_id: Option<i64>, all_requests: bool) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::CancelArg;
        let arg = match (invoke_id, all_requests) {
            (Some(id), false) => CancelArg::InvokeId(i64::from(invoke_id_arg(id)?).into()),
            (None, true) => CancelArg::AllRequests(()),
            _ => return Err(err("cancel: give invoke_id or all_requests=True")),
        };
        staged_cap_invoke(gsm_cap::op_codes::CANCEL, &arg, OperationClass::Two)
    }

    fn __repr__(&self) -> String {
        "gsm_cap".to_string()
    }
}

/// Map a TS 29.078 EventTypeBCSM integer to the codec enum.
fn event_type_bcsm(v: i64) -> PyResult<gsm_cap::types::EventTypeBcsm> {
    use gsm_cap::types::EventTypeBcsm as E;
    Ok(match v {
        2 => E::CollectedInfo,
        3 => E::AnalysedInformation,
        4 => E::RouteSelectFailure,
        5 => E::OCalledPartyBusy,
        6 => E::ONoAnswer,
        7 => E::OAnswer,
        8 => E::OMidCall,
        9 => E::ODisconnect,
        10 => E::OAbandon,
        12 => E::TermAttemptAuthorized,
        13 => E::TBusy,
        14 => E::TNoAnswer,
        15 => E::TAnswer,
        16 => E::TMidCall,
        17 => E::TDisconnect,
        18 => E::TAbandon,
        19 => E::OTermSeized,
        27 => E::CallAccepted,
        50 => E::OChangeOfPosition,
        51 => E::TChangeOfPosition,
        52 => E::OServiceChange,
        53 => E::TServiceChange,
        _ => return Err(err(format!("unknown EventTypeBCSM {v}"))),
    })
}

/// Map a TS 29.078 MonitorMode integer to the codec enum.
fn monitor_mode(v: i64) -> PyResult<gsm_cap::types::MonitorMode> {
    use gsm_cap::types::MonitorMode as M;
    Ok(match v {
        0 => M::Interrupted,
        1 => M::NotifyAndContinue,
        2 => M::Transparent,
        _ => return Err(err(format!("unknown MonitorMode {v}"))),
    })
}

// ── The `inap` namespace ─────────────────────────────────────────────────────

/// The `inap` (INAP CS-1, ITU-T Q.1218 / ETSI EN 300 374-1) namespace singleton.
///
/// INAP is a TCAP-user peer to CAMEL CAP: an IN SCP terminates the SSF-SCF
/// dialogue the same way `gsm_cap` terminates a CAMEL one, but with the
/// fixed-network INAP operation set and the IN application contexts. The
/// termination decorators register a handler per (owned SSN, INAP opcode); the
/// originating builders stage the SCF-to-SSF invokes an SCP sends. Both feed the
/// same [`PyDialogue`] / [`DialogueEngine`] path the CAMEL surface uses.
#[pyclass(name = "Inap", module = "siphon")]
pub struct Inap;

#[pymethods]
impl Inap {
    /// The INAP application-context helpers (`inap.AC.ssp_to_scp`).
    #[getter]
    #[allow(non_snake_case)]
    fn AC(&self) -> InapAc {
        InapAc
    }

    // ── Termination decorators (SSF -> SCF, the SCP terminates) ──

    /// Terminate one or more INAP CS-1 operations, named by their kebab-case
    /// operation names, the same shape as `@gsm_map.on_operation`:
    ///
    /// ```python,ignore
    /// @inap.on_operation("initial-dp")            # the SSF reports a triggered call
    /// @inap.on_operation("event-report-bcsm")     # an armed detection point fired
    /// ```
    ///
    /// An `initial-dp` handler reads the decoded argument off the
    /// [`IncomingOp`](PyIncomingOp) `inap_*` getters (`inap_service_key` /
    /// `inap_called_party_number` / …). Known names: `initial-dp`,
    /// `event-report-bcsm`, `apply-charging-report`, `assist-request-instructions`,
    /// `call-information-report`, `specialized-resource-report`. An unknown name
    /// raises `SigtranError` at decoration time.
    #[pyo3(signature = (arg=None))]
    fn on_operation<'py>(
        &self,
        py: Python<'py>,
        arg: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        on_operation_impl(py, arg, inap_op_table())
    }

    /// Open an INAP CS-1 dialogue the node initiates (an SCP toward the SSF).
    /// Stages `invoke` as the opening operation of a `Begin` toward `called_gt` /
    /// `called_ssn` at point code `dpc` under application context `ac`, and
    /// `await`s the peer's first response as a [`PeerTurn`](PyPeerTurn). Same shape
    /// as `gsm_map.begin(...)`; the operation is carried by the staged invoke.
    #[pyo3(signature = (invoke, *, called_gt, called_ssn, calling_gt, calling_ssn, dpc, ac, opc=None, sls=0))]
    #[allow(clippy::too_many_arguments)]
    fn begin<'py>(
        &self,
        py: Python<'py>,
        invoke: &StagedInvoke,
        called_gt: &str,
        called_ssn: u8,
        calling_gt: &str,
        calling_ssn: u8,
        dpc: u32,
        ac: PyRef<'_, MapAcHandle>,
        opc: Option<u32>,
        sls: u8,
    ) -> PyResult<Bound<'py, PyAny>> {
        origination_begin(
            py,
            invoke,
            called_gt,
            called_ssn,
            calling_gt,
            calling_ssn,
            dpc,
            &ac,
            opc,
            sls,
        )
    }

    // ── Originating builders (SCF -> SSF, the SCP instructs) ──

    /// Stage an INAP RequestReportBCSMEvent invoke: arm the SSF to report the
    /// given BCSM detection points. `events` is a list of `(event_type_bcsm,
    /// monitor_mode)` integer pairs (ITU-T Q.1218), e.g. `(7, 0)` = oAnswer
    /// interrupted, `(9, 1)` = oDisconnect notifyAndContinue. A third element
    /// names the leg the event is armed on, as its number: `(9, 1, 2)` =
    /// oDisconnect on leg 2. It goes out as `legID [2] { sendingSideID [0] }`,
    /// the form an SCF uses toward the SSF.
    #[pyo3(signature = (events))]
    fn request_report_bcsm_event(&self, events: Vec<Bound<'_, PyAny>>) -> PyResult<StagedInvoke> {
        use inap::operations::RequestReportBcsmEventArg;
        use inap::types::{BcsmEvent, LegId};
        let bcsm_events = events
            .iter()
            .map(|event| {
                let (et, mm, leg) = bcsm_event_arg(event)?;
                let mut armed = BcsmEvent::new(inap_event_type_bcsm(et)?, inap_monitor_mode(mm)?);
                armed.leg_id = leg.map(LegId::sending);
                Ok(armed)
            })
            .collect::<PyResult<Vec<_>>>()?;
        staged_inap_invoke(
            inap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            &RequestReportBcsmEventArg::new(bcsm_events),
            OperationClass::Two,
        )
    }

    /// Stage an INAP Connect invoke: instruct the SSF to route the call to
    /// `destination_routing_address` (a list of called-party numbers, each a digit
    /// string or raw bytes; ETS 300 374-1 allows exactly one, Q.1218 up to
    /// three). `original_called_party_id`, when given, preserves the originally
    /// dialled number across the reroute.
    #[pyo3(signature = (*, destination_routing_address, original_called_party_id=None))]
    fn connect(
        &self,
        destination_routing_address: Vec<Bound<'_, PyAny>>,
        original_called_party_id: Option<Bound<'_, PyAny>>,
    ) -> PyResult<StagedInvoke> {
        use inap::operations::ConnectArg;
        let mut dra = destination_routing_address
            .iter()
            .map(called_party)
            .collect::<PyResult<Vec<_>>>()?
            .into_iter()
            .map(Into::into);
        let first = dra
            .next()
            .ok_or_else(|| err("connect: destination_routing_address is empty"))?;
        let mut arg = ConnectArg::new(first);
        arg.destination_routing_address.extend(dra);
        arg.original_called_party_id = original_called_party_id
            .as_ref()
            .map(called_party)
            .transpose()?
            .map(Into::into);
        staged_inap_invoke(inap::op_codes::CONNECT, &arg, OperationClass::Two)
    }

    /// Stage an INAP Continue invoke: let the SSF resume normal call processing
    /// at the detection point. It carries no argument.
    fn continue_(&self) -> StagedInvoke {
        StagedInvoke::new(inap::op_codes::CONTINUE, None, OperationClass::Four)
    }

    /// Stage an INAP ReleaseCall invoke: tear the call down with a Q.850 `cause`.
    #[pyo3(signature = (*, cause))]
    fn release_call(&self, cause: Vec<u8>) -> PyResult<StagedInvoke> {
        use inap::operations::ReleaseCallArg;
        let arg = ReleaseCallArg(cause.into());
        staged_inap_invoke(inap::op_codes::RELEASE_CALL, &arg, OperationClass::Four)
    }

    /// Stage an INAP ApplyCharging invoke: install the encoded charging
    /// characteristics at the SSF (an online-charging control, e.g. a
    /// call-duration limit). `party_to_charge`, when given, names the leg to
    /// meter as its sending-side identity.
    #[pyo3(signature = (*, charging_characteristics, party_to_charge=None))]
    fn apply_charging(
        &self,
        charging_characteristics: Vec<u8>,
        party_to_charge: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use inap::operations::ApplyChargingArg;
        use inap::types::LegId;
        let mut arg = ApplyChargingArg::new(charging_characteristics.into());
        arg.party_to_charge = party_to_charge.map(|l| LegId::SendingSideId(l.into()));
        staged_inap_invoke(inap::op_codes::APPLY_CHARGING, &arg, OperationClass::Two)
    }

    /// Stage an INAP PlayAnnouncement invoke: instruct the SRF to play an
    /// announcement or a tone. Say what to send in one of three ways:
    /// `message_id=` (an elementary announcement id), `tone_id=` (with an
    /// optional `tone_duration=` in seconds), or `information_to_send=`, the BER
    /// encoding of an `InformationToSend` value for anything else (it is decoded
    /// and refused if it is not one). `disconnect_from_ip_forbidden` keeps the
    /// SRF connection up afterwards; `request_announcement_complete` asks for a
    /// specializedResourceReport once it finishes.
    #[pyo3(signature = (*, message_id=None, tone_id=None, tone_duration=None, information_to_send=None, disconnect_from_ip_forbidden=None, request_announcement_complete=None))]
    fn play_announcement(
        &self,
        message_id: Option<u32>,
        tone_id: Option<u32>,
        tone_duration: Option<u32>,
        information_to_send: Option<Vec<u8>>,
        disconnect_from_ip_forbidden: Option<bool>,
        request_announcement_complete: Option<bool>,
    ) -> PyResult<StagedInvoke> {
        use inap::operations::PlayAnnouncementArg;
        let info =
            inap_information_to_send(message_id, tone_id, tone_duration, information_to_send)?
                .ok_or_else(|| {
                    err("play_announcement: give message_id, tone_id or information_to_send")
                })?;
        let mut arg = PlayAnnouncementArg::new(info);
        arg.disconnect_from_ip_forbidden = disconnect_from_ip_forbidden;
        arg.request_announcement_complete = request_announcement_complete;
        staged_inap_invoke(inap::op_codes::PLAY_ANNOUNCEMENT, &arg, OperationClass::Two)
    }

    /// Stage an INAP PromptAndCollectUserInformation invoke: instruct the SRF to
    /// collect digits from the user, optionally after playing a prompt. Say
    /// what to collect with `maximum_digits=` (and `minimum_digits=`), or with
    /// `collected_info=`, the BER encoding of a `CollectedInfo` value. The
    /// prompt is given as for `play_announcement` (`message_id=`, `tone_id=`,
    /// `information_to_send=`), or left out.
    #[pyo3(signature = (*, maximum_digits=None, minimum_digits=None, collected_info=None, disconnect_from_ip_forbidden=None, message_id=None, tone_id=None, tone_duration=None, information_to_send=None))]
    #[allow(clippy::too_many_arguments)]
    fn prompt_and_collect_user_information(
        &self,
        maximum_digits: Option<u8>,
        minimum_digits: Option<u8>,
        collected_info: Option<Vec<u8>>,
        disconnect_from_ip_forbidden: Option<bool>,
        message_id: Option<u32>,
        tone_id: Option<u32>,
        tone_duration: Option<u32>,
        information_to_send: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use inap::operations::PromptAndCollectUserInformationArg;
        use inap::types::{CollectedDigits, CollectedInfo};
        let what =
            match (maximum_digits, collected_info) {
                (Some(max), None) => {
                    let mut digits = CollectedDigits::new(max);
                    digits.minimum_nb_of_digits = minimum_digits;
                    CollectedInfo::CollectedDigits(digits)
                }
                (None, Some(bytes)) => inap::decode::<CollectedInfo>(&bytes)
                    .map_err(|e| err(format!("collected_info is not a CollectedInfo: {e}")))?,
                _ => return Err(err(
                    "prompt_and_collect_user_information: give maximum_digits or collected_info",
                )),
            };
        let mut arg = PromptAndCollectUserInformationArg::new(what);
        arg.disconnect_from_ip_forbidden = disconnect_from_ip_forbidden;
        arg.information_to_send =
            inap_information_to_send(message_id, tone_id, tone_duration, information_to_send)?;
        staged_inap_invoke(
            inap::op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
            &arg,
            OperationClass::One,
        )
    }

    /// Stage an INAP ConnectToResource invoke: connect the call to a specialised
    /// resource at `ip_routing_address` (a called-party-number byte string), or,
    /// with none given, to the SRF colocated with the SSF.
    #[pyo3(signature = (*, ip_routing_address=None))]
    fn connect_to_resource(&self, ip_routing_address: Option<Vec<u8>>) -> PyResult<StagedInvoke> {
        use inap::operations::ConnectToResourceArg;
        use inap::types::ResourceAddress;
        let address = match ip_routing_address {
            Some(address) => ResourceAddress::IpRoutingAddress(address.into()),
            None => ResourceAddress::None(()),
        };
        staged_inap_invoke(
            inap::op_codes::CONNECT_TO_RESOURCE,
            &ConnectToResourceArg::new(address),
            OperationClass::Two,
        )
    }

    fn __repr__(&self) -> String {
        "inap".to_string()
    }
}

/// `inap.AC`, INAP CS-1 application-context helpers.
#[pyclass(name = "InapAc", module = "siphon")]
pub struct InapAc;

#[pymethods]
impl InapAc {
    /// cs1-ssp-to-scp, the Core INAP CS-1 SSP-to-SCP application context
    /// (`0.4.0.1.1.1.0.0`, ETS 300 374-1 clause 6.5). Carried in the AARQ of a
    /// dialogue the node opens toward an SSF.
    #[getter]
    fn ssp_to_scp(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: oid_arcs(inap::application_context::cs1_ssp_to_scp()),
        }
    }

    /// cs1-assist-handoff-ssp-to-scp (`0.4.0.1.1.1.1.0`): the dialogue an
    /// assisting or handed-off SSP opens with AssistRequestInstructions.
    #[getter]
    fn assist_handoff_ssp_to_scp(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: oid_arcs(inap::application_context::cs1_assist_handoff_ssp_to_scp()),
        }
    }

    /// cs1-ip-to-scp (`0.4.0.1.1.1.2.0`): the dialogue an intelligent
    /// peripheral opens with AssistRequestInstructions.
    #[getter]
    fn ip_to_scp(&self) -> MapAcHandle {
        MapAcHandle {
            arcs: oid_arcs(inap::application_context::cs1_ip_to_scp()),
        }
    }
}

/// Encode an INAP operation argument to BER and stage it as an `Invoke` for
/// `dlg.invoke(...)`, carrying the operation code.
fn staged_inap_invoke<T: rasn::Encode>(
    op: i64,
    arg: &T,
    class: OperationClass,
) -> PyResult<StagedInvoke> {
    let bytes = inap::encode(arg).map_err(err)?;
    Ok(StagedInvoke::new(op, Some(bytes), class))
}

/// `disconnectForwardConnection` (TS 29.078 clause 5.3). gsm_cap 3 has no
/// constant for it: the operation has no argument and so no type there.
const DISCONNECT_FORWARD_CONNECTION: i64 = 18;

/// Encode a CAP argument to BER and stage it as an `Invoke` of `op`.
fn staged_cap_invoke<T: rasn::Encode>(
    op: i64,
    arg: &T,
    class: OperationClass,
) -> PyResult<StagedInvoke> {
    let bytes = gsm_cap::encode(arg).map_err(err)?;
    Ok(StagedInvoke::new(op, Some(bytes), class))
}

/// The CAP `InformationToSend` of a PlayAnnouncement or a prompt: an
/// elementary message id, a tone, or the BER of a value, exactly one of them;
/// `None` when none is given.
fn cap_information_to_send(
    message_id: Option<u32>,
    tone_id: Option<u32>,
    tone_duration: Option<u32>,
    encoded: Option<Vec<u8>>,
) -> PyResult<Option<gsm_cap::types::InformationToSend>> {
    use gsm_cap::types::{InbandInfo, InformationToSend, MessageId, Tone};
    Ok(match (message_id, tone_id, encoded) {
        (None, None, None) => None,
        (Some(id), None, None) => Some(InformationToSend::InbandInfo(InbandInfo::new(
            MessageId::ElementaryMessageId(id),
        ))),
        (None, Some(tone_id), None) => Some(InformationToSend::Tone(Tone {
            tone_id,
            duration: tone_duration,
        })),
        (None, None, Some(bytes)) => Some(
            gsm_cap::decode::<InformationToSend>(&bytes)
                .map_err(|e| err(format!("information_to_send is not an InformationToSend: {e}")))?,
        ),
        _ => {
            return Err(err(
                "give one of message_id, tone_id and information_to_send, not several",
            ))
        }
    })
}

/// One `events` entry of a RequestReportBCSMEvent builder: `(event_type,
/// monitor_mode)` or `(event_type, monitor_mode, leg)`.
fn bcsm_event_arg(event: &Bound<'_, PyAny>) -> PyResult<(i64, i64, Option<u8>)> {
    if let Ok((et, mm, leg)) = event.extract::<(i64, i64, u8)>() {
        return Ok((et, mm, Some(leg)));
    }
    let (et, mm) = event.extract::<(i64, i64)>().map_err(|_| {
        err("each event is (event_type_bcsm, monitor_mode) or (event_type_bcsm, monitor_mode, leg)")
    })?;
    Ok((et, mm, None))
}

/// The `InformationToSend` of PlayAnnouncement / PromptAndCollectUserInformation
/// from the builder keywords: an elementary message id, a tone, or the BER of a
/// value. `None` when none of them is given.
fn inap_information_to_send(
    message_id: Option<u32>,
    tone_id: Option<u32>,
    tone_duration: Option<u32>,
    encoded: Option<Vec<u8>>,
) -> PyResult<Option<inap::types::InformationToSend>> {
    use inap::types::{InbandInfo, InformationToSend, MessageId, Tone};
    Ok(match (message_id, tone_id, encoded) {
        (None, None, None) => None,
        (Some(id), None, None) => Some(InformationToSend::InbandInfo(InbandInfo::new(
            MessageId::ElementaryMessageId(id),
        ))),
        (None, Some(tone_id), None) => Some(InformationToSend::Tone(Tone {
            tone_id,
            duration: tone_duration,
        })),
        (None, None, Some(bytes)) => {
            Some(inap::decode::<InformationToSend>(&bytes).map_err(|e| {
                err(format!(
                    "information_to_send is not an InformationToSend: {e}"
                ))
            })?)
        }
        _ => {
            return Err(err(
                "give one of message_id, tone_id and information_to_send, not several",
            ))
        }
    })
}

/// Map an ITU-T Q.1218 EventTypeBCSM integer to the INAP codec enum.
fn inap_event_type_bcsm(v: i64) -> PyResult<inap::types::EventTypeBcsm> {
    use inap::types::EventTypeBcsm as E;
    Ok(match v {
        1 => E::OrigAttemptAuthorized,
        2 => E::CollectedInfo,
        3 => E::AnalysedInformation,
        4 => E::RouteSelectFailure,
        5 => E::OCalledPartyBusy,
        6 => E::ONoAnswer,
        7 => E::OAnswer,
        8 => E::OMidCall,
        9 => E::ODisconnect,
        10 => E::OAbandon,
        12 => E::TermAttemptAuthorized,
        13 => E::TBusy,
        14 => E::TNoAnswer,
        15 => E::TAnswer,
        16 => E::TMidCall,
        17 => E::TDisconnect,
        18 => E::TAbandon,
        _ => return Err(err(format!("unknown EventTypeBCSM {v}"))),
    })
}

/// Map an ITU-T Q.1218 MonitorMode integer to the INAP codec enum.
fn inap_monitor_mode(v: i64) -> PyResult<inap::types::MonitorMode> {
    use inap::types::MonitorMode as M;
    Ok(match v {
        0 => M::Interrupted,
        1 => M::NotifyAndContinue,
        2 => M::Transparent,
        _ => return Err(err(format!("unknown MonitorMode {v}"))),
    })
}

/// Register a Python termination handler for `op` on every owned subsystem (so
/// the handler fires whichever local SSN the message was addressed to).
fn register_termination(op: i64, func: &Bound<'_, PyAny>) {
    register_termination_inner(op, func, false);
}

/// Register a Python catch-all handler for `op` on every owned subsystem. It is
/// lower priority than a specific [`register_termination`], so a bare
/// `@ns.on_operation` never shadows an explicit `on_operation("<name>")`,
/// whichever registered first.
fn register_catch_all(op: i64, func: &Bound<'_, PyAny>) {
    register_termination_inner(op, func, true);
}

fn register_termination_inner(op: i64, func: &Bound<'_, PyAny>, catch_all: bool) {
    let n = node();
    let mut engine = n.engine.lock().unwrap_or_else(|e| e.into_inner());
    let ssns: Vec<u8> = if n.local_ssns.is_empty() {
        // No configured owned SSNs (an unconfigured node): register on the MAP
        // and CAP subsystems so a standalone script still terminates.
        vec![6, 8, SubsystemNumber::Cap.value()]
    } else {
        n.local_ssns.clone()
    };
    for ssn in ssns {
        let handler: Arc<dyn TerminationHandler> = Arc::new(PyHandler {
            func: func.clone().unbind(),
        });
        if catch_all {
            engine.register_fallback(ssn, op, handler);
        } else {
            engine.register(ssn, op, handler);
        }
    }
}

/// A namespace's terminatable operations as `(kebab-name, local operation code)`.
/// The names are the same tokens the content-rule `operation:` selector and
/// `node.assemble_begin(op=...)` use, so one vocabulary spans the whole surface.
type OpTable = &'static [(&'static str, i64)];

/// The polymorphic `on_operation` decorator shared by the `gsm_map` / `gsm_cap` /
/// `inap` namespaces. It mirrors the sibling `@smpp.on_pdu` and the SIP proxy's
/// `@proxy.on_request`:
///
/// * bare `@ns.on_operation` — a catch-all over every operation in `table`
/// * `@ns.on_operation("mo-forward-sm")` — one operation
/// * `@ns.on_operation("mo-forward-sm|mt-forward-sm")` — several, pipe-separated
/// * `@ns.on_operation()` — the catch-all in decorator-call form
///
/// Names are validated against `table` at decoration time, so a typo raises a
/// `SigtranError` instead of registering a handler that never fires.
fn on_operation_impl<'py>(
    py: Python<'py>,
    arg: Option<Bound<'py, PyAny>>,
    table: OpTable,
) -> PyResult<Bound<'py, PyAny>> {
    match arg {
        // Bare decorator `@ns.on_operation` — the argument is the handler itself;
        // register it as a catch-all over every operation now and return it.
        Some(value) if value.is_callable() => {
            for (_, op) in table {
                register_catch_all(*op, &value);
            }
            Ok(value)
        }
        // `@ns.on_operation("a|b")` — a filter string; return a specific decorator.
        Some(value) => {
            let filter: String = value.extract().map_err(|_| {
                err("on_operation expects a handler function or an operation-name string")
            })?;
            let ops = resolve_op_filter(&filter, table)?;
            make_on_operation_decorator(py, ops, false)
        }
        // `@ns.on_operation()` — empty parens; a catch-all decorator, matching the
        // sibling addons' `@proxy.on_request()`.
        None => {
            let ops = table.iter().map(|(_, op)| *op).collect();
            make_on_operation_decorator(py, ops, true)
        }
    }
}

/// Resolve an `on_operation` filter (`"a"` or `"a|b|c"`) to op codes, validating
/// each name against `table`.
fn resolve_op_filter(filter: &str, table: OpTable) -> PyResult<Vec<i64>> {
    let mut ops = Vec::new();
    for name in filter.split('|') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        match table.iter().find(|(n, _)| *n == name) {
            Some((_, op)) => ops.push(*op),
            None => {
                let known = table.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
                return Err(err(format!(
                    "unknown operation {name:?} in on_operation filter; known: {known}"
                )));
            }
        }
    }
    if ops.is_empty() {
        return Err(err("empty on_operation filter"));
    }
    Ok(ops)
}

/// Build the decorator closure `on_operation(...)` returns: it registers its
/// argument (the handler) for each resolved op code and returns it unchanged.
/// `catch_all` picks the lower-priority [`register_catch_all`] path (the bare /
/// empty-parens form) over the specific [`register_termination`] one.
fn make_on_operation_decorator(
    py: Python<'_>,
    ops: Vec<i64>,
    catch_all: bool,
) -> PyResult<Bound<'_, PyAny>> {
    let closure = pyo3::types::PyCFunction::new_closure(
        py,
        None,
        None,
        move |args: &Bound<'_, PyTuple>,
              _kwargs: Option<&Bound<'_, PyDict>>|
              -> PyResult<Py<PyAny>> {
            let func = args.get_item(0)?;
            for op in &ops {
                if catch_all {
                    register_catch_all(*op, &func);
                } else {
                    register_termination(*op, &func);
                }
            }
            Ok(func.unbind())
        },
    )?;
    Ok(closure.into_any())
}

/// The MAP (TS 29.002) operations a `@gsm_map.on_operation(...)` handler can
/// terminate. Codes come from the published `gsm_map` codec.
fn map_op_table() -> OpTable {
    &[
        ("mo-forward-sm", gsm_map::op_codes::MO_FORWARD_SM),
        ("mt-forward-sm", gsm_map::op_codes::MT_FORWARD_SM),
        ("sri-sm", gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM),
        (
            "report-sm-delivery-status",
            gsm_map::op_codes::REPORT_SM_DELIVERY_STATUS,
        ),
        ("ready-for-sm", gsm_map::op_codes::READY_FOR_SM),
        ("update-location", gsm_map::op_codes::UPDATE_LOCATION),
        ("cancel-location", gsm_map::op_codes::CANCEL_LOCATION),
        ("purge-ms", gsm_map::op_codes::PURGE_MS),
        (
            "send-auth-info",
            gsm_map::op_codes::SEND_AUTHENTICATION_INFO,
        ),
        (
            "provide-subscriber-info",
            gsm_map::operations::subscriber_info::op_codes::PROVIDE_SUBSCRIBER_INFO,
        ),
    ]
}

/// The CAMEL CAP (TS 29.078) operations a `@gsm_cap.on_operation(...)` handler
/// can terminate.
fn cap_op_table() -> OpTable {
    &[
        ("initial-dp", gsm_cap::op_codes::INITIAL_DP),
        ("event-report-bcsm", gsm_cap::op_codes::EVENT_REPORT_BCSM),
    ]
}

/// The INAP CS-1 (ITU-T Q.1218) operations an `@inap.on_operation(...)` handler
/// can terminate.
fn inap_op_table() -> OpTable {
    &[
        ("initial-dp", inap::op_codes::INITIAL_DP),
        ("event-report-bcsm", inap::op_codes::EVENT_REPORT_BCSM),
        (
            "apply-charging-report",
            inap::op_codes::APPLY_CHARGING_REPORT,
        ),
        (
            "assist-request-instructions",
            inap::op_codes::ASSIST_REQUEST_INSTRUCTIONS,
        ),
        (
            "call-information-report",
            inap::op_codes::CALL_INFORMATION_REPORT,
        ),
        (
            "specialized-resource-report",
            inap::op_codes::SPECIALIZED_RESOURCE_REPORT,
        ),
    ]
}

/// Resolve a kebab-case operation name to its local op code across the MAP, CAP
/// and INAP termination vocabularies (every name an `on_operation` accepts), so
/// the loopback [`Node::assemble_begin`] shares one vocabulary with the
/// decorators. Falls back to the content-router operation set for the invoke-only
/// names (`connect`, `insert-subscriber-data`). Overlapping names (`initial-dp`,
/// `event-report-bcsm`) carry the same code in every table, so the merge is
/// unambiguous; the application context tells CAP and INAP apart on the wire.
fn operation_op_code(name: &str) -> Option<i64> {
    map_op_table()
        .iter()
        .chain(cap_op_table())
        .chain(inap_op_table())
        .find(|(n, _)| *n == name)
        .map(|(_, op)| *op)
        .or_else(|| Operation::from_kebab(name).map(Operation::op_code))
}

// ── A decoded outbound message (loopback / test seam) ────────────────────────

/// A read-only decode of an outbound TCAP message, produced by
/// [`Node::decode`](Node) for loopback / tests.
#[pyclass(name = "Decoded", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct PyDecoded {
    /// `begin` / `continue` / `end` / `abort` / `unidirectional`.
    #[pyo3(get)]
    kind: String,
    otid: Vec<u8>,
    dtid: Vec<u8>,
    /// The AARQ or AARE application-context OID arcs, if the message carried one.
    #[pyo3(get)]
    app_context: Option<Vec<u32>>,
    invokes: Vec<(i64, Option<Vec<u8>>)>,
    result: Option<(i64, Option<Vec<u8>>)>,
    /// The invoke id of the first `ReturnResultLast`, with or without a result.
    result_invoke_id: Option<i64>,
    error: Option<(i64, i64)>,
    /// Every Reject as `(invoke_id, problem)`.
    rejects: Vec<(Option<i64>, Problem)>,
    /// `p-abort` / `u-abort` for an Abort.
    #[pyo3(get)]
    abort_kind: Option<&'static str>,
    /// The P-Abort cause value of a P-Abort.
    #[pyo3(get)]
    p_abort_cause: Option<i64>,
    /// The abort-source of the ABRT APDU a U-Abort carries (0 dialogue-service-
    /// user, 1 dialogue-service-provider), if it carries one.
    #[pyo3(get)]
    abort_source: Option<i64>,
}

/// The parts of a decoded TCAP message [`PyDecoded::from_tcap`] pulls out: the
/// kind, the transaction ids, and borrows of the dialogue portion + components.
type MsgParts<'a> = (
    &'static str,
    Vec<u8>,
    Vec<u8>,
    Option<&'a DialoguePortion>,
    Option<&'a Vec<Component>>,
);

/// A `ReturnResultLast` for a staged result. Q.773 3.1: the result sequence is
/// there with its operation code and parameter, or not at all.
fn staged_result_component(invoke_id: i8, res: &StagedResult) -> Component {
    Component::ReturnResultLast(ReturnResult {
        invoke_id,
        result: res.param.clone().map(|parameter| ReturnResultValue {
            operation_code: OperationCode::Local(res.op),
            parameter: Some(rasn::types::Any::new(parameter)),
        }),
    })
}

/// Pull the first local `returnResult` out as `(op, parameter)`.
fn first_local_result(rr: &ReturnResult) -> Option<(i64, Option<Vec<u8>>)> {
    let v = rr.result.as_ref()?;
    match v.operation_code {
        OperationCode::Local(op) => Some((op, v.parameter.as_ref().map(|p| p.as_bytes().to_vec()))),
        OperationCode::Global(_) => None,
    }
}

impl PyDecoded {
    fn from_tcap(msg: &TcapMessage) -> Self {
        let (kind, otid, dtid, dp, comps): MsgParts<'_> = match msg {
            TcapMessage::Begin(b) => (
                "begin",
                b.otid.to_vec(),
                Vec::new(),
                b.dialogue_portion.as_ref(),
                b.components.as_ref(),
            ),
            TcapMessage::Continue(c) => (
                "continue",
                c.otid.to_vec(),
                c.dtid.to_vec(),
                c.dialogue_portion.as_ref(),
                c.components.as_ref(),
            ),
            TcapMessage::End(e) => (
                "end",
                Vec::new(),
                e.dtid.to_vec(),
                e.dialogue_portion.as_ref(),
                e.components.as_ref(),
            ),
            TcapMessage::Abort(a) => (
                "abort",
                Vec::new(),
                a.dtid.to_vec(),
                msg.dialogue_portion(),
                None,
            ),
            TcapMessage::Unidirectional(_) => {
                ("unidirectional", Vec::new(), Vec::new(), None, None)
            }
        };

        // The message came out of the strict decoder, so its dialogue portion
        // parses; one that does not is shown as carrying no APDU.
        let pdu = dp.and_then(|d| d.dialogue_pdu().ok().flatten());
        let app_context = pdu.as_ref().and_then(|pdu| match pdu {
            DialoguePdu::Aarq {
                application_context_name,
                ..
            }
            | DialoguePdu::Aare {
                application_context_name,
                ..
            } => Some(application_context_name.as_ref().to_vec()),
            _ => None,
        });
        let (abort_kind, p_abort_cause, abort_source) = match msg {
            TcapMessage::Abort(a) => match a.p_abort_cause() {
                Some(cause) => (Some("p-abort"), Some(cause.value()), None),
                None => (
                    Some("u-abort"),
                    None,
                    match &pdu {
                        Some(DialoguePdu::Abrt { abort_source, .. }) => Some(abort_source.value()),
                        _ => None,
                    },
                ),
            },
            _ => (None, None, None),
        };

        let mut invokes = Vec::new();
        let mut result = None;
        let mut result_invoke_id = None;
        let mut error = None;
        let mut rejects = Vec::new();
        if let Some(cs) = comps {
            for c in cs {
                match c {
                    Component::Invoke(inv) => {
                        if let OperationCode::Local(op) = inv.operation_code {
                            invokes
                                .push((op, inv.parameter.as_ref().map(|p| p.as_bytes().to_vec())));
                        }
                    }
                    Component::ReturnResultLast(rr) | Component::ReturnResultNotLast(rr) => {
                        if result.is_none() {
                            result = first_local_result(rr);
                        }
                        result_invoke_id.get_or_insert(i64::from(rr.invoke_id));
                    }
                    Component::ReturnError(re) => {
                        if let ErrorCode::Local(code) = re.error_code {
                            error.get_or_insert((i64::from(re.invoke_id), code));
                        }
                    }
                    Component::Reject(rj) => {
                        rejects.push((rj.invoke_id.map(i64::from), rj.problem));
                    }
                }
            }
        }

        PyDecoded {
            kind: kind.to_string(),
            otid,
            dtid,
            app_context,
            invokes,
            result,
            result_invoke_id,
            error,
            rejects,
            abort_kind,
            p_abort_cause,
            abort_source,
        }
    }
}

#[pymethods]
impl PyDecoded {
    /// The originating transaction id (bytes).
    #[getter]
    fn otid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.otid)
    }

    /// The destination transaction id (bytes).
    #[getter]
    fn dtid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.dtid)
    }

    /// The first `Invoke` as `(operation_code, argument_bytes_or_None)`, if any.
    #[getter]
    fn invoke<'py>(&self, py: Python<'py>) -> Option<(i64, Option<Bound<'py, PyBytes>>)> {
        self.invokes
            .first()
            .map(|(op, p)| (*op, p.as_ref().map(|b| PyBytes::new(py, b))))
    }

    /// Every `Invoke` the message carried, as `(operation_code, argument)` pairs
    /// (a message can stage several, e.g. a RequestReportBCSMEvent then a Connect).
    #[getter]
    fn invokes<'py>(&self, py: Python<'py>) -> Vec<(i64, Option<Bound<'py, PyBytes>>)> {
        self.invokes
            .iter()
            .map(|(op, p)| (*op, p.as_ref().map(|b| PyBytes::new(py, b))))
            .collect()
    }

    /// The first `ReturnResultLast` as `(operation_code, parameter_bytes_or_None)`.
    #[getter]
    fn result<'py>(&self, py: Python<'py>) -> Option<(i64, Option<Bound<'py, PyBytes>>)> {
        self.result
            .as_ref()
            .map(|(op, p)| (*op, p.as_ref().map(|b| PyBytes::new(py, b))))
    }

    /// The first `ReturnError` as `(invoke_id, error_code)`, if any.
    #[getter]
    fn error(&self) -> Option<(i64, i64)> {
        self.error
    }

    /// The invoke id of the first `ReturnResultLast`, whether or not it carries
    /// a result (`result` is `None` for an operation that returns nothing).
    #[getter]
    fn result_invoke_id(&self) -> Option<i64> {
        self.result_invoke_id
    }

    /// Every `Reject` the message carries, as `(invoke_id, problem_class,
    /// problem_code)`; the invoke id is `None` when it could not be derived.
    #[getter]
    fn rejects(&self) -> Vec<(Option<i64>, &'static str, i64)> {
        self.rejects
            .iter()
            .map(|(id, problem)| {
                let (class, code, _) = problem_parts(problem);
                (*id, class, code)
            })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "Decoded(kind={}, otid={}, dtid={})",
            self.kind,
            hex(&self.otid),
            hex(&self.dtid)
        )
    }
}

// ── The Node handle ──────────────────────────────────────────────────────────

/// The configured node handle returned by [`configure`]. It also exposes the
/// termination round-trip seam used for loopback / tests.
#[pyclass(name = "Node", module = "siphon")]
pub struct Node {
    state: Arc<NodeState>,
}

#[pymethods]
impl Node {
    /// The number of currently-open TCAP dialogues.
    fn open_dialogues(&self) -> usize {
        self.state
            .engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open_dialogues()
    }

    /// Render the Prometheus metrics text.
    fn metrics(&self) -> String {
        crate::metrics::render()
    }

    /// Deliver one inbound SCCP payload (a UDT carrying TCAP) to the dialogue
    /// engine and return the SCCP payloads to send back. `opc`/`dpc` are the
    /// routing-label point codes of the inbound MSU.
    #[pyo3(signature = (payload, *, opc, dpc))]
    fn deliver<'py>(
        &self,
        py: Python<'py>,
        payload: Vec<u8>,
        opc: u32,
        dpc: u32,
    ) -> Vec<Bound<'py, PyBytes>> {
        let msu = Msu {
            opc,
            dpc,
            si: SI_SCCP,
            ni: 0,
            mp: 0,
            sls: 0,
            payload,
        };
        let engine = self.state.engine.lock().unwrap_or_else(|e| e.into_inner());
        engine
            .deliver(&msu, "loopback")
            .into_iter()
            .map(|out| PyBytes::new(py, &out.payload))
            .collect()
    }

    /// Run the dialogue timers for loopback / tests, as the live transport does
    /// once a second: expire invocation timers (the handler is called with a
    /// `PeerTurn` whose `is_timeout` is true) and abort dialogues idle past
    /// their idle timeout. `ahead` moves the clock that many seconds forward, so
    /// a test does not have to wait. Returns the outbound SCCP payloads.
    #[pyo3(signature = (ahead=0.0))]
    fn sweep<'py>(&self, py: Python<'py>, ahead: f64) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let now = std::time::Instant::now() + seconds_arg(ahead, "ahead")?;
        let engine = self.state.engine.lock().unwrap_or_else(|e| e.into_inner());
        Ok(engine
            .sweep(now)
            .into_iter()
            .map(|(_, out)| PyBytes::new(py, &out.payload))
            .collect())
    }

    /// Wrap raw TCAP octets in an inbound SCCP UDT for loopback / tests, as the
    /// other `assemble_*` helpers do for the messages they build. For what they
    /// cannot build: a damaged message, a Reject, an Abort.
    #[pyo3(signature = (tcap, *, called_ssn=6))]
    fn assemble_tcap<'py>(
        &self,
        py: Python<'py>,
        tcap: Vec<u8>,
        called_ssn: u8,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let called = gt_address("15550100", Some(called_ssn));
        let calling = gt_address("15550170", Some(called_ssn));
        let sccp = SccpMessage::Udt(UnitData::new(called, calling, tcap))
            .encode()
            .map_err(err)?;
        Ok(PyBytes::new(py, &sccp))
    }

    /// Assemble an inbound TCAP `Begin` SCCP payload for loopback / tests: a
    /// `Begin(AARQ, Invoke(op))` addressed to our SSN `called_ssn`. `op` is a
    /// kebab-case MAP/CAP operation name. Returns the SCCP payload bytes.
    #[pyo3(signature = (*, op, called_gt, called_ssn, calling_gt, arg=None, ac=None))]
    #[allow(clippy::too_many_arguments)]
    fn assemble_begin<'py>(
        &self,
        py: Python<'py>,
        op: &str,
        called_gt: &str,
        called_ssn: u8,
        calling_gt: &str,
        arg: Option<Vec<u8>>,
        ac: Option<PyRef<'_, MapAcHandle>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let op_code =
            operation_op_code(op).ok_or_else(|| err(format!("unknown operation `{op}`")))?;

        let dialogue_portion = ac.and_then(|h| Oid::new(&h.arcs).map(DialoguePortion::aarq));

        let begin = TcapMessage::Begin(Begin {
            otid: vec![0x11, 0x22, 0x33, 0x44].into(),
            dialogue_portion,
            components: Some(vec![Component::Invoke(Invoke {
                invoke_id: 1,
                linked_id: None,
                operation_code: OperationCode::Local(op_code),
                parameter: arg.map(rasn::types::Any::new),
            })]),
        });
        let tcap_bytes = tcap::encode(&begin).map_err(err)?;

        let called = gt_address(called_gt, Some(called_ssn));
        let calling = gt_address(calling_gt, Some(called_ssn));
        let udt = UnitData::new(called, calling, tcap_bytes);
        let sccp = SccpMessage::Udt(udt).encode().map_err(err)?;
        Ok(PyBytes::new(py, &sccp))
    }

    /// Assemble an inbound TCAP `Continue` SCCP payload for loopback / tests: a
    /// follow-up leg from the peer on an open dialogue, addressed to `dtid` (the
    /// OTID the engine allocated, read off the first reply with `decode`). Pass a
    /// staged component the same builders produce: a [`Result`](StagedResult) (a
    /// peer `returnResultLast`, e.g. `gsm_map.insert_subscriber_data_res()`) or an
    /// [`Invoke`](StagedInvoke). `invoke_id` keys the component; `otid` sets the
    /// peer's own transaction id. Returns the SCCP payload bytes.
    #[pyo3(signature = (*, dtid, staged, invoke_id=1, otid=None))]
    fn assemble_continue<'py>(
        &self,
        py: Python<'py>,
        dtid: Vec<u8>,
        staged: &Bound<'_, PyAny>,
        invoke_id: i64,
        otid: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let invoke_id = invoke_id_arg(invoke_id)?;
        let component = if let Ok(res) = staged.cast::<StagedResult>() {
            let res = res.borrow();
            staged_result_component(invoke_id, &res)
        } else if let Ok(inv) = staged.cast::<StagedInvoke>() {
            let inv = inv.borrow();
            Component::Invoke(Invoke {
                invoke_id,
                linked_id: None,
                operation_code: OperationCode::Local(inv.op),
                parameter: inv
                    .arg
                    .resolve(&[])
                    .map_err(err)?
                    .map(rasn::types::Any::new),
            })
        } else {
            return Err(err(
                "assemble_continue: `staged` must be a Result or an Invoke",
            ));
        };

        let cont = TcapMessage::Continue(TcapContinue {
            otid: otid.unwrap_or_else(|| vec![0x22, 0x22, 0x22, 0x22]).into(),
            dtid: dtid.into(),
            dialogue_portion: None,
            components: Some(vec![component]),
        });
        let tcap_bytes = tcap::encode(&cont).map_err(err)?;

        // The engine keys a follow-up leg on its DTID, so the exact SCCP
        // addressing only needs to be a valid UDT toward a subsystem we own.
        let called = gt_address("15550100", Some(6));
        let calling = gt_address("15550170", Some(6));
        let udt = UnitData::new(called, calling, tcap_bytes);
        let sccp = SccpMessage::Udt(udt).encode().map_err(err)?;
        Ok(PyBytes::new(py, &sccp))
    }

    /// Assemble an inbound TCAP `End` SCCP payload for loopback / tests: the peer
    /// closes an open dialogue addressed to `dtid`, optionally carrying one final
    /// component (`staged` = a [`Result`](StagedResult) or [`Invoke`](StagedInvoke),
    /// or `None` for a bare End). Returns the SCCP payload bytes.
    #[pyo3(signature = (*, dtid, staged=None, invoke_id=1))]
    fn assemble_end<'py>(
        &self,
        py: Python<'py>,
        dtid: Vec<u8>,
        staged: Option<&Bound<'_, PyAny>>,
        invoke_id: i64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let invoke_id = invoke_id_arg(invoke_id)?;
        let components = match staged {
            None => None,
            Some(s) => {
                let component = if let Ok(res) = s.cast::<StagedResult>() {
                    let res = res.borrow();
                    staged_result_component(invoke_id, &res)
                } else if let Ok(inv) = s.cast::<StagedInvoke>() {
                    let inv = inv.borrow();
                    Component::Invoke(Invoke {
                        invoke_id,
                        linked_id: None,
                        operation_code: OperationCode::Local(inv.op),
                        parameter: inv
                            .arg
                            .resolve(&[])
                            .map_err(err)?
                            .map(rasn::types::Any::new),
                    })
                } else {
                    return Err(err("assemble_end: `staged` must be a Result or an Invoke"));
                };
                Some(vec![component])
            }
        };
        let end = TcapMessage::End(tcap::End {
            dtid: dtid.into(),
            dialogue_portion: None,
            components,
        });
        let tcap_bytes = tcap::encode(&end).map_err(err)?;
        let called = gt_address("15550100", Some(6));
        let calling = gt_address("15550170", Some(6));
        let udt = UnitData::new(called, calling, tcap_bytes);
        let sccp = SccpMessage::Udt(udt).encode().map_err(err)?;
        Ok(PyBytes::new(py, &sccp))
    }

    /// Open an **originating** MAP dialogue in-process for loopback / tests: stage
    /// `invoke` as the opening `Begin` toward `called_gt` / `called_ssn` at point
    /// code `dpc`, register an `on_reply(dialogue, peer)` callback the engine calls
    /// on each peer response (to stage the next segment `dlg.invoke(...);
    /// dlg.send()` or let it close), and return the outbound SCCP payload(s) — the
    /// `Begin`. Deliver the peer's response with [`deliver`](Self::deliver) to drive
    /// the follow-up leg. The live-transport analogue is `gsm_map.begin(...)`.
    #[pyo3(signature = (*, invoke, on_reply, called_gt, called_ssn, calling_gt, calling_ssn, dpc, ac, opc=None, sls=0))]
    #[allow(clippy::too_many_arguments)]
    fn originate<'py>(
        &self,
        py: Python<'py>,
        invoke: &StagedInvoke,
        on_reply: Py<PyAny>,
        called_gt: &str,
        called_ssn: u8,
        calling_gt: &str,
        calling_ssn: u8,
        dpc: u32,
        ac: PyRef<'_, MapAcHandle>,
        opc: Option<u32>,
        sls: u8,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let (opc_default, ni) = {
            let router = lock_router(&self.state);
            (
                router.node_point_code(&self.state.tenant).unwrap_or(0),
                router.node_network_indicator(&self.state.tenant),
            )
        };
        let req = OutgoingBegin {
            application_context: ac.arcs.clone(),
            called: gt_address(called_gt, Some(called_ssn)),
            calling: gt_address(calling_gt, Some(calling_ssn)),
            opc: opc.unwrap_or(opc_default),
            dpc,
            ni,
            sls,
            ingress_assoc: String::new(),
        };
        let handler: Arc<dyn TerminationHandler> = Arc::new(OriginationScriptHandler {
            op: invoke.op,
            arg: invoke.arg.resolve(&ac.arcs).map_err(err)?,
            class: invoke.class,
            on_reply,
        });
        let engine = self.state.engine.lock().unwrap_or_else(|e| e.into_inner());
        let (_tid, frames) = engine.begin(req, handler).map_err(err)?;
        Ok(frames
            .into_iter()
            .map(|msu| PyBytes::new(py, &msu.payload))
            .collect())
    }

    /// Decode one outbound SCCP payload (a UDT carrying TCAP) into a read-only
    /// [`Decoded`](PyDecoded) view for loopback / tests: the message kind, the
    /// transaction ids, the AARQ/AARE application context, and the first invoke /
    /// result / error it carries.
    fn decode(&self, payload: Vec<u8>) -> PyResult<PyDecoded> {
        let udt = match SccpMessage::decode(&payload).map_err(err)? {
            SccpMessage::Udt(u) => u,
            _ => return Err(err("payload is not an SCCP UDT")),
        };
        let msg = tcap::decode(&udt.data).map_err(err)?;
        Ok(PyDecoded::from_tcap(&msg))
    }

    fn __repr__(&self) -> String {
        format!(
            "Node(tenant={}, ssns={:?})",
            self.state.tenant, self.state.local_ssns
        )
    }
}

// ── Module-level functions ───────────────────────────────────────────────────

/// Rebuild the process-wide node from a `sigtran.yaml` (a path, an inline YAML
/// string, or a dict) and return a [`Node`] round-trip handle. This is the
/// in-process **loopback / test** seam (the analogue of the sibling addons'
/// test harness): it lets a test assemble genuine inbound MSUs and drive them
/// through the dialogue engine with no live transport. A composing siphon binary
/// configures the live node from its own config with [`configure_from`], not
/// this; a handler script never calls it.
#[pyfunction]
fn configure(source: &Bound<'_, PyAny>) -> PyResult<Node> {
    let cfg = config_from_source(source)?;
    let state = Arc::new(NodeState::from_config(&cfg));
    set_node(state.clone());
    Ok(Node { state })
}

/// Configure the process-wide node from an already-parsed [`Config`]. This is the
/// startup seam a composing siphon binary calls once, after reading its
/// `extensions.sigtran` config and before loading the handler script, the
/// analogue of the sibling addons' `namespace(cfg)`. The `ss7` / `gsm_map` /
/// `gsm_cap` / `inap` namespaces then program this node.
pub fn configure_from(cfg: &Config) {
    set_node(Arc::new(NodeState::from_config(cfg)));
}

/// The siphon addon **runtime task**: the closure a composing siphon binary hands
/// to `SiphonServer::register_task`. It boots the live SIGTRAN transport for the
/// process-wide node on siphon's tokio runtime, attaches the dialogue engine
/// (inbound MAP/CAP/INAP termination) and the origination drain (outbound
/// `gsm_map.begin(...)`), and keeps the transport alive for the process lifetime.
///
/// Ordering contract: call [`configure_from`] first (at builder time, before the
/// script loads) so the script's decorators register into the very node this task
/// then drives. The task runs after the script has loaded, so by the time it
/// snapshots the node the routing tables and termination handlers are in place.
pub fn task(cfg: Config) -> impl FnOnce(ScriptHandle) + Send + 'static {
    runtime_task(cfg, None)
}

/// [`task`] with an [admission policy](crate::admission) for new dialogues:
/// the live router puts every TCAP `Begin` / `Unidirectional` it relays or
/// terminates to `policy`, and refuses the ones it refuses. The same ordering
/// contract as [`task`] applies.
pub fn task_with_admission(
    cfg: Config,
    policy: Arc<dyn crate::admission::AdmissionPolicy>,
) -> impl FnOnce(ScriptHandle) + Send + 'static {
    runtime_task(cfg, Some(policy))
}

fn runtime_task(
    cfg: Config,
    policy: Option<Arc<dyn crate::admission::AdmissionPolicy>>,
) -> impl FnOnce(ScriptHandle) + Send + 'static {
    move |script| {
        // Move the router + engine the script just programmed out of the node's
        // load-time mutexes into the Arcs the transport shares. After this the
        // live wire owns them: routing and handlers are fixed at load, so the
        // router stays lock-free on the hot path (the line-rate guarantee). The
        // throwaway replacements keep the node type intact and are never used.
        let node = node();
        let router = {
            let mut guard = node.router.lock().unwrap_or_else(|e| e.into_inner());
            let mut router = std::mem::replace(&mut *guard, Router::new(&cfg));
            router.set_admission_policy(policy);
            Arc::new(router)
        };
        let engine = {
            let mut guard = node.engine.lock().unwrap_or_else(|e| e.into_inner());
            Arc::new(std::mem::replace(
                &mut *guard,
                DialogueEngine::new(cfg.tcap.clone()),
            ))
        };

        let handle = script.tokio_handle().clone();
        handle.spawn(async move {
            let mut transport =
                match TransportHandle::start_tenant(&cfg, DEFAULT_TENANT, router).await {
                    Ok(transport) => transport,
                    Err(error) => {
                        eprintln!("siphon-sigtran: transport failed to start: {error}");
                        return;
                    }
                };
            // Inbound termination and outbound origination share one engine so a
            // response to an originated Begin correlates on its dialogue.
            transport.serve_dialogues(engine.clone());
            transport.serve_originations(engine);
            set_origin_tx(transport.origin_sender());
            // Hold the transport (and every association task it spawned) for the
            // life of the process; dropping it would abort them all.
            std::future::pending::<()>().await;
        });
    }
}

// ── Module wiring ────────────────────────────────────────────────────────────

fn add_contents(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SigtranError", py.get_type::<SigtranError>())?;
    m.add("MistypedParameter", py.get_type::<MistypedParameter>())?;

    // Namespace singletons.
    m.add("ss7", Bound::new(py, Ss7)?)?;
    m.add("gsm_map", Bound::new(py, GsmMap)?)?;
    m.add("gsm_cap", Bound::new(py, GsmCap)?)?;
    m.add("inap", Bound::new(py, Inap)?)?;

    // Types a script imports for typing / construction.
    m.add_class::<Node>()?;
    m.add_class::<PyIncomingOp>()?;
    m.add_class::<PyPeerTurn>()?;
    m.add_class::<PyComponent>()?;
    m.add_class::<PyDecoded>()?;
    m.add_class::<PyDialogue>()?;
    m.add_class::<Address>()?;
    m.add_class::<MapAcHandle>()?;
    m.add_class::<StagedInvoke>()?;
    m.add_class::<StagedResult>()?;
    cap::add_classes(m)?;

    // Module functions.
    // Nothing here may carry a name the host gives one of its own namespaces:
    // this runs after the host has filled the module, and `add` replaces.
    m.add_function(wrap_pyfunction!(configure, m)?)?;
    Ok(())
}

/// The siphon namespace-mount seam. A composing siphon binary calls this once at
/// startup with the `siphon` package module as `parent`; it mounts the `ss7` /
/// `gsm_map` / `gsm_cap` / `inap` namespace singletons, the `SigtranError`
/// exception, and the shared types onto it. It adds no name the host uses for a
/// namespace of its own (`metrics` among them): the node's Prometheus text is
/// `ss7.metrics()`. A hot-reloaded
/// script then reaches them with `from siphon import ss7, gsm_map, gsm_cap, inap`,
/// programs the Rust routing tables live, and registers MAP/CAP/INAP termination
/// handlers. The binary builds the live node those namespaces drive with
/// [`configure_from`] (from its `extensions.sigtran` config) before loading the
/// script.
///
/// The namespace singletons drive one process-wide [`node`]. A composing binary
/// that prefers per-namespace mounting can instead register [`Ss7`] / [`GsmMap`]
/// / [`GsmCap`] / [`Inap`] individually (they are `#[pyclass]` values), but
/// `register` is the one-call form and the surface the tests drive.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(py, parent)
}
