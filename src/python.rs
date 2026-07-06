//! The siphon addon face: a PyO3 surface that exposes the **same** SIGTRAN
//! routing brain and MAP/CAP dialogue engine the crate ships, as a scriptable
//! siphon node. It is a siphon addon, not a standalone package. No wheel, no
//! PyPI. It builds and is tested against siphon-sip, the way the sibling addons
//! `siphon-smpp` and `siphon-http` are.
//!
//! Compiled only with `--features python`; the default crate build pulls neither
//! pyo3 nor siphon, so consumers of the pure-Rust routing brain stay lean. The
//! single seam is [`register`]: a composing siphon binary calls it at startup to
//! mount the `ss7` / `gsm_map` / `gsm_cap` namespaces (plus `configure` /
//! `metrics` and the shared types) onto the `siphon` package module, so scripts
//! import them with `from siphon import ss7, gsm_map, gsm_cap`.
//!
//! # The model
//!
//! One process-wide [`node`] holds the routing tables (a [`Router`], live via
//! `ss7.routes` / `ss7.gtt` / `ss7.content`), the [`DialogueEngine`], and the
//! Python hook tables. [`configure`] (re)builds it from a `sigtran.yaml`, so a
//! script configures the node first, then programs it.
//!
//! * **Routing** stays in Rust at line rate. Python overrides it three ways:
//!   program the tables live, defer a rule to a named hook
//!   (`@ss7.content.on(name)`), or take a selector-gated general hook
//!   (`@ss7.on_route(when=...)`). The decision constructors (`ss7.route`,
//!   `ss7.drop`, `ss7.route_default`, `ss7.allow`) build a [`Decision`] the
//!   async override layer resolves.
//! * **Termination** registers a Python handler per MAP/CAP operation
//!   (`@gsm_map.on_mo_forward_sm`, `@gsm_cap.on_initial_dp`, …). When a dialogue
//!   terminates, the handler drives a [`PyDialogue`] handle (`invoke` / `reply` /
//!   `send` / `end`). An `async def` handler runs to completion on an asyncio
//!   loop, mirroring how a handler runs on siphon's runtime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyModuleMethods};

use rasn::types::{OctetString, Oid};
use sccp::{GlobalTitle, SccpAddress, SccpMessage, SubsystemNumber, UnitData};
use tcap::dialogue::{DialoguePdu, DialoguePortion};
use tcap::{
    Begin, Component, Continue as TcapContinue, ErrorCode, Invoke, OperationCode, ReturnResult,
    ReturnResultValue, TcapMessage,
};

use crate::config::{Config, ContentRule, GttRule, DEFAULT_TENANT};
use crate::content::{ContentEngine, MapView as CoreMapView, Operation};
use crate::dialogue::{
    Dialogue as CoreDialogue, DialogueEngine, IncomingOp as CoreIncomingOp, PeerComponent,
    PeerTurn, TerminationHandler,
};
use crate::mtp3::route::Destination;
use crate::routing::Router;
use crate::transport::framing::{Msu, SI_SCCP};

// ── Error ────────────────────────────────────────────────────────────────────
create_exception!(
    siphon_sigtran,
    SigtranError,
    PyException,
    "siphon-sigtran configuration / SS7 protocol error."
);

fn err(msg: impl std::fmt::Display) -> PyErr {
    SigtranError::new_err(msg.to_string())
}

/// Encode a MAP result struct to BER and stage it as a `ReturnResultLast` for
/// `dlg.reply(...)`, carrying the operation code.
fn staged_map_res<T: rasn::Encode>(op: i64, res: &T) -> PyResult<StagedResult> {
    let param = rasn::ber::encode(res).map_err(err)?;
    Ok(StagedResult {
        op,
        param: Some(param),
    })
}

/// Encode a MAP argument struct to BER and stage it as an `Invoke` for
/// `dlg.invoke(...)`, carrying the operation code.
fn staged_map_invoke<T: rasn::Encode>(op: i64, arg: &T) -> PyResult<StagedInvoke> {
    let bytes = rasn::ber::encode(arg).map_err(err)?;
    Ok(StagedInvoke {
        op,
        arg: Some(bytes),
    })
}

/// A UMTS/EPS authentication quintuplet as `(rand, xres, ck, ik, autn)` bytes.
type Quintuplet = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
/// A GSM authentication triplet as `(rand, sres, kc)` bytes.
type Triplet = (Vec<u8>, Vec<u8>, Vec<u8>);

// ── Node state ───────────────────────────────────────────────────────────────

/// Everything a scriptable node owns: the routing tables, the termination
/// engine, and the Python hook tables. Interior-mutable so the `ss7` /
/// `gsm_map` / `gsm_cap` namespace singletons can all drive one node.
struct NodeState {
    router: Mutex<Router>,
    engine: Mutex<DialogueEngine>,
    tenant: String,
    /// The subsystems we own; a termination decorator registers on each.
    local_ssns: Vec<u8>,
    /// Deferred content hooks by name (`@ss7.content.on(name)`).
    content_hooks: Mutex<HashMap<String, Py<PyAny>>>,
    /// General route hooks (`@ss7.on_route(when=...)`), in registration order.
    route_hooks: Mutex<Vec<(String, Py<PyAny>)>>,
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
            content_hooks: Mutex::new(HashMap::new()),
            route_hooks: Mutex::new(Vec::new()),
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
    // A dict (or any object): serialise to YAML via a serde_yaml::Value bridge.
    let value = py_to_yaml(source)?;
    let text = serde_yaml::to_string(&value).map_err(err)?;
    Config::parse(&text).map_err(err)
}

/// Convert a Python value (dict / list / scalar) into a `serde_yaml::Value` so
/// the typed config deserialiser can validate it: one schema, no hand-mapping.
fn py_to_yaml(obj: &Bound<'_, PyAny>) -> PyResult<serde_yaml::Value> {
    use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
    use serde_yaml::Value;

    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        return Ok(Value::String(s.extract::<String>()?));
    }
    if let Ok(i) = obj.cast::<PyInt>() {
        return Ok(Value::Number(i.extract::<i64>()?.into()));
    }
    if let Ok(f) = obj.cast::<PyFloat>() {
        return Ok(Value::Number(f.extract::<f64>()?.into()));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        let mut seq = Vec::with_capacity(list.len());
        for item in list.iter() {
            seq.push(py_to_yaml(&item)?);
        }
        return Ok(Value::Sequence(seq));
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = serde_yaml::Mapping::new();
        for (k, v) in dict.iter() {
            let key = Value::String(k.str()?.extract::<String>()?);
            map.insert(key, py_to_yaml(&v)?);
        }
        return Ok(Value::Mapping(map));
    }
    Err(err(format!(
        "cannot convert {} to a config value",
        obj.get_type().name()?
    )))
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

// ── Routing decision ─────────────────────────────────────────────────────────

/// A routing decision a hook returns: route onward, drop, defer to the static
/// tables (`route_default`), or pass a screen (`allow`).
#[pyclass(name = "RouteDecision", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct Decision {
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    dpc: Option<u32>,
    #[pyo3(get)]
    ssn: Option<u8>,
    #[pyo3(get)]
    linkset: Option<String>,
    #[pyo3(get)]
    tenant: Option<String>,
    #[pyo3(get)]
    reason: Option<String>,
}

#[pymethods]
impl Decision {
    fn __repr__(&self) -> String {
        format!(
            "RouteDecision(kind={}, dpc={:?}, ssn={:?}, linkset={:?}, tenant={:?}, reason={:?})",
            self.kind, self.dpc, self.ssn, self.linkset, self.tenant, self.reason
        )
    }
}

impl Decision {
    fn bare(kind: &str) -> Self {
        Decision {
            kind: kind.to_string(),
            dpc: None,
            ssn: None,
            linkset: None,
            tenant: None,
            reason: None,
        }
    }
}

// ── Decoded MAP/CAP view (content + route hooks) ─────────────────────────────

/// A read-only decoded MAP/CAP view handed to a content / route hook.
#[pyclass(name = "MapView", module = "siphon", skip_from_py_object)]
#[derive(Clone, Default)]
pub struct PyMapView {
    #[pyo3(get)]
    operation: Option<String>,
    #[pyo3(get)]
    cgpa_gt: Option<String>,
    #[pyo3(get)]
    cdpa_gt: Option<String>,
    #[pyo3(get)]
    imsi: Option<String>,
    #[pyo3(get)]
    msisdn: Option<String>,
    #[pyo3(get)]
    opc: Option<u32>,
    #[pyo3(get)]
    dpc: Option<u32>,
}

#[pymethods]
impl PyMapView {
    #[new]
    #[pyo3(signature = (*, operation=None, cgpa_gt=None, cdpa_gt=None, imsi=None, msisdn=None, opc=None, dpc=None))]
    fn new(
        operation: Option<String>,
        cgpa_gt: Option<String>,
        cdpa_gt: Option<String>,
        imsi: Option<String>,
        msisdn: Option<String>,
        opc: Option<u32>,
        dpc: Option<u32>,
    ) -> Self {
        PyMapView {
            operation,
            cgpa_gt,
            cdpa_gt,
            imsi,
            msisdn,
            opc,
            dpc,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "MapView(operation={:?}, cgpa_gt={:?}, cdpa_gt={:?}, imsi={:?}, msisdn={:?})",
            self.operation, self.cgpa_gt, self.cdpa_gt, self.imsi, self.msisdn
        )
    }
}

impl PyMapView {
    /// The content-engine view, used when a hook consults the Rust tables. Kept
    /// so a future async override layer can evaluate against the same rules.
    #[allow(dead_code)]
    fn to_core(&self) -> CoreMapView {
        CoreMapView {
            operation: self.operation.as_deref().and_then(Operation::from_kebab),
            cgpa_gt: self.cgpa_gt.clone(),
            cdpa_gt: self.cdpa_gt.clone(),
            imsi: self.imsi.clone(),
            msisdn: self.msisdn.clone(),
        }
    }
}

// ── Staged components ────────────────────────────────────────────────────────

/// A staged `Invoke` produced by an originating helper (`gsm_map.mt_forward_sm`,
/// `gsm_cap.connect`, …), consumed by `dlg.invoke(...)`.
#[pyclass(name = "Invoke", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct StagedInvoke {
    op: i64,
    arg: Option<Vec<u8>>,
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
}

#[pymethods]
impl PyIncomingOp {
    /// The raw BER argument bytes, if the Invoke carried a parameter.
    #[getter]
    fn argument<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.argument.as_ref().map(|a| PyBytes::new(py, a))
    }

    /// The originating SMS address (`SM-RP-OA`) of a MO/MT-ForwardSM, if decoded.
    #[getter]
    fn sm_rp_oa<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.decode_mo_field(py, MoField::Oa)
    }

    /// The destination SMS address (`SM-RP-DA`) of a MO/MT-ForwardSM, if decoded.
    #[getter]
    fn sm_rp_da<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.decode_mo_field(py, MoField::Da)
    }

    /// The SMS TPDU (`SM-RP-UI`) of a MO/MT-ForwardSM, if decoded.
    #[getter]
    fn sm_rp_ui<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.decode_mo_field(py, MoField::Ui)
    }

    /// The `calledPartyNumber` of a CAMEL initialDP, if decoded.
    #[getter]
    fn called_party_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let bytes = self.argument.as_ref()?;
        let idp: gsm_cap::operations::InitialDpArg = gsm_cap::decode(bytes).ok()?;
        idp.called_party_number
            .map(|n| PyBytes::new(py, n.as_ref()))
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

/// One decoded component of a peer's follow-up turn.
#[derive(Clone)]
struct PeerComp {
    kind: &'static str,
    operation_code: Option<i64>,
    invoke_id: i64,
    parameter: Option<Vec<u8>>,
    error_code: Option<i64>,
}

/// The decoded peer view a termination handler receives on a follow-up leg of a
/// held-open dialogue (the peer's `Continue` or `End`). It carries the peer's
/// operation code and the decoded result / invoke / error, so a script can, for
/// example, observe an insertSubscriberData `returnResultLast` and then finish
/// the updateLocation with its own result. The opening leg gets an
/// [`IncomingOp`](PyIncomingOp) instead; branch on `is_peer_turn`.
#[pyclass(name = "PeerTurn", module = "siphon", skip_from_py_object)]
#[derive(Clone)]
pub struct PyPeerTurn {
    is_end: bool,
    comps: Vec<PeerComp>,
}

impl PyPeerTurn {
    fn from_peer(peer: &PeerTurn) -> Self {
        let comps = peer
            .components
            .iter()
            .map(|c| match c {
                PeerComponent::Invoke {
                    invoke_id,
                    operation_code,
                    argument,
                } => PeerComp {
                    kind: "invoke",
                    operation_code: Some(*operation_code),
                    invoke_id: *invoke_id,
                    parameter: argument.clone(),
                    error_code: None,
                },
                PeerComponent::Result {
                    invoke_id,
                    operation_code,
                    parameter,
                } => PeerComp {
                    kind: "result",
                    operation_code: *operation_code,
                    invoke_id: *invoke_id,
                    parameter: parameter.clone(),
                    error_code: None,
                },
                PeerComponent::Error {
                    invoke_id,
                    error_code,
                } => PeerComp {
                    kind: "error",
                    operation_code: None,
                    invoke_id: *invoke_id,
                    parameter: None,
                    error_code: Some(*error_code),
                },
            })
            .collect();
        PyPeerTurn {
            is_end: peer.is_end,
            comps,
        }
    }

    fn first(&self) -> Option<&PeerComp> {
        self.comps.first()
    }

    fn first_of(&self, kind: &str) -> Option<&PeerComp> {
        self.comps.iter().find(|c| c.kind == kind)
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

    /// Whether this turn arrived in a TCAP `End` (the peer closed the dialogue).
    #[getter]
    fn is_end(&self) -> bool {
        self.is_end
    }

    /// The operation code of the first component: a `returnResultLast` echoes the
    /// operation it answers, an `Invoke` carries its own. `None` if absent.
    #[getter]
    fn operation_code(&self) -> Option<i64> {
        self.first().and_then(|c| c.operation_code)
    }

    /// The invoke id of the first component, if any.
    #[getter]
    fn invoke_id(&self) -> Option<i64> {
        self.first().map(|c| c.invoke_id)
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
        format!(
            "PeerTurn(is_end={}, components={})",
            self.is_end,
            self.comps.len()
        )
    }
}

enum MoField {
    Oa,
    Da,
    Ui,
}

impl PyIncomingOp {
    /// Best-effort decode of a MO/MT-ForwardSM argument field. Returns `None`
    /// when the argument is absent or is not a forward-SM (the getter is
    /// meaningful only for the SMS relay operations).
    fn decode_mo_field<'py>(&self, py: Python<'py>, field: MoField) -> Option<Bound<'py, PyBytes>> {
        use gsm_map::operations::{mo_forward_sm::MoForwardSmArg, mt_forward_sm::MtForwardSmArg};
        use gsm_map::{SmRpDa, SmRpOa};

        let bytes = self.argument.as_ref()?;

        // Both MO and MT forward-SM carry the same three fields; try MO then MT.
        let (da, oa, ui): (SmRpDa, SmRpOa, OctetString) =
            if let Ok(a) = rasn::ber::decode::<MoForwardSmArg>(bytes) {
                (a.sm_rp_da, a.sm_rp_oa, a.sm_rp_ui)
            } else if let Ok(a) = rasn::ber::decode::<MtForwardSmArg>(bytes) {
                (a.sm_rp_da, a.sm_rp_oa, a.sm_rp_ui)
            } else {
                return None;
            };

        match field {
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
        }
    }
}

// ── The dialogue handle (command buffer) ─────────────────────────────────────

#[derive(Clone)]
enum DlgCmd {
    Invoke {
        op: i64,
        arg: Option<Vec<u8>>,
    },
    Reply {
        op: i64,
        result: Option<Vec<u8>>,
    },
    ReplyTo {
        id: i64,
        op: i64,
        result: Option<Vec<u8>>,
    },
    Error {
        id: i64,
        code: i64,
    },
    Send,
    End,
    Abort,
}

/// The live dialogue handle a termination handler drives. It records the
/// components the handler stages (`invoke` / `reply` / `error`) and the flush
/// points (`send` / `end` / `abort`); the engine replays them onto the real
/// Rust dialogue to build the wire TCAP. This keeps the handler's view simple
/// and the wire encoding in Rust.
#[pyclass(name = "Dialogue", module = "siphon")]
pub struct PyDialogue {
    cmds: Mutex<Vec<DlgCmd>>,
    otid: Vec<u8>,
    dtid: Vec<u8>,
}

#[pymethods]
impl PyDialogue {
    /// Stage an `Invoke` (from an originating helper), e.g.
    /// `dlg.invoke(gsm_map.mt_forward_sm(...))`.
    fn invoke(&self, invoke: &StagedInvoke) {
        self.push(DlgCmd::Invoke {
            op: invoke.op,
            arg: invoke.arg.clone(),
        });
    }

    /// Stage a `ReturnResultLast` answering the opening invoke.
    fn reply(&self, result: &StagedResult) {
        self.push(DlgCmd::Reply {
            op: result.op,
            result: result.param.clone(),
        });
    }

    /// Stage a `ReturnResultLast` answering a specific invoke id.
    fn reply_to(&self, invoke_id: i64, result: &StagedResult) {
        self.push(DlgCmd::ReplyTo {
            id: invoke_id,
            op: result.op,
            result: result.param.clone(),
        });
    }

    /// Stage a `ReturnError` answering a specific invoke id.
    fn error(&self, invoke_id: i64, error_code: i64) {
        self.push(DlgCmd::Error {
            id: invoke_id,
            code: error_code,
        });
    }

    /// Flush the staged components as a `Continue` (the dialogue stays open).
    fn send(&self) {
        self.push(DlgCmd::Send);
    }

    /// Flush the staged components as an `End`, closing the dialogue.
    fn end(&self) {
        self.push(DlgCmd::End);
    }

    /// Abort the dialogue (a dialogue-service-user abort).
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

    /// Await this leg's result. Originating multi-leg flows use it to wait for a
    /// segment's `returnResultLast`. It returns an awaitable bridged onto tokio
    /// (the same shape the sibling addons' send helpers use); awaiting it needs a
    /// running node (a live SCTP transport driven by a siphon binary), so without
    /// one it resolves to that error.
    fn result<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Err::<(), PyErr>(err(
                "dlg.result() needs a running node (a live SCTP transport driven by a siphon binary)",
            ))
        })
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
    fn new(otid: Vec<u8>, dtid: Vec<u8>) -> Self {
        PyDialogue {
            cmds: Mutex::new(Vec::new()),
            otid,
            dtid,
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
fn replay(dlg: &mut CoreDialogue, cmds: Vec<DlgCmd>) {
    for cmd in cmds {
        match cmd {
            DlgCmd::Invoke { op, arg } => {
                dlg.invoke(op, arg);
            }
            DlgCmd::Reply { op, result } => dlg.reply(op, result),
            DlgCmd::ReplyTo { id, op, result } => dlg.reply_to(id, op, result),
            DlgCmd::Error { id, code } => dlg.error(id, code),
            DlgCmd::Send => dlg.send(),
            DlgCmd::End => dlg.end(),
            DlgCmd::Abort => dlg.abort(tcap::dialogue::AbortSource::DialogueServiceUser),
        }
    }
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
}

impl PyHandler {
    fn run(&self, dlg: &mut CoreDialogue, leg: Leg<'_>) {
        Python::attach(|py| {
            let pydlg = match Bound::new(
                py,
                PyDialogue::new(dlg.otid().to_vec(), dlg.dtid().to_vec()),
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("siphon-sigtran: building Dialogue failed: {e}");
                    return;
                }
            };

            let call = match leg {
                Leg::Begin(o) => {
                    let arg = PyIncomingOp {
                        operation_code: o.operation_code,
                        invoke_id: o.invoke_id,
                        calling_gt: o.calling_gt.clone(),
                        called_gt: o.called_gt.clone(),
                        argument: o.argument.clone(),
                    };
                    match Bound::new(py, arg) {
                        Ok(a) => self.func.bind(py).call1((&pydlg, &a)),
                        Err(e) => {
                            eprintln!("siphon-sigtran: building IncomingOp failed: {e}");
                            return;
                        }
                    }
                }
                Leg::Continue(peer) => match Bound::new(py, PyPeerTurn::from_peer(peer)) {
                    Ok(t) => self.func.bind(py).call1((&pydlg, &t)),
                    Err(e) => {
                        eprintln!("siphon-sigtran: building PeerTurn failed: {e}");
                        return;
                    }
                },
                Leg::Start => self.func.bind(py).call1((&pydlg,)),
            };

            match call {
                Ok(result) => {
                    if let Err(e) = drive(py, &result) {
                        eprintln!("siphon-sigtran: termination handler raised: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("siphon-sigtran: termination handler raised: {e}");
                    return;
                }
            }
            let cmds = pydlg.borrow().take();
            replay(dlg, cmds);
        });
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

    /// A general routing override, gated by a `when=` selector expression (kept
    /// off the hot path for everything else). Used as a decorator.
    #[pyo3(signature = (when=None))]
    fn on_route(&self, when: Option<String>) -> HookRegistrar {
        HookRegistrar {
            kind: HookKind::Route,
            key: when.unwrap_or_default(),
        }
    }

    /// Build a "route onward" decision. Name one of dpc / linkset / tenant (with
    /// an optional ssn).
    #[pyo3(signature = (*, dpc=None, ssn=None, linkset=None, tenant=None))]
    fn route(
        &self,
        dpc: Option<u32>,
        ssn: Option<u8>,
        linkset: Option<String>,
        tenant: Option<String>,
    ) -> Decision {
        Decision {
            kind: "route".to_string(),
            dpc,
            ssn,
            linkset,
            tenant,
            reason: None,
        }
    }

    /// Build a "drop / screen" decision with a reason.
    #[pyo3(signature = (reason=None))]
    fn drop(&self, reason: Option<String>) -> Decision {
        Decision {
            reason,
            ..Decision::bare("drop")
        }
    }

    /// Build a "let the Rust tables / config decide" decision.
    fn route_default(&self) -> Decision {
        Decision::bare("default")
    }

    /// Build an "allow / pass the screen" decision.
    fn allow(&self) -> Decision {
        Decision::bare("allow")
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
        let mut m = serde_yaml::Mapping::new();
        m.insert("match".into(), py_to_yaml(r#match)?);
        m.insert("to".into(), py_to_yaml(to)?);
        let rule: GttRule = serde_yaml::from_value(serde_yaml::Value::Mapping(m)).map_err(err)?;
        self.push_rule(rule)
    }

    fn __repr__(&self) -> String {
        "ss7.gtt".to_string()
    }
}

impl Gtt {
    fn add_prefix(&self, gt: &str, dpc: u32, ssn: u8) -> PyResult<()> {
        let yaml = format!("match: {{ gt_prefix: \"{gt}\" }}\nto: {{ dpc: {dpc}, ssn: {ssn} }}\n");
        let rule: GttRule = serde_yaml::from_str(&yaml).map_err(err)?;
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
        let mut m = serde_yaml::Mapping::new();
        m.insert("name".into(), name.into());
        m.insert("match".into(), py_to_yaml(r#match)?);
        m.insert("action".into(), py_to_yaml(action)?);
        let rule: ContentRule =
            serde_yaml::from_value(serde_yaml::Value::Mapping(m)).map_err(err)?;
        with_content(|c| c.add_rule(&rule))
    }

    /// Reference a named address table (`ss7.content.address_table("home-subs")`);
    /// call `.add(gt)` on it to program a served-subscriber GT live.
    fn address_table(&self, name: &str) -> AddressTable {
        AddressTable {
            name: name.to_string(),
        }
    }

    /// Register a deferred hook for a rule whose action is `{python: <name>}`.
    /// Used as a decorator: `@ss7.content.on("on_np_dip")`.
    fn on(&self, name: &str) -> HookRegistrar {
        HookRegistrar {
            kind: HookKind::Content,
            key: name.to_string(),
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
    if rt.content.is_none() {
        rt.content = Some(ContentEngine::empty());
    }
    f(rt.content.as_mut().expect("content engine present"));
    Ok(())
}

// ── Hook registrars (decorators) ─────────────────────────────────────────────

#[derive(Clone, Copy)]
enum HookKind {
    Content,
    Route,
}

/// A callable returned by `@ss7.content.on(name)` / `@ss7.on_route(when=...)`;
/// applying it to a function records the hook.
#[pyclass(name = "HookRegistrar", module = "siphon")]
pub struct HookRegistrar {
    kind: HookKind,
    key: String,
}

#[pymethods]
impl HookRegistrar {
    fn __call__(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        let n = node();
        match self.kind {
            HookKind::Content => {
                n.content_hooks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(self.key.clone(), func.clone_ref(py));
            }
            HookKind::Route => {
                n.route_hooks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((self.key.clone(), func.clone_ref(py)));
            }
        }
        func
    }
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

    /// Terminate mobile-originated ForwardSM (`@gsm_map.on_mo_forward_sm`).
    fn on_mo_forward_sm(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, Operation::MoForwardSm.op_code(), &func);
        func
    }

    /// Terminate mobile-terminated ForwardSM (`@gsm_map.on_mt_forward_sm`).
    fn on_mt_forward_sm(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, Operation::MtForwardSm.op_code(), &func);
        func
    }

    /// Terminate SendRoutingInfoForSM (`@gsm_map.on_send_routing_info_for_sm`).
    fn on_send_routing_info_for_sm(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, Operation::SriSm.op_code(), &func);
        func
    }

    /// Terminate updateLocation (`@gsm_map.on_update_location`).
    fn on_update_location(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, Operation::UpdateLocation.op_code(), &func);
        func
    }

    /// Terminate sendAuthenticationInfo (`@gsm_map.on_send_authentication_info`).
    fn on_send_authentication_info(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_map::op_codes::SEND_AUTHENTICATION_INFO, &func);
        func
    }

    /// Terminate cancelLocation (`@gsm_map.on_cancel_location`).
    fn on_cancel_location(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_map::op_codes::CANCEL_LOCATION, &func);
        func
    }

    /// Terminate purgeMS (`@gsm_map.on_purge_ms`).
    fn on_purge_ms(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_map::op_codes::PURGE_MS, &func);
        func
    }

    /// Terminate readyForSM (`@gsm_map.on_ready_for_sm`).
    fn on_ready_for_sm(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_map::op_codes::READY_FOR_SM, &func);
        func
    }

    /// Terminate reportSM-DeliveryStatus (`@gsm_map.on_report_sm_delivery_status`).
    fn on_report_sm_delivery_status(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_map::op_codes::REPORT_SM_DELIVERY_STATUS, &func);
        func
    }

    /// Terminate provideSubscriberInfo (`@gsm_map.on_provide_subscriber_info`).
    fn on_provide_subscriber_info(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(
            py,
            gsm_map::operations::subscriber_info::op_codes::PROVIDE_SUBSCRIBER_INFO,
            &func,
        );
        func
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
        imsi: Vec<u8>,
        network_node_number: Vec<u8>,
        lmsi: Option<Vec<u8>>,
    ) -> PyResult<StagedResult> {
        use gsm_map::operations::sri_sm::RoutingInfoForSmRes;
        use gsm_map::types::LocationInfoWithLmsi;
        let res = RoutingInfoForSmRes {
            imsi: imsi.into(),
            location_info_with_lmsi: LocationInfoWithLmsi {
                network_node_number: network_node_number.into(),
                lmsi: lmsi.map(Into::into),
                gprs_node_indicator: None,
                additional_number: None,
            },
        };
        staged_map_res(gsm_map::op_codes::SEND_ROUTING_INFO_FOR_SM, &res)
    }

    /// Build an updateLocation result carrying the `hlr_number`: the successful
    /// close of a location update, sent once the VLR has taken the subscriber data.
    #[pyo3(signature = (*, hlr_number))]
    fn update_location_res(&self, hlr_number: Vec<u8>) -> PyResult<StagedResult> {
        use gsm_map::operations::location::UpdateLocationRes;
        let res = UpdateLocationRes {
            hlr_number: hlr_number.into(),
        };
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
        let set = match (quintuplets, triplets) {
            (Some(q), _) => Some(AuthenticationSetList::QuintupletList(
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
            (None, Some(t)) => Some(AuthenticationSetList::TripletList(
                t.into_iter()
                    .map(|(rand, sres, kc)| AuthenticationTriplet {
                        rand: rand.into(),
                        sres: sres.into(),
                        kc: kc.into(),
                    })
                    .collect(),
            )),
            (None, None) => None,
        };
        let res = SendAuthenticationInfoRes {
            authentication_set_list: set,
        };
        staged_map_res(gsm_map::op_codes::SEND_AUTHENTICATION_INFO, &res)
    }

    /// Build an insertSubscriberData result: the VLR accepting the pushed data.
    fn insert_subscriber_data_res(&self) -> PyResult<StagedResult> {
        use gsm_map::operations::subscriber_data::{op_codes, InsertSubscriberDataRes};
        let res = InsertSubscriberDataRes {
            teleservice_list: None,
            bearer_service_list: None,
            odb_general_data: None,
        };
        staged_map_res(op_codes::INSERT_SUBSCRIBER_DATA, &res)
    }

    /// Build a cancelLocation result: the VLR confirming it dropped the record.
    fn cancel_location_res(&self) -> PyResult<StagedResult> {
        use gsm_map::operations::location::CancelLocationRes;
        staged_map_res(gsm_map::op_codes::CANCEL_LOCATION, &CancelLocationRes {})
    }

    /// Build a purgeMS result. `freeze_tmsi` / `freeze_p_tmsi` ask the VLR/SGSN
    /// to hold the (P-)TMSI back from reuse for a while.
    #[pyo3(signature = (*, freeze_tmsi=false, freeze_p_tmsi=false))]
    fn purge_ms_res(&self, freeze_tmsi: bool, freeze_p_tmsi: bool) -> PyResult<StagedResult> {
        use gsm_map::operations::location::PurgeMsRes;
        let res = PurgeMsRes {
            freeze_tmsi: freeze_tmsi.then_some(()),
            freeze_p_tmsi: freeze_p_tmsi.then_some(()),
        };
        staged_map_res(gsm_map::op_codes::PURGE_MS, &res)
    }

    /// Build a readyForSM result: the HLR acknowledging the alert.
    fn ready_for_sm_res(&self) -> PyResult<StagedResult> {
        use gsm_map::operations::ready_for_sm::ReadyForSmRes;
        staged_map_res(gsm_map::op_codes::READY_FOR_SM, &ReadyForSmRes {})
    }

    /// Stage an insertSubscriberData invoke: the HLR pushes subscriber data to
    /// the VLR inside a held-open updateLocation. `imsi` / `msisdn` are the TBCD
    /// address bytes.
    #[pyo3(signature = (*, imsi=None, msisdn=None))]
    fn insert_subscriber_data(
        &self,
        imsi: Option<Vec<u8>>,
        msisdn: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_map::operations::subscriber_data::{op_codes, InsertSubscriberDataArg};
        let arg = InsertSubscriberDataArg {
            imsi: imsi.map(Into::into),
            msisdn: msisdn.map(Into::into),
            category: None,
            subscriber_status: None,
            bearer_service_list: None,
            teleservice_list: None,
            odb_data: None,
            roaming_restricted_in_sgsn_due_to_unsupported_feature: None,
            network_access_mode: None,
        };
        staged_map_invoke(op_codes::INSERT_SUBSCRIBER_DATA, &arg)
    }

    /// Stage an MO-ForwardSM invoke: relay a mobile-originated `tpdu` from
    /// `msisdn` to the service centre `sc_addr` (an IWMSC handing MO SMS on to
    /// the SMSC). `imsi` is the optional originating IMSI.
    #[pyo3(signature = (*, sc_addr, msisdn, tpdu, imsi=None))]
    fn mo_forward_sm(
        &self,
        sc_addr: Vec<u8>,
        msisdn: Vec<u8>,
        tpdu: Vec<u8>,
        imsi: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
        use gsm_map::{SmRpDa, SmRpOa};
        let arg = MoForwardSmArg {
            sm_rp_da: SmRpDa::ServiceCentreAddressDa(sc_addr.into()),
            sm_rp_oa: SmRpOa::MsIsdn(msisdn.into()),
            sm_rp_ui: tpdu.into(),
            imsi: imsi.map(Into::into),
        };
        staged_map_invoke(gsm_map::op_codes::MO_FORWARD_SM, &arg)
    }

    /// Stage an MT-ForwardSM invoke: deliver `tpdu` to `imsi` from `sc_addr`,
    /// with `more_messages_to_send` set on all but the last segment.
    #[pyo3(signature = (*, imsi, sc_addr, tpdu, more_messages_to_send=false))]
    fn mt_forward_sm(
        &self,
        imsi: Vec<u8>,
        sc_addr: Vec<u8>,
        tpdu: Vec<u8>,
        more_messages_to_send: bool,
    ) -> PyResult<StagedInvoke> {
        use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
        use gsm_map::{SmRpDa, SmRpOa};
        let arg = MtForwardSmArg {
            sm_rp_da: SmRpDa::Imsi(imsi.into()),
            sm_rp_oa: SmRpOa::ServiceCentreAddressOa(sc_addr.into()),
            sm_rp_ui: tpdu.into(),
            more_messages_to_send: more_messages_to_send.then_some(()),
        };
        let bytes = rasn::ber::encode(&arg).map_err(err)?;
        Ok(StagedInvoke {
            op: Operation::MtForwardSm.op_code(),
            arg: Some(bytes),
        })
    }

    /// Originate a SendRoutingInfoForSM to the HLR (routed by GTT). Returns an
    /// awaitable that resolves to the HLR's routing info; awaiting it needs a
    /// running node (a live SCTP transport driven by a siphon binary), so without
    /// one it resolves to that error.
    #[pyo3(signature = (*, msisdn, sc_addr))]
    fn send_routing_info_for_sm<'py>(
        &self,
        py: Python<'py>,
        msisdn: Vec<u8>,
        sc_addr: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let _ = (msisdn, sc_addr);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Err::<(), PyErr>(err(
                "gsm_map.send_routing_info_for_sm needs a running node (a live SCTP transport)",
            ))
        })
    }

    /// Open an originating dialogue we initiate (an SMSC's MT delivery). Flushing
    /// it (`send` / `end`) over the wire needs a running node; the composing
    /// siphon binary drives origination over the transport.
    #[pyo3(signature = (*, to, ssn=8, ac=None))]
    fn begin(&self, to: &Address, ssn: u8, ac: Option<PyRef<'_, MapAcHandle>>) -> PyDialogue {
        let _ = (to, ssn, ac);
        PyDialogue::new(Vec::new(), Vec::new())
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

/// An application-context OID handle (its arcs), carried into `gsm_map.begin`.
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
    /// Terminate a CAMEL initialDP (`@gsm_cap.on_initial_dp`).
    fn on_initial_dp(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_cap::op_codes::INITIAL_DP, &func);
        func
    }

    /// Terminate a CAMEL EventReportBCSM (`@gsm_cap.on_event_report_bcsm`): the
    /// gsmSSF reporting an armed detection point back to the SCP inside an open
    /// dialogue.
    fn on_event_report_bcsm(&self, py: Python<'_>, func: Py<PyAny>) -> Py<PyAny> {
        register_termination(py, gsm_cap::op_codes::EVENT_REPORT_BCSM, &func);
        func
    }

    /// Stage a CAP Connect invoke: reroute the call to
    /// `destination_routing_address` (a list of called-party-number byte strings).
    #[pyo3(signature = (*, destination_routing_address))]
    fn connect(&self, destination_routing_address: Vec<Vec<u8>>) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ConnectArg;
        let arg = ConnectArg {
            destination_routing_address: destination_routing_address
                .into_iter()
                .map(Into::into)
                .collect(),
            original_called_party_id: None,
            calling_partys_category: None,
            redirecting_party_id: None,
            generic_numbers: None,
        };
        let bytes = gsm_cap::encode(&arg).map_err(err)?;
        Ok(StagedInvoke {
            op: gsm_cap::op_codes::CONNECT,
            arg: Some(bytes),
        })
    }

    /// Stage a CAP ReleaseCall invoke: tear the call down with a Q.850 `cause`.
    #[pyo3(signature = (*, cause))]
    fn release_call(&self, cause: Vec<u8>) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ReleaseCallArg;
        let arg = ReleaseCallArg {
            cause: cause.into(),
        };
        let bytes = gsm_cap::encode(&arg).map_err(err)?;
        Ok(StagedInvoke {
            op: gsm_cap::op_codes::RELEASE_CALL,
            arg: Some(bytes),
        })
    }

    /// Stage a CAP RequestReportBCSMEvent invoke: arm the gsmSSF to report the
    /// given BCSM detection points. `events` is a list of
    /// `(event_type_bcsm, monitor_mode)` integer pairs (TS 29.078), e.g.
    /// `(7, 0)` = oAnswer interrupted, `(9, 1)` = oDisconnect notifyAndContinue.
    #[pyo3(signature = (events))]
    fn request_report_bcsm_event(&self, events: Vec<(i64, i64)>) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::RequestReportBcsmEventArg;
        use gsm_cap::types::BcsmEvent;
        let bcsm_events = events
            .into_iter()
            .map(|(et, mm)| {
                Ok(BcsmEvent {
                    event_type_bcsm: event_type_bcsm(et)?,
                    monitor_mode: monitor_mode(mm)?,
                    leg_id: None,
                })
            })
            .collect::<PyResult<Vec<_>>>()?;
        let arg = RequestReportBcsmEventArg { bcsm_events };
        let bytes = gsm_cap::encode(&arg).map_err(err)?;
        Ok(StagedInvoke {
            op: gsm_cap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            arg: Some(bytes),
        })
    }

    /// Stage a CAP ApplyCharging invoke: hand the gsmSSF the encoded charging
    /// characteristics (an online-charging control, e.g. a call-duration limit).
    /// `party_to_charge` names the leg to meter.
    #[pyo3(signature = (*, charging_characteristics, party_to_charge=None))]
    fn apply_charging(
        &self,
        charging_characteristics: Vec<u8>,
        party_to_charge: Option<Vec<u8>>,
    ) -> PyResult<StagedInvoke> {
        use gsm_cap::operations::ApplyChargingArg;
        let arg = ApplyChargingArg {
            ach_billing_charging_characteristics: charging_characteristics.into(),
            party_to_charge: party_to_charge.map(Into::into),
        };
        let bytes = gsm_cap::encode(&arg).map_err(err)?;
        Ok(StagedInvoke {
            op: gsm_cap::op_codes::APPLY_CHARGING,
            arg: Some(bytes),
        })
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
        9 => E::ODisconnect,
        10 => E::OAbandon,
        12 => E::TermAttemptAuthorized,
        13 => E::TBusy,
        14 => E::TNoAnswer,
        15 => E::TAnswer,
        17 => E::TDisconnect,
        18 => E::TAbandon,
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

/// Register a Python termination handler for `op` on every owned subsystem (so
/// the handler fires whichever local SSN the message was addressed to).
fn register_termination(py: Python<'_>, op: i64, func: &Py<PyAny>) {
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
            func: func.clone_ref(py),
        });
        engine.register(ssn, op, handler);
    }
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
    error: Option<(i64, i64)>,
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
            TcapMessage::Abort(a) => ("abort", Vec::new(), a.dtid.to_vec(), None, None),
            TcapMessage::Unidirectional(_) => {
                ("unidirectional", Vec::new(), Vec::new(), None, None)
            }
        };

        let app_context = dp
            .and_then(DialoguePortion::dialogue_pdu)
            .and_then(|pdu| match pdu {
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

        let mut invokes = Vec::new();
        let mut result = None;
        let mut error = None;
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
                    }
                    Component::ReturnError(re) => {
                        if let ErrorCode::Local(code) = re.error_code {
                            error.get_or_insert((re.invoke_id, code));
                        }
                    }
                    _ => {}
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
            error,
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
        let op_code = Operation::from_kebab(op)
            .map(Operation::op_code)
            .ok_or_else(|| err(format!("unknown operation `{op}`")))?;

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
        let component = if let Ok(res) = staged.cast::<StagedResult>() {
            let res = res.borrow();
            Component::ReturnResultLast(ReturnResult {
                invoke_id,
                result: Some(ReturnResultValue {
                    operation_code: OperationCode::Local(res.op),
                    parameter: res.param.clone().map(rasn::types::Any::new),
                }),
            })
        } else if let Ok(inv) = staged.cast::<StagedInvoke>() {
            let inv = inv.borrow();
            Component::Invoke(Invoke {
                invoke_id,
                linked_id: None,
                operation_code: OperationCode::Local(inv.op),
                parameter: inv.arg.clone().map(rasn::types::Any::new),
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

    /// Run a registered content hook against a decoded view and return its
    /// decision (drives the `async def` hook to completion). Raises if no hook of
    /// that name is registered.
    fn dispatch_content(
        &self,
        py: Python<'_>,
        name: &str,
        view: &PyMapView,
    ) -> PyResult<Py<PyAny>> {
        let handler = self
            .state
            .content_hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|h| h.clone_ref(py))
            .ok_or_else(|| err(format!("no content hook `{name}` registered")))?;
        let result = handler.bind(py).call1((view.clone(),))?;
        finish(py, result)
    }

    fn __repr__(&self) -> String {
        format!(
            "Node(tenant={}, ssns={:?})",
            self.state.tenant, self.state.local_ssns
        )
    }
}

/// Resolve a hook's return value, driving a coroutine to completion first.
fn finish(py: Python<'_>, result: Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    let asyncio = py.import("asyncio")?;
    if asyncio
        .call_method1("iscoroutine", (&result,))?
        .is_truthy()?
    {
        let event_loop = asyncio.call_method0("new_event_loop")?;
        let outcome = event_loop.call_method1("run_until_complete", (&result,));
        let _ = event_loop.call_method0("close");
        return Ok(outcome?.unbind());
    }
    Ok(result.unbind())
}

// ── Module-level functions ───────────────────────────────────────────────────

/// Configure the process-wide node from a `sigtran.yaml` (a path, an inline YAML
/// string, or a dict). Returns a [`Node`] handle; the `ss7` / `gsm_map` /
/// `gsm_cap` namespaces then program that node.
#[pyfunction]
fn configure(source: &Bound<'_, PyAny>) -> PyResult<Node> {
    let cfg = config_from_source(source)?;
    let state = Arc::new(NodeState::from_config(&cfg));
    set_node(state.clone());
    Ok(Node { state })
}

/// Render the Prometheus metrics text-exposition for the whole node.
#[pyfunction]
fn metrics() -> String {
    crate::metrics::render()
}

// ── Module wiring ────────────────────────────────────────────────────────────

fn add_contents(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SigtranError", py.get_type::<SigtranError>())?;

    // Namespace singletons.
    m.add("ss7", Bound::new(py, Ss7)?)?;
    m.add("gsm_map", Bound::new(py, GsmMap)?)?;
    m.add("gsm_cap", Bound::new(py, GsmCap)?)?;

    // Types a script imports for typing / construction.
    m.add_class::<Node>()?;
    m.add_class::<Decision>()?;
    m.add_class::<PyMapView>()?;
    m.add_class::<PyIncomingOp>()?;
    m.add_class::<PyPeerTurn>()?;
    m.add_class::<PyDecoded>()?;
    m.add_class::<PyDialogue>()?;
    m.add_class::<Address>()?;
    m.add_class::<MapAcHandle>()?;
    m.add_class::<StagedInvoke>()?;
    m.add_class::<StagedResult>()?;

    // Module functions.
    m.add_function(wrap_pyfunction!(configure, m)?)?;
    m.add_function(wrap_pyfunction!(metrics, m)?)?;
    Ok(())
}

/// The siphon integration seam. A composing siphon binary calls this once at
/// startup with the `siphon` package module as `parent`; it mounts the `ss7` /
/// `gsm_map` / `gsm_cap` namespace singletons, the `configure` / `metrics`
/// functions, the `SigtranError` exception, and the shared types onto it. A
/// hot-reloaded script then reaches them with
/// `from siphon import ss7, gsm_map, gsm_cap`, programs the Rust routing tables
/// live, and registers MAP/CAP termination handlers.
///
/// The namespace singletons drive one process-wide [`node`]. A composing binary
/// that prefers per-namespace mounting can instead register [`Ss7`] / [`GsmMap`]
/// / [`GsmCap`] individually (they are `#[pyclass]` values), but `register` is
/// the one-call form and the surface the tests drive.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(py, parent)
}
