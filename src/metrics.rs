//! Process-wide counters and gauges the transport, router, and dialogue engine
//! maintain, plus a Prometheus text-exposition renderer.
//!
//! Everything here is kept deliberately cheap so the routing hot path never
//! pays more than a relaxed atomic `fetch_add` (and never an allocation). The
//! per-message families ([`msu`], [`gtt_translation`], [`gtt_error`]) are backed
//! by fixed atomic arrays, so a line-rate MSU stream allocates nothing. The
//! low-frequency, label-rich families (state gauges, route availability,
//! MTP3-management events, content-rule hits, invoke timeouts) live behind a
//! mutex-guarded map and are only touched on a state change or a rule hit, not
//! per transit MSU.
//!
//! There is deliberately **no** per-scrape registry crate and no `tenant` label:
//! the renderer walks a handful of statics. Embed [`render`] behind whatever
//! scrape endpoint the host serves (a tiny HTTP handler that returns its
//! string), or read the individual accessors directly in a test.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

// ── Loop guards (phase 2) ────────────────────────────────────────────────────

/// Why the transfer path decided an inbound MSU was a loop and dropped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    /// The MSU's OPC equals our own point code: a message we originated has come
    /// back to us.
    OwnOpc,
    /// The resolved egress is the very AS / linkset the MSU arrived on: sending
    /// it there would reflect it straight back.
    RouteReflect,
    /// The SCCP hop counter reached zero at a global-title translation: the
    /// standard GTT loop breaker (Q.713). The message is discarded and, when it
    /// asked to be returned on error, an XUDTS/LUDTS with cause "hop counter
    /// violation" is sent back to the originator.
    HopCounter,
}

impl LoopKind {
    /// The `kind` label value used in the exposed metric.
    pub fn label(self) -> &'static str {
        match self {
            LoopKind::OwnOpc => "own-opc",
            LoopKind::RouteReflect => "route-reflect",
            LoopKind::HopCounter => "hop-counter",
        }
    }
}

static LOOPS_OWN_OPC: AtomicU64 = AtomicU64::new(0);
static LOOPS_ROUTE_REFLECT: AtomicU64 = AtomicU64::new(0);
static LOOPS_HOP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn loop_cell(kind: LoopKind) -> &'static AtomicU64 {
    match kind {
        LoopKind::OwnOpc => &LOOPS_OWN_OPC,
        LoopKind::RouteReflect => &LOOPS_ROUTE_REFLECT,
        LoopKind::HopCounter => &LOOPS_HOP_COUNTER,
    }
}

/// Count one dropped loop of the given kind.
pub fn record_loop(kind: LoopKind) {
    loop_cell(kind).fetch_add(1, Ordering::Relaxed);
}

/// The current count of dropped loops of the given kind.
pub fn loops_detected(kind: LoopKind) -> u64 {
    loop_cell(kind).load(Ordering::Relaxed)
}

// ── ISUP screening (SI=5 transit path) ───────────────────────────────────────

/// Why an ISUP MSU was screened (dropped) on the SI=5 transit path. A peer of
/// the [`LoopKind`] loop guards: same fixed-array atomic shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenReason {
    /// The message matched an explicit `block` screening rule.
    Rule,
    /// No rule matched and the screening default action is `block`.
    Default,
    /// The message would not decode as ISUP and the screening default action is
    /// `block` (a malformed frame is never silently mis-routed).
    DecodeError,
}

impl ScreenReason {
    /// The `reason` label value used in the exposed metric.
    pub fn label(self) -> &'static str {
        match self {
            ScreenReason::Rule => "rule",
            ScreenReason::Default => "default",
            ScreenReason::DecodeError => "decode-error",
        }
    }
}

static ISUP_SCREENED_RULE: AtomicU64 = AtomicU64::new(0);
static ISUP_SCREENED_DEFAULT: AtomicU64 = AtomicU64::new(0);
static ISUP_SCREENED_DECODE: AtomicU64 = AtomicU64::new(0);

fn screen_cell(reason: ScreenReason) -> &'static AtomicU64 {
    match reason {
        ScreenReason::Rule => &ISUP_SCREENED_RULE,
        ScreenReason::Default => &ISUP_SCREENED_DEFAULT,
        ScreenReason::DecodeError => &ISUP_SCREENED_DECODE,
    }
}

/// Count one ISUP MSU screened (dropped) for the given reason.
pub fn record_isup_screened(reason: ScreenReason) {
    screen_cell(reason).fetch_add(1, Ordering::Relaxed);
}

/// The current count of ISUP MSUs screened for the given reason.
pub fn isup_screened(reason: ScreenReason) -> u64 {
    screen_cell(reason).load(Ordering::Relaxed)
}

// ── MSU traffic counters (hot path, fixed arrays, zero allocation) ───────────

/// The direction an MSU crossed the node, for [`msu`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Received from a peer (ingress).
    Rx,
    /// Transmitted to a peer (egress).
    Tx,
}

impl Dir {
    fn label(self) -> &'static str {
        match self {
            Dir::Rx => "rx",
            Dir::Tx => "tx",
        }
    }
}

// [dir][si]: dir is 0=rx / 1=tx; si is the 4-bit Service Indicator (0..=15).
static MSU_TOTAL: [[AtomicU64; 16]; 2] = [
    [const { AtomicU64::new(0) }; 16],
    [const { AtomicU64::new(0) }; 16],
];

/// Count one MSU crossing the node in the given direction with Service Indicator
/// `si`. Backed by a fixed array, so the transfer path allocates nothing.
pub fn msu(dir: Dir, si: u8) {
    MSU_TOTAL[dir as usize][(si & 0x0F) as usize].fetch_add(1, Ordering::Relaxed);
}

/// The MSU count for a direction + Service Indicator.
pub fn msu_total(dir: Dir, si: u8) -> u64 {
    MSU_TOTAL[dir as usize][(si & 0x0F) as usize].load(Ordering::Relaxed)
}

// ── SCCP GTT counters (hot path, fixed arrays) ───────────────────────────────

/// The kind of result a GTT lookup produced, for [`gtt_translation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GttResultKind {
    /// Terminated locally.
    Local,
    /// Translated to a concrete point code + SSN.
    Dpc,
    /// Resolved into a GTT group (cost / weighted-share).
    Group,
    /// Handed off to another routing domain.
    Tenant,
}

impl GttResultKind {
    fn index(self) -> usize {
        self as usize
    }
    fn label(self) -> &'static str {
        match self {
            GttResultKind::Local => "local",
            GttResultKind::Dpc => "dpc",
            GttResultKind::Group => "group",
            GttResultKind::Tenant => "tenant",
        }
    }
    const ALL: [GttResultKind; 4] = [Self::Local, Self::Dpc, Self::Group, Self::Tenant];
}

static GTT_TRANSLATIONS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Count one successful GTT translation of the given result kind.
pub fn gtt_translation(kind: GttResultKind) {
    GTT_TRANSLATIONS[kind.index()].fetch_add(1, Ordering::Relaxed);
}

/// The count of GTT translations that produced the given result kind.
pub fn gtt_translations(kind: GttResultKind) -> u64 {
    GTT_TRANSLATIONS[kind.index()].load(Ordering::Relaxed)
}

/// Why a GTT lookup failed, for [`gtt_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GttError {
    /// No rule matched the global title.
    NoTranslation,
    /// The message was addressed to a subsystem we do not own / that is down.
    SsnProhibited,
    /// The translation succeeded but no MTP3 route reaches the resolved DPC.
    NoRoute,
}

impl GttError {
    fn index(self) -> usize {
        self as usize
    }
    fn label(self) -> &'static str {
        match self {
            GttError::NoTranslation => "no-translation",
            GttError::SsnProhibited => "ssn-prohibited",
            GttError::NoRoute => "no-route",
        }
    }
    const ALL: [GttError; 3] = [Self::NoTranslation, Self::SsnProhibited, Self::NoRoute];
}

static GTT_ERRORS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Count one GTT error of the given reason.
pub fn gtt_error(reason: GttError) {
    GTT_ERRORS[reason.index()].fetch_add(1, Ordering::Relaxed);
}

/// The count of GTT errors with the given reason.
pub fn gtt_errors(reason: GttError) -> u64 {
    GTT_ERRORS[reason.index()].load(Ordering::Relaxed)
}

// ── Dialogue / TCAP counters (dialogue engine) ───────────────────────────────

static ACTIVE_DIALOGUES: AtomicI64 = AtomicI64::new(0);
static DIALOGUE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// A source that aborted a dialogue, for [`abort`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortSource {
    /// The dialogue user aborted (ABRT, dialogue-service-user).
    User,
    /// The dialogue provider aborted (ABRT, dialogue-service-provider), or a
    /// TCAP P-Abort.
    Provider,
    /// The node itself aborted (no handler, over the dialogue ceiling, malformed).
    Local,
}

impl AbortSource {
    fn index(self) -> usize {
        self as usize
    }
    fn label(self) -> &'static str {
        match self {
            AbortSource::User => "user",
            AbortSource::Provider => "provider",
            AbortSource::Local => "local",
        }
    }
    const ALL: [AbortSource; 3] = [Self::User, Self::Provider, Self::Local];
}

static ABORTS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Raise the active-dialogue gauge by one (a dialogue opened).
pub fn dialogue_opened() {
    ACTIVE_DIALOGUES.fetch_add(1, Ordering::Relaxed);
}

/// Lower the active-dialogue gauge by one (a dialogue closed).
pub fn dialogue_closed() {
    ACTIVE_DIALOGUES.fetch_sub(1, Ordering::Relaxed);
}

/// The current number of open dialogues.
pub fn active_dialogues() -> i64 {
    ACTIVE_DIALOGUES.load(Ordering::Relaxed)
}

/// Count one dialogue that timed out (no activity within the dialogue timer).
pub fn dialogue_timeout() {
    DIALOGUE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
}

/// The count of timed-out dialogues.
pub fn dialogue_timeouts() -> u64 {
    DIALOGUE_TIMEOUTS.load(Ordering::Relaxed)
}

/// Count one abort from the given source.
pub fn abort(source: AbortSource) {
    ABORTS[source.index()].fetch_add(1, Ordering::Relaxed);
}

/// The count of aborts from the given source.
pub fn aborts(source: AbortSource) -> u64 {
    ABORTS[source.index()].load(Ordering::Relaxed)
}

// ── Labelled, low-frequency families (mutex-guarded maps) ────────────────────

/// The map-backed families. Guarded together; only touched on a state change,
/// an invoke timeout, an MTP3-management event, or a content-rule hit, never on
/// the pure transit path.
#[derive(Default)]
struct Labelled {
    /// `sigtran_association_state{assoc,adaptation}` (0 down, 1 inactive, 2 up).
    association_state: BTreeMap<(String, String), i64>,
    /// `sigtran_asp_state{asp,as}` (0 inactive, 1 active).
    asp_state: BTreeMap<(String, String), i64>,
    /// `sigtran_linkset_available{linkset}` (0/1).
    linkset_available: BTreeMap<String, i64>,
    /// `sigtran_linkset_active_links{linkset}`.
    linkset_active_links: BTreeMap<String, i64>,
    /// `sigtran_m2pa_link_state{link}` (0 failed, 1 aligned, 2 in-service).
    m2pa_link_state: BTreeMap<String, i64>,
    /// `sigtran_route_available{dpc}` (0/1).
    route_available: BTreeMap<u32, i64>,
    /// `sigtran_mtp3mg_events_total{dpc,type}`.
    mtp3mg_events: BTreeMap<(u32, &'static str), u64>,
    /// `sigtran_content_rule_hits_total{rule,action}`.
    content_rule_hits: BTreeMap<(String, String), u64>,
    /// `sigtran_invoke_timeouts_total{operation}` (operation = op code).
    invoke_timeouts: BTreeMap<i64, u64>,
}

static LABELLED: Mutex<Option<Labelled>> = Mutex::new(None);

fn labelled() -> MutexGuard<'static, Option<Labelled>> {
    let mut g = LABELLED.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        *g = Some(Labelled::default());
    }
    g
}

/// A single M2PA link liveness value, for [`set_m2pa_link_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M2paLinkState {
    /// Out of alignment / failed.
    Failed,
    /// Aligned / proving, not yet carrying.
    Aligned,
    /// In service, carrying MSUs.
    InService,
}

impl M2paLinkState {
    fn value(self) -> i64 {
        match self {
            M2paLinkState::Failed => 0,
            M2paLinkState::Aligned => 1,
            M2paLinkState::InService => 2,
        }
    }
}

/// Set the `sigtran_association_state{assoc,adaptation}` gauge (0 down, 1 SCTP
/// up but adaptation inactive, 2 adaptation active/carrying).
pub fn set_association_state(assoc: &str, adaptation: &str, state: i64) {
    if let Some(m) = labelled().as_mut() {
        m.association_state
            .insert((assoc.to_string(), adaptation.to_string()), state);
    }
}

/// Set the `sigtran_asp_state{asp,as}` gauge (0 inactive, 1 active).
pub fn set_asp_state(asp: &str, as_name: &str, active: bool) {
    if let Some(m) = labelled().as_mut() {
        m.asp_state
            .insert((asp.to_string(), as_name.to_string()), i64::from(active));
    }
}

/// Set the `sigtran_linkset_available{linkset}` gauge and its active-link count.
pub fn set_linkset(linkset: &str, available: bool, active_links: usize) {
    if let Some(m) = labelled().as_mut() {
        m.linkset_available
            .insert(linkset.to_string(), i64::from(available));
        m.linkset_active_links
            .insert(linkset.to_string(), active_links as i64);
    }
}

/// Set the `sigtran_m2pa_link_state{link}` gauge.
pub fn set_m2pa_link_state(link: &str, state: M2paLinkState) {
    if let Some(m) = labelled().as_mut() {
        m.m2pa_link_state.insert(link.to_string(), state.value());
    }
}

/// Set the `sigtran_route_available{dpc}` gauge (0/1).
pub fn set_route_available(dpc: u32, available: bool) {
    if let Some(m) = labelled().as_mut() {
        m.route_available.insert(dpc, i64::from(available));
    }
}

/// The kind of MTP3-management event, for [`mtp3mg_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mtp3MgKind {
    /// Transfer-prohibited (destination unavailable / M3UA DUNA).
    Tfp,
    /// Transfer-allowed (destination available / M3UA DAVA).
    Tfa,
    /// Route paused.
    Pause,
    /// Route resumed.
    Resume,
    /// Congestion (SCON / TFC).
    Congestion,
}

impl Mtp3MgKind {
    fn label(self) -> &'static str {
        match self {
            Mtp3MgKind::Tfp => "tfp",
            Mtp3MgKind::Tfa => "tfa",
            Mtp3MgKind::Pause => "pause",
            Mtp3MgKind::Resume => "resume",
            Mtp3MgKind::Congestion => "congestion",
        }
    }
}

/// Count one MTP3-management event affecting a DPC.
pub fn mtp3mg_event(dpc: u32, kind: Mtp3MgKind) {
    if let Some(m) = labelled().as_mut() {
        *m.mtp3mg_events.entry((dpc, kind.label())).or_insert(0) += 1;
    }
}

/// The count of MTP3-management events of a kind for a DPC.
pub fn mtp3mg_events(dpc: u32, kind: Mtp3MgKind) -> u64 {
    labelled()
        .as_ref()
        .and_then(|m| m.mtp3mg_events.get(&(dpc, kind.label())).copied())
        .unwrap_or(0)
}

/// Count one content-rule hit by rule name and action.
pub fn content_rule_hit(rule: &str, action: &str) {
    if let Some(m) = labelled().as_mut() {
        // `get_mut` first so a repeated hit on an already-seen rule allocates
        // nothing; only a rule's first hit inserts an owned key.
        if let Some(v) = m
            .content_rule_hits
            .get_mut(&(rule.to_string(), action.to_string()))
        {
            *v += 1;
        } else {
            m.content_rule_hits
                .insert((rule.to_string(), action.to_string()), 1);
        }
    }
}

/// The count of content-rule hits for a rule + action.
pub fn content_rule_hits(rule: &str, action: &str) -> u64 {
    labelled()
        .as_ref()
        .and_then(|m| {
            m.content_rule_hits
                .get(&(rule.to_string(), action.to_string()))
                .copied()
        })
        .unwrap_or(0)
}

/// Count one invoke that timed out awaiting its result (operation = op code).
pub fn invoke_timeout(operation: i64) {
    if let Some(m) = labelled().as_mut() {
        *m.invoke_timeouts.entry(operation).or_insert(0) += 1;
    }
}

/// The count of invoke timeouts for an operation code.
pub fn invoke_timeouts(operation: i64) -> u64 {
    labelled()
        .as_ref()
        .and_then(|m| m.invoke_timeouts.get(&operation).copied())
        .unwrap_or(0)
}

// ── Renderer ─────────────────────────────────────────────────────────────────

/// Render every metric family in Prometheus text-exposition format. Wire this
/// into a scrape endpoint; the values are read at call time. No `tenant` label
/// is exposed.
pub fn render() -> String {
    let mut out = String::new();

    // Loop guards.
    help(
        &mut out,
        "sigtran_loops_detected_total",
        "MSUs dropped by the MTP3 transfer-path loop guards.",
        "counter",
    );
    for kind in [
        LoopKind::OwnOpc,
        LoopKind::RouteReflect,
        LoopKind::HopCounter,
    ] {
        line(
            &mut out,
            "sigtran_loops_detected_total",
            &[("kind", kind.label())],
            loops_detected(kind),
        );
    }

    // ISUP screening.
    help(
        &mut out,
        "sigtran_isup_screened_total",
        "ISUP MSUs dropped by the SI=5 transit-path screening rules, by reason.",
        "counter",
    );
    for reason in [
        ScreenReason::Rule,
        ScreenReason::Default,
        ScreenReason::DecodeError,
    ] {
        line(
            &mut out,
            "sigtran_isup_screened_total",
            &[("reason", reason.label())],
            isup_screened(reason),
        );
    }

    // MSU traffic.
    help(
        &mut out,
        "sigtran_msu_total",
        "MSUs handled, by direction and Service Indicator.",
        "counter",
    );
    for dir in [Dir::Rx, Dir::Tx] {
        for si in 0u8..16 {
            let v = msu_total(dir, si);
            if v > 0 {
                line(
                    &mut out,
                    "sigtran_msu_total",
                    &[("dir", dir.label()), ("si", &si.to_string())],
                    v,
                );
            }
        }
    }

    // GTT.
    help(
        &mut out,
        "sigtran_gtt_translations_total",
        "Successful GTT translations, by result kind.",
        "counter",
    );
    for kind in GttResultKind::ALL {
        line(
            &mut out,
            "sigtran_gtt_translations_total",
            &[("result", kind.label())],
            gtt_translations(kind),
        );
    }
    help(
        &mut out,
        "sigtran_gtt_errors_total",
        "Failed GTT lookups, by reason.",
        "counter",
    );
    for reason in GttError::ALL {
        line(
            &mut out,
            "sigtran_gtt_errors_total",
            &[("reason", reason.label())],
            gtt_errors(reason),
        );
    }

    // Dialogue / TCAP.
    help(
        &mut out,
        "sigtran_active_dialogues",
        "Currently open TCAP dialogues.",
        "gauge",
    );
    line_i(
        &mut out,
        "sigtran_active_dialogues",
        &[],
        active_dialogues(),
    );
    help(
        &mut out,
        "sigtran_dialogue_timeouts_total",
        "Dialogues aged out by the dialogue timer.",
        "counter",
    );
    line(
        &mut out,
        "sigtran_dialogue_timeouts_total",
        &[],
        dialogue_timeouts(),
    );
    help(
        &mut out,
        "sigtran_abort_total",
        "TCAP aborts, by source.",
        "counter",
    );
    for source in AbortSource::ALL {
        line(
            &mut out,
            "sigtran_abort_total",
            &[("source", source.label())],
            aborts(source),
        );
    }

    // Labelled families.
    let guard = labelled();
    if let Some(m) = guard.as_ref() {
        help(
            &mut out,
            "sigtran_association_state",
            "SCTP association state (0 down, 1 up, 2 adaptation active).",
            "gauge",
        );
        for ((assoc, adapt), v) in &m.association_state {
            line_i(
                &mut out,
                "sigtran_association_state",
                &[("assoc", assoc), ("adaptation", adapt)],
                *v,
            );
        }

        help(
            &mut out,
            "sigtran_asp_state",
            "M3UA ASP state (0 inactive, 1 active).",
            "gauge",
        );
        for ((asp, as_name), v) in &m.asp_state {
            line_i(
                &mut out,
                "sigtran_asp_state",
                &[("asp", asp), ("as", as_name)],
                *v,
            );
        }

        help(
            &mut out,
            "sigtran_linkset_available",
            "M2PA linkset availability (0/1).",
            "gauge",
        );
        for (name, v) in &m.linkset_available {
            line_i(
                &mut out,
                "sigtran_linkset_available",
                &[("linkset", name)],
                *v,
            );
        }
        help(
            &mut out,
            "sigtran_linkset_active_links",
            "In-service links in an M2PA linkset.",
            "gauge",
        );
        for (name, v) in &m.linkset_active_links {
            line_i(
                &mut out,
                "sigtran_linkset_active_links",
                &[("linkset", name)],
                *v,
            );
        }

        help(
            &mut out,
            "sigtran_m2pa_link_state",
            "M2PA link state (0 failed, 1 aligned, 2 in-service).",
            "gauge",
        );
        for (name, v) in &m.m2pa_link_state {
            line_i(&mut out, "sigtran_m2pa_link_state", &[("link", name)], *v);
        }

        help(
            &mut out,
            "sigtran_route_available",
            "Whether a DPC currently resolves to an available egress (0/1).",
            "gauge",
        );
        for (dpc, v) in &m.route_available {
            line_i(
                &mut out,
                "sigtran_route_available",
                &[("dpc", &dpc.to_string())],
                *v,
            );
        }

        help(
            &mut out,
            "sigtran_mtp3mg_events_total",
            "MTP3-management events, by DPC and type.",
            "counter",
        );
        for ((dpc, ty), v) in &m.mtp3mg_events {
            line(
                &mut out,
                "sigtran_mtp3mg_events_total",
                &[("dpc", &dpc.to_string()), ("type", ty)],
                *v,
            );
        }

        help(
            &mut out,
            "sigtran_content_rule_hits_total",
            "Content-routing rule hits, by rule and action.",
            "counter",
        );
        for ((rule, action), v) in &m.content_rule_hits {
            line(
                &mut out,
                "sigtran_content_rule_hits_total",
                &[("rule", rule), ("action", action)],
                *v,
            );
        }

        help(
            &mut out,
            "sigtran_invoke_timeouts_total",
            "Invokes aged out awaiting a result, by operation.",
            "counter",
        );
        for (op, v) in &m.invoke_timeouts {
            line(
                &mut out,
                "sigtran_invoke_timeouts_total",
                &[("operation", &op.to_string())],
                *v,
            );
        }
    }

    out
}

fn help(out: &mut String, name: &str, help: &str, ty: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(ty);
    out.push('\n');
}

fn labels(out: &mut String, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        return;
    }
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(v);
        out.push('"');
    }
    out.push('}');
}

fn line(out: &mut String, name: &str, ls: &[(&str, &str)], value: u64) {
    out.push_str(name);
    labels(out, ls);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn line_i(out: &mut String, name: &str, ls: &[(&str, &str)], value: i64) {
    out.push_str(name);
    labels(out, ls);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_labels_are_stable() {
        assert_eq!(LoopKind::OwnOpc.label(), "own-opc");
        assert_eq!(LoopKind::RouteReflect.label(), "route-reflect");
        assert_eq!(LoopKind::HopCounter.label(), "hop-counter");
    }

    #[test]
    fn screen_reason_labels_and_counter() {
        assert_eq!(ScreenReason::Rule.label(), "rule");
        assert_eq!(ScreenReason::Default.label(), "default");
        assert_eq!(ScreenReason::DecodeError.label(), "decode-error");
        let before = isup_screened(ScreenReason::Rule);
        record_isup_screened(ScreenReason::Rule);
        assert_eq!(isup_screened(ScreenReason::Rule), before + 1);
        // A different reason cell is untouched.
        let dflt = isup_screened(ScreenReason::Default);
        record_isup_screened(ScreenReason::DecodeError);
        assert_eq!(isup_screened(ScreenReason::Default), dflt);
    }

    #[test]
    fn render_carries_every_family_header() {
        // The families share process-wide state with the other tests, so assert
        // on the shape (every HELP/TYPE header present), not exact counts.
        let text = render();
        for family in [
            "sigtran_loops_detected_total",
            "sigtran_isup_screened_total",
            "sigtran_msu_total",
            "sigtran_gtt_translations_total",
            "sigtran_gtt_errors_total",
            "sigtran_active_dialogues",
            "sigtran_dialogue_timeouts_total",
            "sigtran_abort_total",
            "sigtran_association_state",
            "sigtran_asp_state",
            "sigtran_linkset_available",
            "sigtran_linkset_active_links",
            "sigtran_m2pa_link_state",
            "sigtran_route_available",
            "sigtran_mtp3mg_events_total",
            "sigtran_content_rule_hits_total",
            "sigtran_invoke_timeouts_total",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "missing family {family}"
            );
        }
    }

    #[test]
    fn msu_counter_increments_the_matching_cell() {
        let before = msu_total(Dir::Rx, 3);
        msu(Dir::Rx, 3);
        assert_eq!(msu_total(Dir::Rx, 3), before + 1);
        // A different SI is untouched.
        let isup_before = msu_total(Dir::Rx, 5);
        msu(Dir::Tx, 5);
        assert_eq!(msu_total(Dir::Rx, 5), isup_before);
    }

    #[test]
    fn gtt_result_and_error_labels() {
        assert_eq!(GttResultKind::Group.label(), "group");
        assert_eq!(GttError::NoTranslation.label(), "no-translation");
        let before = gtt_translations(GttResultKind::Dpc);
        gtt_translation(GttResultKind::Dpc);
        assert_eq!(gtt_translations(GttResultKind::Dpc), before + 1);
    }

    #[test]
    fn active_dialogue_gauge_rises_and_falls() {
        let base = active_dialogues();
        dialogue_opened();
        dialogue_opened();
        assert_eq!(active_dialogues(), base + 2);
        dialogue_closed();
        assert_eq!(active_dialogues(), base + 1);
        dialogue_closed();
        assert_eq!(active_dialogues(), base);
    }

    #[test]
    fn labelled_families_round_trip() {
        set_association_state("hlr-a", "m3ua", 2);
        set_asp_state("hlr-a", "hlr", true);
        set_linkset("transit", true, 2);
        set_m2pa_link_state("xit-1", M2paLinkState::InService);
        set_route_available(2000, true);
        mtp3mg_event(2000, Mtp3MgKind::Pause);
        content_rule_hit("sri-sm-np", "python");
        content_rule_hit("sri-sm-np", "python");
        invoke_timeout(45);

        assert_eq!(mtp3mg_events(2000, Mtp3MgKind::Pause), 1);
        assert_eq!(content_rule_hits("sri-sm-np", "python"), 2);
        assert_eq!(invoke_timeouts(45), 1);

        let text = render();
        assert!(text.contains("sigtran_association_state{assoc=\"hlr-a\",adaptation=\"m3ua\"} 2"));
        assert!(text.contains("sigtran_route_available{dpc=\"2000\"} 1"));
        assert!(text
            .contains("sigtran_content_rule_hits_total{rule=\"sri-sm-np\",action=\"python\"} 2"));
    }
}
