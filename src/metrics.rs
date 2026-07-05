//! Process-wide counters the transport plane increments and a scrape endpoint
//! renders. Kept deliberately tiny: plain atomics, no registry crate, so the
//! routing hot path pays only a relaxed `fetch_add` when something noteworthy
//! happens.
//!
//! Today it carries the transfer-path loop guards. A message the transfer path
//! recognises as a loop is dropped and counted here so an operator can alarm on
//! `sigtran_loops_detected_total` climbing.

use std::sync::atomic::{AtomicU64, Ordering};

/// Why the transfer path decided an inbound MSU was a loop and dropped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    /// The MSU's OPC equals our own point code: a message we originated has come
    /// back to us.
    OwnOpc,
    /// The resolved egress is the very AS / linkset the MSU arrived on: sending
    /// it there would reflect it straight back.
    RouteReflect,
}

impl LoopKind {
    /// The `kind` label value used in the exposed metric.
    pub fn label(self) -> &'static str {
        match self {
            LoopKind::OwnOpc => "own-opc",
            LoopKind::RouteReflect => "route-reflect",
        }
    }
}

static LOOPS_OWN_OPC: AtomicU64 = AtomicU64::new(0);
static LOOPS_ROUTE_REFLECT: AtomicU64 = AtomicU64::new(0);

fn cell(kind: LoopKind) -> &'static AtomicU64 {
    match kind {
        LoopKind::OwnOpc => &LOOPS_OWN_OPC,
        LoopKind::RouteReflect => &LOOPS_ROUTE_REFLECT,
    }
}

/// Count one dropped loop of the given kind.
pub fn record_loop(kind: LoopKind) {
    cell(kind).fetch_add(1, Ordering::Relaxed);
}

/// The current count of dropped loops of the given kind.
pub fn loops_detected(kind: LoopKind) -> u64 {
    cell(kind).load(Ordering::Relaxed)
}

/// Render the metrics in Prometheus text-exposition format. Wire this into a
/// scrape endpoint; the values are read atomically at call time.
pub fn render() -> String {
    let mut out = String::new();
    out.push_str(
        "# HELP sigtran_loops_detected_total MSUs dropped by the MTP3 transfer-path loop guards.\n",
    );
    out.push_str("# TYPE sigtran_loops_detected_total counter\n");
    for kind in [LoopKind::OwnOpc, LoopKind::RouteReflect] {
        out.push_str(&format!(
            "sigtran_loops_detected_total{{kind=\"{}\"}} {}\n",
            kind.label(),
            loops_detected(kind)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable() {
        assert_eq!(LoopKind::OwnOpc.label(), "own-opc");
        assert_eq!(LoopKind::RouteReflect.label(), "route-reflect");
    }

    #[test]
    fn render_carries_both_series() {
        // record_loop mutates process-wide counters shared with the transport
        // tests, so assert on shape, not exact counts.
        let text = render();
        assert!(text.contains("# TYPE sigtran_loops_detected_total counter"));
        assert!(text.contains("sigtran_loops_detected_total{kind=\"own-opc\"}"));
        assert!(text.contains("sigtran_loops_detected_total{kind=\"route-reflect\"}"));
    }

    #[test]
    fn record_increments_the_matching_series() {
        let before = loops_detected(LoopKind::OwnOpc);
        record_loop(LoopKind::OwnOpc);
        assert!(loops_detected(LoopKind::OwnOpc) > before);
    }
}
