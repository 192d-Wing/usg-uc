//! Shared sync status + the metrics/health HTTP surface.
//!
//! Each reconcile cycle records its outcome into a [`SyncStatus`]; a small
//! Axum server renders it as Prometheus metrics at `/metrics` so central
//! dashboards can chart per-site staleness (`central_epoch - applied_epoch`)
//! and error rates, and answer `/healthz` / `/readyz`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::source::Outcome;

/// Mutable per-agent status, shared between the reconcile loop (writer) and
/// the metrics server (reader).
#[derive(Debug, Default)]
struct Inner {
    /// Epoch the local shard is at (last applied).
    applied_epoch: i64,
    /// Epoch central reported on the last successful probe.
    central_epoch: i64,
    /// Unix seconds of the last successful reconcile (0 = never).
    last_success_secs: u64,
    /// Total reconcile cycles attempted.
    reconcile_total: u64,
    /// Total cycles that ended in an error.
    errors_total: u64,
    /// Whether the last cycle succeeded (drives readiness once primed).
    last_ok: bool,
    /// Whether at least one cycle has completed.
    primed: bool,
}

/// Thread-safe handle to the agent's status.
#[derive(Clone)]
pub struct SyncStatus {
    site: Arc<str>,
    inner: Arc<Mutex<Inner>>,
}

impl SyncStatus {
    /// New status for `site`, before any cycle has run.
    #[must_use]
    pub fn new(site: &str) -> Self {
        Self {
            site: Arc::from(site),
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a successful cycle and its outcome.
    pub fn record_success(&self, outcome: &Outcome) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut s = self.lock();
        s.reconcile_total += 1;
        s.last_ok = true;
        s.primed = true;
        s.last_success_secs = now;
        let epoch = match *outcome {
            Outcome::UpToDate { epoch } | Outcome::Snapshotted { epoch, .. } => epoch,
            Outcome::DeltaApplied { to, .. } => to,
        };
        s.applied_epoch = epoch;
        s.central_epoch = epoch;
    }

    /// Record a failed cycle.
    pub fn record_error(&self) {
        let mut s = self.lock();
        s.reconcile_total += 1;
        s.errors_total += 1;
        s.last_ok = false;
        s.primed = true;
    }

    /// Render the current status as Prometheus text.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write as _;
        let s = self.lock();
        let site = &self.site;
        let staleness = (s.central_epoch - s.applied_epoch).max(0);
        let mut out = String::new();
        let mut metric = |name: &str, kind: &str, help: &str, val: i64| {
            let _ = writeln!(out, "# HELP sbc_config_sync_{name} {help}");
            let _ = writeln!(out, "# TYPE sbc_config_sync_{name} {kind}");
            let _ = writeln!(out, "sbc_config_sync_{name}{{site=\"{site}\"}} {val}");
        };
        metric(
            "applied_epoch",
            "gauge",
            "Local shard epoch (last applied)",
            s.applied_epoch,
        );
        metric(
            "central_epoch",
            "gauge",
            "Central shard epoch (last probe)",
            s.central_epoch,
        );
        metric(
            "staleness_epochs",
            "gauge",
            "central_epoch - applied_epoch",
            staleness,
        );
        metric(
            "last_success_timestamp_seconds",
            "gauge",
            "Unix time of the last successful reconcile",
            i64::try_from(s.last_success_secs).unwrap_or(i64::MAX),
        );
        metric(
            "reconcile_total",
            "counter",
            "Total reconcile cycles attempted",
            i64::try_from(s.reconcile_total).unwrap_or(i64::MAX),
        );
        metric(
            "errors_total",
            "counter",
            "Total reconcile cycles that errored",
            i64::try_from(s.errors_total).unwrap_or(i64::MAX),
        );
        drop(s);
        out
    }

    /// `true` once a cycle has run and the most recent one succeeded.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        let s = self.lock();
        s.primed && s.last_ok
    }
}

/// Build the metrics/health router.
pub fn router(status: SyncStatus) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(status)
}

async fn readyz(State(status): State<SyncStatus>) -> Response {
    if status.is_ready() {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unready").into_response()
    }
}

async fn metrics(State(status): State<SyncStatus>) -> Response {
    (
        [("content-type", "text/plain; version=0.0.4")],
        status.render_prometheus(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_staleness_and_counters() {
        let status = SyncStatus::new("MUHJ");
        assert!(!status.is_ready(), "not ready before any cycle");

        status.record_success(&Outcome::Snapshotted { epoch: 5, rows: 3 });
        status.record_error();

        let text = status.render_prometheus();
        assert!(text.contains("sbc_config_sync_applied_epoch{site=\"MUHJ\"} 5"));
        assert!(text.contains("sbc_config_sync_staleness_epochs{site=\"MUHJ\"} 0"));
        assert!(text.contains("sbc_config_sync_reconcile_total{site=\"MUHJ\"} 2"));
        assert!(text.contains("sbc_config_sync_errors_total{site=\"MUHJ\"} 1"));
        // Last cycle errored → not ready.
        assert!(!status.is_ready());

        // A success flips readiness and updates the gauges.
        status.record_success(&Outcome::DeltaApplied {
            from: 5,
            to: 8,
            changes: 2,
        });
        assert!(status.is_ready());
        assert!(
            status
                .render_prometheus()
                .contains("applied_epoch{site=\"MUHJ\"} 8")
        );
    }
}
