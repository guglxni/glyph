//! Lightweight in-process metrics + control-plane HTTP server for the GLYPH
//! TEE worker.
//!
//! Counters use atomic primitives — no external metrics dependency. Routes:
//!
//! - `/metrics` — Prometheus exposition (text v0.0.4)
//! - `/healthz` — liveness probe (200 OK)
//! - `/audit`   — sealed audit log JSON, streamed via the audit_log module
//!
//! The HTTP server is now [`axum`]-based (closes T39) so HTTP framing is
//! handled by `hyper` instead of the previous hand-rolled `BufReader::read_line`
//! that left dangling header bytes in the socket.
//!
//! ## Tracked Metrics
//! - `glyph_intents_total{status}` — accepted vs rejected
//! - `glyph_proof_generation_total{status}` — success vs failure
//! - `glyph_policy_violations_total` — policy rule rejections
//! - `glyph_requests_too_large_total` — DoS protection triggers
//! - `glyph_signature_failures_total` — Ed25519 verification failures
//! - `glyph_audit_entries_appended_total` — appends to the sealed audit log (WS-6)
//! - `glyph_audit_root_anchored_total` — successful on-chain audit-root anchors (WS-6)
//! - `glyph_rate_limited_total` — HTTP 429 responses returned by the rate limiter (WS-5)
//! - `glyph_mtls_handshake_failed_total` — TLS handshake failures (WS-5)
//! - `glyph_uptime_seconds` — process uptime

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Serialize;

use crate::audit_log::{AuditEntry, AuditLog};
use crate::vendors::TeeProvider;

/// Global metrics counters for the GLYPH TEE worker.
#[derive(Debug)]
pub struct WorkerMetrics {
    pub intents_received: AtomicU64,
    pub intents_accepted: AtomicU64,
    pub intents_policy_rejected: AtomicU64,
    pub intents_sig_failed: AtomicU64,
    pub requests_too_large: AtomicU64,
    pub proofs_generated: AtomicU64,
    pub proofs_failed: AtomicU64,
    pub attestations_ok: AtomicU64,
    pub attestations_failed: AtomicU64,
    pub attestation_stale_rejections: AtomicU64,
    /// WS-6: tamper-evident audit log emissions.
    pub audit_entries_appended: AtomicU64,
    /// WS-6: successful periodic anchoring of the Merkle root on-chain.
    pub audit_root_anchored: AtomicU64,
    /// WS-5: HTTP 429s emitted by the per-IP rate limiter. Per-IP labels are
    /// captured in `rate_limited_per_ip` for the `{ip}` cardinality.
    pub rate_limited_total: AtomicU64,
    pub rate_limited_per_ip: Mutex<HashMap<IpAddr, u64>>,
    /// WS-5: TLS handshake failures (no client cert, bad cert, etc.).
    pub mtls_handshake_failed: AtomicU64,
    pub started_at: Instant,
}

impl WorkerMetrics {
    pub fn new() -> Self {
        Self {
            intents_received: AtomicU64::new(0),
            intents_accepted: AtomicU64::new(0),
            intents_policy_rejected: AtomicU64::new(0),
            intents_sig_failed: AtomicU64::new(0),
            requests_too_large: AtomicU64::new(0),
            proofs_generated: AtomicU64::new(0),
            proofs_failed: AtomicU64::new(0),
            attestations_ok: AtomicU64::new(0),
            attestations_failed: AtomicU64::new(0),
            attestation_stale_rejections: AtomicU64::new(0),
            audit_entries_appended: AtomicU64::new(0),
            audit_root_anchored: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            rate_limited_per_ip: Mutex::new(HashMap::new()),
            mtls_handshake_failed: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    pub fn record_intent_received(&self) {
        self.intents_received.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_intent_accepted(&self) {
        self.intents_accepted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_policy_rejection(&self) {
        self.intents_policy_rejected.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_sig_failure(&self) {
        self.intents_sig_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_too_large(&self) {
        self.requests_too_large.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_proof_success(&self) {
        self.proofs_generated.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_proof_failure(&self) {
        self.proofs_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_attestation_success(&self) {
        self.attestations_ok.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_attestation_failure(&self) {
        self.attestations_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_attestation_stale_rejection(&self) {
        self.attestation_stale_rejections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_audit_entry_appended(&self) {
        self.audit_entries_appended.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_audit_root_anchored(&self) {
        self.audit_root_anchored.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_rate_limited(&self, ip: IpAddr) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
        let mut g = self.rate_limited_per_ip.lock().unwrap();
        *g.entry(ip).or_insert(0) += 1;
    }
    pub fn record_mtls_handshake_failed(&self) {
        self.mtls_handshake_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Serialize metrics in Prometheus text format.
    pub fn to_prometheus_text(&self) -> String {
        let uptime = self.started_at.elapsed().as_secs();
        let received = self.intents_received.load(Ordering::Relaxed);
        let accepted = self.intents_accepted.load(Ordering::Relaxed);
        let policy_rejected = self.intents_policy_rejected.load(Ordering::Relaxed);
        let sig_failed = self.intents_sig_failed.load(Ordering::Relaxed);
        let too_large = self.requests_too_large.load(Ordering::Relaxed);
        let proofs_ok = self.proofs_generated.load(Ordering::Relaxed);
        let proofs_err = self.proofs_failed.load(Ordering::Relaxed);
        let attest_ok = self.attestations_ok.load(Ordering::Relaxed);
        let attest_err = self.attestations_failed.load(Ordering::Relaxed);
        let attest_stale = self.attestation_stale_rejections.load(Ordering::Relaxed);
        let audit_appended = self.audit_entries_appended.load(Ordering::Relaxed);
        let audit_anchored = self.audit_root_anchored.load(Ordering::Relaxed);
        let rate_limited = self.rate_limited_total.load(Ordering::Relaxed);
        let mtls_fail = self.mtls_handshake_failed.load(Ordering::Relaxed);

        let mut out = format!(
            "# HELP glyph_intents_received_total Total intents received\n\
             # TYPE glyph_intents_received_total counter\n\
             glyph_intents_received_total {received}\n\
             # HELP glyph_intents_accepted_total Intents accepted by policy and proven\n\
             # TYPE glyph_intents_accepted_total counter\n\
             glyph_intents_accepted_total {accepted}\n\
             # HELP glyph_intents_policy_rejected_total Intents rejected by policy engine\n\
             # TYPE glyph_intents_policy_rejected_total counter\n\
             glyph_intents_policy_rejected_total {policy_rejected}\n\
             # HELP glyph_intents_sig_failed_total Intents rejected due to signature failure\n\
             # TYPE glyph_intents_sig_failed_total counter\n\
             glyph_intents_sig_failed_total {sig_failed}\n\
             # HELP glyph_requests_too_large_total Requests rejected due to size limit\n\
             # TYPE glyph_requests_too_large_total counter\n\
             glyph_requests_too_large_total {too_large}\n\
             # HELP glyph_proofs_generated_total Groth16 proofs successfully generated\n\
             # TYPE glyph_proofs_generated_total counter\n\
             glyph_proofs_generated_total {proofs_ok}\n\
             # HELP glyph_proofs_failed_total Groth16 proof generation failures\n\
             # TYPE glyph_proofs_failed_total counter\n\
             glyph_proofs_failed_total {proofs_err}\n\
             # HELP glyph_attestations_ok_total Successful TEE attestations\n\
             # TYPE glyph_attestations_ok_total counter\n\
             glyph_attestations_ok_total {attest_ok}\n\
             # HELP glyph_attestations_failed_total Failed TEE attestation operations\n\
             # TYPE glyph_attestations_failed_total counter\n\
             glyph_attestations_failed_total {attest_err}\n\
             # HELP glyph_attestation_stale_rejections_total Intents rejected for stale attestation\n\
             # TYPE glyph_attestation_stale_rejections_total counter\n\
             glyph_attestation_stale_rejections_total {attest_stale}\n\
             # HELP glyph_audit_entries_appended_total Sealed audit-log entries appended (WS-6)\n\
             # TYPE glyph_audit_entries_appended_total counter\n\
             glyph_audit_entries_appended_total {audit_appended}\n\
             # HELP glyph_audit_root_anchored_total Successful on-chain audit-root anchors (WS-6)\n\
             # TYPE glyph_audit_root_anchored_total counter\n\
             glyph_audit_root_anchored_total {audit_anchored}\n\
             # HELP glyph_rate_limited_total HTTP 429 responses emitted by the per-IP rate limiter (WS-5)\n\
             # TYPE glyph_rate_limited_total counter\n\
             glyph_rate_limited_total {rate_limited}\n\
             # HELP glyph_mtls_handshake_failed_total mTLS handshake failures (WS-5)\n\
             # TYPE glyph_mtls_handshake_failed_total counter\n\
             glyph_mtls_handshake_failed_total {mtls_fail}\n\
             # HELP glyph_uptime_seconds Worker process uptime in seconds\n\
             # TYPE glyph_uptime_seconds gauge\n\
             glyph_uptime_seconds {uptime}\n"
        );

        // Per-IP rate-limit hits with `{ip}` label.
        let per_ip = self.rate_limited_per_ip.lock().unwrap();
        if !per_ip.is_empty() {
            out.push_str("# HELP glyph_rate_limited_per_ip_total Per-IP rate-limit hits (WS-5)\n");
            out.push_str("# TYPE glyph_rate_limited_per_ip_total counter\n");
            for (ip, count) in per_ip.iter() {
                out.push_str(&format!(
                    "glyph_rate_limited_per_ip_total{{ip=\"{ip}\"}} {count}\n"
                ));
            }
        }

        out
    }
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state for the axum router.
#[derive(Clone)]
pub struct ControlPlaneState {
    pub metrics: Arc<WorkerMetrics>,
    /// Audit log + the TEE provider that can unseal it for `/audit`.
    pub audit: Option<Arc<tokio::sync::Mutex<AuditLog>>>,
    pub provider: Option<Arc<dyn TeeProvider>>,
}

#[derive(Serialize)]
struct AuditResponse {
    sequence_high: u64,
    entries: Vec<AuditEntry>,
}

async fn metrics_handler(State(s): State<ControlPlaneState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        s.metrics.to_prometheus_text(),
    )
}

async fn healthz_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn audit_handler(State(s): State<ControlPlaneState>) -> impl IntoResponse {
    let Some(audit) = s.audit else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "audit log not configured".to_string(),
        )
            .into_response();
    };
    let Some(provider) = s.provider else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "audit provider not configured".to_string(),
        )
            .into_response();
    };
    let guard = audit.lock().await;
    match guard.read_full_chain(provider.as_ref()) {
        Ok(entries) => {
            let body = AuditResponse {
                sequence_high: guard.sequence_high(),
                entries,
            };
            axum::Json(body).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read audit log: {e}"),
        )
            .into_response(),
    }
}

/// Build the axum router. Exposed so integration tests can mount it without
/// binding a real socket.
pub fn build_router(state: ControlPlaneState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz_handler))
        .route("/audit", get(audit_handler))
        .with_state(state)
}

/// Spawn the control-plane HTTP server (axum). Listens on `GLYPH_METRICS_ADDR`
/// (default `127.0.0.1:9091`). Production deployments must keep this loopback
/// unless `GLYPH_METRICS_PUBLIC_BIND=1` is set explicitly — the caller is
/// responsible for that policy at startup.
pub async fn spawn_control_plane(state: ControlPlaneState) -> std::io::Result<()> {
    let addr = std::env::var("GLYPH_METRICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9091".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "control plane listening (axum: /metrics, /healthz, /audit)");
    let router = build_router(state);
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_counting() {
        let m = WorkerMetrics::new();
        m.record_intent_received();
        m.record_intent_received();
        m.record_intent_accepted();
        m.record_policy_rejection();
        m.record_proof_success();
        m.record_audit_entry_appended();

        assert_eq!(m.intents_received.load(Ordering::Relaxed), 2);
        assert_eq!(m.intents_accepted.load(Ordering::Relaxed), 1);
        assert_eq!(m.intents_policy_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(m.proofs_generated.load(Ordering::Relaxed), 1);
        assert_eq!(m.audit_entries_appended.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_prometheus_output_format() {
        let m = WorkerMetrics::new();
        m.record_intent_received();
        m.record_intent_accepted();
        m.record_audit_entry_appended();
        let text = m.to_prometheus_text();
        assert!(text.contains("glyph_intents_received_total 1"));
        assert!(text.contains("glyph_audit_entries_appended_total 1"));
        assert!(text.contains("# TYPE glyph_uptime_seconds gauge"));
    }
}
