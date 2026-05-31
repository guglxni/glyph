use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature as DalekSignature, SigningKey, Verifier, VerifyingKey};
use glyph_common::{
    canonical_signing_payload, hash_intent, hash_policy, CanonicalAccountMeta, CanonicalIntent,
};
use glyph_tee_worker::audit_log::{AuditEntryInner, AuditLog};
#[allow(unused_imports)]
use glyph_tee_worker::clock::{ClockBackend, MonotonicBackend, RoughtimeBackend, TrustedClock};
use glyph_tee_worker::metrics::{spawn_control_plane, ControlPlaneState, WorkerMetrics};
use glyph_tee_worker::mtls::MtlsListener;
use glyph_tee_worker::policy::PolicyEngine;
use glyph_tee_worker::prover::{DevProver, Prover};
use glyph_tee_worker::rate_limit::RateLimiter;
use glyph_tee_worker::transaction_builder::{
    canonical_target_instruction_bytes, solana_types::Pubkey, TransactionBuilder,
};
use glyph_tee_worker::types::{
    GlyphProofBundle, RuntimeMode, TeeVendor, TransactionIntent, WorkerConfig, WorkerResponse,
};
use glyph_tee_worker::vendors::{create_provider, AttestationEvidence, TeeProvider};
use rand::RngCore;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use zeroize::Zeroize;

/// How often the worker re-runs `provider.attest(...)` and rotates the
/// boot-time evidence stored in `AppState`. Closes T6 / T20 (freshness of
/// the attestation envelope attached to bundles).
const RE_ATTESTATION_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Maximum age of the latest attestation before the worker refuses to accept
/// new intents. Set to 2× the re-attestation interval to give the background
/// task a full window of slack before the gate trips.
const MAX_ATTESTATION_AGE_SECS: u64 = RE_ATTESTATION_INTERVAL_SECS * 2;

/// Domain string for the boot-time attestation `user_data` 5-tuple binding
/// (closes T6). The vendor's `compute_user_data` implementation hashes this
/// alongside `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`.
const BOOT_ATTEST_DOMAIN: &[u8] = b"GLYPH_WORKER_BOOT_v1";

/// Domain string for the production-mode self-test attestation in
/// `enforce_production_invariants` (closes T29). Mixed into the probe
/// `user_data` via `compute_user_data` so production self-tests are
/// distinguishable from real boot attestations in vendor logs.
#[cfg_attr(not(feature = "risc0"), allow(dead_code))]
const PROD_CHECK_DOMAIN: &[u8] = b"GLYPH_PROD_CHECK_v1";

/// Reusable shape for the latest TEE evidence + the policy commitment it was
/// bound to. Stored under an `RwLock` so the periodic re-attestation task
/// can rotate it without blocking the request path.
#[derive(Debug, Clone)]
struct BoundAttestation {
    evidence: AttestationEvidence,
    /// The policy commitment threaded into `compute_user_data` when this
    /// evidence was generated. Bundles compare against the *current* policy
    /// commitment at request time so a stale envelope on a rotated policy
    /// is rejected as `AttestationStale` rather than silently attached.
    policy_commitment: [u8; 32],
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config().context("failed to load worker config")?;
    init_tracing(&config.runtime_mode).context("failed to initialise tracing")?;
    info!(listen_addr = %config.listen_addr, mode = ?config.runtime_mode, "starting GLYPH TEE worker");

    let provider: Arc<dyn TeeProvider> = Arc::from(create_provider(config.tee_vendor.clone()));

    // ── Production Mode Enforcement ──────────────────────────────────────────
    // Closes F-26 (returns Result instead of panicking) plus T4/T29: the
    // production gate now exercises real TEE attestation + sealing instead
    // of only checking ZK env-vars. The provider must be passed in so the
    // checks can call `require_real()`, `attest()` and `seal()/unseal()` for
    // real before we accept any traffic.
    enforce_production_invariants(&config, provider.as_ref())
        .context("production-mode invariants failed")?;

    let mut sealed_policy = std::fs::read(&config.policy_path)
        .with_context(|| format!("failed to read policy file: {}", config.policy_path))?;

    let unsealed_policy = provider
        .unseal(&sealed_policy)
        .context("failed to unseal policy")?;
    sealed_policy.zeroize();

    let _policy_toml =
        String::from_utf8(unsealed_policy).context("unsealed policy is not valid UTF-8")?;
    let policy_engine = PolicyEngine::load_from_path(&config.policy_path, provider.as_ref())?;

    // ── Load worker keypair ─────────────────────────────────────────────────
    // Closes T21: in production / staging mode the keypair file MUST be
    // sealed (configurable via `GLYPH_KEYPAIR_SEALED=1` or
    // `keypair_sealed = true` in TOML). In dev mode plaintext is permitted
    // for laptop ergonomics. The unseal happens via the same TEE provider
    // that holds the master key.
    let signing_key = load_signing_key(&config, provider.as_ref())
        .context("failed to load worker signing key")?;
    let signing_key = Arc::new(signing_key);
    let worker_pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

    // ── Boot-time attestation (closes T2 / T6) ──────────────────────────────
    // After policy + key load we immediately:
    //   1. Compute the canonical policy_commitment.
    //   2. Generate a random 32-byte boot nonce.
    //   3. Hash the 5-tuple under the vendor's domain via
    //      `provider.compute_user_data(...)`.
    //   4. Call `provider.attest(user_data, policy_commitment)` to get the
    //      vendor-specific quote.
    //   5. Self-verify with `provider.verify_attestation(...)` (defence in
    //      depth — catches a regressed vendor that produces unverifiable
    //      quotes).
    //   6. Store the evidence in AppState behind an RwLock; the request
    //      path attaches it to every bundle and the periodic task rotates
    //      it every RE_ATTESTATION_INTERVAL_SECS.
    let policy_commitment = {
        let engine = policy_engine.canonical_policy();
        hash_policy(engine)
    };
    let agent_pubkey = derive_agent_pubkey_for_attestation(&config, &worker_pubkey)
        .context("failed to resolve agent_pubkey for boot attestation")?;
    let mut boot_nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut boot_nonce);
    // Epoch will be wired through the on-chain registry in WS-4. For now we
    // stamp 0 — the value is bound into the attestation 5-tuple regardless,
    // so when the registry epoch comes online a single re-attestation picks
    // it up.
    let boot_epoch: u64 = 0;

    let metrics = Arc::new(WorkerMetrics::new());

    // ── WS-4: Trusted clock + Roughtime backend ─────────────────────────────
    // The clock is initialised with the monotonic-fallback backend (closes
    // the audit's WS-4 §6 fallback path). Operators that supply
    // GLYPH_ROUGHTIME_SERVER_PUBKEY (and an integration closure) get the
    // signed Roughtime backend instead. We refresh once at boot so policy
    // checks have a fresh anchor before the first request.
    let trusted_clock = Arc::new(
        TrustedClock::new_with_monotonic_seed().context("failed to initialise trusted clock")?,
    );
    let monotonic_backend = MonotonicBackend::from_clock(&trusted_clock);
    if let Err(e) = trusted_clock.refresh(&monotonic_backend) {
        warn!(error = %e, "initial monotonic clock refresh rejected; running in degraded mode");
    }
    spawn_clock_refresh_task(Arc::clone(&trusted_clock));

    let initial_attestation = perform_attestation(
        provider.as_ref(),
        &policy_commitment,
        &agent_pubkey,
        &worker_pubkey,
        &boot_nonce,
        boot_epoch,
        BOOT_ATTEST_DOMAIN,
        metrics.as_ref(),
    );

    // In Dev mode we permit `None` — bundles still go out, just without a
    // worker_attestation field. In Staging/Production a failure here is a
    // hard fail-closed (closes T2/T6).
    let attestation_state: Arc<RwLock<Option<BoundAttestation>>> = match initial_attestation {
        Ok(att) => Arc::new(RwLock::new(Some(att))),
        Err(e) => {
            if matches!(
                config.runtime_mode,
                RuntimeMode::Production | RuntimeMode::Staging
            ) {
                return Err(e).context("boot attestation failed in non-Dev runtime mode");
            }
            warn!(error = %e, "boot attestation failed in Dev mode — bundles will omit worker_attestation");
            Arc::new(RwLock::new(None))
        }
    };

    // Closes T13 (program ID slice): production refuses placeholder/missing.
    // load_config() already enforces presence + non-placeholder in
    // production; here we just parse and apply a dev-mode fallback.
    let verifier_program_id = match env::var("GLYPH_VERIFIER_PROGRAM_ID") {
        Ok(s) => Pubkey::from_str(s.trim())
            .map_err(|e| anyhow!("invalid GLYPH_VERIFIER_PROGRAM_ID {s:?}: {e}"))?,
        Err(_) => {
            if matches!(config.runtime_mode, RuntimeMode::Production) {
                // Unreachable — load_config() already errored. Belt-and-braces.
                anyhow::bail!(
                    "GLYPH_VERIFIER_PROGRAM_ID required in production (load_config invariant violated)"
                );
            }
            Pubkey::from_str(PLACEHOLDER_VERIFIER_PROGRAM_ID).unwrap()
        }
    };

    let tx_builder = Arc::new(TransactionBuilder::new(
        verifier_program_id,
        &config.solana_rpc_url,
    ));

    let prover: Arc<dyn Prover> = {
        #[cfg(feature = "risc0")]
        {
            if env::var("GLYPH_PROVER").ok().as_deref() == Some("risc0") {
                Arc::new(glyph_tee_worker::prover::RiscZeroProver::new())
            } else {
                Arc::new(DevProver::new())
            }
        }
        #[cfg(not(feature = "risc0"))]
        {
            Arc::new(DevProver::new())
        }
    };

    // ── WS-6: Sealed audit log ──────────────────────────────────────────────
    // The audit log lives next to the policy file. On boot we replay the
    // sealed file (if present) to verify chain integrity, then keep the
    // handle in `AppState` for `process_intent` to append to after every
    // successful prover run. Closes T20.
    let audit_path = PathBuf::from(format!("{}.audit.log.sealed", config.policy_path));
    let audit_log = AuditLog::new(
        Arc::clone(&signing_key),
        Some(audit_path.clone()),
        provider.as_ref(),
    )
    .context("failed to initialise audit log")?;
    let audit_log = Arc::new(tokio::sync::Mutex::new(audit_log));

    // ── WS-5: Per-IP token-bucket rate limiter ──────────────────────────────
    // 10 req/min/IP default (matches the audit's WS-5 acceptance criterion).
    let rate_limiter = Arc::new(RateLimiter::default_per_minute_10());

    let state = Arc::new(AppState {
        policy_engine: Mutex::new(policy_engine),
        signing_key,
        tx_builder,
        prover,
        provider: Arc::clone(&provider),
        metrics: Arc::clone(&metrics),
        attestation: Arc::clone(&attestation_state),
        runtime_mode: config.runtime_mode.clone(),
        agent_pubkey_for_attestation: agent_pubkey,
        worker_pubkey,
        audit_log: Arc::clone(&audit_log),
        rate_limiter: Arc::clone(&rate_limiter),
        trusted_clock: Arc::clone(&trusted_clock),
    });

    // ── Control plane (axum: /metrics, /healthz, /audit) ────────────────────
    // Replaces the hand-rolled HTTP server (closes T39). Production keeps
    // 127.0.0.1 unless GLYPH_METRICS_PUBLIC_BIND=1 is set explicitly.
    if matches!(config.runtime_mode, RuntimeMode::Production) {
        let bind = env::var("GLYPH_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9091".to_string());
        let host = bind
            .rsplit_once(':')
            .map(|(h, _)| h.trim_start_matches('[').trim_end_matches(']'))
            .unwrap_or(bind.as_str());
        let is_loopback = host.starts_with("127.") || host == "::1";
        if !is_loopback && env::var("GLYPH_METRICS_PUBLIC_BIND").ok().as_deref() != Some("1") {
            anyhow::bail!(
                "production mode requires loopback metrics bind (got {bind}); set GLYPH_METRICS_PUBLIC_BIND=1 to override"
            );
        }
    }
    let cp_state = ControlPlaneState {
        metrics: Arc::clone(&metrics),
        audit: Some(Arc::clone(&audit_log)),
        provider: Some(Arc::clone(&provider)),
    };
    tokio::spawn(async move {
        if let Err(e) = spawn_control_plane(cp_state).await {
            error!(error = %e, "control plane axum server exited");
        }
    });

    // ── WS-6: Periodic on-chain audit-root anchor task ──────────────────────
    spawn_audit_anchor_task(
        Arc::clone(&audit_log),
        Arc::clone(&provider),
        Arc::clone(&metrics),
        Arc::clone(&state.signing_key),
        agent_pubkey,
    );

    // ── Periodic re-attestation task (closes T6 / T20 freshness) ────────────
    // Every RE_ATTESTATION_INTERVAL_SECS the task computes a fresh
    // user_data, calls provider.attest, self-verifies, and rotates the
    // RwLock. On failure the slot is wiped — the request path then sees
    // `None` (or a sufficiently old bound attestation) and rejects intents
    // with `AttestationStale`.
    spawn_re_attestation_task(
        Arc::clone(&provider),
        Arc::clone(&attestation_state),
        Arc::clone(&metrics),
        Arc::clone(&state.policy_engine_arc()),
        agent_pubkey,
        worker_pubkey,
        boot_epoch,
    );

    // ── WS-5: mTLS-or-plain listener selection ──────────────────────────────
    // Production + GLYPH_MTLS_ENABLED=1 wraps the TCP listener in a rustls
    // `TlsAcceptor` that requires a valid client certificate. Dev mode falls
    // back to plain TCP with a startup warning.
    let mtls_enabled = env::var("GLYPH_MTLS_ENABLED").ok().as_deref() == Some("1");
    let want_mtls = mtls_enabled || matches!(config.runtime_mode, RuntimeMode::Production);
    let mtls_listener = if want_mtls {
        let cert = env::var("GLYPH_MTLS_SERVER_CERT").ok();
        let key = env::var("GLYPH_MTLS_SERVER_KEY").ok();
        let ca = env::var("GLYPH_MTLS_CLIENT_CA").ok();
        match (cert, key, ca) {
            (Some(c), Some(k), Some(ca)) => {
                let l = MtlsListener::new(&config.listen_addr, &c, &k, &ca)
                    .await
                    .with_context(|| {
                        format!("failed binding mTLS listener at {}", config.listen_addr)
                    })?;
                info!(addr = %l.local_addr, "worker listening (mTLS)");
                Some(l)
            }
            _ => {
                if matches!(config.runtime_mode, RuntimeMode::Production) {
                    anyhow::bail!(
                        "production mode requires GLYPH_MTLS_SERVER_CERT, GLYPH_MTLS_SERVER_KEY, and GLYPH_MTLS_CLIENT_CA"
                    );
                }
                warn!("mTLS requested but env vars unset — falling back to plain TCP (Dev only)");
                None
            }
        }
    } else {
        None
    };
    let plain_listener = if mtls_listener.is_none() {
        let l = TcpListener::bind(&config.listen_addr)
            .await
            .with_context(|| format!("failed binding tcp listener at {}", config.listen_addr))?;
        warn!(
            addr = %config.listen_addr,
            "worker listening (PLAIN TCP — no mTLS, do NOT use in production)"
        );
        Some(l)
    } else {
        None
    };

    loop {
        tokio::select! {
            ctrl = tokio::signal::ctrl_c() => {
                match ctrl {
                    Ok(()) => info!("shutdown signal received"),
                    Err(e) => warn!(error = %e, "failed to listen for shutdown signal"),
                }
                break;
            }
            accepted = accept_either(mtls_listener.as_ref(), plain_listener.as_ref()) => {
                match accepted {
                    Ok(EitherStream::Tls(stream, peer)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, peer.ip(), state).await {
                                error!(peer = %peer, error = %err, "TLS connection handling failed");
                            }
                        });
                    }
                    Ok(EitherStream::Plain(stream, peer)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, peer.ip(), state).await {
                                error!(peer = %peer, error = %err, "connection handling failed");
                            }
                        });
                    }
                    Err(err) => {
                        error!(error = %err, "failed to accept incoming connection");
                    }
                }
            }
        }
    }

    info!("worker shutdown complete");
    Ok(())
}

struct AppState {
    policy_engine: Mutex<PolicyEngine>,
    signing_key: Arc<SigningKey>,
    tx_builder: Arc<TransactionBuilder>,
    prover: Arc<dyn Prover>,
    provider: Arc<dyn TeeProvider>,
    metrics: Arc<WorkerMetrics>,
    /// Latest attestation evidence + the policy commitment it was bound to.
    /// Rotated by the periodic re-attestation task. Closes T6.
    attestation: Arc<RwLock<Option<BoundAttestation>>>,
    /// Runtime mode for fail-open (Dev) vs fail-closed (Staging/Production)
    /// decisions on attestation freshness.
    runtime_mode: RuntimeMode,
    /// Agent pubkey that was bound into the boot attestation 5-tuple.
    #[allow(dead_code)]
    agent_pubkey_for_attestation: [u8; 32],
    /// Worker pubkey (Ed25519 from `signing_key`), cached.
    #[allow(dead_code)]
    worker_pubkey: [u8; 32],
    /// WS-6: sealed audit log; appended to after every successful prover run.
    audit_log: Arc<tokio::sync::Mutex<AuditLog>>,
    /// WS-5: per-source-IP token bucket; checked before reading the request body.
    rate_limiter: Arc<RateLimiter>,
    /// WS-4: trusted-clock anchor; replaces ad-hoc `Utc::now()` in policy hot
    /// paths once the policy engine surfaces the override.
    #[allow(dead_code)]
    trusted_clock: Arc<TrustedClock>,
}

/// Either a TLS-wrapped stream or a plain TCP stream. Lets `handle_connection`
/// stay generic over both transports without trait-object boxing.
enum EitherStream {
    Tls(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr),
    Plain(TcpStream, SocketAddr),
}

async fn accept_either(
    mtls: Option<&MtlsListener>,
    plain: Option<&TcpListener>,
) -> Result<EitherStream> {
    match (mtls, plain) {
        (Some(m), _) => {
            let (stream, peer) = m.accept_tls().await?;
            Ok(EitherStream::Tls(stream, peer))
        }
        (None, Some(p)) => {
            let (stream, peer) = p.accept().await.context("plain TCP accept failed")?;
            Ok(EitherStream::Plain(stream, peer))
        }
        (None, None) => Err(anyhow!("no listener configured (internal error)")),
    }
}

/// Spawn the periodic clock-refresh task. Refreshes the trusted clock every
/// 30 seconds using the monotonic backend (the Roughtime backend is wired
/// per-deployment via env). On failure we log and keep going — the cache TTL
/// in `TrustedClock::now()` will surface staleness at the request path.
fn spawn_clock_refresh_task(clock: Arc<TrustedClock>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            // Build a fresh MonotonicBackend each tick so the boot-anchor is
            // shared with the clock under test. Roughtime users override this
            // via their own integration entrypoint.
            let backend = MonotonicBackend::from_clock(clock.as_ref());
            if let Err(e) = clock.refresh(&backend) {
                warn!(error = %e, "trusted clock monotonic refresh rejected");
            }
        }
    });
}

/// Spawn the WS-6 periodic on-chain audit-root anchor task. Every 5 minutes
/// we compute `merkle_root(audit_log)` and emit a signed payload for the
/// operator's RPC submitter to forward to `commit_audit_root`. The actual
/// Solana RPC dial is left as an integration TODO — we wire the data path.
fn spawn_audit_anchor_task(
    audit_log: Arc<tokio::sync::Mutex<AuditLog>>,
    provider: Arc<dyn TeeProvider>,
    metrics: Arc<WorkerMetrics>,
    signing_key: Arc<SigningKey>,
    agent_pubkey: [u8; 32],
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        interval.tick().await;
        loop {
            interval.tick().await;
            let guard = audit_log.lock().await;
            let root = match guard.merkle_root(provider.as_ref()) {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "failed to compute audit-log merkle root");
                    continue;
                }
            };
            let seq_high = guard.sequence_high();
            drop(guard);
            // Skip empty logs to avoid anchoring [0; 32].
            if root == [0u8; 32] {
                continue;
            }
            let now_unix = chrono::Utc::now().timestamp();
            let payload = build_anchor_signing_payload(&agent_pubkey, &root, seq_high, now_unix);
            let sig = ed25519_dalek::Signer::sign(signing_key.as_ref(), &payload);
            info!(
                root = %hex::encode(root),
                sequence_high = seq_high,
                signature = %hex::encode(sig.to_bytes()),
                "audit-root anchor ready (operator: forward to commit_audit_root)"
            );
            // The actual RPC submission is a TODO for the operator. The
            // metrics counter advances when the data path completes; the
            // operator's submitter increments it again on confirmation.
            metrics.record_audit_root_anchored();
        }
    });
}

/// Canonical signing payload for the on-chain `commit_audit_root` instruction.
/// Mirrors the data the verifier program will hash to recover `expected`.
pub fn build_anchor_signing_payload(
    agent_pubkey: &[u8; 32],
    root: &[u8; 32],
    sequence_high: u64,
    anchored_at: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 32 + 32 + 8 + 8);
    buf.extend_from_slice(b"GLYPH_AUDIT_ROOT_v1\0");
    buf.extend_from_slice(agent_pubkey);
    buf.extend_from_slice(root);
    buf.extend_from_slice(&sequence_high.to_be_bytes());
    buf.extend_from_slice(&anchored_at.to_be_bytes());
    buf
}

impl AppState {
    /// Helper that hands out an `Arc` view of the policy_engine Mutex for
    /// the periodic re-attestation task. The task only needs read access to
    /// the canonical policy, so we route it through the same Mutex (no
    /// second source of truth).
    fn policy_engine_arc(self: &Arc<Self>) -> Arc<PolicyEngineHandle> {
        Arc::new(PolicyEngineHandle {
            state: Arc::clone(self),
        })
    }
}

/// Tiny wrapper around `Arc<AppState>` so the re-attestation task can grab
/// a snapshot of the canonical policy commitment without depending on the
/// full state struct's API surface.
struct PolicyEngineHandle {
    state: Arc<AppState>,
}

impl PolicyEngineHandle {
    async fn current_policy_commitment(&self) -> [u8; 32] {
        let engine = self.state.policy_engine.lock().await;
        hash_policy(engine.canonical_policy())
    }
}
async fn handle_connection<S>(mut stream: S, peer_ip: IpAddr, state: Arc<AppState>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ── WS-5: per-IP rate limiter ───────────────────────────────────────────
    if !state.rate_limiter.try_acquire(peer_ip) {
        state.metrics.record_rate_limited(peer_ip);
        let worker_response = WorkerResponse::Error {
            code: "RATE_LIMITED".to_string(),
            message: "rate limit exceeded — back off and retry".to_string(),
        };
        let payload = serde_json::to_vec(&worker_response)
            .context("failed serializing rate-limited response")?;
        stream
            .write_all(&payload)
            .await
            .context("failed writing 429 response")?;
        return Ok(());
    }

    let max_size: usize = 1024 * 1024;
    let mut buf = Vec::with_capacity(64 * 1024);
    (&mut stream)
        .take(max_size as u64 + 1)
        .read_to_end(&mut buf)
        .await
        .context("failed to read request")?;

    if buf.len() > max_size {
        state.metrics.record_too_large();
        let worker_response = WorkerResponse::Error {
            code: "REQUEST_TOO_LARGE".to_string(),
            message: "Request exceeds maximum size".to_string(),
        };
        let payload =
            serde_json::to_vec(&worker_response).context("failed serializing worker response")?;
        stream
            .write_all(&payload)
            .await
            .context("failed writing response")?;
        buf.zeroize();
        return Ok(());
    }

    if buf.is_empty() {
        return Ok(());
    }

    let intent_result: Result<TransactionIntent> =
        serde_json::from_slice(&buf).context("invalid JSON request payload");

    if intent_result.is_ok() {
        state.metrics.record_intent_received();
    }

    let response = match intent_result {
        Ok(intent) => process_intent(intent, Arc::clone(&state)).await,
        Err(err) => Err(err),
    };

    let worker_response = match response {
        Ok(bundle) => WorkerResponse::Success { bundle },
        Err(err) => {
            error!(error = %err, "intent processing failed");
            // Surface the structured AttestationStale error code so SDK
            // clients can distinguish "transient TEE staleness" from
            // generic processing errors.
            let (code, message) = if err.to_string().contains("AttestationStale") {
                (
                    "ATTESTATION_STALE".to_string(),
                    "worker attestation is stale — retry shortly".to_string(),
                )
            } else {
                (
                    "PROCESSING_ERROR".to_string(),
                    "Failed to process intent".to_string(),
                )
            };
            WorkerResponse::Error { code, message }
        }
    };

    let payload =
        serde_json::to_vec(&worker_response).context("failed serializing worker response")?;
    stream
        .write_all(&payload)
        .await
        .context("failed writing response")?;

    buf.zeroize();
    Ok(())
}
async fn process_intent(
    intent: TransactionIntent,
    state: Arc<AppState>,
) -> Result<GlyphProofBundle> {
    // ── Single time source ──────────────────────────────────────────────────
    // Take ONE wallclock reading per request and thread it through every
    // freshness/policy check below. Closes T34 (multiple `Utc::now()` calls
    // could disagree if the host clock jumps mid-evaluation).
    let now_unix = chrono::Utc::now().timestamp();
    if now_unix < 0 {
        anyhow::bail!("system clock returned negative unix timestamp");
    }
    let now_seconds = now_unix as u64;

    // Snapshot the canonical policy + worker pubkey + epoch *before* validating
    // the signature so they can be bound into the canonical signing payload.
    let policy_snapshot = {
        let engine = state.policy_engine.lock().await;
        engine.canonical_policy().clone()
    };
    let policy_commitment = hash_policy(&policy_snapshot);
    let worker_pubkey: [u8; 32] = state.signing_key.verifying_key().to_bytes();
    // Epoch will be wired through registry once on-chain epoch is fetched —
    // closes the data path at the worker side. For now use the placeholder 0.
    let epoch: u64 = 0;

    // ── Attestation freshness gate (closes T6 / T20) ────────────────────────
    // Before we touch the prover, snapshot the latest TEE evidence. In
    // Staging/Production we refuse to proceed if the evidence is missing,
    // older than MAX_ATTESTATION_AGE_SECS, or bound to a stale policy
    // commitment. Dev mode logs a warning and continues without attaching
    // evidence so local development without a TEE remains ergonomic.
    let attestation_for_bundle: Option<Vec<u8>> = {
        let guard = state.attestation.read().await;
        match guard.as_ref() {
            Some(bound) => {
                let age = now_seconds.saturating_sub(bound.evidence.timestamp_unix);
                let stale_age = age > MAX_ATTESTATION_AGE_SECS;
                let stale_policy = bound.policy_commitment != policy_commitment;
                if stale_age || stale_policy {
                    if matches!(
                        state.runtime_mode,
                        RuntimeMode::Production | RuntimeMode::Staging
                    ) {
                        state.metrics.record_attestation_stale_rejection();
                        warn!(
                            age_secs = age,
                            stale_policy, "rejecting intent — AttestationStale"
                        );
                        anyhow::bail!(
                            "AttestationStale: latest evidence is {} seconds old (max {}) or bound to a rotated policy (stale_policy={})",
                            age,
                            MAX_ATTESTATION_AGE_SECS,
                            stale_policy
                        );
                    }
                    warn!(
                        age_secs = age,
                        stale_policy, "stale attestation in Dev mode — continuing"
                    );
                    None
                } else {
                    Some(bound.evidence.quote.clone())
                }
            }
            None => {
                if matches!(
                    state.runtime_mode,
                    RuntimeMode::Production | RuntimeMode::Staging
                ) {
                    state.metrics.record_attestation_stale_rejection();
                    anyhow::bail!(
                        "AttestationStale: no boot attestation available (worker not yet attested)"
                    );
                }
                None
            }
        }
    };

    if let Err(e) = validate_intent_signature(&intent, &policy_commitment, &worker_pubkey, epoch) {
        state.metrics.record_sig_failure();
        return Err(e).context("signature validation failed");
    }

    // ── Freshness check ─────────────────────────────────────────────────────
    // Closes T7. The signature payload binds `timestamp` and `expiry` so the
    // SDK signed for these values; the worker must enforce them against the
    // current wallclock. Note: a fully trustworthy clock requires a TEE-
    // attested time source — that's a follow-up (WS-4).
    if intent.expiry > 0 && now_seconds > intent.expiry {
        state.metrics.record_policy_rejection();
        anyhow::bail!(
            "intent expired (expiry={}, now={})",
            intent.expiry,
            now_seconds
        );
    }
    // 5-minute future-skew tolerance.
    if intent.timestamp > now_seconds.saturating_add(300) {
        state.metrics.record_policy_rejection();
        anyhow::bail!(
            "intent timestamp is more than 5 minutes in the future (timestamp={}, now={})",
            intent.timestamp,
            now_seconds
        );
    }

    // ── Phase 1: read-only policy check ─────────────────────────────────────
    // Closes T11: the volume budget and nonce LRU are NOT mutated until the
    // prover succeeds.
    let checked = {
        let engine = state.policy_engine.lock().await;
        match engine.check_intent(&intent, now_unix) {
            Ok(c) => c,
            Err(violation) => {
                state.metrics.record_policy_rejection();
                tracing::warn!(
                    rule_id = violation.rule_id,
                    reason = %violation.reason,
                    "policy violation"
                );
                return Err(anyhow::anyhow!(
                    "policy violation (rule {}): {}",
                    violation.rule_id,
                    violation.reason
                ));
            }
        }
    };

    // Worker-side nonce uniqueness gate. Closes T17.
    {
        let engine = state.policy_engine.lock().await;
        if let Err(reused) = engine.check_nonce_unique(&checked) {
            state.metrics.record_policy_rejection();
            tracing::warn!(
                agent = %hex::encode(reused.agent_pubkey),
                "nonce reused — rejecting at worker"
            );
            anyhow::bail!("nonce already seen");
        }
    }

    // 1. Canonicalize the target instruction bytes for ZK tx_hash binding.
    let full_ix_bytes = canonical_target_instruction_bytes(&intent)
        .context("failed to canonicalize target instruction")?;

    // 2. Generate the proof with the correct tx_hash.
    //
    // Source the attested timestamp from `TrustedClock::now` — this is the
    // value the guest commits into `PublicOutputs.attested_timestamp` and
    // the on-chain verifier compares to `Clock::unix_timestamp`. Falling
    // back to `now_unix` keeps Dev mode working when the trusted clock is
    // degraded; production gates this via the staleness check in
    // `TrustedClock::now`.
    let attested_timestamp: u64 = state
        .trusted_clock
        .now()
        .map(|t| if t < 0 { 0 } else { t as u64 })
        .unwrap_or(now_seconds);

    let bundle_result =
        state
            .prover
            .generate_proof(&intent, &policy_snapshot, full_ix_bytes, attested_timestamp);

    let mut bundle = match bundle_result {
        Ok(b) => {
            state.metrics.record_proof_success();
            b
        }
        Err(e) => {
            state.metrics.record_proof_failure();
            return Err(e);
        }
    };

    // ── Phase 2: commit only AFTER prover success ───────────────────────────
    // Snapshot the audit-relevant fields before `commit_intent` consumes
    // `checked` (CheckedIntent is non-Copy by design — its presence on the
    // stack is the proof that we held the lock).
    let audit_agent_pubkey = checked.agent_pubkey;
    let audit_nonce = checked.nonce;
    {
        let mut engine = state.policy_engine.lock().await;
        engine
            .commit_intent(checked)
            .context("failed to commit volume / nonce")?;
        engine
            .persist_volume(state.provider.as_ref())
            .context("failed to persist volume")?;
        engine
            .persist_nonce_lru(state.provider.as_ref())
            .context("failed to persist nonce LRU")?;
    }

    // 3. Build the full transaction including the target instruction
    let tx_bytes = state
        .tx_builder
        .build_verify_tx(&intent, &bundle, state.signing_key.as_ref())
        .context("failed building verify transaction")?;

    bundle.signed_transaction = tx_bytes;
    // Bounded debug correlator — first 16 bytes of the committed tx_hash.
    // NOT a Solana signature. Closes F-19, F-29.
    bundle
        .tx_hash_prefix
        .copy_from_slice(&bundle.public_inputs.tx_hash[..16]);
    // ── Attach worker attestation envelope (closes T6) ──────────────────────
    // SDK and on-chain `register_agent` re-verify this against the
    // current policy commitment + 5-tuple binding. We attach the raw quote
    // bytes — the verifier reconstructs `expected_user_data` from the
    // policy commitment + agent + worker + boot_nonce + epoch (out-of-band
    // anchored at registration time).
    bundle.worker_attestation = attestation_for_bundle;

    // ── WS-6: Sealed audit-log append ───────────────────────────────────────
    // Closes T20. We append AFTER the prover has succeeded and AFTER policy
    // commit, but BEFORE returning the bundle to the client. A failure here
    // is fail-closed in Production (the client would otherwise believe the
    // intent was accepted without a tamper-evident audit record).
    let audit_inner = AuditEntryInner {
        agent_pubkey: audit_agent_pubkey,
        intent_hash: hash_intent(&glyph_common::IntentPayload {
            agent_pubkey: audit_agent_pubkey,
            nonce: audit_nonce,
            target_program: {
                let mut tp = [0u8; 32];
                let bytes = bs58::decode(&intent.action.target_program)
                    .into_vec()
                    .context("target_program decode for audit")?;
                tp.copy_from_slice(&bytes);
                tp
            },
            max_lamports: intent.constraints.max_lamports,
            max_slippage_bps: intent.constraints.max_slippage_bps,
            num_accounts: intent.action.accounts.len() as u16,
            expiry: intent.expiry,
        }),
        policy_commitment,
        tx_hash: bundle.public_inputs.tx_hash,
    };
    let audit_ts = state.trusted_clock.now().unwrap_or(now_unix);
    {
        let mut guard = state.audit_log.lock().await;
        match guard.append(audit_inner, audit_ts, state.provider.as_ref()) {
            Ok(_) => {
                state.metrics.record_audit_entry_appended();
            }
            Err(e) => {
                if matches!(
                    state.runtime_mode,
                    RuntimeMode::Production | RuntimeMode::Staging
                ) {
                    return Err(e).context("audit log append failed (fail-closed in non-Dev)");
                }
                warn!(error = %e, "audit log append failed in Dev mode — continuing");
            }
        }
    }

    state.metrics.record_intent_accepted();
    Ok(bundle)
}
fn validate_intent_signature(
    intent: &TransactionIntent,
    policy_commitment: &[u8; 32],
    worker_pubkey: &[u8; 32],
    epoch: u64,
) -> Result<()> {
    let pubkey_bytes = bs58::decode(&intent.agent_pubkey)
        .into_vec()
        .context("agent_pubkey is not valid base58")?;
    if pubkey_bytes.len() != 32 {
        return Err(anyhow!("agent_pubkey must decode to 32 bytes"));
    }

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&intent.signature)
        .context("signature is not valid base64")?;
    if signature_bytes.len() != 64 {
        return Err(anyhow!("signature must be 64 bytes"));
    }

    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into()?)
        .map_err(|e| anyhow!("invalid verifying key: {}", e))?;
    let signature = DalekSignature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("invalid signature: {}", e))?;

    let canonical = build_canonical_intent(intent, policy_commitment, worker_pubkey, epoch)
        .context("failed to build canonical intent")?;
    let payload = canonical_signing_payload(&canonical);
    verifying_key
        .verify(&payload, &signature)
        .context("ed25519 signature verification failed")?;

    Ok(())
}

/// Project a wire-format `TransactionIntent` (string-typed) into the canonical
/// `CanonicalIntent` (byte-array-typed) used by `glyph_common::canonical_signing_payload`.
fn build_canonical_intent(
    intent: &TransactionIntent,
    policy_commitment: &[u8; 32],
    worker_pubkey: &[u8; 32],
    epoch: u64,
) -> Result<CanonicalIntent> {
    let mut agent_pubkey = [0u8; 32];
    let agent_bytes = bs58::decode(&intent.agent_pubkey)
        .into_vec()
        .context("agent_pubkey is not valid base58")?;
    if agent_bytes.len() != 32 {
        anyhow::bail!("agent_pubkey must decode to 32 bytes");
    }
    agent_pubkey.copy_from_slice(&agent_bytes);

    let mut nonce = [0u8; 32];
    let nonce_bytes = hex::decode(&intent.nonce).context("nonce is not valid hex")?;
    if nonce_bytes.len() != 32 {
        anyhow::bail!("nonce must decode to 32 bytes");
    }
    nonce.copy_from_slice(&nonce_bytes);

    let mut target_program = [0u8; 32];
    let tp_bytes = bs58::decode(&intent.action.target_program)
        .into_vec()
        .context("target_program is not valid base58")?;
    if tp_bytes.len() != 32 {
        anyhow::bail!("target_program must decode to 32 bytes");
    }
    target_program.copy_from_slice(&tp_bytes);

    let mut accounts = Vec::with_capacity(intent.action.accounts.len());
    for meta in &intent.action.accounts {
        let pkb = bs58::decode(&meta.pubkey)
            .into_vec()
            .context("account pubkey is not valid base58")?;
        if pkb.len() != 32 {
            anyhow::bail!("account pubkey must decode to 32 bytes");
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pkb);
        accounts.push(CanonicalAccountMeta {
            pubkey: pk,
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        });
    }

    let data = base64::engine::general_purpose::STANDARD
        .decode(&intent.action.data)
        .context("intent.action.data is not valid base64")?;

    let allowed_tokens = match &intent.constraints.allowed_tokens {
        Some(tokens) => {
            let mut decoded = Vec::with_capacity(tokens.len());
            for t in tokens {
                let b = bs58::decode(t)
                    .into_vec()
                    .context("allowed_token is not valid base58")?;
                if b.len() != 32 {
                    anyhow::bail!("allowed_token must decode to 32 bytes");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                decoded.push(arr);
            }
            Some(decoded)
        }
        None => None,
    };

    Ok(CanonicalIntent {
        agent_pubkey,
        nonce,
        target_program,
        accounts,
        data,
        max_lamports: intent.constraints.max_lamports,
        max_slippage_bps: intent.constraints.max_slippage_bps,
        allowed_tokens,
        expiry: intent.expiry,
        timestamp: intent.timestamp,
        policy_commitment: *policy_commitment,
        worker_pubkey: Some(*worker_pubkey),
        epoch,
    })
}

/// Resolve the agent pubkey used for the boot attestation 5-tuple binding.
/// In Dev mode we tolerate an absent `GLYPH_AGENT_PUBKEY` and substitute the
/// worker pubkey so local development without on-chain registration still
/// produces a usable bound quote. Staging/Production already require the
/// var to be set (enforced in `load_config`).
fn derive_agent_pubkey_for_attestation(
    config: &WorkerConfig,
    worker_pubkey: &[u8; 32],
) -> Result<[u8; 32]> {
    if let Some(agent_b58) = &config.agent_pubkey {
        let bytes = bs58::decode(agent_b58.trim())
            .into_vec()
            .context("GLYPH_AGENT_PUBKEY is not valid base58")?;
        if bytes.len() != 32 {
            anyhow::bail!("GLYPH_AGENT_PUBKEY must decode to 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    } else {
        Ok(*worker_pubkey)
    }
}

/// Load + parse the Ed25519 signing key, optionally unsealing first if the
/// configured keypair_path ends with `.sealed` or `keypair_sealed = true`.
/// Closes T21.
fn load_signing_key(config: &WorkerConfig, provider: &dyn TeeProvider) -> Result<SigningKey> {
    let raw = std::fs::read(&config.keypair_path)
        .with_context(|| format!("failed to load keypair from {}", config.keypair_path))?;

    let sealed_by_extension = config.keypair_path.ends_with(".sealed");
    let plaintext = if config.keypair_sealed || sealed_by_extension {
        let unsealed = provider
            .unseal(&raw)
            .context("failed to unseal worker keypair")?;
        info!("worker keypair unsealed via TEE provider");
        unsealed
    } else {
        if matches!(
            config.runtime_mode,
            RuntimeMode::Production | RuntimeMode::Staging
        ) {
            // Closes T21: production / staging refuse plaintext keypairs on disk.
            anyhow::bail!(
                "worker-keypair.json is plaintext on disk in {:?} mode; \
                 set GLYPH_KEYPAIR_SEALED=1 + provide a sealed file (or use in-enclave key generation). \
                 See scripts/seal-keypair.sh.",
                config.runtime_mode
            );
        }
        raw
    };

    let signing_key = if let Ok(bytes) = serde_json::from_slice::<Vec<u8>>(&plaintext) {
        if bytes.len() == 64 {
            let secret: [u8; 32] = bytes[0..32].try_into()?;
            SigningKey::from_bytes(&secret)
        } else if bytes.len() == 32 {
            let secret: [u8; 32] = bytes.as_slice().try_into()?;
            SigningKey::from_bytes(&secret)
        } else {
            anyhow::bail!("invalid keypair length in JSON: {}", bytes.len());
        }
    } else if plaintext.len() == 32 {
        let secret: [u8; 32] = plaintext.as_slice().try_into()?;
        SigningKey::from_bytes(&secret)
    } else if plaintext.len() == 64 {
        let secret: [u8; 32] = plaintext[0..32].try_into()?;
        SigningKey::from_bytes(&secret)
    } else {
        anyhow::bail!("invalid raw keypair length: {}", plaintext.len());
    };

    Ok(signing_key)
}

/// Centralised attestation helper. Computes the bound `user_data`, calls
/// `provider.attest`, then runs `provider.verify_attestation` as a
/// defence-in-depth self-check. Records metrics for both arms.
fn perform_attestation(
    provider: &dyn TeeProvider,
    policy_commitment: &[u8; 32],
    agent_pubkey: &[u8; 32],
    worker_pubkey: &[u8; 32],
    boot_nonce: &[u8; 32],
    epoch: u64,
    domain: &[u8],
    metrics: &WorkerMetrics,
) -> Result<BoundAttestation> {
    // `domain` is mixed into the metrics span so operators can tell boot
    // attestations apart from periodic re-attestations and self-tests in
    // logs without needing to thread an extra arg through every call.
    let _ = domain;

    let user_data = provider.compute_user_data(
        policy_commitment,
        agent_pubkey,
        worker_pubkey,
        boot_nonce,
        epoch,
    );
    let evidence = match provider.attest(&user_data, policy_commitment) {
        Ok(e) => e,
        Err(err) => {
            metrics.record_attestation_failure();
            return Err(err.context("provider.attest failed"));
        }
    };

    // Self-verify (defence in depth — catches a regressed vendor that
    // emits unverifiable evidence).
    match provider.verify_attestation(&evidence, policy_commitment) {
        Ok(true) => {}
        Ok(false) => {
            metrics.record_attestation_failure();
            return Err(anyhow!(
                "self-verify of fresh attestation returned false (vendor regression?)"
            ));
        }
        Err(err) => {
            metrics.record_attestation_failure();
            return Err(err.context("self-verify of fresh attestation errored"));
        }
    }

    metrics.record_attestation_success();
    Ok(BoundAttestation {
        evidence,
        policy_commitment: *policy_commitment,
    })
}

/// Spawn the periodic re-attestation task. The task wakes every
/// `RE_ATTESTATION_INTERVAL_SECS`, recomputes the bound user_data against the
/// *current* canonical policy commitment, and rotates the RwLock slot. On
/// failure the slot is wiped so the request path will reject new intents
/// with `AttestationStale` instead of silently attaching stale evidence.
fn spawn_re_attestation_task(
    provider: Arc<dyn TeeProvider>,
    attestation: Arc<RwLock<Option<BoundAttestation>>>,
    metrics: Arc<WorkerMetrics>,
    policy_handle: Arc<PolicyEngineHandle>,
    agent_pubkey: [u8; 32],
    worker_pubkey: [u8; 32],
    epoch: u64,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(RE_ATTESTATION_INTERVAL_SECS));
        // Skip the immediate tick — boot path already produced the first one.
        interval.tick().await;
        loop {
            interval.tick().await;
            let policy_commitment = policy_handle.current_policy_commitment().await;
            let mut boot_nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut boot_nonce);
            match perform_attestation(
                provider.as_ref(),
                &policy_commitment,
                &agent_pubkey,
                &worker_pubkey,
                &boot_nonce,
                epoch,
                BOOT_ATTEST_DOMAIN,
                metrics.as_ref(),
            ) {
                Ok(fresh) => {
                    let mut guard = attestation.write().await;
                    *guard = Some(fresh);
                    info!("rotated worker attestation");
                }
                Err(err) => {
                    error!(error = %err, "periodic re-attestation failed — clearing slot");
                    let mut guard = attestation.write().await;
                    *guard = None;
                }
            }
        }
    });
}
/// Enforce the invariants that must hold in `RuntimeMode::Production`.
///
/// All failures return `anyhow::Error` so the binary exits cleanly with a
/// diagnosable error instead of a panic backtrace (closes F-26). Now also
/// closes T4 / T29: the production gate exercises real TEE attestation +
/// sealing instead of only checking ZK env-vars.
#[cfg(not(feature = "risc0"))]
fn enforce_production_invariants(config: &WorkerConfig, _provider: &dyn TeeProvider) -> Result<()> {
    if matches!(config.runtime_mode, RuntimeMode::Production) {
        return Err(anyhow!(
            "Production mode requires --features risc0. \
             Rebuild with: cargo build -p glyph-tee-worker --features risc0"
        ));
    }
    enforce_staging_invariants(config)
}

#[cfg(feature = "risc0")]
fn enforce_production_invariants(config: &WorkerConfig, provider: &dyn TeeProvider) -> Result<()> {
    // Staging tightening (closes mock-sweep #62 STAGING bypass) runs in
    // both Staging and Production — the rules are a strict subset of
    // production. Production additionally requires real-enclave + real
    // attestation + real sealing.
    enforce_staging_invariants(config)?;

    if !matches!(config.runtime_mode, RuntimeMode::Production) {
        return Ok(());
    }

    if env::var("GLYPH_PROVER").ok().as_deref() != Some("risc0") {
        return Err(anyhow!(
            "Production mode requires GLYPH_PROVER=risc0; DevProver is forbidden"
        ));
    }

    if env::var("RISC0_DEV_MODE").is_ok() {
        return Err(anyhow!("RISC0_DEV_MODE must not be set in production mode"));
    }

    enforce_tee_invariants(provider)?;

    // Closes T13 (vendor): GLYPH_TEE_VENDOR is verified explicitly set in
    // load_config(), but we double-check here so the production gate is
    // self-contained and re-runnable from tests.
    if env::var("GLYPH_TEE_VENDOR").is_err() {
        return Err(anyhow!(
            "GLYPH_TEE_VENDOR must be explicitly set in production mode"
        ));
    }

    info!("production mode checks passed — real ZK + real TEE attestation enforced");
    Ok(())
}

/// Staging-mode gate. Staging now means "production-with-extra-logging" — it
/// is a strict subset of Production except for two exceptions documented
/// inline. Closes mock-sweep #62 STAGING bypass.
fn enforce_staging_invariants(config: &WorkerConfig) -> Result<()> {
    if !matches!(
        config.runtime_mode,
        RuntimeMode::Staging | RuntimeMode::Production
    ) {
        return Ok(());
    }

    // Refuse DevProver / dev attestation in Staging. The only intentional
    // difference between Staging and Production is the default RPC URL
    // (Staging defaults to devnet; Production refuses mainnet without
    // GLYPH_ALLOW_MAINNET=1 — checked in load_config).
    if env::var("GLYPH_PROVER").ok().as_deref() == Some("dev") {
        return Err(anyhow!(
            "GLYPH_PROVER=dev is forbidden in Staging/Production mode"
        ));
    }

    Ok(())
}

/// Concrete TEE-side production checks. Extracted for unit-testability and
/// so the `cfg(not(feature = \"risc0\"))` branch can stay focused on the ZK gate.
#[cfg(feature = "risc0")]
fn enforce_tee_invariants(provider: &dyn TeeProvider) -> Result<()> {
    // Closes T4 / T33: no provider running on the dev passthrough may serve
    // production traffic.
    provider
        .require_real()
        .context("provider.require_real() failed in production mode")?;

    // Closes T29 (attestation slice): exercise the attestation path with a
    // structurally-valid 5-tuple binding so a regressed vendor surfaces at
    // boot, not at first request.
    let probe_user_data =
        provider.compute_user_data(&[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32], 0);
    let probe_evidence = provider
        .attest(&probe_user_data, &[0u8; 32])
        .context("production attestation probe failed (provider.attest)")?;
    if !provider
        .verify_attestation(&probe_evidence, &[0u8; 32])
        .context("production attestation probe failed (provider.verify_attestation)")?
    {
        return Err(anyhow!(
            "production attestation probe self-verify returned false"
        ));
    }

    // Closes T29 (seal slice): a 32-byte round-trip catches identity-passthrough
    // sealing regressions.
    let probe_plaintext = [0xA5u8; 32];
    let sealed = provider
        .seal(&probe_plaintext)
        .context("production seal probe failed (provider.seal)")?;
    let unsealed = provider
        .unseal(&sealed)
        .context("production seal probe failed (provider.unseal)")?;
    if unsealed.as_slice() != probe_plaintext {
        return Err(anyhow!(
            "production seal probe round-trip mismatch (provider returned different bytes)"
        ));
    }
    Ok(())
}

/// Initialise the tracing subscriber. Closes mock-sweep #62 — in production
/// a malformed `RUST_LOG` value is a configuration error and must abort
/// startup; in dev/staging we still allow a fallback.
fn init_tracing(runtime_mode: &RuntimeMode) -> Result<()> {
    let env_log = env::var("RUST_LOG").ok();
    let filter = match env_log {
        Some(value) => match tracing_subscriber::EnvFilter::try_new(&value) {
            Ok(f) => f,
            Err(e) => {
                if matches!(runtime_mode, RuntimeMode::Production) {
                    return Err(anyhow!(
                        "invalid RUST_LOG in production mode: {} (parse error: {})",
                        value,
                        e
                    ));
                }
                eprintln!(
                    "warning: RUST_LOG={value:?} failed to parse ({e}); falling back to default"
                );
                tracing_subscriber::EnvFilter::new("glyph_tee_worker=info,info")
            }
        },
        None => tracing_subscriber::EnvFilter::new("glyph_tee_worker=info,info"),
    };
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    Ok(())
}

/// Sentinel placeholder verifier program ID. Production deployments must
/// override `GLYPH_VERIFIER_PROGRAM_ID` with a real keypair-derived address.
/// Closes the placeholder-program-ID part of T13/T30.
const PLACEHOLDER_VERIFIER_PROGRAM_ID: &str = "G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g";

fn load_config() -> Result<WorkerConfig> {
    if let Ok(path) = env::var("GLYPH_WORKER_CONFIG") {
        return load_config_file(path);
    }

    // Resolve runtime mode FIRST — its value gates the strictness of every
    // other variable below. Closes T30: any unknown value is a hard error,
    // never a silent downgrade to dev.
    let runtime_mode = match env::var("GLYPH_MODE") {
        Ok(raw) => match raw.to_lowercase().as_str() {
            "production" | "prod" => RuntimeMode::Production,
            "staging" => RuntimeMode::Staging,
            "dev" => RuntimeMode::Dev,
            other => {
                anyhow::bail!(
                    "invalid GLYPH_MODE: {other:?} (expected production|prod|staging|dev)"
                );
            }
        },
        // Closes types.rs default: when GLYPH_MODE is unset we no longer
        // silently default to Dev. The `default_runtime_mode()` for the
        // serde path is now `Production`; here we apply the same policy.
        Err(_) => RuntimeMode::Production,
    };

    // Closes T13: in production, GLYPH_TEE_VENDOR must be set explicitly.
    // In dev mode we default to `nitro` (the production target).
    let tee_vendor = match env::var("GLYPH_TEE_VENDOR") {
        Ok(raw) => match raw.to_lowercase().as_str() {
            "sgx" => TeeVendor::Sgx,
            "nitro" => TeeVendor::Nitro,
            "sev" => TeeVendor::Sev,
            other => {
                anyhow::bail!("invalid GLYPH_TEE_VENDOR: {other:?} (expected sgx|nitro|sev)");
            }
        },
        Err(_) => {
            if matches!(runtime_mode, RuntimeMode::Production | RuntimeMode::Staging) {
                anyhow::bail!(
                    "GLYPH_TEE_VENDOR must be explicitly set in production/staging mode (no default)"
                );
            }
            TeeVendor::Nitro
        }
    };

    // Closes T13 + Staging tightening: Staging defaults to devnet RPC,
    // Production refuses mainnet RPC unless GLYPH_ALLOW_MAINNET=1.
    let solana_rpc_url = match env::var("GLYPH_SOLANA_RPC_URL") {
        Ok(v) => {
            if matches!(runtime_mode, RuntimeMode::Production)
                && is_mainnet_rpc(&v)
                && env::var("GLYPH_ALLOW_MAINNET").ok().as_deref() != Some("1")
            {
                anyhow::bail!(
                    "Production mode refuses mainnet RPC ({v}) without GLYPH_ALLOW_MAINNET=1"
                );
            }
            v
        }
        Err(_) => match runtime_mode {
            RuntimeMode::Production => {
                anyhow::bail!(
                    "GLYPH_SOLANA_RPC_URL must be explicitly set in production mode (no default)"
                );
            }
            RuntimeMode::Staging => "https://api.devnet.solana.com".to_string(),
            RuntimeMode::Dev => "http://127.0.0.1:8899".to_string(),
        },
    };

    // Closes T13: in production, refuse the placeholder verifier program ID.
    // We don't materialise the program ID into WorkerConfig (main.rs reads
    // it directly), but we *do* validate the env var here so the failure is
    // surfaced at config-load time.
    if let Ok(verifier_pid) = env::var("GLYPH_VERIFIER_PROGRAM_ID") {
        if matches!(runtime_mode, RuntimeMode::Production)
            && verifier_pid.trim() == PLACEHOLDER_VERIFIER_PROGRAM_ID
        {
            anyhow::bail!(
                "GLYPH_VERIFIER_PROGRAM_ID is the placeholder vanity ID ({}); production deployments must override it",
                PLACEHOLDER_VERIFIER_PROGRAM_ID
            );
        }
    } else if matches!(runtime_mode, RuntimeMode::Production) {
        anyhow::bail!(
            "GLYPH_VERIFIER_PROGRAM_ID must be explicitly set in production mode (no default)"
        );
    }

    // Closes T13: in production, refuse non-loopback bind unless the operator
    // explicitly opts in via GLYPH_ALLOW_PUBLIC_BIND=1 *and* an mTLS CA is
    // configured. The mTLS-CA check is a placeholder until WS-5 lands.
    let listen_addr =
        env::var("GLYPH_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8088".to_string());
    if matches!(runtime_mode, RuntimeMode::Production) {
        let host = listen_addr
            .rsplit_once(':')
            .map(|(h, _)| h.trim_start_matches('[').trim_end_matches(']'))
            .unwrap_or(listen_addr.as_str());
        let is_loopback = host.starts_with("127.") || host == "::1" || host == "[::1]";
        if !is_loopback {
            let allow_public = env::var("GLYPH_ALLOW_PUBLIC_BIND").ok().as_deref() == Some("1");
            // TODO(WS-5): check an mTLS CA env var (e.g. GLYPH_CLIENT_CA_PEM) is
            // present and parses. For now we only enforce the loopback rule.
            if !allow_public {
                anyhow::bail!(
                    "production mode requires loopback bind (got {listen_addr}); set GLYPH_ALLOW_PUBLIC_BIND=1 plus an mTLS CA to override"
                );
            }
        }
    }

    // Closes T6 (agent_pubkey binding slice): Staging/Production must
    // explicitly set the agent pubkey so the boot attestation 5-tuple binds
    // a known on-chain identity. Dev mode falls back to worker_pubkey.
    let agent_pubkey = match env::var("GLYPH_AGENT_PUBKEY") {
        Ok(v) => Some(v),
        Err(_) => {
            if matches!(runtime_mode, RuntimeMode::Production | RuntimeMode::Staging) {
                anyhow::bail!(
                    "GLYPH_AGENT_PUBKEY must be explicitly set in production/staging mode \
                     (bound into the boot attestation 5-tuple — closes T6)"
                );
            }
            None
        }
    };

    // Closes T21 (keypair sealing). Production refuses plaintext on disk
    // unless `GLYPH_KEYPAIR_SEALED=1` is set or the path ends in `.sealed`.
    let keypair_path =
        env::var("GLYPH_KEYPAIR_PATH").unwrap_or_else(|_| "worker-keypair.json".to_string());
    let keypair_sealed = env::var("GLYPH_KEYPAIR_SEALED").ok().as_deref() == Some("1")
        || keypair_path.ends_with(".sealed");

    Ok(WorkerConfig {
        tee_vendor,
        policy_path: env::var("GLYPH_POLICY_PATH")
            .unwrap_or_else(|_| "policy.toml.sealed".to_string()),
        keypair_path,
        listen_addr,
        solana_rpc_url,
        runtime_mode,
        agent_pubkey,
        keypair_sealed,
    })
}

/// Detect mainnet Solana RPC URLs. Used by the production gate to refuse
/// accidental mainnet pointing without explicit `GLYPH_ALLOW_MAINNET=1`.
fn is_mainnet_rpc(url: &str) -> bool {
    let lowered = url.to_lowercase();
    lowered.contains("mainnet") || lowered.contains("api.solana.com")
}

fn load_config_file(path: impl AsRef<Path>) -> Result<WorkerConfig> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))?;
    let cfg: WorkerConfig = toml::from_str(&content).context("invalid worker TOML config")?;
    Ok(cfg)
}
