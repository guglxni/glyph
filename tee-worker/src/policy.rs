use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{NonceReused, PolicyRule, PolicyViolation, TransactionIntent};

// Re-export canonical types for the rest of the worker
pub use glyph_common::{
    canonical_serialize_policy, hash_policy, Policy as CanonicalPolicy, TimeWindow,
};

/// TOML configuration format for policy.
/// This is the human-friendly format that gets converted to the canonical Policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    pub rules: PolicyRulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRulesConfig {
    pub max_lamports_per_tx: u64,
    /// Program IDs as base58 strings
    pub allowed_programs: Vec<String>,
    pub time_window: Option<TimeWindowConfig>,
    pub max_daily_volume_lamports: u64,
    pub require_slippage_bps_lte: Option<u16>,
    /// Token mints as base58 strings
    pub allowed_token_mints: Option<Vec<String>>,
    pub max_accounts_per_tx: Option<u16>,
    #[serde(default)]
    pub require_signer_present: bool,
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindowConfig {
    pub start_hour_utc: u8,
    pub end_hour_utc: u8,
}

fn default_version() -> u32 {
    1
}

use crate::vendors::TeeProvider;

/// Maximum number of (agent_pubkey, nonce) pairs the worker remembers in
/// memory. Keeps the LRU bounded; on overflow the oldest entry is evicted.
/// The on-chain nonce PDA remains the authoritative gate.
pub const NONCE_LRU_CAPACITY: usize = 4096;

/// Evaluates intents against policy and tracks daily volume with file persistence.
pub struct PolicyEngine {
    config: PolicyConfig,
    canonical: CanonicalPolicy,
    daily_volume_tracker: BTreeMap<String, u64>,
    volume_file: Option<PathBuf>,
    /// Worker-side replay cache. Maps `(agent_pubkey, nonce)` to the unix
    /// timestamp at which the worker first observed it. We keep at most
    /// `NONCE_LRU_CAPACITY` entries — when full we evict the oldest by
    /// timestamp. Closes T17.
    nonce_lru: BTreeMap<([u8; 32], [u8; 32]), i64>,
    /// Sealed nonce-LRU file path (mirrors `volume_file`). Persisted via the
    /// same TEE seal/unseal mechanism. Closes T17 persistence.
    nonce_lru_file: Option<PathBuf>,
}

/// Output of `check_intent`. Carries everything `commit_intent` needs to
/// mutate state safely without re-running rule logic. Closes T11.
#[derive(Debug, Clone)]
pub struct CheckedIntent {
    pub date_key: String,
    pub proposed_volume: u64,
    pub agent_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    /// Wall time used for this evaluation (single `now()` call, threaded
    /// through). Closes T34.
    pub now_unix: i64,
}

impl PolicyEngine {
    pub fn from_toml_str(contents: &str) -> Result<Self> {
        let config: PolicyConfig =
            toml::from_str(contents).context("failed to parse policy TOML")?;
        // Validate time window bounds at parse time. Closes T24.
        validate_time_window(&config)?;
        let canonical = config_to_canonical(&config)?;
        Ok(Self {
            config,
            canonical,
            daily_volume_tracker: BTreeMap::new(),
            volume_file: None,
            nonce_lru: BTreeMap::new(),
            nonce_lru_file: None,
        })
    }

    pub fn load_from_path(path: impl AsRef<Path>, provider: &dyn TeeProvider) -> Result<Self> {
        let policy_toml = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read policy file: {}", path.as_ref().display()))?;
        let mut engine = Self::from_toml_str(&policy_toml)?;

        // Use the *full filename* as the prefix so two policy files that share
        // a stem (e.g. `default.toml` + `default.alt.toml`) cannot collide on
        // the persisted volume file. Closes T23.
        let path_str = path.as_ref().to_string_lossy();
        let volume_path = PathBuf::from(format!("{}.volume.json.sealed", path_str));
        let nonce_path = PathBuf::from(format!("{}.nonces.json.sealed", path_str));

        engine.load_volume(&volume_path, provider);
        engine.load_nonce_lru(&nonce_path, provider);
        engine.volume_file = Some(volume_path);
        engine.nonce_lru_file = Some(nonce_path);

        Ok(engine)
    }

    /// Get the canonical policy (for commitment hashing and circuit input).
    pub fn canonical_policy(&self) -> &CanonicalPolicy {
        &self.canonical
    }

    /// Get the TOML config.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Check an intent against the full policy WITHOUT mutating any state.
    ///
    /// Closes T11: the daily-volume budget and nonce LRU are *not* updated
    /// here — only `commit_intent` mutates them, and only after the prover
    /// has succeeded. Closes T34: the caller passes a single `now_unix`
    /// timestamp so all rule decisions use the same wallclock value.
    pub fn check_intent(
        &self,
        intent: &TransactionIntent,
        now_unix: i64,
    ) -> Result<CheckedIntent, PolicyViolation> {
        let rules = &self.config.rules;

        // Rule 9 — TOML-level policy expiry. 0 = never expires.
        if rules.expires_at != 0 {
            if now_unix >= 0 && (now_unix as u64) >= rules.expires_at {
                return Err(PolicyViolation::new(
                    PolicyRule::PolicyExpired,
                    "policy expired",
                ));
            }
        }

        // Rule 1: MaxLamportsPerTx
        if intent.constraints.max_lamports > rules.max_lamports_per_tx {
            return Err(PolicyViolation::new(
                PolicyRule::MaxLamportsPerTx,
                "intent.max_lamports exceeds policy.max_lamports_per_tx",
            ));
        }

        // Rule 2: AllowedPrograms
        if !rules
            .allowed_programs
            .iter()
            .any(|p| p == &intent.action.target_program)
        {
            return Err(PolicyViolation::new(
                PolicyRule::AllowedPrograms,
                "target_program not in allowed_programs",
            ));
        }

        // Rule 3: TimeWindow — NOW ENFORCED IN-CIRCUIT (WS-8).
        //
        // The guest reads a TEE-attested `attested_timestamp` and the
        // on-chain verifier checks it against `Clock::unix_timestamp` with
        // ±`ATTESTED_TIMESTAMP_MAX_DRIFT_SECS` tolerance (closes AUDIT_TEE
        // T9). The host-clock check that used to live here is intentionally
        // removed so the proof is the single source of truth on this rule.
        // The `time_window` field is still validated structurally at policy
        // load (`validate_time_window`).

        // Rule 4: MaxDailyVolumeLamports — read-only here.
        let date_dt: DateTime<Utc> = Utc.timestamp_opt(now_unix, 0).single().ok_or_else(|| {
            PolicyViolation::new(
                PolicyRule::MaxDailyVolumeLamports,
                "invalid now_unix timestamp",
            )
        })?;
        let date_key = date_dt.format("%Y-%m-%d").to_string();
        let current = *self.daily_volume_tracker.get(&date_key).unwrap_or(&0);
        // Closes T22: explicit overflow rejection instead of saturating.
        let proposed = current.checked_add(intent.constraints.max_lamports).ok_or_else(|| {
            PolicyViolation::new(
                PolicyRule::MaxDailyVolumeLamports,
                "daily volume would overflow u64",
            )
        })?;
        if proposed > rules.max_daily_volume_lamports {
            return Err(PolicyViolation::new(
                PolicyRule::MaxDailyVolumeLamports,
                "intent would exceed max_daily_volume_lamports",
            ));
        }

        // Rule 5: RequireSlippageBpsLte
        if let Some(max_bps) = rules.require_slippage_bps_lte {
            match intent.constraints.max_slippage_bps {
                Some(actual) if actual <= max_bps => {}
                _ => {
                    return Err(PolicyViolation::new(
                        PolicyRule::RequireSlippageBpsLte,
                        "intent.max_slippage_bps missing or above policy maximum",
                    ));
                }
            }
        }

        // Rule 6: AllowedTokenMints
        // Closes T26: when a non-empty allowlist is configured, the intent
        // MUST present `allowed_tokens` AND every entry must be in the
        // allowlist. An intent that omits the field is rejected.
        if let Some(allowed) = &rules.allowed_token_mints {
            if !allowed.is_empty() {
                let Some(requested_tokens) = &intent.constraints.allowed_tokens else {
                    return Err(PolicyViolation::new(
                        PolicyRule::AllowedTokenMints,
                        "intent omitted allowed_tokens but policy requires it",
                    ));
                };
                let allowed_set: std::collections::BTreeSet<&str> =
                    allowed.iter().map(String::as_str).collect();
                for token in requested_tokens {
                    if !allowed_set.contains(token.as_str()) {
                        return Err(PolicyViolation::new(
                            PolicyRule::AllowedTokenMints,
                            "intent contains token not in allowed_token_mints",
                        ));
                    }
                }
            }
        }

        // Rule 7: MaxAccountsPerTx
        if let Some(max_accounts) = rules.max_accounts_per_tx {
            if intent.action.accounts.len() > max_accounts as usize {
                return Err(PolicyViolation::new(
                    PolicyRule::MaxAccountsPerTx,
                    "intent has more accounts than max_accounts_per_tx",
                ));
            }
        }

        // Rule 8: RequireSignerPresent
        if rules.require_signer_present
            && !intent.action.accounts.iter().any(|a| a.is_signer)
        {
            return Err(PolicyViolation::new(
                PolicyRule::RequireSignerPresent,
                "no signer account present",
            ));
        }

        let agent_pubkey = decode_agent_pubkey(&intent.agent_pubkey).map_err(|_| {
            PolicyViolation::new(
                PolicyRule::RequireSignerPresent,
                "agent_pubkey not 32 bytes",
            )
        })?;
        let nonce = decode_nonce(&intent.nonce).map_err(|_| {
            PolicyViolation::new(
                PolicyRule::RequireSignerPresent,
                "nonce not 32 bytes",
            )
        })?;

        Ok(CheckedIntent {
            date_key,
            proposed_volume: proposed,
            agent_pubkey,
            nonce,
            now_unix,
        })
    }

    /// Reject the intent if (agent_pubkey, nonce) was already observed.
    /// This is a worker-local LRU; the on-chain nonce PDA is the authoritative
    /// uniqueness gate. Closes T17.
    pub fn check_nonce_unique(&self, checked: &CheckedIntent) -> Result<(), NonceReused> {
        if self
            .nonce_lru
            .contains_key(&(checked.agent_pubkey, checked.nonce))
        {
            return Err(NonceReused {
                agent_pubkey: checked.agent_pubkey,
                nonce: checked.nonce,
            });
        }
        Ok(())
    }

    /// Commit the daily-volume increment AND record the nonce. Only call
    /// after the prover has succeeded. Closes T11 / T17.
    pub fn commit_intent(&mut self, checked: CheckedIntent) -> Result<()> {
        // Record nonce first, with bounded eviction.
        if self.nonce_lru.len() >= NONCE_LRU_CAPACITY {
            // Evict the oldest entry (smallest timestamp).
            if let Some((oldest_key, _)) = self
                .nonce_lru
                .iter()
                .min_by_key(|(_, &ts)| ts)
                .map(|(k, v)| (*k, *v))
            {
                self.nonce_lru.remove(&oldest_key);
            }
        }
        self.nonce_lru
            .insert((checked.agent_pubkey, checked.nonce), checked.now_unix);

        // Commit volume.
        self.daily_volume_tracker
            .insert(checked.date_key, checked.proposed_volume);
        Ok(())
    }

    /// Backwards-compatible read-mutate combined evaluator. Used by existing
    /// unit tests; production callers should use `check_intent` +
    /// `commit_intent`.
    pub fn evaluate_intent(
        &mut self,
        intent: &TransactionIntent,
    ) -> Result<(), PolicyViolation> {
        let now = Utc::now().timestamp();
        let checked = self.check_intent(intent, now)?;
        self.commit_intent(checked)
            .map_err(|e| PolicyViolation::new(PolicyRule::MaxDailyVolumeLamports, e.to_string()))?;
        Ok(())
    }

    /// Load daily volume from persistent storage (unsealing first).
    ///
    /// **Panics** on tampering: a missing file is treated as "first run" and
    /// produces an empty tracker, but a file that exists yet fails to unseal
    /// or fails to parse JSON aborts the worker. Closes T12.
    fn load_volume(&mut self, path: &Path, provider: &dyn TeeProvider) {
        let sealed_data = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                panic!(
                    "failed to read sealed volume file at {}: {}",
                    path.display(),
                    e
                );
            }
        };

        let unsealed = provider
            .unseal(&sealed_data)
            .unwrap_or_else(|e| panic!("volume file at {} failed to unseal: {}", path.display(), e));

        let tracker: BTreeMap<String, u64> = serde_json::from_slice(&unsealed)
            .unwrap_or_else(|e| {
                panic!(
                    "volume file at {} parsed as invalid JSON: {}",
                    path.display(),
                    e
                )
            });

        // Only keep today's entry to avoid unbounded growth.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        if let Some(vol) = tracker.get(&today) {
            self.daily_volume_tracker.insert(today, *vol);
        }
    }

    /// Persist daily volume to file (sealing first).
    pub fn persist_volume(&self, provider: &dyn TeeProvider) -> Result<()> {
        if let Some(path) = &self.volume_file {
            // Only persist today's entry
            let today = Utc::now().format("%Y-%m-%d").to_string();
            let mut snapshot = BTreeMap::new();
            if let Some(vol) = self.daily_volume_tracker.get(&today) {
                snapshot.insert(today, *vol);
            }
            let json = serde_json::to_vec(&snapshot).context("failed to serialize volume tracker")?;
            let sealed = provider.seal(&json).context("failed to seal volume tracker")?;
            std::fs::write(path, sealed).context("failed to write sealed volume file")?;
        }
        Ok(())
    }

    /// Load the persisted nonce LRU. Mirrors `load_volume`'s tamper-evidence:
    /// missing file is benign; corrupt file panics.
    fn load_nonce_lru(&mut self, path: &Path, provider: &dyn TeeProvider) {
        let sealed_data = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                panic!(
                    "failed to read sealed nonce-LRU file at {}: {}",
                    path.display(),
                    e
                );
            }
        };
        let unsealed = provider.unseal(&sealed_data).unwrap_or_else(|e| {
            panic!(
                "nonce LRU file at {} failed to unseal: {}",
                path.display(),
                e
            )
        });

        // Stored as Vec<(agent, nonce, ts)> for stable JSON.
        type Entry = ([u8; 32], [u8; 32], i64);
        let entries: Vec<Entry> = serde_json::from_slice(&unsealed).unwrap_or_else(|e| {
            panic!(
                "nonce LRU file at {} parsed as invalid JSON: {}",
                path.display(),
                e
            )
        });
        for (agent, nonce, ts) in entries.into_iter().take(NONCE_LRU_CAPACITY) {
            self.nonce_lru.insert((agent, nonce), ts);
        }
    }

    /// Persist the nonce LRU via the TEE seal mechanism. Best-effort — the
    /// on-chain nonce PDA is the source of truth.
    pub fn persist_nonce_lru(&self, provider: &dyn TeeProvider) -> Result<()> {
        if let Some(path) = &self.nonce_lru_file {
            let entries: Vec<([u8; 32], [u8; 32], i64)> = self
                .nonce_lru
                .iter()
                .map(|(&(a, n), &t)| (a, n, t))
                .collect();
            let json = serde_json::to_vec(&entries).context("failed to serialize nonce LRU")?;
            let sealed = provider.seal(&json).context("failed to seal nonce LRU")?;
            std::fs::write(path, sealed).context("failed to write sealed nonce LRU")?;
        }
        Ok(())
    }
}

fn decode_agent_pubkey(s: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(s)
        .into_vec()
        .context("agent_pubkey is not valid base58")?;
    if bytes.len() != 32 {
        anyhow::bail!("agent_pubkey must decode to 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_nonce(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("nonce is not valid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("nonce must decode to 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Validate `time_window` bounds at policy load. Returns `Err` if either
/// `start_hour_utc` or `end_hour_utc` is `>= 24`. Closes T24.
fn validate_time_window(config: &PolicyConfig) -> Result<()> {
    if let Some(window) = &config.rules.time_window {
        if window.start_hour_utc > 23 {
            anyhow::bail!(
                "policy time_window.start_hour_utc must be 0..=23 (got {})",
                window.start_hour_utc
            );
        }
        if window.end_hour_utc > 23 {
            anyhow::bail!(
                "policy time_window.end_hour_utc must be 0..=23 (got {})",
                window.end_hour_utc
            );
        }
    }
    Ok(())
}

/// Convert human-friendly TOML config to canonical glyph-common::Policy.
/// String pubkeys are decoded to [u8; 32] byte arrays.
pub fn config_to_canonical(config: &PolicyConfig) -> Result<CanonicalPolicy> {
    let allowed_programs: Vec<[u8; 32]> = config
        .rules
        .allowed_programs
        .iter()
        .map(|s| {
            let bytes = bs58::decode(s)
                .into_vec()
                .with_context(|| format!("invalid base58 program ID: {s}"))?;
            if bytes.len() != 32 {
                anyhow::bail!("program ID must be 32 bytes: {s}");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<Vec<_>>>()?;

    let allowed_token_mints: Option<Vec<[u8; 32]>> = config
        .rules
        .allowed_token_mints
        .as_ref()
        .map(|mints| {
            mints
                .iter()
                .map(|s| {
                    let bytes = bs58::decode(s)
                        .into_vec()
                        .with_context(|| format!("invalid base58 token mint: {s}"))?;
                    if bytes.len() != 32 {
                        anyhow::bail!("token mint must be 32 bytes: {s}");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Ok(arr)
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;

    let time_window = config.rules.time_window.as_ref().map(|tw| TimeWindow {
        start_hour_utc: tw.start_hour_utc,
        end_hour_utc: tw.end_hour_utc,
    });

    Ok(CanonicalPolicy {
        version: config.version,
        max_lamports_per_tx: config.rules.max_lamports_per_tx,
        allowed_programs,
        time_window,
        max_daily_volume_lamports: config.rules.max_daily_volume_lamports,
        max_slippage_bps: config.rules.require_slippage_bps_lte,
        allowed_token_mints,
        max_accounts_per_tx: config.rules.max_accounts_per_tx,
        require_signer_present: config.rules.require_signer_present,
        expires_at: config.rules.expires_at,
    })
}
