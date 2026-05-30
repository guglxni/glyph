//! Generate canonical-byte test vectors for cross-language SDK parity.
//!
//! Run via the wrapper script:
//!   bash scripts/gen-test-vectors.sh
//!
//! Or directly:
//!   cargo run -p glyph-common --features vector-gen --bin gen-test-vectors -- \
//!     sdk/test-vectors
//!
//! For every `intents/*.input.json` it writes:
//!   <stem>.canonical.bytes      hex-encoded canonical_signing_payload(...)
//!   <stem>.signed.json          {"sha256": hex(sha256(canonical_bytes))}
//!
//! For every `policies/*.input.json` it writes:
//!   <stem>.canonical.bytes      hex-encoded canonical_serialize_policy(...)
//!   <stem>.signed.json          {"sha256": hex(sha256(canonical_bytes))}

use std::fs;
use std::path::{Path, PathBuf};

use glyph_common::{
    canonical_serialize_policy, canonical_signing_payload, sha256, CanonicalAccountMeta,
    CanonicalIntent, Policy, TimeWindow,
};
use serde_json::Value;

fn read_hex32(v: &Value, field: &str) -> [u8; 32] {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing field {field}"));
    let bytes = hex::decode(s).expect("invalid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn read_opt_hex32(v: &Value, field: &str) -> Option<[u8; 32]> {
    match v.get(field) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            let bytes = hex::decode(s).expect("invalid hex");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Some(out)
        }
        _ => panic!("field {field} must be hex string or null"),
    }
}

fn read_u64_str(v: &Value, field: &str) -> u64 {
    match v.get(field) {
        Some(Value::String(s)) => s.parse().expect("invalid u64 string"),
        Some(Value::Number(n)) => n.as_u64().expect("u64 in range"),
        _ => panic!("missing/invalid u64 field {field}"),
    }
}

fn parse_intent(v: &Value) -> CanonicalIntent {
    let agent_pubkey = read_hex32(v, "agent_pubkey");
    let nonce = read_hex32(v, "nonce");
    let target_program = read_hex32(v, "target_program");

    let accounts = v["accounts"]
        .as_array()
        .expect("accounts must be array")
        .iter()
        .map(|a| CanonicalAccountMeta {
            pubkey: read_hex32(a, "pubkey"),
            is_signer: a["is_signer"].as_bool().unwrap_or(false),
            is_writable: a["is_writable"].as_bool().unwrap_or(false),
        })
        .collect();

    let data = match v.get("data_hex") {
        Some(Value::String(s)) => hex::decode(s).expect("invalid hex data"),
        _ => Vec::new(),
    };

    let max_lamports = read_u64_str(v, "max_lamports");
    let max_slippage_bps = match v.get("max_slippage_bps") {
        Some(Value::Null) | None => None,
        Some(Value::Number(n)) => Some(n.as_u64().unwrap() as u16),
        _ => panic!("invalid max_slippage_bps"),
    };

    let allowed_tokens = match v.get("allowed_tokens") {
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for t in arr {
                let s = t.as_str().expect("allowed_tokens entry must be hex string");
                let mut a = [0u8; 32];
                a.copy_from_slice(&hex::decode(s).expect("invalid hex"));
                out.push(a);
            }
            Some(out)
        }
        Some(Value::Null) | None => None,
        _ => panic!("invalid allowed_tokens"),
    };

    CanonicalIntent {
        agent_pubkey,
        nonce,
        target_program,
        accounts,
        data,
        max_lamports,
        max_slippage_bps,
        allowed_tokens,
        expiry: read_u64_str(v, "expiry"),
        timestamp: read_u64_str(v, "timestamp"),
        policy_commitment: read_hex32(v, "policy_commitment"),
        worker_pubkey: read_opt_hex32(v, "worker_pubkey"),
        epoch: read_u64_str(v, "epoch"),
    }
}

fn parse_policy(v: &Value) -> Policy {
    let allowed_programs = v["allowed_programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let mut a = [0u8; 32];
            a.copy_from_slice(&hex::decode(s.as_str().unwrap()).unwrap());
            a
        })
        .collect();

    let time_window = match v.get("time_window") {
        Some(Value::Object(_)) => Some(TimeWindow {
            start_hour_utc: v["time_window"]["start_hour_utc"].as_u64().unwrap() as u8,
            end_hour_utc: v["time_window"]["end_hour_utc"].as_u64().unwrap() as u8,
        }),
        _ => None,
    };

    let max_slippage_bps = match v.get("max_slippage_bps") {
        Some(Value::Null) | None => None,
        Some(Value::Number(n)) => Some(n.as_u64().unwrap() as u16),
        _ => None,
    };

    let allowed_token_mints = match v.get("allowed_token_mints") {
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for s in arr {
                let mut a = [0u8; 32];
                a.copy_from_slice(&hex::decode(s.as_str().unwrap()).unwrap());
                out.push(a);
            }
            Some(out)
        }
        _ => None,
    };

    let max_accounts_per_tx = v
        .get("max_accounts_per_tx")
        .and_then(Value::as_u64)
        .map(|n| n as u16);

    Policy {
        version: v["version"].as_u64().unwrap() as u32,
        max_lamports_per_tx: read_u64_str(v, "max_lamports_per_tx"),
        allowed_programs,
        time_window,
        max_daily_volume_lamports: read_u64_str(v, "max_daily_volume_lamports"),
        max_slippage_bps,
        allowed_token_mints,
        max_accounts_per_tx,
        require_signer_present: v["require_signer_present"].as_bool().unwrap_or(false),
        expires_at: read_u64_str(v, "expires_at"),
    }
}

fn process_dir<F>(dir: &Path, key: &str, encode: F)
where
    F: Fn(&Value) -> Vec<u8>,
{
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("cannot read {}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.ends_with(".input.json"))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();

    for path in entries {
        let raw = fs::read_to_string(&path).expect("read input");
        let v: Value = serde_json::from_str(&raw).expect("invalid JSON");
        let bytes = encode(&v[key]);
        let stem = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap()
            .trim_end_matches(".input.json")
            .to_string();
        let bytes_path = dir.join(format!("{stem}.canonical.bytes"));
        let signed_path = dir.join(format!("{stem}.signed.json"));

        fs::write(&bytes_path, hex::encode(&bytes)).unwrap();
        let digest = sha256(&bytes);
        let signed = serde_json::json!({
            "sha256": hex::encode(digest),
            "len": bytes.len(),
        });
        fs::write(
            &signed_path,
            serde_json::to_string_pretty(&signed).unwrap(),
        )
        .unwrap();

        eprintln!("wrote {} ({} bytes)", bytes_path.display(), bytes.len());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "sdk/test-vectors".to_string());
    let root = PathBuf::from(root);

    let intents_dir = root.join("intents");
    let policies_dir = root.join("policies");

    process_dir(&intents_dir, "intent", |v| {
        canonical_signing_payload(&parse_intent(v))
    });
    process_dir(&policies_dir, "policy", |v| {
        canonical_serialize_policy(&parse_policy(v))
    });
}
