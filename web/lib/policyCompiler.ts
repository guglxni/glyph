/**
 * Natural-language → GLYPH policy compilation (client side).
 *
 * The LLM proposes JSON; THIS module is the deterministic "schema guard" the
 * enhancement doc (docs/integrations/nl-to-policy-compilation.md) describes:
 *   - parse the model's JSON robustly (strip prose / code fences),
 *   - reject unknown keys,
 *   - clamp out-of-range values,
 *   - coerce SOL → lamports,
 *   - drop hallucinated rules,
 * then map the guarded result onto the canonical `Policy` shape that lib/glyph.ts
 * hashes — so the policy_commitment is computed with the REAL serializer.
 */

import type { Policy } from "./glyph";

// ─── Well-known program / mint IDs (also embedded in the system prompt) ─────────

export const PROGRAM_IDS: Record<string, string> = {
  jupiter: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
  system: "11111111111111111111111111111111",
  "spl token": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  token: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  memo: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
};

export const MINT_IDS: Record<string, string> = {
  usdc: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  wsol: "So11111111111111111111111111111111111111112",
  sol: "So11111111111111111111111111111111111111112",
};

// The 9-rule schema the model must target (verbatim names from policy-dsl.md).
export const POLICY_SCHEMA_KEYS = [
  "version",
  "max_lamports_per_tx",
  "allowed_programs",
  "time_window",
  "max_daily_volume_lamports",
  "require_slippage_bps_lte",
  "allowed_token_mints",
  "max_accounts_per_tx",
  "require_signer_present",
  "expires_at",
] as const;

const LAMPORTS_PER_SOL = 1_000_000_000n;
const U64_MAX = 18_446_744_073_709_551_615n;
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export const SYSTEM_PROMPT = `You are GLYPH's natural-language → policy compiler. GLYPH is a verifiable guardrail layer for autonomous AI agents on Solana. You translate a plain-English description of what an agent is allowed to do into a GLYPH policy expressed as STRICT JSON.

Output ONLY a single JSON object. No prose, no markdown, no code fences.

The JSON object has EXACTLY these keys (omit none; use null where a rule is not requested):
{
  "version": 1,
  "max_lamports_per_tx": <integer lamports or null>,
  "allowed_programs": [<base58 program id strings>],
  "time_window": { "start_hour_utc": <0-23>, "end_hour_utc": <0-23> } | null,
  "max_daily_volume_lamports": <integer lamports or null>,
  "require_slippage_bps_lte": <integer basis points 0-10000 or null>,
  "allowed_token_mints": [<base58 mint strings>] | null,
  "max_accounts_per_tx": <integer or null>,
  "require_signer_present": <true|false>,
  "expires_at": <unix seconds integer or null>
}

Rules:
- 1 SOL = 1,000,000,000 lamports. Convert all SOL amounts to integer lamports.
- "business hours" = time_window 9..17 UTC unless the user states otherwise.
- Map well-known names to ids:
  Jupiter      -> JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
  System       -> 11111111111111111111111111111111
  SPL Token    -> TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
  Memo         -> MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
  USDC (mint)  -> EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
  wSOL (mint)  -> So11111111111111111111111111111111111111112
- "stablecoins only" / "USDC only" -> allowed_token_mints = ["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"].
- "must be signed" / "require a signer" -> require_signer_present = true.
- "tight slippage" -> require_slippage_bps_lte = 50. "expire Friday" -> set expires_at to the next Friday 23:59 UTC as a unix timestamp.
- If the user does not mention a rule, set it to null (or [] for allowed_programs, false for require_signer_present).
- Never invent program ids or mints that the user did not imply. Use only the mapping above plus any explicit base58 the user provides.`;

// ─── Robust JSON extraction (model may wrap JSON in prose / fences) ─────────────

export function extractJson(raw: string): unknown {
  const trimmed = raw.trim();
  // strip ```json ... ``` fences if present
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fence ? fence[1] : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    // fall back to first {...} block
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(candidate.slice(start, end + 1));
    }
    throw new Error("Model output did not contain valid JSON.");
  }
}

// ─── Schema guard ───────────────────────────────────────────────────────────────

export interface GuardResult {
  policy: Policy;
  notes: string[];
}

function asBigInt(v: unknown): bigint | null {
  if (typeof v === "number" && Number.isFinite(v)) return BigInt(Math.trunc(v));
  if (typeof v === "bigint") return v;
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return BigInt(v.trim());
  return null;
}

function asInt(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return parseInt(v.trim(), 10);
  return null;
}

function clampBig(v: bigint, min: bigint, max: bigint, notes: string[], field: string): bigint {
  if (v < min) {
    notes.push(`clamped ${field} ${v} up to ${min}`);
    return min;
  }
  if (v > max) {
    notes.push(`clamped ${field} ${v} down to ${max}`);
    return max;
  }
  return v;
}

function validBase58List(
  raw: unknown,
  notes: string[],
  field: string
): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item === "string" && BASE58_RE.test(item.trim())) {
      out.push(item.trim());
    } else {
      notes.push(`dropped invalid ${field} entry "${String(item).slice(0, 24)}"`);
    }
  }
  return out;
}

/**
 * Deterministically validate + normalise the model's object into a canonical
 * Policy. Returns the guarded policy plus human-readable notes about every
 * clamp / drop / coercion the guard performed.
 */
export function guardPolicy(obj: unknown): GuardResult {
  const notes: string[] = [];
  if (typeof obj !== "object" || obj === null) {
    throw new Error("Compiled policy is not a JSON object.");
  }
  const src = obj as Record<string, unknown>;

  // Reject unknown keys.
  for (const key of Object.keys(src)) {
    if (!(POLICY_SCHEMA_KEYS as readonly string[]).includes(key)) {
      notes.push(`dropped unknown key "${key}"`);
    }
  }

  // version — pinned to 1 (the on-chain default). Note if the model changed it.
  const version = asInt(src.version);
  if (version !== null && version !== 1) {
    notes.push(`forced version ${version} → 1 (GLYPH on-chain default)`);
  }

  // max_lamports_per_tx (u64)
  let maxLamports = asBigInt(src.max_lamports_per_tx);
  if (maxLamports === null) {
    notes.push("max_lamports_per_tx missing → defaulted to 1 SOL");
    maxLamports = LAMPORTS_PER_SOL;
  } else {
    maxLamports = clampBig(maxLamports, 0n, U64_MAX, notes, "max_lamports_per_tx");
  }

  // allowed_programs
  const allowedPrograms = validBase58List(src.allowed_programs, notes, "allowed_programs");

  // time_window
  let timeWindow: Policy["time_window"] = null;
  if (src.time_window && typeof src.time_window === "object") {
    const tw = src.time_window as Record<string, unknown>;
    let start = asInt(tw.start_hour_utc);
    let end = asInt(tw.end_hour_utc);
    if (start !== null && end !== null) {
      if (start < 0 || start > 23) {
        notes.push(`clamped time_window.start_hour_utc ${start} into 0..23`);
        start = Math.max(0, Math.min(23, start));
      }
      if (end < 0 || end > 23) {
        notes.push(`clamped time_window.end_hour_utc ${end} into 0..23`);
        end = Math.max(0, Math.min(23, end));
      }
      timeWindow = { start_hour_utc: start, end_hour_utc: end };
    } else {
      notes.push("dropped malformed time_window");
    }
  }

  // max_daily_volume_lamports (u64)
  let maxDaily = asBigInt(src.max_daily_volume_lamports);
  if (maxDaily === null) {
    maxDaily = 0n;
  } else {
    maxDaily = clampBig(maxDaily, 0n, U64_MAX, notes, "max_daily_volume_lamports");
  }

  // require_slippage_bps_lte (u16, 0..10000)
  let slippage: number | null = null;
  {
    const s = asInt(src.require_slippage_bps_lte);
    if (s !== null) {
      if (s < 0 || s > 10000) {
        notes.push(`clamped require_slippage_bps_lte ${s} into 0..10000`);
        slippage = Math.max(0, Math.min(10000, s));
      } else {
        slippage = s;
      }
    }
  }

  // allowed_token_mints (optional list)
  let mints: string[] | null = null;
  if (Array.isArray(src.allowed_token_mints)) {
    const list = validBase58List(src.allowed_token_mints, notes, "allowed_token_mints");
    mints = list.length > 0 ? list : null;
  }

  // max_accounts_per_tx (u16)
  let maxAccounts: number | null = null;
  {
    const a = asInt(src.max_accounts_per_tx);
    if (a !== null) {
      if (a < 0 || a > 65535) {
        notes.push(`clamped max_accounts_per_tx ${a} into 0..65535`);
        maxAccounts = Math.max(0, Math.min(65535, a));
      } else {
        maxAccounts = a;
      }
    }
  }

  // require_signer_present
  const requireSigner = src.require_signer_present === true;

  // expires_at (u64 unix seconds; 0 = never)
  let expiresAt = asBigInt(src.expires_at);
  if (expiresAt === null) {
    expiresAt = 0n;
  } else {
    expiresAt = clampBig(expiresAt, 0n, U64_MAX, notes, "expires_at");
  }

  const policy: Policy = {
    version: 1,
    max_lamports_per_tx: maxLamports,
    allowed_programs: allowedPrograms,
    time_window: timeWindow,
    max_daily_volume_lamports: maxDaily,
    max_slippage_bps: slippage,
    allowed_token_mints: mints,
    max_accounts_per_tx: maxAccounts,
    require_signer_present: requireSigner,
    expires_at: expiresAt,
  };

  return { policy, notes };
}

// ─── TOML rendering (matches policy-dsl.md [[rules]] layout) ─────────────────────

const PROGRAM_LABELS: Record<string, string> = {
  JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4: "Jupiter",
  "11111111111111111111111111111111": "System",
  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA: "SPL Token",
  MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr: "Memo",
};

function quoteList(items: string[]): string {
  return `[${items.map((x) => `"${x}"`).join(", ")}]`;
}

export function policyToToml(p: Policy): string {
  const lines: string[] = [];
  lines.push("# GLYPH policy — compiled from natural language.");
  lines.push("# The agent's transactions must satisfy all of these rules.");
  lines.push("");

  lines.push("[[rules]]");
  lines.push(`type = "MaxLamportsPerTx"`);
  lines.push(`max_lamports = ${p.max_lamports_per_tx.toString()}   # ${fmtSol(p.max_lamports_per_tx)}`);
  lines.push("");

  if (p.allowed_programs.length > 0) {
    lines.push("[[rules]]");
    lines.push(`type = "AllowedPrograms"`);
    lines.push(`programs = ${quoteList(p.allowed_programs)}`);
    const labels = p.allowed_programs.map((id) => PROGRAM_LABELS[id]).filter(Boolean);
    if (labels.length) lines.push(`# ${labels.join(" · ")}`);
    lines.push("");
  }

  if (p.time_window) {
    lines.push("[[rules]]");
    lines.push(`type = "TimeWindow"`);
    lines.push(`start_hour = ${p.time_window.start_hour_utc}`);
    lines.push(`end_hour = ${p.time_window.end_hour_utc}`);
    lines.push("");
  }

  if (p.max_daily_volume_lamports > 0n) {
    lines.push("[[rules]]");
    lines.push(`type = "MaxDailyVolumeLamports"`);
    lines.push(`max_lamports = ${p.max_daily_volume_lamports.toString()}   # ${fmtSol(p.max_daily_volume_lamports)}`);
    lines.push("");
  }

  if (p.max_slippage_bps != null) {
    lines.push("[[rules]]");
    lines.push(`type = "RequireSlippageBpsLte"`);
    lines.push(`max_bps = ${p.max_slippage_bps}`);
    lines.push("");
  }

  if (p.allowed_token_mints && p.allowed_token_mints.length > 0) {
    lines.push("[[rules]]");
    lines.push(`type = "AllowedTokenMints"`);
    lines.push(`mints = ${quoteList(p.allowed_token_mints)}`);
    lines.push("");
  }

  if (p.max_accounts_per_tx != null) {
    lines.push("[[rules]]");
    lines.push(`type = "MaxAccountsPerTx"`);
    lines.push(`max_accounts = ${p.max_accounts_per_tx}`);
    lines.push("");
  }

  if (p.require_signer_present) {
    lines.push("[[rules]]");
    lines.push(`type = "RequireSignerPresent"`);
    lines.push(`signer = "<agent-owner-pubkey>"`);
    lines.push("");
  }

  if (p.expires_at > 0n) {
    lines.push("[[rules]]");
    lines.push(`type = "PolicyExpired"`);
    lines.push(`expires_at = ${p.expires_at.toString()}`);
    lines.push("");
  }

  return lines.join("\n").trimEnd() + "\n";
}

function fmtSol(lamports: bigint): string {
  const sol = Number(lamports) / 1e9;
  return `${sol} SOL`;
}

// ─── Example chips (from the enhancement doc) ────────────────────────────────────

export const EXAMPLE_PROMPTS = [
  "Let my agent trade up to 1 SOL per day on Jupiter during business hours",
  "Only USDC transfers, max 0.5 SOL each, must be signed",
  "Stablecoins only, tight slippage, expire Friday",
];
