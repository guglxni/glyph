"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import {
  EXPECTED_POLICY_COMMITMENT,
  INTENTS,
  POLICY,
  type DemoIntent,
} from "@/lib/data";
import {
  evaluate,
  hashIntent,
  hashPolicy,
  hashTxBinding,
  toHex,
  type Decision,
} from "@/lib/glyph";
import { CopyHash, Pill } from "./ui";

type Computed = {
  decision: Decision;
  policyCommitment: string;
  intentHash: string;
  txHash: string;
};

const PROTOCOL_GLYPHS: Record<string, string> = {
  system: "◎",
  token: "⬡",
  memo: "✎",
  jupiter: "⇄",
};

export function PolicyConsole() {
  const [activeId, setActiveId] = useState(INTENTS[0].id);
  const [computed, setComputed] = useState<Record<string, Computed>>({});
  const [parityOk, setParityOk] = useState<boolean | null>(null);

  const active = useMemo<DemoIntent>(
    () => INTENTS.find((i) => i.id === activeId) ?? INTENTS[0],
    [activeId]
  );

  // Compute all hashes once, in-browser, with the real canonical serializer.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const policyCommitment = toHex(await hashPolicy(POLICY));
      const next: Record<string, Computed> = {};
      for (const di of INTENTS) {
        const [ih, th] = await Promise.all([
          hashIntent(di.intent),
          hashTxBinding(di.intent),
        ]);
        next[di.id] = {
          decision: evaluate(POLICY, di.intent),
          policyCommitment,
          intentHash: toHex(ih),
          txHash: toHex(th),
        };
      }
      if (cancelled) return;
      setComputed(next);
      setParityOk(policyCommitment === EXPECTED_POLICY_COMMITMENT);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const result = computed[active.id];
  const isAllow = result?.decision.type === "allow";

  return (
    <div className="grid gap-6 lg:grid-cols-[340px_1fr]">
      {/* ── Left: intent selector ── */}
      <div className="flex flex-col gap-3">
        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <span className="eyebrow">
              <span className="h-1 w-1 rounded-full bg-glyph" />
              Pick an action
            </span>
            <span className="text-2xs text-white/35">4 intents · 1 policy</span>
          </div>
          <div className="flex flex-col gap-2">
            {INTENTS.map((di) => {
              const c = computed[di.id];
              const allow = c?.decision.type === "allow";
              const selected = di.id === activeId;
              return (
                <button
                  key={di.id}
                  onClick={() => setActiveId(di.id)}
                  className={`group relative flex items-center gap-3 rounded-xl border px-3 py-3 text-left transition-all ${
                    selected
                      ? "border-glyph/40 bg-glyph/[0.06] shadow-glow"
                      : "border-white/[0.07] bg-white/[0.01] hover:border-white/20 hover:bg-white/[0.03]"
                  }`}
                >
                  <span
                    className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg text-base ${
                      selected ? "bg-glyph/15 text-glyph-300" : "bg-white/[0.04] text-white/50"
                    }`}
                  >
                    {PROTOCOL_GLYPHS[di.id] ?? "•"}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-white/90">
                      {di.label}
                    </span>
                    <span className="block truncate text-2xs text-white/45">{di.protocol}</span>
                  </span>
                  {c &&
                    (allow ? (
                      <Pill tone="glyph" className="shrink-0">ALLOW</Pill>
                    ) : (
                      <Pill tone="deny" className="shrink-0">DENY</Pill>
                    ))}
                </button>
              );
            })}
          </div>
        </div>

        {/* policy summary */}
        <div className="card p-4">
          <span className="eyebrow">
            <span className="h-1 w-1 rounded-full bg-zk" />
            The one policy
          </span>
          <dl className="mt-3 space-y-1.5 font-mono text-2xs">
            <Row k="version" v={String(POLICY.version)} />
            <Row k="max_lamports_per_tx" v="1 SOL" />
            <Row k="max_daily_volume" v="5 SOL" />
            <Row k="max_accounts_per_tx" v="16" />
            <Row k="require_signer" v="true" />
            <Row k="allowed_programs" v="System · Token · Memo" />
          </dl>
        </div>
      </div>

      {/* ── Right: evaluation result ── */}
      <div className="card relative overflow-hidden p-0">
        {/* top status bar */}
        <div
          className={`flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4 transition-colors ${
            !result
              ? "border-white/[0.06]"
              : isAllow
                ? "border-glyph/20 bg-glyph/[0.04]"
                : "border-deny/20 bg-deny/[0.04]"
          }`}
        >
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm text-white/80">{active.label}</span>
            <span className="text-2xs text-white/35">→ TEE policy engine</span>
          </div>
          <AnimatePresence mode="wait">
            {result && (
              <motion.div
                key={active.id + (isAllow ? "a" : "d")}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.9 }}
                transition={{ duration: 0.25 }}
              >
                {isAllow ? (
                  <span className="inline-flex items-center gap-2 rounded-full bg-glyph/15 px-3 py-1 text-sm font-semibold text-glyph-300">
                    ✓ ALLOW
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-2 rounded-full bg-deny/15 px-3 py-1 text-sm font-semibold text-deny-400">
                    ✕ DENY
                  </span>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className="space-y-5 p-5">
          <p className="text-sm leading-relaxed text-white/55">{active.blurb}</p>

          {/* deny reason */}
          <AnimatePresence>
            {result && !isAllow && result.decision.type === "deny" && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="rounded-lg border border-deny/25 bg-deny/[0.06] p-3 text-sm">
                  <span className="font-mono text-2xs uppercase tracking-wider text-deny-400">
                    rule {result.decision.code} · {result.decision.rule}
                  </span>
                  <p className="mt-1 text-white/70">{result.decision.reason}</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* intent fields */}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="target_program">
              <CopyHash value={active.intent.target_program} truncate />
            </Field>
            <Field label="accounts">
              <span className="hash text-white/70">{active.intent.accounts.length} metas</span>
            </Field>
            <Field label="max_lamports">
              <span className="hash text-white/70">
                {(Number(active.intent.max_lamports) / 1e9).toFixed(3)} SOL
              </span>
            </Field>
            <Field label="data (opaque bytes)">
              <span className="hash text-white/70">{active.intent.data || "—"}</span>
            </Field>
          </div>

          {/* the money shot: identical commitment */}
          <div
            className={`rounded-xl border p-4 transition-colors ${
              parityOk
                ? "border-glyph/30 bg-glyph/[0.05]"
                : "border-white/10 bg-white/[0.02]"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="eyebrow !text-white/55">
                <span className="h-1 w-1 rounded-full bg-glyph" />
                policy_commitment — SHA-256, computed in your browser
              </span>
              {parityOk && <Pill tone="glyph">identical across all programs</Pill>}
            </div>
            <div className="mt-2.5">
              {result ? (
                <CopyHash value={result.policyCommitment} tone="glyph" />
              ) : (
                <span className="block h-7 w-full animate-pulse rounded bg-white/[0.04]" />
              )}
            </div>
            <p className="mt-2.5 text-2xs leading-relaxed text-white/40">
              Same hash for System, SPL Token and Memo. The policy binds the agent — not the
              target program. That is what makes GLYPH horizontal by construction.
            </p>
          </div>

          {/* per-intent binding hashes */}
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border border-white/[0.07] bg-white/[0.015] p-3">
              <span className="text-2xs uppercase tracking-wider text-white/40">intent_hash</span>
              <div className="mt-1.5">
                {result ? (
                  <CopyHash value={result.intentHash} truncate />
                ) : (
                  <span className="block h-6 animate-pulse rounded bg-white/[0.04]" />
                )}
              </div>
            </div>
            <div className="rounded-lg border border-zk/20 bg-zk/[0.04] p-3">
              <span className="text-2xs uppercase tracking-wider text-zk-300/80">
                tx_hash → binds ix[1]
              </span>
              <div className="mt-1.5">
                {result ? (
                  <CopyHash value={result.txHash} truncate />
                ) : (
                  <span className="block h-6 animate-pulse rounded bg-white/[0.04]" />
                )}
              </div>
            </div>
          </div>

          {/* parity footer */}
          <div className="flex items-center justify-between border-t border-white/[0.06] pt-3 text-2xs">
            <span className="text-white/40">
              Byte-for-byte parity with the Rust canonical serializer
            </span>
            {parityOk === null ? (
              <span className="text-white/40">computing…</span>
            ) : parityOk ? (
              <span className="font-mono text-glyph-300">✓ parity verified</span>
            ) : (
              <span className="font-mono text-deny-400">✕ mismatch</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-white/40">{k}</dt>
      <dd className="text-right text-white/75">{v}</dd>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-white/[0.07] bg-white/[0.015] p-3">
      <span className="text-2xs uppercase tracking-wider text-white/40">{label}</span>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}
