"use client";

import { useEffect, useState } from "react";
import {
  hashPolicy,
  hashIntent,
  hashTxBinding,
  evaluate,
  toHex,
  type Decision,
} from "@/lib/glyph";
import {
  POLICY,
  INTENTS,
  EXPECTED_POLICY_COMMITMENT,
} from "@/lib/data";
import { Card, Hash } from "./ui";

const POLICY_TOML = `# Multi-Protocol Policy — one policy, four programs
[[rules]]                                   # rule 0
program_id = "1111…1111"   # System Program
action     = "allow"
max_amount = 1_000_000_000                  # 1 SOL cap

[[rules]]                                   # rule 1
program_id = "Tokenkeg…5DA" # SPL Token
action     = "allow"

[[rules]]                                   # rule 2
program_id = "JUP6Lkb…yMjA" # Jupiter
action     = "deny"

[[rules]]                                   # rule 3
program_id = "MemoSq4g…fcHr" # Memo
action     = "allow"
require_memo = true`;

interface Computed {
  policyCommitment: string;
  intentHash: string;
  txHash: string;
  decision: Decision;
}

export default function PolicyConsole() {
  const [selected, setSelected] = useState(0);
  const [policyCommitment, setPolicyCommitment] = useState<string | null>(null);
  const [perIntent, setPerIntent] = useState<Record<string, Computed>>({});

  // Compute the policy commitment once + every intent's hashes on mount.
  useEffect(() => {
    let alive = true;
    (async () => {
      const pc = toHex(await hashPolicy(POLICY));
      if (!alive) return;
      setPolicyCommitment(pc);
      const map: Record<string, Computed> = {};
      for (const di of INTENTS) {
        const [ih, tx] = await Promise.all([
          hashIntent(di.intent),
          hashTxBinding(di.intent),
        ]);
        map[di.id] = {
          policyCommitment: pc,
          intentHash: toHex(ih),
          txHash: toHex(tx),
          decision: evaluate(POLICY, di.intent),
        };
      }
      if (alive) setPerIntent(map);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const active = INTENTS[selected];
  const computed = perIntent[active.id];
  const parityOk =
    policyCommitment !== null &&
    policyCommitment === EXPECTED_POLICY_COMMITMENT;

  const decisionAllow = computed?.decision.type === "allow";

  return (
    <Card className="overflow-hidden">
      {/* commitment banner */}
      <div className="border-b border-line bg-panel2/60 px-5 py-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="font-mono text-[11px] uppercase tracking-widest text-faint">
            policy_commitment · computed in your browser
          </div>
          {policyCommitment && (
            <span
              className={`font-mono text-[11px] ${
                parityOk ? "text-accent" : "text-danger"
              }`}
            >
              {parityOk ? "● matches verified artifact" : "● mismatch"}
            </span>
          )}
        </div>
        <Hash
          value={policyCommitment ?? "computing…"}
          className="mt-1.5 block text-[13px] text-ink"
        />
        <div className="mt-1 font-mono text-[11px] text-faint">
          identical across System · Token · Memo · Jupiter →{" "}
          <span className="text-sub">one policy, any program</span>
        </div>
      </div>

      <div className="grid md:grid-cols-[300px_1fr]">
        {/* left: policy + intent picker */}
        <div className="border-b border-line md:border-b-0 md:border-r">
          <pre className="scroll-thin overflow-x-auto border-b border-line bg-bg/60 px-5 py-4 font-mono text-[11.5px] leading-relaxed text-sub">
            {POLICY_TOML}
          </pre>
          <div className="p-3">
            <div className="px-2 pb-2 font-mono text-[11px] uppercase tracking-widest text-faint">
              pick an intent
            </div>
            <div className="flex flex-col gap-1.5">
              {INTENTS.map((di, i) => {
                const c = perIntent[di.id];
                const allow = c?.decision.type === "allow";
                const isActive = i === selected;
                return (
                  <button
                    key={di.id}
                    onClick={() => setSelected(i)}
                    className={`group flex items-center justify-between rounded-lg border px-3 py-2.5 text-left transition-all ${
                      isActive
                        ? "border-accent/40 bg-accent/[0.06]"
                        : "border-line bg-panel hover:border-line/80 hover:bg-panel2"
                    }`}
                  >
                    <div>
                      <div className="text-[13px] font-medium text-ink">
                        {di.label}
                      </div>
                      <div className="text-[11px] text-faint">{di.protocol}</div>
                    </div>
                    {c && (
                      <span
                        className={`font-mono text-[10px] uppercase tracking-wider ${
                          allow ? "text-accent" : "text-danger"
                        }`}
                      >
                        {allow ? "allow" : "deny"}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* right: decision + hashes */}
        <div className="p-5">
          <div className="text-[13px] text-sub">{active.blurb}</div>

          {/* decision */}
          <div
            className={`mt-4 flex items-center gap-3 rounded-lg border px-4 py-3.5 ${
              !computed
                ? "border-line bg-panel"
                : decisionAllow
                ? "border-accent/40 bg-accent/[0.07]"
                : "border-danger/40 bg-danger/[0.07]"
            }`}
          >
            <span
              className={`inline-flex h-7 w-7 items-center justify-center rounded-full ${
                !computed
                  ? "bg-line text-faint"
                  : decisionAllow
                  ? "bg-accent/20 text-accent"
                  : "bg-danger/20 text-danger"
              }`}
            >
              {decisionAllow ? "✓" : computed ? "✕" : "…"}
            </span>
            <div>
              <div
                className={`font-mono text-sm font-semibold tracking-wide ${
                  !computed
                    ? "text-faint"
                    : decisionAllow
                    ? "text-accent"
                    : "text-danger"
                }`}
              >
                {!computed
                  ? "EVALUATING"
                  : decisionAllow
                  ? "ALLOW"
                  : "DENY"}
              </div>
              <div className="text-[12px] text-sub">
                {computed?.decision.type === "deny"
                  ? `${computed.decision.reason} · rule "${computed.decision.rule}" (code ${computed.decision.code})`
                  : decisionAllow
                  ? "intent satisfies the policy — proof would be generated"
                  : "computing…"}
              </div>
            </div>
          </div>

          {/* hashes */}
          <div className="mt-5 space-y-3.5">
            <HashRow label="policy_commitment" value={computed?.policyCommitment} accent />
            <HashRow label="intent_hash" value={computed?.intentHash} />
            <HashRow label="tx_hash" value={computed?.txHash} />
          </div>

          <p className="mt-5 text-[12px] leading-relaxed text-faint">
            All three digests are SHA-256 over the canonical encoding ported
            byte-for-byte from{" "}
            <span className="font-mono text-sub">glyph-core</span>. The TEE
            worker and RISC Zero guest hash the exact same bytes — so the proof
            the on-chain verifier checks is bound to precisely this policy and
            this intent.
          </p>
        </div>
      </div>
    </Card>
  );
}

function HashRow({
  label,
  value,
  accent,
}: {
  label: string;
  value?: string;
  accent?: boolean;
}) {
  return (
    <div>
      <div className="font-mono text-[11px] uppercase tracking-widest text-faint">
        {label}
      </div>
      <Hash
        value={value ?? "…"}
        className={`mt-1 block text-[12.5px] ${accent ? "text-accent" : "text-sub"}`}
      />
    </div>
  );
}
