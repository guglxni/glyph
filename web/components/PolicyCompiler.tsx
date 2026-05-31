"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useCallback, useEffect, useMemo, useState } from "react";
import { chat, isConfigured } from "@/lib/llm";
import {
  evaluate,
  hashIntent,
  hashPolicy,
  hashTxBinding,
  toHex,
  type Decision,
  type Intent,
  type Policy,
} from "@/lib/glyph";
import {
  EXAMPLE_PROMPTS,
  extractJson,
  guardPolicy,
  PROGRAM_IDS,
  policyToToml,
  SYSTEM_PROMPT,
} from "@/lib/policyCompiler";
import { LlmSettings, useLlmSettings } from "./LlmSettings";
import { useWalletContext } from "./WalletProvider";
import { CopyHash, Pill } from "./ui";

const DEMO_AGENT = "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt";

// Sample intents to probe a freshly-compiled policy. agent_pubkey is overridden
// with the connected wallet when available.
function sampleIntents(agent: string): { id: string; label: string; intent: Intent }[] {
  return [
    {
      id: "sys",
      label: "System transfer · 0.4 SOL",
      intent: {
        agent_pubkey: agent,
        nonce: "1111111111111111111111111111111111111111111111111111111111111111",
        target_program: PROGRAM_IDS.system,
        accounts: [
          { pubkey: agent, is_signer: true, is_writable: true },
          { pubkey: "3n1mC8x9aY9b7xQ9wZqg2t8rP4kF6vH1sJ5dN2eL7uVx", is_signer: false, is_writable: true },
        ],
        data: "AgAAAECcXAAAAAAA",
        max_lamports: 400_000_000n,
        max_slippage_bps: null,
        expiry: 1_764_003_600n,
      },
    },
    {
      id: "jup",
      label: "Jupiter swap · 0.5 SOL",
      intent: {
        agent_pubkey: agent,
        nonce: "4444444444444444444444444444444444444444444444444444444444444444",
        target_program: PROGRAM_IDS.jupiter,
        accounts: [{ pubkey: agent, is_signer: true, is_writable: true }],
        data: "AQIDBAUGBwg=",
        max_lamports: 500_000_000n,
        max_slippage_bps: 30,
        expiry: 1_764_003_600n,
      },
    },
    {
      id: "big",
      label: "System transfer · 9 SOL",
      intent: {
        agent_pubkey: agent,
        nonce: "5555555555555555555555555555555555555555555555555555555555555555",
        target_program: PROGRAM_IDS.system,
        accounts: [
          { pubkey: agent, is_signer: true, is_writable: true },
          { pubkey: "3n1mC8x9aY9b7xQ9wZqg2t8rP4kF6vH1sJ5dN2eL7uVx", is_signer: false, is_writable: true },
        ],
        data: "AgAAAECcXAAAAAAA",
        max_lamports: 9_000_000_000n,
        max_slippage_bps: null,
        expiry: 1_764_003_600n,
      },
    },
    {
      id: "unsigned",
      label: "Memo · no signer",
      intent: {
        agent_pubkey: agent,
        nonce: "6666666666666666666666666666666666666666666666666666666666666666",
        target_program: PROGRAM_IDS.memo,
        accounts: [{ pubkey: "3n1mC8x9aY9b7xQ9wZqg2t8rP4kF6vH1sJ5dN2eL7uVx", is_signer: false, is_writable: false }],
        data: "Z2x5cGg6IHVuaXZlcnNhbCBndWFyZHJhaWw=",
        max_lamports: 0n,
        max_slippage_bps: null,
        expiry: 1_764_003_600n,
      },
    },
  ];
}

type ProbeRow = { id: string; label: string; decision: Decision; intentHash: string; txHash: string };

export function PolicyCompiler() {
  const [settings, setSettings] = useLlmSettings();
  const { address } = useWalletContext();
  const agent = address ?? DEMO_AGENT;

  const [prompt, setPrompt] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [toml, setToml] = useState<string>("");
  const [notes, setNotes] = useState<string[]>([]);
  const [commitment, setCommitment] = useState<string>("");
  const [probes, setProbes] = useState<ProbeRow[]>([]);
  const [rawJson, setRawJson] = useState<string>("");

  const configured = useMemo(() => isConfigured(settings), [settings]);

  const recompute = useCallback(
    async (p: Policy) => {
      setCommitment(toHex(await hashPolicy(p)));
      const rows: ProbeRow[] = [];
      for (const s of sampleIntents(agent)) {
        const [ih, th] = await Promise.all([hashIntent(s.intent), hashTxBinding(s.intent)]);
        rows.push({
          id: s.id,
          label: s.label,
          decision: evaluate(p, s.intent),
          intentHash: toHex(ih),
          txHash: toHex(th),
        });
      }
      setProbes(rows);
    },
    [agent]
  );

  // Re-probe when the wallet (agent identity) changes and a policy exists.
  useEffect(() => {
    if (policy) void recompute(policy);
  }, [policy, recompute]);

  const compile = async (text: string) => {
    if (!text.trim()) return;
    if (!configured) {
      setError("Configure an LLM provider first (the key icon).");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { content } = await chat(
        settings,
        [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: text.trim() },
        ],
        { jsonMode: true }
      );
      setRawJson(content);
      const parsed = extractJson(content);
      const { policy: guarded, notes: guardNotes } = guardPolicy(parsed);
      setNotes(guardNotes);
      setToml(policyToToml(guarded));
      setPolicy(guarded);
      await recompute(guarded);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Compilation failed.");
      setPolicy(null);
      setToml("");
      setCommitment("");
      setProbes([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      {/* ── Left: prompt ── */}
      <div className="card flex flex-col p-5">
        <div className="flex items-center justify-between gap-3">
          <span className="eyebrow">
            <span className="h-1 w-1 rounded-full bg-glyph" />
            Describe the policy
          </span>
          <LlmSettings settings={settings} onChange={setSettings} />
        </div>

        <textarea
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          rows={4}
          placeholder="e.g. Let my agent trade up to 1 SOL per day on Jupiter during business hours"
          className="mt-4 w-full resize-none rounded-xl border border-white/12 bg-white/[0.02] p-3.5 text-sm leading-relaxed text-white/90 outline-none transition-colors placeholder:text-white/30 focus:border-glyph/45"
        />

        <div className="mt-3 flex flex-wrap gap-1.5">
          {EXAMPLE_PROMPTS.map((ex) => (
            <button
              key={ex}
              onClick={() => setPrompt(ex)}
              className="rounded-full border border-white/10 bg-white/[0.02] px-2.5 py-1 text-left text-2xs text-white/60 transition-colors hover:border-glyph/30 hover:text-glyph-300"
            >
              {ex}
            </button>
          ))}
        </div>

        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={() => compile(prompt)}
            disabled={loading || !prompt.trim()}
            className="btn-primary !px-5 !py-2.5 text-sm disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? (
              <span className="inline-flex items-center gap-2">
                <Spinner /> Compiling…
              </span>
            ) : (
              "Compile to policy →"
            )}
          </button>
          {!configured && (
            <span className="text-2xs text-amber-300">↑ set your LLM key first</span>
          )}
        </div>

        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <p className="mt-3 rounded-lg border border-deny/25 bg-deny/[0.06] p-3 text-sm text-deny-400">
                {error}
              </p>
            </motion.div>
          )}
        </AnimatePresence>

        <p className="mt-auto pt-5 text-2xs leading-relaxed text-white/40">
          This is GLYPH&rsquo;s natural-language → policy DSL compiler. The LLM proposes JSON; a
          deterministic schema guard in your browser clamps it to the 9-rule DSL. The agent that
          writes policy is exactly what GLYPH guards.
        </p>
      </div>

      {/* ── Right: result ── */}
      <div className="card relative overflow-hidden p-0">
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-4">
          <span className="font-mono text-sm text-white/80">compiled policy</span>
          {commitment ? (
            <Pill tone="glyph">9-rule DSL</Pill>
          ) : (
            <span className="text-2xs text-white/35">awaiting input</span>
          )}
        </div>

        <div className="space-y-5 p-5">
          {!policy ? (
            <div className="grid place-items-center rounded-xl border border-dashed border-white/10 bg-white/[0.01] py-12 text-center">
              <p className="max-w-xs text-sm text-white/45">
                Describe a policy on the left and compile it. The TOML, the real
                policy_commitment, and live ALLOW/DENY tests appear here.
              </p>
            </div>
          ) : (
            <>
              {/* TOML */}
              <div>
                <span className="eyebrow !text-white/55">
                  <span className="h-1 w-1 rounded-full bg-zk" />
                  policy.toml
                </span>
                <pre className="mt-2 max-h-60 overflow-auto rounded-xl border border-white/[0.07] bg-ink-950/60 p-3.5 font-mono text-2xs leading-relaxed text-white/75">
                  {toml}
                </pre>
              </div>

              {/* schema guard notes */}
              {notes.length > 0 && (
                <div className="rounded-lg border border-amber-400/20 bg-amber-400/[0.04] p-3">
                  <span className="font-mono text-2xs uppercase tracking-wider text-amber-300">
                    schema guard · {notes.length} adjustment{notes.length > 1 ? "s" : ""}
                  </span>
                  <ul className="mt-1.5 space-y-0.5">
                    {notes.map((n, i) => (
                      <li key={i} className="font-mono text-2xs text-white/55">
                        · {n}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* commitment */}
              <div className="rounded-xl border border-glyph/30 bg-glyph/[0.05] p-4">
                <span className="eyebrow !text-white/55">
                  <span className="h-1 w-1 rounded-full bg-glyph" />
                  policy_commitment — SHA-256, computed in your browser
                </span>
                <div className="mt-2.5">
                  {commitment ? (
                    <CopyHash value={commitment} tone="glyph" />
                  ) : (
                    <span className="block h-7 w-full animate-pulse rounded bg-white/[0.04]" />
                  )}
                </div>
                <p className="mt-2.5 text-2xs leading-relaxed text-white/40">
                  Same canonical serializer as the Rust SDK, the TEE worker and the on-chain
                  verifier. This is the value that would be registered on-chain for your agent.
                </p>
              </div>

              {/* probes */}
              <div>
                <span className="eyebrow !text-white/55">
                  <span className="h-1 w-1 rounded-full bg-zk" />
                  test intents against YOUR policy
                  {address && (
                    <span className="ml-1 font-mono text-2xs text-glyph-300">
                      · agent {address.slice(0, 4)}…{address.slice(-4)}
                    </span>
                  )}
                </span>
                <div className="mt-2 grid gap-2">
                  {probes.map((row) => {
                    const allow = row.decision.type === "allow";
                    return (
                      <div
                        key={row.id}
                        className={`flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5 ${
                          allow
                            ? "border-glyph/25 bg-glyph/[0.04]"
                            : "border-deny/25 bg-deny/[0.05]"
                        }`}
                      >
                        <div className="min-w-0">
                          <div className="truncate text-sm text-white/85">{row.label}</div>
                          {!allow && row.decision.type === "deny" && (
                            <div className="truncate font-mono text-2xs text-deny-400">
                              rule {row.decision.code} · {row.decision.rule}
                            </div>
                          )}
                        </div>
                        {allow ? (
                          <Pill tone="glyph" className="shrink-0">
                            ✓ ALLOW
                          </Pill>
                        ) : (
                          <Pill tone="deny" className="shrink-0">
                            ✕ DENY
                          </Pill>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {rawJson && (
                <details className="group">
                  <summary className="cursor-pointer text-2xs text-white/40 hover:text-white/70">
                    raw model output
                  </summary>
                  <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-white/[0.07] bg-ink-950/60 p-3 font-mono text-2xs text-white/55">
                    {rawJson}
                  </pre>
                </details>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 0 1 8-8V0a12 12 0 0 0-12 12h4z" />
    </svg>
  );
}
