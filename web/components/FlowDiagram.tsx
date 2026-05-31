"use client";

import { AnimatePresence, motion, useInView } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { Pill } from "./ui";

type Step = {
  n: number;
  tag: string;
  title: string;
  body: string;
  artifact: string;
  artifactLabel: string;
  tone: "glyph" | "zk" | "neutral";
};

const STEPS: Step[] = [
  {
    n: 1,
    tag: "Agent",
    title: "Build a signed TransactionIntent",
    body: "The agent assembles its desired action — target_program, accounts and data as opaque bytes — and signs it with Ed25519. GLYPH never needs to understand the target program.",
    artifact: "TransactionIntent { target_program, accounts[], data, sig }",
    artifactLabel: "signed intent",
    tone: "neutral",
  },
  {
    n: 2,
    tag: "TEE Worker",
    title: "Evaluate the 9-rule policy inside a TEE",
    body: "A trusted enclave (SGX / Nitro / SEV) runs the declarative policy against the intent → allow or deny, and computes the canonical policy_commitment (SHA-256).",
    artifact: "policy_commitment = d086deb3…0053cb · decision = ALLOW",
    artifactLabel: "attested decision",
    tone: "glyph",
  },
  {
    n: 3,
    tag: "RISC Zero zkVM",
    title: "Prove policy satisfaction in zero-knowledge",
    body: "The decision is re-executed inside the RISC Zero zkVM, producing a STARK that is wrapped to a Groth16 proof over BN254 — succinct enough to verify on-chain.",
    artifact: "STARK → Groth16 (BN254) · journal { tx_hash, commitment }",
    artifactLabel: "succinct proof",
    tone: "zk",
  },
  {
    n: 4,
    tag: "Solana",
    title: "verify_and_execute — proof gates the action",
    body: "verify_and_execute is ix[0]. It runs a real BN254 pairing check, asserts hash(ix[1]) == journal.tx_hash, consumes a nonce PDA — then the runtime executes ix[1]. No proof, no execution.",
    artifact: "pairing ✓ · bind ix[1] ✓ · nonce consumed → execute target",
    artifactLabel: "on-chain enforcement",
    tone: "glyph",
  },
];

const TONE: Record<string, { ring: string; text: string; dot: string; bg: string }> = {
  glyph: {
    ring: "border-glyph/40",
    text: "text-glyph-300",
    dot: "bg-glyph",
    bg: "bg-glyph/[0.06]",
  },
  zk: {
    ring: "border-zk/45",
    text: "text-zk-300",
    dot: "bg-zk",
    bg: "bg-zk/[0.06]",
  },
  neutral: {
    ring: "border-white/25",
    text: "text-white/80",
    dot: "bg-white/60",
    bg: "bg-white/[0.04]",
  },
};

export function FlowDiagram() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });
  const [active, setActive] = useState(0);
  const [autoplay, setAutoplay] = useState(true);

  // Auto-advance once visible, until user interacts.
  useEffect(() => {
    if (!inView || !autoplay) return;
    const id = setInterval(() => {
      setActive((a) => (a + 1) % STEPS.length);
    }, 2600);
    return () => clearInterval(id);
  }, [inView, autoplay]);

  return (
    <div ref={ref}>
      {/* Step rail */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {STEPS.map((s, i) => {
          const t = TONE[s.tone];
          const isActive = i === active;
          const isDone = inView && i < active;
          return (
            <button
              key={s.n}
              onClick={() => {
                setAutoplay(false);
                setActive(i);
              }}
              className={`group relative overflow-hidden rounded-xl border p-3 text-left transition-all ${
                isActive
                  ? `${t.ring} ${t.bg} shadow-card`
                  : "border-white/[0.07] bg-white/[0.01] hover:border-white/20"
              }`}
            >
              <div className="flex items-center justify-between">
                <span
                  className={`grid h-6 w-6 place-items-center rounded-md font-mono text-2xs ${
                    isActive || isDone ? `${t.bg} ${t.text}` : "bg-white/[0.05] text-white/40"
                  }`}
                >
                  {isDone ? "✓" : s.n}
                </span>
                {isActive && (
                  <motion.span
                    layoutId="flow-dot"
                    className={`h-1.5 w-1.5 rounded-full ${t.dot}`}
                  />
                )}
              </div>
              <span
                className={`mt-2 block text-2xs font-medium uppercase tracking-wider ${
                  isActive ? t.text : "text-white/45"
                }`}
              >
                {s.tag}
              </span>
              {/* progress bar */}
              {isActive && autoplay && (
                <motion.span
                  key={active}
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 2.6, ease: "linear" }}
                  className={`absolute bottom-0 left-0 h-0.5 w-full origin-left ${t.dot}`}
                />
              )}
            </button>
          );
        })}
      </div>

      {/* Connector arrows (desktop) */}
      <div className="my-3 hidden items-center justify-between px-10 sm:flex">
        {[0, 1, 2].map((i) => (
          <motion.span
            key={i}
            className="text-white/25"
            animate={{ opacity: active > i ? 1 : 0.25, x: active === i ? [0, 4, 0] : 0 }}
            transition={{ repeat: active === i ? Infinity : 0, duration: 1.4 }}
          >
            ▸
          </motion.span>
        ))}
      </div>

      {/* Detail panel */}
      <div className="card mt-3 min-h-[240px] overflow-hidden p-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={active}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
          >
            {(() => {
              const s = STEPS[active];
              const t = TONE[s.tone];
              return (
                <>
                  <div className="flex items-center gap-3">
                    <Pill tone={s.tone}>
                      Step {s.n} · {s.tag}
                    </Pill>
                  </div>
                  <h3 className="mt-3 text-xl font-semibold tracking-tight text-white sm:text-2xl">
                    {s.title}
                  </h3>
                  <p className="mt-2 max-w-2xl text-sm leading-relaxed text-white/55 sm:text-base">
                    {s.body}
                  </p>
                  <div className={`mt-5 rounded-lg border ${t.ring} ${t.bg} p-3`}>
                    <span className="text-2xs uppercase tracking-wider text-white/40">
                      {s.artifactLabel}
                    </span>
                    <p className={`mt-1 font-mono text-xs ${t.text} break-all`}>{s.artifact}</p>
                  </div>
                </>
              );
            })()}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
