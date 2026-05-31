"use client";

import { motion } from "framer-motion";
import { EXPLORER_PROGRAM, GITHUB_URL } from "@/lib/data";
import { BlurWords, DecryptedText, GradientText, ReactBitsBackdrop, SignalRail, SpotlightCard } from "./ReactBitsDecor";
import { LiveDot } from "./ui";

export function Hero() {
  return (
    <section id="top" className="relative overflow-hidden pt-32 sm:pt-40">
      {/* ambient background */}
      <ReactBitsBackdrop />

      <div className="container-glyph relative">
        <motion.a
          href={EXPLORER_PROGRAM}
          target="_blank"
          rel="noreferrer"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="mx-auto flex w-fit items-center gap-2.5 rounded-full border border-glyph/25 bg-glyph/[0.06] px-3.5 py-1.5 text-2xs font-medium text-glyph-300 transition-colors hover:border-glyph/40"
        >
          <LiveDot />
          <DecryptedText text="Live on Solana devnet — real BN254 verifier deployed" />
          <span className="text-glyph/60">↗</span>
        </motion.a>

        <motion.h1
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1], delay: 0.06 }}
          className="mx-auto mt-7 max-w-4xl text-balance text-center text-4xl font-semibold leading-[1.05] tracking-tightest text-white sm:text-6xl"
        >
          <BlurWords text="The" />{" "}
          <GradientText>verifiable guardrail layer</GradientText>{" "}
          <BlurWords text="for autonomous AI agents on Solana" />
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1], delay: 0.14 }}
          className="mx-auto mt-6 max-w-2xl text-pretty text-center text-base leading-relaxed text-white/55 sm:text-lg"
        >
          One policy. Any program. An agent&rsquo;s action is checked against a declarative
          policy, that decision is proven in zero-knowledge, and the proof is verified
          on-chain&nbsp;&mdash;&nbsp;<span className="text-white/80">before the action executes.</span>
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1], delay: 0.22 }}
          className="mt-9 flex flex-wrap items-center justify-center gap-3"
        >
          <a href="#console" className="btn-primary">
            Try the demo
            <span aria-hidden>↓</span>
          </a>
          <a href={EXPLORER_PROGRAM} target="_blank" rel="noreferrer" className="btn-ghost">
            View on Explorer ↗
          </a>
          <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="btn-ghost">
            GitHub ↗
          </a>
        </motion.div>

        {/* horizontal vs vertical strip */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1], delay: 0.32 }}
          className="mx-auto mt-16 max-w-3xl"
        >
          <SpotlightCard className="flex flex-col items-stretch gap-px bg-white/[0.02] sm:flex-row">
            {[
              { k: "Same proofs", v: "one RISC Zero circuit" },
              { k: "Same policy engine", v: "one declarative DSL" },
              { k: "Different programs", v: "System · Token · Memo · …" },
            ].map((c, i) => (
              <div
                key={i}
                className="flex-1 border-white/[0.06] px-5 py-4 text-center sm:border-l first:sm:border-l-0"
              >
                <div className="text-sm font-medium text-white/85">{c.k}</div>
                <div className="mt-0.5 font-mono text-2xs text-white/45">{c.v}</div>
              </div>
            ))}
          </SpotlightCard>
          <div className="mt-3">
            <SignalRail />
          </div>
        </motion.div>
      </div>
    </section>
  );
}
