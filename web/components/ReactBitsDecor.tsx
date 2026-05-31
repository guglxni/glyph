"use client";

import { motion, useInView, useReducedMotion } from "framer-motion";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

const SCRAMBLE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>[]{}#$";

export function ReactBitsBackdrop({ intensity = "hero" }: { intensity?: "hero" | "section" }) {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      <div
        className={`absolute inset-0 rb-dot-grid ${
          intensity === "hero" ? "opacity-55" : "opacity-30"
        }`}
      />
      <div className="absolute inset-0 rb-noise opacity-[0.045]" />
      <div className="absolute left-1/2 top-0 h-72 w-[min(58rem,90vw)] -translate-x-1/2 rounded-full bg-[radial-gradient(circle,rgba(20,241,149,0.16),rgba(138,43,226,0.08)_42%,transparent_72%)] blur-3xl motion-safe:animate-rb-aurora" />
      <div className="absolute inset-x-0 bottom-0 h-44 bg-gradient-to-b from-transparent to-ink-950" />
    </div>
  );
}

export function GradientText({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`rb-gradient-text ${className}`}>{children}</span>;
}

export function BlurWords({
  text,
  className = "",
  delay = 0.035,
}: {
  text: string;
  className?: string;
  delay?: number;
}) {
  const reduceMotion = useReducedMotion();
  const words = useMemo(() => text.split(" "), [text]);
  return (
    <span className={`inline-flex flex-wrap justify-center gap-x-[0.25em] ${className}`}>
      {words.map((word, i) => (
        <motion.span
          key={`${word}-${i}`}
          initial={reduceMotion ? false : { opacity: 0, y: 12, filter: "blur(10px)" }}
          animate={reduceMotion ? undefined : { opacity: 1, y: 0, filter: "blur(0px)" }}
          transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1], delay: i * delay }}
          className="inline-block"
        >
          {word}
        </motion.span>
      ))}
    </span>
  );
}

export function DecryptedText({
  text,
  className = "",
  speed = 34,
}: {
  text: string;
  className?: string;
  speed?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  const reduceMotion = useReducedMotion();
  const [display, setDisplay] = useState(text);

  useEffect(() => {
    if (!inView || reduceMotion) {
      setDisplay(text);
      return;
    }
    let frame = 0;
    const maxFrames = Math.max(10, text.length + 6);
    const timer = window.setInterval(() => {
      frame += 1;
      setDisplay(
        text
          .split("")
          .map((char, i) => {
            if (char === " " || i < frame - 4) return char;
            return SCRAMBLE_CHARS[(i + frame) % SCRAMBLE_CHARS.length];
          })
          .join("")
      );
      if (frame > maxFrames) {
        window.clearInterval(timer);
        setDisplay(text);
      }
    }, speed);
    return () => window.clearInterval(timer);
  }, [inView, reduceMotion, speed, text]);

  return (
    <span ref={ref} className={className} aria-label={text}>
      <span aria-hidden>{display}</span>
    </span>
  );
}

export function SpotlightCard({
  children,
  className = "",
  spotlight = "rgba(20, 241, 149, 0.18)",
}: {
  children: ReactNode;
  className?: string;
  spotlight?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: 50, y: 50 });
  const [active, setActive] = useState(false);

  return (
    <div
      ref={ref}
      onMouseMove={(e) => {
        const rect = ref.current?.getBoundingClientRect();
        if (!rect) return;
        setPos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
      }}
      onMouseEnter={() => setActive(true)}
      onMouseLeave={() => setActive(false)}
      onFocus={() => setActive(true)}
      onBlur={() => setActive(false)}
      className={`rb-spotlight card relative overflow-hidden ${className}`}
      style={
        {
          "--spotlight-x": `${pos.x}px`,
          "--spotlight-y": `${pos.y}px`,
          "--spotlight-opacity": active ? 1 : 0,
          "--spotlight-color": spotlight,
        } as React.CSSProperties
      }
    >
      {children}
    </div>
  );
}

export function TiltCard({ children, className = "" }: { children: ReactNode; className?: string }) {
  const reduceMotion = useReducedMotion();
  return (
    <motion.div
      whileHover={reduceMotion ? undefined : { y: -4, rotateX: 1.5, rotateY: -1.5 }}
      transition={{ duration: 0.15, ease: "easeOut" }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function FeatureMatrix() {
  const features = [
    "BYOK LLM proxy",
    "Schema guard",
    "9-rule DSL",
    "Policy TOML",
    "Wallet identity",
    "Agent registry",
    "Ed25519 delegation",
    "Intent hashing",
    "Tx binding",
    "Nonce PDA",
    "TEE attestation",
    "Policy commitment",
    "RISC Zero guest",
    "Groth16 wrap",
    "BN254 pairing",
    "Journal binding",
    "VK PDA",
    "VK rotation",
    "Devnet deploy",
    "Live RPC reads",
    "Lean proofs",
    "Rust parity",
    "TS parity",
    "CI proof run",
    "x86 prover",
    "Artifact upload",
    "Audit trail",
    "Daily volume",
    "Time window",
    "Program allowlist",
  ];

  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
      {features.map((feature, i) => (
        <TiltCard key={feature}>
          <SpotlightCard className="group h-full p-3.5" spotlight={i % 3 === 1 ? "rgba(138,43,226,0.20)" : "rgba(20,241,149,0.16)"}>
            <div className="relative flex items-center gap-3">
              <span className="grid size-7 shrink-0 place-items-center rounded-md border border-white/10 bg-white/[0.035] font-mono text-[0.68rem] text-white/45">
                {(i + 1).toString().padStart(2, "0")}
              </span>
              <span className="text-sm text-white/72 transition-colors group-hover:text-white">
                {feature}
              </span>
            </div>
          </SpotlightCard>
        </TiltCard>
      ))}
    </div>
  );
}

export function SignalRail() {
  const items = ["intent", "policy", "commitment", "journal", "proof", "pairing", "execute"];
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.018] px-3 py-2">
      <div className="rb-rail flex w-max items-center gap-2">
        {[...items, ...items].map((item, i) => (
          <span key={`${item}-${i}`} className="font-mono text-2xs uppercase tracking-[0.18em] text-white/38">
            {item}
            <span className="mx-2 text-glyph/45">/</span>
          </span>
        ))}
      </div>
    </div>
  );
}
