"use client";

import { motion, useInView, type Variants } from "framer-motion";
import { useEffect, useRef, useState, type ReactNode } from "react";

// ─── Scroll reveal ────────────────────────────────────────────────────────────

export const fadeUp: Variants = {
  hidden: { opacity: 0, y: 18 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] },
  },
};

export const stagger: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08, delayChildren: 0.05 } },
};

export function Reveal({
  children,
  className,
  delay = 0,
  as = "div",
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
  as?: "div" | "section" | "li" | "header";
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  const MotionTag = motion[as] as typeof motion.div;
  return (
    <MotionTag
      ref={ref}
      className={className}
      initial="hidden"
      animate={inView ? "show" : "hidden"}
      variants={{
        hidden: { opacity: 0, y: 22 },
        show: {
          opacity: 1,
          y: 0,
          transition: { duration: 0.65, ease: [0.16, 1, 0.3, 1], delay },
        },
      }}
    >
      {children}
    </MotionTag>
  );
}

// ─── Section heading ──────────────────────────────────────────────────────────

export function SectionHeading({
  eyebrow,
  title,
  intro,
  align = "left",
}: {
  eyebrow: string;
  title: ReactNode;
  intro?: ReactNode;
  align?: "left" | "center";
}) {
  return (
    <div className={align === "center" ? "mx-auto max-w-2xl text-center" : "max-w-3xl"}>
      <span className="eyebrow">
        <span className="h-1 w-1 rounded-full bg-glyph" />
        {eyebrow}
      </span>
      <h2 className="mt-4 text-balance text-3xl font-semibold tracking-tightest text-white sm:text-4xl">
        {title}
      </h2>
      {intro && (
        <p className="mt-4 text-pretty text-base leading-relaxed text-white/55 sm:text-lg">
          {intro}
        </p>
      )}
    </div>
  );
}

// ─── Pill / badge ─────────────────────────────────────────────────────────────

export function Pill({
  children,
  tone = "neutral",
  className = "",
}: {
  children: ReactNode;
  tone?: "neutral" | "glyph" | "zk" | "deny";
  className?: string;
}) {
  const tones: Record<string, string> = {
    neutral: "border-white/12 bg-white/[0.03] text-white/70",
    glyph: "border-glyph/30 bg-glyph/10 text-glyph-300",
    zk: "border-zk/35 bg-zk/12 text-zk-300",
    deny: "border-deny/35 bg-deny/12 text-deny-400",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-2xs font-medium ${tones[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

// ─── Live indicator ───────────────────────────────────────────────────────────

export function LiveDot({ tone = "glyph" }: { tone?: "glyph" | "amber" }) {
  const color = tone === "glyph" ? "bg-glyph" : "bg-amber-400";
  return (
    <span className="relative flex h-2 w-2">
      <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${color} opacity-60`} />
      <span className={`relative inline-flex h-2 w-2 rounded-full ${color}`} />
    </span>
  );
}

// ─── Copyable hash ────────────────────────────────────────────────────────────

export function CopyHash({
  value,
  label,
  truncate = false,
  tone = "neutral",
}: {
  value: string;
  label?: string;
  truncate?: boolean;
  tone?: "neutral" | "glyph";
}) {
  const [copied, setCopied] = useState(false);
  const shown =
    truncate && value.length > 20
      ? `${value.slice(0, 10)}…${value.slice(-8)}`
      : value;
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        });
      }}
      title="Click to copy"
      className={`group inline-flex max-w-full items-center gap-2 rounded-md border px-2 py-1 text-left transition-colors ${
        tone === "glyph"
          ? "border-glyph/25 bg-glyph/[0.06] hover:border-glyph/45"
          : "border-white/10 bg-white/[0.02] hover:border-white/20"
      }`}
    >
      {label && <span className="text-2xs uppercase tracking-wider text-white/40">{label}</span>}
      <span className={`hash ${tone === "glyph" ? "text-glyph-300" : "text-white/75"}`}>
        {shown}
      </span>
      <span className="text-2xs text-white/35 transition-colors group-hover:text-white/60">
        {copied ? "copied" : "copy"}
      </span>
    </button>
  );
}

// ─── Counter (animate to value when in view) ──────────────────────────────────

export function Counter({
  to,
  suffix = "",
  duration = 1200,
}: {
  to: number;
  suffix?: string;
  duration?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const [val, setVal] = useState(0);

  useEffect(() => {
    if (!inView) return;
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(eased * to));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, to, duration]);

  return (
    <span ref={ref}>
      {val}
      {suffix}
    </span>
  );
}
