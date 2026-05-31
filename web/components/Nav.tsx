"use client";

import { useEffect, useState } from "react";
import { GITHUB_URL } from "@/lib/data";

const LINKS = [
  { href: "#flow", label: "How it works" },
  { href: "#console", label: "Demo" },
  { href: "#onchain", label: "On-chain" },
  { href: "#trust", label: "Trust stack" },
  { href: "#research", label: "Research" },
];

export function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-all duration-300 ${
        scrolled
          ? "border-b border-white/[0.06] bg-ink-950/80 backdrop-blur-xl"
          : "border-b border-transparent"
      }`}
    >
      <nav className="container-glyph flex h-16 items-center justify-between">
        <a href="#top" className="group flex items-center gap-2.5" aria-label="GLYPH home">
          <Logo />
          <span className="text-[0.95rem] font-semibold tracking-tight text-white">GLYPH</span>
        </a>

        <div className="hidden items-center gap-1 md:flex">
          {LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="rounded-full px-3.5 py-2 text-sm text-white/55 transition-colors hover:bg-white/[0.04] hover:text-white"
            >
              {l.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="hidden rounded-full border border-white/12 bg-white/[0.02] px-3.5 py-2 text-sm text-white/80 transition-colors hover:border-white/25 hover:bg-white/[0.06] sm:inline-flex"
          >
            GitHub ↗
          </a>
          <a href="#console" className="btn-primary !px-4 !py-2 text-sm">
            Try the demo
          </a>
          <button
            onClick={() => setOpen((o) => !o)}
            className="grid h-9 w-9 place-items-center rounded-full border border-white/12 text-white/70 md:hidden"
            aria-label="Menu"
          >
            {open ? "✕" : "☰"}
          </button>
        </div>
      </nav>

      {open && (
        <div className="border-t border-white/[0.06] bg-ink-950/95 backdrop-blur-xl md:hidden">
          <div className="container-glyph flex flex-col py-3">
            {LINKS.map((l) => (
              <a
                key={l.href}
                href={l.href}
                onClick={() => setOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm text-white/70 hover:bg-white/[0.04]"
              >
                {l.label}
              </a>
            ))}
          </div>
        </div>
      )}
    </header>
  );
}

export function Logo({ className = "h-7 w-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <defs>
        <linearGradient id="glyph-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#14F195" />
          <stop offset="100%" stopColor="#8A2BE2" />
        </linearGradient>
      </defs>
      <path
        d="M16 4l10.4 6v12L16 28 5.6 22V10L16 4z"
        fill="none"
        stroke="url(#glyph-g)"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="15" r="3.4" fill="url(#glyph-g)" />
    </svg>
  );
}
