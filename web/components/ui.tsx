import React from "react";

export function Mono({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <span className={`font-mono ${className}`}>{children}</span>;
}

export function Hash({ value, className = "" }: { value: string; className?: string }) {
  return (
    <span
      className={`font-mono text-[12px] break-all text-sub ${className}`}
      title={value}
    >
      {value}
    </span>
  );
}

export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-3 font-mono text-[11px] uppercase tracking-[0.22em] text-faint">
      {children}
    </div>
  );
}

export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-xl border border-line bg-panel/70 backdrop-blur ${className}`}
    >
      {children}
    </div>
  );
}

export function ExtLink({
  href,
  children,
  className = "",
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className={`inline-flex items-center gap-1.5 text-accent transition-colors hover:text-ink ${className}`}
    >
      {children}
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" className="opacity-70">
        <path
          d="M7 17L17 7M17 7H8M17 7v9"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </a>
  );
}
