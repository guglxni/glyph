import PolicyConsole from "@/components/PolicyConsole";
import OnChainStatus from "@/components/OnChainStatus";
import { Card, ExtLink, SectionLabel } from "@/components/ui";
import {
  EXPLORER_PROGRAM,
  PROGRAM_ID,
  GITHUB_URL,
} from "@/lib/data";
import Link from "next/link";

export default function Home() {
  return (
    <main className="bg-field min-h-screen">
      <div className="mx-auto max-w-page px-5 pb-24 pt-7 sm:px-7">
        {/* nav */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Logo />
            <span className="font-mono text-sm font-semibold tracking-tight text-ink">
              GLYPH
            </span>
          </div>
          <nav className="flex items-center gap-5 text-[13px] text-sub">
            <Link href="/about" className="hover:text-ink">
              About
            </Link>
            <ExtLink href={GITHUB_URL}>GitHub</ExtLink>
          </nav>
        </header>

        {/* ---------- Section A: Hero ---------- */}
        <section className="animate-fadeUp pt-20 sm:pt-28">
          <a
            href={EXPLORER_PROGRAM}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/[0.06] px-3 py-1 text-[12px] text-accent transition-colors hover:border-accent/60"
          >
            <span className="h-1.5 w-1.5 animate-pulseDot rounded-full bg-accent" />
            Live on Solana devnet
            <span className="font-mono text-[11px] text-accent/70">
              {PROGRAM_ID.slice(0, 4)}…{PROGRAM_ID.slice(-4)}
            </span>
          </a>

          <h1 className="mt-6 max-w-3xl text-[34px] font-semibold leading-[1.08] tracking-tight text-ink sm:text-[46px]">
            Verifiable guardrail layer for autonomous agents on Solana.
          </h1>
          <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-sub sm:text-[16px]">
            GLYPH cryptographically binds an AI agent&apos;s allowed actions to a
            policy, proves each action obeys that policy inside a zkVM, and lets
            an on-chain Groth16 verifier gate execution. One policy commitment
            guards <span className="text-ink">any</span> target program —
            System, SPL Token, Memo, Jupiter, or your own.
          </p>

          <div className="mt-7 flex flex-wrap items-center gap-3">
            <a
              href="#console"
              className="rounded-lg bg-accent px-4 py-2.5 text-[13px] font-medium text-bg transition-opacity hover:opacity-90"
            >
              Try the policy console
            </a>
            <ExtLink
              href={EXPLORER_PROGRAM}
              className="rounded-lg border border-line px-4 py-2.5 text-[13px] !text-sub hover:!text-ink"
            >
              View program on explorer
            </ExtLink>
          </div>

          <div className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-4">
            {[
              ["Program-agnostic", "one policy, any program"],
              ["Zero-knowledge", "RISC Zero · Groth16"],
              ["On-chain gated", "ix binds → ix executes"],
              ["Live", "deployed + initialized"],
            ].map(([t, s]) => (
              <div key={t} className="bg-panel px-4 py-4">
                <div className="text-[13px] font-medium text-ink">{t}</div>
                <div className="mt-0.5 text-[11.5px] text-faint">{s}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ---------- Section B: Policy console ---------- */}
        <section id="console" className="scroll-mt-6 pt-24">
          <SectionLabel>Interactive policy console</SectionLabel>
          <h2 className="mb-2 text-[22px] font-semibold tracking-tight text-ink">
            One policy. Four programs. Same commitment.
          </h2>
          <p className="mb-6 max-w-2xl text-[14px] leading-relaxed text-sub">
            Below is the real multi-protocol policy. Pick any intent — the
            commitment, intent hash, tx hash and ALLOW/DENY decision are computed
            live in your browser using the exact canonical encoding from the
            GLYPH SDK.
          </p>
          <PolicyConsole />
        </section>

        {/* ---------- Section C: On-chain proof ---------- */}
        <section className="pt-24">
          <SectionLabel>Live on-chain proof</SectionLabel>
          <h2 className="mb-2 text-[22px] font-semibold tracking-tight text-ink">
            It&apos;s really deployed. Verify it yourself.
          </h2>
          <p className="mb-6 max-w-2xl text-[14px] leading-relaxed text-sub">
            This panel reads devnet directly. No backend, no cache — the accounts
            below are fetched from the public RPC when this page loads.
          </p>
          <OnChainStatus />
        </section>

        {/* ---------- Section D: How it works ---------- */}
        <section className="pt-24">
          <SectionLabel>How it works</SectionLabel>
          <h2 className="mb-2 text-[22px] font-semibold tracking-tight text-ink">
            A three-layer trust stack.
          </h2>
          <p className="mb-6 max-w-2xl text-[14px] leading-relaxed text-sub">
            Each layer narrows what the agent can do and produces evidence the
            next layer checks — ending at an on-chain verifier that gates
            execution.
          </p>

          <div className="grid gap-3 md:grid-cols-3">
            <StackCard
              n="01"
              title="TEE worker"
              tag="attested compute"
              body="The agent's policy + intent are evaluated inside a trusted execution environment. It produces the canonical commitments and prepares the witness for proving."
            />
            <StackCard
              n="02"
              title="RISC Zero zkVM"
              tag="zero-knowledge"
              body="The guest re-derives the policy_commitment, intent_hash and the ALLOW decision, then emits a succinct receipt — wrapped to a Groth16 proof for cheap on-chain verification."
            />
            <StackCard
              n="03"
              title="On-chain verifier"
              tag="Groth16 · Solana"
              body="The program checks the proof against the seeded verifying key and the committed policy. Only if it verifies does the bound target instruction get to run."
            />
          </div>

          <Card className="mt-3 p-5">
            <div className="font-mono text-[11px] uppercase tracking-widest text-faint">
              transaction binding
            </div>
            <div className="mt-3 grid items-center gap-3 sm:grid-cols-[1fr_auto_1fr]">
              <div className="rounded-lg border border-line bg-panel2 px-4 py-3">
                <div className="font-mono text-[12px] text-accent">
                  ix[0] verify_and_execute
                </div>
                <div className="mt-1 text-[12px] text-sub">
                  verifies the proof + binds the next instruction&apos;s hash to
                  the proven intent.
                </div>
              </div>
              <div className="hidden text-faint sm:block">→</div>
              <div className="rounded-lg border border-line bg-panel2 px-4 py-3">
                <div className="font-mono text-[12px] text-ink">
                  ix[1] target program
                </div>
                <div className="mt-1 text-[12px] text-sub">
                  executes the model action — but only because ix[0] proved it
                  was allowed.
                </div>
              </div>
            </div>
            <p className="mt-4 text-[12px] leading-relaxed text-faint">
              Because ix[0] commits to ix[1]&apos;s exact bytes, an agent
              can&apos;t prove one action and execute another. The guardrail is
              enforced atomically by the runtime, not by trust.
            </p>
          </Card>

          <div className="mt-5 flex flex-wrap gap-4 text-[13px]">
            <ExtLink href={GITHUB_URL}>GitHub repository</ExtLink>
            <ExtLink href={`${GITHUB_URL}/tree/main/docs`}>Documentation</ExtLink>
            <ExtLink href={EXPLORER_PROGRAM}>Program on explorer</ExtLink>
          </div>
        </section>

        {/* footer */}
        <footer className="mt-24 flex flex-wrap items-center justify-between gap-4 border-t border-line pt-7 text-[12px] text-faint">
          <div className="flex items-center gap-2">
            <Logo small />
            <span className="font-mono">GLYPH</span>
            <span>· verifiable agent guardrails on Solana</span>
          </div>
          <div className="font-mono">devnet · {PROGRAM_ID.slice(0, 8)}…</div>
        </footer>
      </div>
    </main>
  );
}

function StackCard({
  n,
  title,
  tag,
  body,
}: {
  n: string;
  title: string;
  tag: string;
  body: string;
}) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[11px] text-faint">{n}</span>
        <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-sub">
          {tag}
        </span>
      </div>
      <div className="mt-3 text-[15px] font-semibold text-ink">{title}</div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-sub">{body}</p>
    </Card>
  );
}

function Logo({ small = false }: { small?: boolean }) {
  const s = small ? 16 : 22;
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" aria-hidden>
      <rect x="3" y="3" width="18" height="18" rx="5" stroke="#3dd68c" strokeWidth="1.6" />
      <path
        d="M8 12.5l2.6 2.6L16 9.5"
        stroke="#3dd68c"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
