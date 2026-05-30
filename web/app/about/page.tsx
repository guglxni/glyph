import Link from "next/link";
import { ExtLink, Card } from "@/components/ui";
import {
  GITHUB_URL,
  PROGRAM_ID,
  EXPLORER_PROGRAM,
  EXPLORER_DEPLOY_TX,
  VK_HASH,
  PROVER,
  EXPECTED_POLICY_COMMITMENT,
} from "@/lib/data";

export const metadata = {
  title: "About — GLYPH",
};

export default function About() {
  return (
    <main className="bg-field min-h-screen">
      <div className="mx-auto max-w-[760px] px-5 pb-24 pt-7 sm:px-7">
        <header className="flex items-center justify-between">
          <Link href="/" className="font-mono text-sm font-semibold text-ink">
            ← GLYPH
          </Link>
          <ExtLink href={GITHUB_URL}>GitHub</ExtLink>
        </header>

        <h1 className="mt-16 text-[32px] font-semibold tracking-tight text-ink">
          What GLYPH is
        </h1>
        <p className="mt-5 text-[15px] leading-relaxed text-sub">
          Autonomous agents increasingly hold keys and sign transactions. The
          open question is not &quot;can the agent act&quot; but &quot;can you
          prove it only acted within bounds you set?&quot; GLYPH answers that
          with cryptography instead of trust.
        </p>
        <p className="mt-4 text-[15px] leading-relaxed text-sub">
          You author a policy — an ordered allow/deny ruleset over target
          programs and constraints. GLYPH commits to it with a SHA-256 hash over
          a canonical encoding. Every action the agent wants to take is hashed
          the same way, evaluated against the policy inside a RISC Zero zkVM, and
          wrapped into a Groth16 proof. An on-chain Solana program verifies that
          proof against a seeded verifying key and only then lets the bound
          target instruction execute.
        </p>

        <h2 className="mt-12 text-[19px] font-semibold tracking-tight text-ink">
          Why &quot;one policy, any program&quot; matters
        </h2>
        <p className="mt-4 text-[15px] leading-relaxed text-sub">
          The commitment is over the policy, not over a specific protocol. The
          same{" "}
          <span className="font-mono text-[12.5px] text-accent">
            {EXPECTED_POLICY_COMMITMENT.slice(0, 16)}…
          </span>{" "}
          guards a System transfer, an SPL Token op, a Memo, and denies a Jupiter
          swap — without changing a single line of the verifier. The guardrail is
          program-agnostic by construction.
        </p>

        <h2 className="mt-12 text-[19px] font-semibold tracking-tight text-ink">
          Live facts
        </h2>
        <Card className="mt-4 p-5">
          <dl className="grid gap-3 font-mono text-[12.5px] sm:grid-cols-[150px_1fr]">
            <dt className="text-faint">cluster</dt>
            <dd className="text-sub">Solana devnet</dd>
            <dt className="text-faint">program id</dt>
            <dd className="break-all text-sub">{PROGRAM_ID}</dd>
            <dt className="text-faint">vk_hash</dt>
            <dd className="break-all text-accent">{VK_HASH}</dd>
            <dt className="text-faint">prover</dt>
            <dd className="text-sub">{PROVER}</dd>
          </dl>
          <div className="mt-4 flex flex-wrap gap-4 text-[13px]">
            <ExtLink href={EXPLORER_PROGRAM}>program</ExtLink>
            <ExtLink href={EXPLORER_DEPLOY_TX}>deploy tx</ExtLink>
            <ExtLink href={GITHUB_URL}>source</ExtLink>
          </div>
        </Card>

        <p className="mt-12 text-[13px] text-faint">
          GLYPH implements a layered-accountability architecture for verifiable
          AI agents, brought on-chain for Solana.
        </p>
      </div>
    </main>
  );
}
