import { FlowDiagram } from "@/components/FlowDiagram";
import { Hero } from "@/components/Hero";
import { Logo, Nav } from "@/components/Nav";
import { OnChainStatus } from "@/components/OnChainStatus";
import { PolicyCompiler } from "@/components/PolicyCompiler";
import { PolicyConsole } from "@/components/PolicyConsole";
import {
  FeatureMatrix,
  GradientText,
  ReactBitsBackdrop,
  SignalRail,
  SpotlightCard,
  TiltCard,
} from "@/components/ReactBitsDecor";
import { WalletProvider } from "@/components/WalletProvider";
import { Counter, Pill, Reveal, SectionHeading } from "@/components/ui";
import {
  EXPLORER_DEPLOY_TX,
  GITHUB_URL,
  PROGRAM_ID,
  PROVER,
  VK_HASH,
} from "@/lib/data";

// ─── On-chain confirmed devnet transactions ───────────────────────────────────
const TXS: { label: string; sig: string }[] = [
  {
    label: "deploy",
    sig: "2pidHYhjZxPmdw6tZnX4PW9j6yokU2HNvt3KAngu9GCt7GDe1j1vT2UVGCAY4RCoDLiGDrG6hHo4SF2KzPdE1tv",
  },
  {
    label: "initialize",
    sig: "4fYZ5F7ouvzAwNdPWiXoNgpQ8UHfrqA8DNG3p9AeUMvFcqMwo3upxTAygruCEwdpJBkKrMj8CvzLj75ZLJQ3AhfX",
  },
  {
    label: "initialize_verifier_vk",
    sig: "5AL4qKJhAHjnLtGRNDaEvubZNnx2hcmJBMMwcbo3h1YC2SeHvxXYQfM1mTrPHaCGGGpKenL1fc1Wg1qmA6eHhMzh",
  },
  {
    label: "seed_vk",
    sig: "5hJo9JyjdEKUqxwgFEusmxVVh9tR1kebJiRhwuKgb3zxXhPFUMV4uc6JxmAhJMrTT5ULiFMvxBYsRAzPEaK9gAvk",
  },
  {
    label: "initialize_vk_multisig",
    sig: "BxwF1fFFdfXPRx2tis9uXgPuXDLULdbERuBtR18e3Y6jcCAzBm7SJU2Z5Vph8wGjmkCzbRJ7HxaG9GBRhgrWuDC",
  },
  {
    label: "register_agent",
    sig: "2Nfa9aZc1Uv5DQg3qz4TY68dTFXWGqMuYB2NPf52XZhQepBsLM3Mecg4bKMEoGvWQdSc6JCMDDqXR17AvWKwDBLN",
  },
];

const explorerTx = (sig: string) =>
  `https://explorer.solana.com/tx/${sig}?cluster=devnet`;

// ─── Trust stack ──────────────────────────────────────────────────────────────
const LAYERS = [
  {
    n: "01",
    name: "Hardware",
    sub: "Trusted Execution Environment",
    detail: "SGX · Nitro · SEV",
    body: "Policy evaluation runs inside a hardware enclave that attests to the exact code it executed. The host OS can't tamper with the decision.",
    tone: "neutral" as const,
  },
  {
    n: "02",
    name: "Cryptography",
    sub: "RISC Zero zkVM",
    detail: "STARK → Groth16",
    body: "The decision is re-proven in a zero-knowledge VM. The resulting succinct proof attests that the policy was satisfied — without revealing the policy internals.",
    tone: "zk" as const,
  },
  {
    n: "03",
    name: "Consensus",
    sub: "On-chain Groth16 verifier",
    detail: "real BN254 pairing",
    body: "Solana itself verifies the proof with a real BN254 pairing check before the action executes. Enforcement lives in consensus, not in a promise.",
    tone: "glyph" as const,
  },
];

// ─── Competitive framing ──────────────────────────────────────────────────────
const COMPARE = [
  { others: "Build an agent", glyph: "Make all agents safe" },
  { others: "Vertical app, one protocol", glyph: "Horizontal guardrail, any protocol" },
  { others: "Trust the bot", glyph: "Cryptographic proof of compliance" },
  { others: "Off-chain promises", glyph: "On-chain enforcement" },
];

// ─── Metrics band ─────────────────────────────────────────────────────────────
const METRICS: { value: number; suffix?: string; label: string; pre?: string }[] = [
  { value: 114, label: "passing tests" },
  { value: 19, label: "Lean 4 theorems · 0 sorry" },
  { value: 9, label: "rule policy DSL" },
  { value: 6, label: "job CI pipeline" },
];

const THESIS_PILLARS = [
  {
    k: "Delegation",
    v: "human intent binds agent authority to a concrete policy commitment",
  },
  {
    k: "Privacy",
    v: "policy evaluation can remain inside a TEE while exposing only commitments",
  },
  {
    k: "Verifiability",
    v: "RISC Zero execution produces a journal that is proven and checked on-chain",
  },
  {
    k: "Auditability",
    v: "Solana records the verifier state, policy commitment, and replay-safe action trail",
  },
];

export default function Page() {
  return (
    <WalletProvider>
      <Nav />
      <main>
        <Hero />

        {/* ── Research implementation ── */}
        <section className="relative border-y border-white/[0.05] bg-ink-900/45 py-20 sm:py-24">
          <ReactBitsBackdrop intensity="section" />
          <div className="container-glyph relative">
            <Reveal>
              <div className="grid gap-10 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] lg:items-end">
                <div>
                  <span className="eyebrow">
                    <span className="h-1 w-1 rounded-full bg-zk" />
                    Implementation of arXiv:2509.00085v1
                  </span>
                  <h2 className="mt-4 max-w-3xl text-balance text-3xl font-semibold tracking-tightest text-white sm:text-5xl">
                    The research paper, made executable.
                  </h2>
                  <p className="mt-4 max-w-2xl text-pretty text-base leading-relaxed text-white/58 sm:text-lg">
                    GLYPH is the working Solana implementation of{" "}
                    <span className="text-white/85">
                      Private, Verifiable, and Auditable AI Systems
                    </span>{" "}
                    from the bundled research source{" "}
                    <span className="font-mono text-zk-200">arXiv-2509.00085v1/</span>.
                    It turns the thesis stack into a live path: authenticated delegation,
                    BYOK policy compilation, TEE-side checks, RISC Zero proofs, and Groth16
                    enforcement before agent actions execute.
                  </p>
                  <div className="mt-6 flex flex-wrap gap-3">
                    <Pill tone="zk">paper source bundled in repo</Pill>
                    <Pill tone="glyph">live Solana implementation</Pill>
                    <Pill tone="neutral">agent-agnostic guardrails</Pill>
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  {THESIS_PILLARS.map((item, i) => (
                    <Reveal key={item.k} delay={i * 0.05}>
                      <SpotlightCard className="h-full p-5">
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-2xs text-white/35">
                            0{i + 1}
                          </span>
                          <span className="h-1.5 w-1.5 rounded-full bg-glyph" />
                        </div>
                        <h3 className="mt-4 text-base font-semibold text-white">{item.k}</h3>
                        <p className="mt-2 text-sm leading-relaxed text-white/52">{item.v}</p>
                      </SpotlightCard>
                    </Reveal>
                  ))}
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── Problem ── */}
        <section className="relative py-24 sm:py-32">
          <div className="container-glyph">
            <Reveal>
              <SectionHeading
                eyebrow="The problem"
                title={
                  <>
                    Agents are moving real value with{" "}
                    <span className="text-deny-400">no enforced limits</span> and{" "}
                    <span className="text-deny-400">no proof</span> they stayed in bounds.
                  </>
                }
                intro="Autonomous agents now hold keys and sign transactions on Solana. Today the only thing standing between an agent and your funds is the agent's own code — a trust black box. If it misbehaves, gets jailbroken, or is simply wrong, there is no on-chain limit and no evidence of what it was allowed to do."
              />
            </Reveal>

            <div className="mt-12 grid gap-4 md:grid-cols-3">
              {[
                {
                  t: "No enforced limits",
                  b: "Spend caps, allowlists and rate limits live in off-chain code an attacker can bypass. The chain accepts whatever the key signs.",
                },
                {
                  t: "No proof of compliance",
                  b: "Even a well-behaved agent can't prove it stayed within policy. There is nothing auditable to point to after the fact.",
                },
                {
                  t: "Trust doesn't compose",
                  b: "Every protocol re-invents its own bot safety. Nothing is portable across perps, prediction markets, or privacy apps.",
                },
              ].map((c, i) => (
                <Reveal key={c.t} delay={i * 0.08}>
                  <div className="card h-full p-6">
                    <span className="grid h-9 w-9 place-items-center rounded-lg bg-deny/10 text-deny-400">
                      !
                    </span>
                    <h3 className="mt-4 text-base font-semibold text-white">{c.t}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-white/55">{c.b}</p>
                  </div>
                </Reveal>
              ))}
            </div>

            <Reveal delay={0.1}>
              <div className="mt-10 rounded-2xl border border-glyph/20 bg-glyph/[0.04] p-6 sm:p-8">
                <p className="text-pretty text-lg font-medium leading-relaxed text-white sm:text-xl">
                  GLYPH is a{" "}
                  <span className="text-glyph-300">horizontal trust layer</span>. It doesn&rsquo;t
                  compete with perps, prediction or privacy protocols&nbsp;&mdash;&nbsp;it makes
                  agents safe across all of them.
                </p>
                <p className="mt-3 font-mono text-sm text-white/50">
                  Same proofs, same policy engine — different target programs.
                </p>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── E2E flow ── */}
        <section id="flow" className="relative scroll-mt-20 border-y border-white/[0.05] bg-ink-900/40 py-24 sm:py-32">
          <div aria-hidden className="pointer-events-none absolute inset-0 bg-dots opacity-30" />
          <div className="container-glyph relative">
            <Reveal>
              <SectionHeading
                eyebrow="End-to-end"
                title="From intent to on-chain enforcement, in four steps"
                intro="Walk the full pipeline. Each step produces a cryptographic artifact the next step consumes — culminating in a proof Solana verifies before anything executes."
              />
            </Reveal>
            <Reveal delay={0.1}>
              <div className="mt-12">
                <FlowDiagram />
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── React Bits visual layer ── */}
        <section className="relative overflow-hidden border-y border-white/[0.05] py-24 sm:py-32">
          <ReactBitsBackdrop intensity="section" />
          <div className="container-glyph relative">
            <Reveal>
              <SectionHeading
                eyebrow="Live system surface"
                title={
                  <>
                    <GradientText>Thirty moving parts</GradientText>, one enforceable path
                  </>
                }
                intro="The demo surface mirrors the product architecture: identity, policy compilation, deterministic hashing, ZK proving, and on-chain enforcement are visible as one connected system."
              />
            </Reveal>
            <Reveal delay={0.08}>
              <div className="mt-8">
                <SignalRail />
              </div>
            </Reveal>
            <Reveal delay={0.12}>
              <div className="mt-8">
                <FeatureMatrix />
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── NL → Policy compiler (live centerpiece) ── */}
        <section
          id="compiler"
          className="relative scroll-mt-20 border-y border-white/[0.05] bg-gradient-to-b from-glyph/[0.03] to-transparent py-24 sm:py-32"
        >
          <div aria-hidden className="pointer-events-none absolute inset-0">
            <div className="absolute left-1/2 top-0 h-[260px] w-[680px] -translate-x-1/2 rounded-full bg-glyph/[0.06] blur-[130px]" />
          </div>
          <div className="container-glyph relative">
            <Reveal>
              <SectionHeading
                eyebrow="Live · bring your own LLM"
                title={
                  <>
                    Author a policy in <GradientText>plain English</GradientText>
                  </>
                }
                intro="GLYPH's natural-language → policy DSL compiler, live. Describe what your agent may do; your own LLM (any OpenAI-compatible provider — OpenAI, Anthropic, Gemini, Groq, OpenRouter, xAI, Ollama, LM Studio, or a self-hosted LiteLLM proxy) compiles it to the canonical 9-rule policy. A deterministic schema guard clamps the output, then the real policy_commitment is computed in your browser — byte-for-byte identical to the Rust SDK — and you test intents against it. Connect a wallet to bind the policy to your own agent identity."
              />
            </Reveal>
            <Reveal delay={0.1}>
              <div className="mt-12">
                <PolicyCompiler />
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── Interactive console ── */}
        <section id="console" className="relative scroll-mt-20 py-24 sm:py-32">
          <div className="container-glyph">
            <Reveal>
              <SectionHeading
                eyebrow="Interactive demo"
                title={
                  <>
                    One policy, <GradientText>any program</GradientText>
                  </>
                }
                intro="Pick an agent action. GLYPH evaluates it against a single declarative policy and computes the canonical policy_commitment — live, in your browser, byte-for-byte identical to the Rust SDK, the TEE worker and the on-chain verifier. Three different programs, one identical commitment, and a correctly-denied fourth."
              />
            </Reveal>
            <Reveal delay={0.1}>
              <div className="mt-12">
                <PolicyConsole />
              </div>
            </Reveal>
            <Reveal delay={0.15}>
              <p className="mt-6 max-w-3xl text-sm leading-relaxed text-white/45">
                <span className="text-white/70">Program-agnostic by construction.</span> Intents
                carry target_program, accounts and data as opaque bytes. The allowlist is a
                per-agent policy field — never hardcoded — so the same engine guards any program
                without code changes.
              </p>
            </Reveal>
          </div>
        </section>

        {/* ── On-chain proof ── */}
        <section id="onchain" className="relative scroll-mt-20 border-y border-white/[0.05] bg-ink-900/40 py-24 sm:py-32">
          <div className="container-glyph">
            <Reveal>
              <SectionHeading
                eyebrow="Live on-chain"
                title="Real infrastructure, deployed to devnet"
                intro="These accounts are queried live over the public devnet RPC on page load — not screenshots. The verifying key is a real seeded Groth16 VK, and every initialization transaction is confirmed on-chain."
              />
            </Reveal>

            <div className="mt-12 grid gap-6 lg:grid-cols-[1fr_minmax(0,0.85fr)]">
              <Reveal>
                <OnChainStatus />
              </Reveal>

              <Reveal delay={0.08}>
                <div className="card h-full p-6">
                  <span className="eyebrow">
                    <span className="h-1 w-1 rounded-full bg-glyph" />
                    Confirmed devnet transactions
                  </span>
                  <div className="mt-4 grid gap-2">
                    {TXS.map((tx) => (
                      <a
                        key={tx.sig}
                        href={explorerTx(tx.sig)}
                        target="_blank"
                        rel="noreferrer"
                        className="group flex items-center justify-between gap-3 rounded-lg border border-white/[0.06] bg-white/[0.015] px-3 py-2.5 transition-colors hover:border-glyph/30 hover:bg-glyph/[0.04]"
                      >
                        <span className="font-mono text-xs text-white/80 group-hover:text-glyph-300">
                          {tx.label}
                        </span>
                        <span className="font-mono text-2xs text-white/35 group-hover:text-white/60">
                          {tx.sig.slice(0, 8)}…{tx.sig.slice(-6)} ↗
                        </span>
                      </a>
                    ))}
                  </div>

                  <div className="mt-5 space-y-2 border-t border-white/[0.06] pt-4 font-mono text-2xs">
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-white/40">program</span>
                      <span className="text-right text-white/70">{PROGRAM_ID.slice(0, 16)}…</span>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-white/40">vk_hash</span>
                      <span className="text-right text-white/70">{VK_HASH.slice(0, 16)}…</span>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-white/40">prover</span>
                      <span className="text-right text-white/70">{PROVER}</span>
                    </div>
                  </div>
                </div>
              </Reveal>
            </div>

            {/* honesty note */}
            <Reveal delay={0.1}>
              <div className="mt-6 flex flex-col gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/[0.04] p-5 sm:flex-row sm:items-start">
                <Pill tone="neutral" className="shrink-0 border-amber-400/30 text-amber-300">
                  honest status
                </Pill>
                <p className="text-sm leading-relaxed text-white/60">
                  The final <span className="font-mono text-amber-200">verify_and_execute</span>{" "}
                  step requires a Groth16 proof generated on x86 (Apple Silicon can&rsquo;t produce
                  it locally). That step is CI-generated and currently pending — we don&rsquo;t
                  claim the full round-trip has executed on-chain. Everything else shown here is
                  live and real.
                  <a
                    href={EXPLORER_DEPLOY_TX}
                    target="_blank"
                    rel="noreferrer"
                    className="ml-2 text-glyph-300 hover:underline"
                  >
                    See the deploy tx ↗
                  </a>
                </p>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── Trust stack ── */}
        <section id="trust" className="relative scroll-mt-20 py-24 sm:py-32">
          <div className="container-glyph">
            <Reveal>
              <SectionHeading
                eyebrow="Defense in depth"
                title="Three independent layers of trust"
                intro="GLYPH does not ask you to trust one thing. An attacker must defeat hardware attestation, a zero-knowledge proof, and on-chain consensus — all three — to push a non-compliant action."
              />
            </Reveal>

            <div className="mt-12 grid gap-4 lg:grid-cols-3">
              {LAYERS.map((l, i) => {
                const tone =
                  l.tone === "glyph"
                    ? { ring: "hover:border-glyph/40", text: "text-glyph-300", bg: "bg-glyph/10" }
                    : l.tone === "zk"
                      ? { ring: "hover:border-zk/45", text: "text-zk-300", bg: "bg-zk/12" }
                      : { ring: "hover:border-white/25", text: "text-white/80", bg: "bg-white/[0.06]" };
                return (
                  <Reveal key={l.n} delay={i * 0.08}>
                    <TiltCard className="h-full">
                      <SpotlightCard className={`group h-full p-6 transition-colors ${tone.ring}`}>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-2xs text-white/35">{l.n}</span>
                        <span className={`rounded-full ${tone.bg} px-2.5 py-1 font-mono text-2xs ${tone.text}`}>
                          {l.detail}
                        </span>
                      </div>
                      <h3 className={`mt-4 text-lg font-semibold ${tone.text}`}>{l.name}</h3>
                      <p className="mt-0.5 text-2xs uppercase tracking-wider text-white/40">{l.sub}</p>
                      <p className="mt-3 text-sm leading-relaxed text-white/55">{l.body}</p>
                      </SpotlightCard>
                    </TiltCard>
                  </Reveal>
                );
              })}
            </div>
          </div>
        </section>

        {/* ── Competitive framing ── */}
        <section className="relative border-y border-white/[0.05] bg-ink-900/40 py-24 sm:py-32">
          <div className="container-glyph">
            <Reveal>
              <SectionHeading
                eyebrow="Why horizontal beats vertical"
                title="A vertical bot competes with 100 bots. A trust layer compounds with the ecosystem."
                intro="Every new agent and every new program is a user of GLYPH — not a competitor. Value grows with the network instead of fighting it."
              />
            </Reveal>

            <Reveal delay={0.1}>
              <div className="card mt-12 overflow-hidden">
                <div className="grid grid-cols-2 border-b border-white/[0.07] text-sm font-medium">
                  <div className="px-5 py-4 text-white/45">Other approaches</div>
                  <div className="px-5 py-4 text-glyph-300">GLYPH</div>
                </div>
                {COMPARE.map((row, i) => (
                  <div
                    key={i}
                    className="grid grid-cols-2 border-b border-white/[0.05] last:border-0"
                  >
                    <div className="flex items-center gap-2 px-5 py-4 text-sm text-white/50">
                      <span className="text-deny-400/70">✕</span>
                      {row.others}
                    </div>
                    <div className="flex items-center gap-2 border-l border-white/[0.05] bg-glyph/[0.02] px-5 py-4 text-sm text-white/85">
                      <span className="text-glyph">✓</span>
                      {row.glyph}
                    </div>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── Research credibility ── */}
        <section id="research" className="relative scroll-mt-20 py-24 sm:py-32">
          <div className="container-glyph">
            <div className="grid gap-12 lg:grid-cols-[1fr_minmax(0,0.9fr)] lg:items-center">
              <Reveal>
                <span className="eyebrow">
                  <span className="h-1 w-1 rounded-full bg-zk" />
                  Research credibility
                </span>
                <h2 className="mt-4 text-balance text-3xl font-semibold tracking-tightest text-white sm:text-4xl">
                  arXiv:2509.00085v1, shipped as live Solana infrastructure
                </h2>
                <p className="mt-4 text-base leading-relaxed text-white/55 sm:text-lg">
                  GLYPH implements the layered accountability architecture from Tobin South&rsquo;s
                  MIT PhD dissertation,{" "}
                  <span className="text-white/80">
                    &ldquo;Private, Verifiable, and Auditable AI Systems.&rdquo;
                  </span>{" "}
                  The repository includes the full paper source at{" "}
                  <span className="font-mono text-zk-200">arXiv-2509.00085v1/</span>, and this
                  interface is the implementation layer: natural-language scope, authenticated
                  delegation, confidential enforcement, succinct proof, and auditable on-chain
                  execution.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  <a
                    href="https://arxiv.org/abs/2509.00085"
                    target="_blank"
                    rel="noreferrer"
                    className="btn-ghost"
                  >
                    arXiv:2509.00085 ↗
                  </a>
                  <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="btn-ghost">
                    Read the source ↗
                  </a>
                </div>
              </Reveal>

              <Reveal delay={0.1}>
                <div className="card relative overflow-hidden p-6">
                  <div aria-hidden className="absolute -right-16 -top-16 h-48 w-48 rounded-full bg-zk/15 blur-3xl" />
                  <div className="relative space-y-4">
                    {[
                      { k: "Private", v: "policy internals never leave the enclave / proof" },
                      { k: "Verifiable", v: "succinct ZK proof of policy satisfaction" },
                      { k: "Auditable", v: "on-chain commitment + nonce trail per action" },
                    ].map((row) => (
                      <div key={row.k} className="flex items-start gap-3">
                        <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md bg-zk/12 font-mono text-2xs text-zk-300">
                          {row.k[0]}
                        </span>
                        <div>
                          <div className="text-sm font-medium text-white/90">{row.k}</div>
                          <div className="text-2xs text-white/45">{row.v}</div>
                        </div>
                      </div>
                    ))}
                    <div className="border-t border-white/[0.06] pt-4">
                      <p className="font-mono text-2xs text-white/40">
                        19 Lean 4 theorems · 0 sorry — the policy semantics are formally verified.
                      </p>
                    </div>
                  </div>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ── Metrics band ── */}
        <section className="relative border-y border-white/[0.05] bg-gradient-to-b from-glyph/[0.04] to-transparent py-16">
          <div className="container-glyph">
            <Reveal>
              <div className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.03] sm:grid-cols-4">
                {METRICS.map((m) => (
                  <div key={m.label} className="bg-ink-900/60 px-5 py-8 text-center">
                    <div className="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                      <Counter to={m.value} suffix={m.suffix} />
                    </div>
                    <div className="mt-2 text-xs text-white/50">{m.label}</div>
                  </div>
                ))}
              </div>
              <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-center">
                <Pill tone="glyph">real BN254 pairing</Pill>
                <Pill tone="zk">RISC Zero zkVM</Pill>
                <Pill tone="neutral">SGX · Nitro · SEV</Pill>
                <Pill tone="neutral">program-agnostic by construction</Pill>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── CTA ── */}
        <section className="relative py-24 sm:py-32">
          <div aria-hidden className="pointer-events-none absolute inset-0">
            <div className="absolute left-1/2 top-1/2 h-[300px] w-[700px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-glyph/[0.08] blur-[130px]" />
          </div>
          <div className="container-glyph relative text-center">
            <Reveal>
              <h2 className="mx-auto max-w-2xl text-balance text-3xl font-semibold tracking-tightest text-white sm:text-5xl">
                Make every agent safe&nbsp;&mdash;&nbsp;<GradientText>cryptographically.</GradientText>
              </h2>
              <p className="mx-auto mt-5 max-w-xl text-base text-white/55 sm:text-lg">
                One policy. Any program. Cryptographically proven, on-chain.
              </p>
              <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
                <a href="#console" className="btn-primary">Try the demo ↑</a>
                <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="btn-ghost">
                  Explore the code ↗
                </a>
              </div>
            </Reveal>
          </div>
        </section>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-white/[0.06] py-12">
        <div className="container-glyph">
          <div className="flex flex-col items-start justify-between gap-8 sm:flex-row">
            <div className="max-w-sm">
              <div className="flex items-center gap-2.5">
                <Logo className="h-6 w-6" />
                <span className="font-semibold tracking-tight text-white">GLYPH</span>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-white/45">
                The verifiable guardrail layer for autonomous AI agents on Solana. One policy,
                any program, cryptographically proven on-chain.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm">
              <div className="space-y-2">
                <div className="text-2xs uppercase tracking-wider text-white/35">Product</div>
                <FooterLink href="#flow">How it works</FooterLink>
                <FooterLink href="#console">Demo</FooterLink>
                <FooterLink href="#onchain">On-chain</FooterLink>
              </div>
              <div className="space-y-2">
                <div className="text-2xs uppercase tracking-wider text-white/35">Resources</div>
                <FooterLink href={GITHUB_URL} ext>GitHub</FooterLink>
                <FooterLink href="https://arxiv.org/abs/2509.00085" ext>arXiv paper</FooterLink>
                <FooterLink href={`https://explorer.solana.com/address/${PROGRAM_ID}?cluster=devnet`} ext>
                  Explorer
                </FooterLink>
              </div>
            </div>
          </div>
          <div className="mt-10 flex flex-col items-center justify-between gap-3 border-t border-white/[0.06] pt-6 text-2xs text-white/35 sm:flex-row">
            <span>Built for the Solana Fellowship capstone · devnet</span>
            <span className="font-mono">program {PROGRAM_ID.slice(0, 8)}…{PROGRAM_ID.slice(-6)}</span>
          </div>
        </div>
      </footer>
    </WalletProvider>
  );
}

function FooterLink({
  href,
  children,
  ext,
}: {
  href: string;
  children: React.ReactNode;
  ext?: boolean;
}) {
  return (
    <a
      href={href}
      {...(ext ? { target: "_blank", rel: "noreferrer" } : {})}
      className="block text-white/55 transition-colors hover:text-glyph-300"
    >
      {children}
      {ext && <span className="text-white/30"> ↗</span>}
    </a>
  );
}
