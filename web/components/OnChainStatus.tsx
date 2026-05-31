"use client";

import { Connection, PublicKey } from "@solana/web3.js";
import { useEffect, useState } from "react";
import {
  CONFIG_PDA,
  EXPLORER_CONFIG,
  EXPLORER_PROGRAM,
  EXPLORER_VK,
  PROGRAM_ID,
  RPC_URL,
  VK_PDA,
} from "@/lib/data";
import { LiveDot, Pill } from "./ui";

type AcctState = {
  exists: boolean;
  owner?: string;
  lamports?: number;
  dataLen?: number;
  executable?: boolean;
};

type Status = "loading" | "live" | "error";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const BPF_LOADERS = new Set([
  "BPFLoaderUpgradeab1e11111111111111111111111",
  "BPFLoader2111111111111111111111111111111111",
]);

export function OnChainStatus() {
  const [status, setStatus] = useState<Status>("loading");
  const [program, setProgram] = useState<AcctState | null>(null);
  const [config, setConfig] = useState<AcctState | null>(null);
  const [vk, setVk] = useState<AcctState | null>(null);
  const [slot, setSlot] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const conn = new Connection(RPC_URL, "confirmed");
        const [progAi, cfgAi, vkAi, currentSlot] = await Promise.all([
          conn.getAccountInfo(new PublicKey(PROGRAM_ID)),
          conn.getAccountInfo(new PublicKey(CONFIG_PDA)),
          conn.getAccountInfo(new PublicKey(VK_PDA)),
          conn.getSlot("confirmed"),
        ]);
        if (cancelled) return;

        const toState = (ai: Awaited<ReturnType<typeof conn.getAccountInfo>>): AcctState =>
          ai
            ? {
                exists: true,
                owner: ai.owner.toBase58(),
                lamports: ai.lamports,
                dataLen: ai.data.length,
                executable: ai.executable,
              }
            : { exists: false };

        setProgram(toState(progAi));
        setConfig(toState(cfgAi));
        setVk(toState(vkAi));
        setSlot(currentSlot);
        setStatus(progAi && cfgAi && vkAi ? "live" : "error");
      } catch {
        if (!cancelled) setStatus("error");
      }
    };
    run();
    return () => {
      cancelled = true;
    };
  }, []);

  const rows: {
    label: string;
    addr: string;
    href: string;
    state: AcctState | null;
    note: string;
  }[] = [
    {
      label: "glyph-verifier program",
      addr: PROGRAM_ID,
      href: EXPLORER_PROGRAM,
      state: program,
      note: "executable",
    },
    {
      label: "Config PDA",
      addr: CONFIG_PDA,
      href: EXPLORER_CONFIG,
      state: config,
      note: "owned by program",
    },
    {
      label: "Verifying Key PDA",
      addr: VK_PDA,
      href: EXPLORER_VK,
      state: vk,
      note: "real Groth16 VK",
    },
  ];

  return (
    <div className="card overflow-hidden">
      {/* header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-4">
        <div className="flex items-center gap-2.5">
          {status === "loading" ? (
            <>
              <span className="h-2 w-2 animate-pulse-dot rounded-full bg-white/40" />
              <span className="text-sm text-white/60">Querying devnet RPC…</span>
            </>
          ) : status === "live" ? (
            <>
              <LiveDot />
              <span className="text-sm font-medium text-glyph-300">Live on devnet</span>
            </>
          ) : (
            <>
              <span className="h-2 w-2 rounded-full bg-amber-400" />
              <span className="text-sm text-amber-300">RPC unavailable — addresses are real & on-chain</span>
            </>
          )}
        </div>
        {slot != null && (
          <span className="font-mono text-2xs text-white/40">slot {slot.toLocaleString()}</span>
        )}
      </div>

      {/* rows */}
      <div className="divide-y divide-white/[0.05]">
        {rows.map((r) => {
          const ownerOk =
            r.state?.owner === PROGRAM_ID ||
            (r.label.includes("program") &&
              (r.state?.executable || (r.state?.owner && BPF_LOADERS.has(r.state.owner))));
          return (
            <div key={r.addr} className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white/85">{r.label}</span>
                  {r.state?.exists && (
                    <Pill tone="glyph" className="px-2 py-0.5">
                      ● account exists
                    </Pill>
                  )}
                </div>
                <a
                  href={r.href}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1 inline-block font-mono text-2xs text-white/45 transition-colors hover:text-glyph-300"
                >
                  {r.addr.slice(0, 22)}… ↗
                </a>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-2 font-mono text-2xs text-white/50">
                {r.state?.exists ? (
                  <>
                    {r.state.dataLen != null && (
                      <span className="rounded bg-white/[0.04] px-2 py-1">
                        {r.state.dataLen.toLocaleString()} bytes
                      </span>
                    )}
                    {ownerOk && (
                      <span className="rounded bg-glyph/10 px-2 py-1 text-glyph-300">
                        ✓ {r.note}
                      </span>
                    )}
                  </>
                ) : status === "loading" ? (
                  <span className="h-5 w-24 animate-pulse rounded bg-white/[0.04]" />
                ) : (
                  <span className="rounded bg-white/[0.04] px-2 py-1">on-chain</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
