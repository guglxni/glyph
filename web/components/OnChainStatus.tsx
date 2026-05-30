"use client";

import { useEffect, useState } from "react";
import { Connection, PublicKey } from "@solana/web3.js";
import {
  RPC_URL,
  PROGRAM_ID,
  CONFIG_PDA,
  VK_PDA,
  VK_HASH,
  PROVER,
  EXPLORER_CONFIG,
  EXPLORER_VK,
  EXPLORER_DEPLOY_TX,
} from "@/lib/data";
import { Card, ExtLink, Hash } from "./ui";

type AcctState =
  | { status: "loading" }
  | { status: "ok"; owner: string; len: number; lamports: number; executable?: boolean }
  | { status: "missing" }
  | { status: "error"; message: string };

function useAccount(address: string): AcctState {
  const [state, setState] = useState<AcctState>({ status: "loading" });
  useEffect(() => {
    let alive = true;
    const conn = new Connection(RPC_URL, "confirmed");
    conn
      .getAccountInfo(new PublicKey(address))
      .then((info) => {
        if (!alive) return;
        if (!info) {
          setState({ status: "missing" });
          return;
        }
        setState({
          status: "ok",
          owner: info.owner.toBase58(),
          len: info.data.length,
          lamports: info.lamports,
          executable: info.executable,
        });
      })
      .catch((e) => {
        if (!alive) return;
        setState({ status: "error", message: String(e?.message ?? e) });
      });
    return () => {
      alive = false;
    };
  }, [address]);
  return state;
}

function StatusDot({ s }: { s: AcctState }) {
  const color =
    s.status === "ok"
      ? "bg-accent"
      : s.status === "loading"
      ? "bg-amber"
      : "bg-danger";
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />;
}

function ownerLabel(owner: string): string {
  if (owner === PROGRAM_ID) return "GLYPH program ✓";
  if (owner === "BPFLoaderUpgradeab1e11111111111111111111111")
    return "BPF Upgradeable Loader ✓";
  return owner;
}

function AccountRow({
  title,
  address,
  explorer,
  state,
  ownedByProgram,
}: {
  title: string;
  address: string;
  explorer: string;
  state: AcctState;
  ownedByProgram?: boolean;
}) {
  return (
    <div className="border-t border-line px-5 py-4 first:border-t-0">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <StatusDot s={state} />
          <span className="text-sm font-medium text-ink">{title}</span>
        </div>
        <ExtLink href={explorer} className="text-[12px]">
          explorer
        </ExtLink>
      </div>
      <div className="mt-2">
        <Hash value={address} />
      </div>
      <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1.5 font-mono text-[12px] sm:grid-cols-3">
        {state.status === "loading" && (
          <span className="text-faint">querying devnet…</span>
        )}
        {state.status === "missing" && (
          <span className="text-danger">account not found</span>
        )}
        {state.status === "error" && (
          <span className="text-danger">rpc error: {state.message}</span>
        )}
        {state.status === "ok" && (
          <>
            <div>
              <span className="text-faint">owner </span>
              <span className={ownedByProgram ? "text-accent" : "text-sub"}>
                {ownerLabel(state.owner)}
              </span>
            </div>
            <div>
              <span className="text-faint">data </span>
              <span className="text-sub">{state.len} bytes</span>
            </div>
            <div>
              <span className="text-faint">rent </span>
              <span className="text-sub">
                {(state.lamports / 1e9).toFixed(5)} SOL
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function OnChainStatus() {
  const program = useAccount(PROGRAM_ID);
  const config = useAccount(CONFIG_PDA);
  const vk = useAccount(VK_PDA);

  const allOk =
    program.status === "ok" && config.status === "ok" && vk.status === "ok";

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
        <div className="flex items-center gap-2 text-sm">
          <span className="font-mono text-[11px] uppercase tracking-widest text-faint">
            devnet · live read
          </span>
        </div>
        <div className="font-mono text-[12px]">
          {allOk ? (
            <span className="text-accent">● all accounts live</span>
          ) : (
            <span className="text-sub">resolving…</span>
          )}
        </div>
      </div>

      <AccountRow
        title="Verifier program"
        address={PROGRAM_ID}
        explorer={EXPLORER_CONFIG.replace(CONFIG_PDA, PROGRAM_ID)}
        state={program}
      />
      <AccountRow
        title="Config PDA"
        address={CONFIG_PDA}
        explorer={EXPLORER_CONFIG}
        state={config}
        ownedByProgram
      />
      <AccountRow
        title="Verifying-key PDA"
        address={VK_PDA}
        explorer={EXPLORER_VK}
        state={vk}
        ownedByProgram
      />

      <div className="border-t border-line bg-panel2/60 px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-widest text-faint">
              seeded vk_hash
            </div>
            <Hash value={VK_HASH} className="mt-1 block text-accent" />
          </div>
          <div>
            <div className="font-mono text-[11px] uppercase tracking-widest text-faint">
              prover
            </div>
            <div className="mt-1 font-mono text-[12px] text-sub">{PROVER}</div>
          </div>
        </div>
        <div className="mt-4 text-[13px] text-sub">
          These accounts are queried straight from{" "}
          <span className="font-mono text-ink">api.devnet.solana.com</span> in
          your browser. The Config and VK PDAs being owned by the program proves
          GLYPH is deployed and initialized.{" "}
          <ExtLink href={EXPLORER_DEPLOY_TX}>view deploy transaction</ExtLink>
        </div>
      </div>
    </Card>
  );
}
