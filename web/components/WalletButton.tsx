"use client";

import { Connection, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { RPC_URL } from "@/lib/data";
import { truncatePubkey, type StandardWallet } from "@/lib/wallet";
import { useWalletContext } from "./WalletProvider";

export function WalletButton() {
  const {
    available,
    connected,
    connecting,
    address,
    walletName,
    error,
    canSignMessage,
    connect,
    disconnect,
  } = useWalletContext();
  const [open, setOpen] = useState(false);
  const [balance, setBalance] = useState<number | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const onPick = async (w: StandardWallet) => {
    await connect(w);
    setOpen(false);
  };

  const refreshBalance = async () => {
    if (!address) return;
    setBusy(true);
    setStatus(null);
    try {
      const conn = new Connection(RPC_URL, "confirmed");
      const lamports = await conn.getBalance(new PublicKey(address));
      setBalance(lamports / LAMPORTS_PER_SOL);
      setStatus("Devnet balance refreshed.");
    } catch (e) {
      setStatus(e instanceof Error ? e.message : "Failed to fetch balance.");
    } finally {
      setBusy(false);
    }
  };

  const requestAirdrop = async () => {
    if (!address) return;
    setBusy(true);
    setStatus("Requesting 1 devnet SOL…");
    try {
      const conn = new Connection(RPC_URL, "confirmed");
      const sig = await conn.requestAirdrop(new PublicKey(address), LAMPORTS_PER_SOL);
      await conn.confirmTransaction(sig, "confirmed");
      const lamports = await conn.getBalance(new PublicKey(address));
      setBalance(lamports / LAMPORTS_PER_SOL);
      setStatus(`Airdrop confirmed · ${sig.slice(0, 8)}…${sig.slice(-6)}`);
    } catch (e) {
      setStatus(e instanceof Error ? e.message : "Airdrop failed.");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (connected && open) void refreshBalance();
    if (!connected) {
      setBalance(null);
      setStatus(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connected, open, address]);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-2 text-sm transition-colors ${
          connected
            ? "border-glyph/40 bg-glyph/[0.08] text-glyph-300 hover:border-glyph/60"
            : "border-white/12 bg-white/[0.02] text-white/80 hover:border-white/25 hover:bg-white/[0.06]"
        }`}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className={`h-2 w-2 rounded-full ${connected ? "bg-glyph" : "bg-white/30"}`} />
        {connected && address ? (
          <span className="font-mono text-xs">{truncatePubkey(address)}</span>
        ) : connecting ? (
          "Connecting…"
        ) : (
          "Connect Wallet"
        )}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
            className="absolute right-0 z-50 mt-2 w-72 overflow-hidden rounded-xl border border-white/10 bg-ink-950/95 p-2 shadow-2xl backdrop-blur-xl"
            role="menu"
          >
            {connected ? (
              <div className="p-2">
                <div className="text-2xs uppercase tracking-wider text-white/40">Connected</div>
                <div className="mt-1 flex items-center gap-2">
                  <span className="font-mono text-sm text-glyph-300">
                    {address ? truncatePubkey(address) : "—"}
                  </span>
                  {walletName && <span className="text-2xs text-white/40">· {walletName}</span>}
                </div>
                <p className="mt-2 text-2xs leading-relaxed text-white/45">
                  This is the human delegator / agent identity GLYPH binds policy to on devnet.
                  Use it to fund demos and sign policy commitments.
                </p>
                <div className="mt-3 rounded-lg border border-white/[0.08] bg-white/[0.02] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-2xs uppercase tracking-wider text-white/35">
                      Devnet balance
                    </span>
                    <span className="font-mono text-sm text-white/80">
                      {balance === null ? "…" : `${balance.toFixed(3)} SOL`}
                    </span>
                  </div>
                  <div className="mt-3 grid grid-cols-2 gap-2">
                    <button
                      onClick={refreshBalance}
                      disabled={busy}
                      className="rounded-lg border border-white/10 px-3 py-2 text-2xs text-white/70 transition-colors hover:border-glyph/30 hover:bg-glyph/[0.05] disabled:opacity-50"
                    >
                      Refresh
                    </button>
                    <button
                      onClick={requestAirdrop}
                      disabled={busy}
                      className="rounded-lg border border-glyph/25 bg-glyph/[0.06] px-3 py-2 text-2xs text-glyph-300 transition-colors hover:border-glyph/45 disabled:opacity-50"
                    >
                      Airdrop 1 SOL
                    </button>
                  </div>
                  <div className="mt-2 font-mono text-2xs text-white/38">
                    {canSignMessage ? "message signing available" : "message signing unavailable"}
                  </div>
                  {status && (
                    <p className="mt-2 break-words text-2xs leading-relaxed text-white/45">
                      {status}
                    </p>
                  )}
                </div>
                <button
                  onClick={() => {
                    disconnect();
                    setOpen(false);
                  }}
                  className="mt-3 w-full rounded-lg border border-white/10 px-3 py-2 text-sm text-white/70 transition-colors hover:border-deny/30 hover:bg-deny/[0.06] hover:text-deny-400"
                >
                  Disconnect
                </button>
              </div>
            ) : available.length === 0 ? (
              <div className="p-3">
                <p className="text-sm text-white/70">No Solana wallet detected.</p>
                <p className="mt-1.5 text-2xs leading-relaxed text-white/45">
                  Install a Wallet-Standard wallet (Phantom, Solflare, Backpack) and reopen this
                  menu.
                </p>
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                <div className="px-2 py-1.5 text-2xs uppercase tracking-wider text-white/40">
                  Choose a wallet
                </div>
                {available.map((w) => (
                  <button
                    key={w.name}
                    onClick={() => onPick(w)}
                    className="flex items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-white/[0.05]"
                    role="menuitem"
                  >
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={w.icon} alt="" className="h-6 w-6 rounded-md" />
                    <span className="text-sm text-white/85">{w.name}</span>
                  </button>
                ))}
                <p className="px-2 pb-1 pt-2 text-2xs leading-relaxed text-white/40">
                  Detected via the Wallet Standard. Devnet actions: balance, faucet, message
                  signing, and policy binding.
                </p>
              </div>
            )}
            {error && <p className="mt-2 px-2 text-2xs text-deny-400">{error}</p>}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
