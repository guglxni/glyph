"use client";

import { createContext, useContext, type ReactNode } from "react";
import { useWallet, type UseWallet } from "@/lib/wallet";

const WalletContext = createContext<UseWallet | null>(null);

/**
 * Single source of truth for wallet connection so the Nav button and the
 * policy compiler share the same connected pubkey.
 */
export function WalletProvider({ children }: { children: ReactNode }) {
  const wallet = useWallet();
  return <WalletContext.Provider value={wallet}>{children}</WalletContext.Provider>;
}

export function useWalletContext(): UseWallet {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWalletContext must be used within <WalletProvider>");
  return ctx;
}
