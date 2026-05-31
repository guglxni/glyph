/**
 * Minimal, FOSS wallet connection built directly on the Wallet Standard.
 *
 * No heavy adapter stack — we read `window.navigator.wallets` (the Wallet
 * Standard app registry) and use the standard `connect` / `disconnect`
 * features. This detects Phantom, Solflare, Backpack and any other
 * Wallet-Standard-compliant Solana wallet. The connected pubkey becomes the
 * agent identity GLYPH binds policy to, and wallets that support it can sign a
 * policy-delegation message.
 */

"use client";

import { getWallets } from "@wallet-standard/app";
import { useCallback, useEffect, useRef, useState } from "react";

// ─── Wallet Standard minimal typings (avoids a dependency) ──────────────────────

interface StandardAccount {
  address: string; // base58
  publicKey: Uint8Array;
  chains: readonly string[];
  features: readonly string[];
}

interface ConnectFeature {
  connect: (input?: { silent?: boolean }) => Promise<{ accounts: readonly StandardAccount[] }>;
}
interface DisconnectFeature {
  disconnect: () => Promise<void>;
}
interface EventsFeature {
  on: (event: "change", listener: (props: { accounts?: readonly StandardAccount[] }) => void) => () => void;
}
interface SignMessageFeature {
  signMessage: (input: {
    account: StandardAccount;
    message: Uint8Array;
  }) => Promise<{ signedMessage?: Uint8Array; signature: Uint8Array }>;
}

export interface StandardWallet {
  name: string;
  icon: string;
  chains: readonly string[];
  accounts: readonly StandardAccount[];
  features: Record<string, unknown>;
}

function isSolanaWallet(w: StandardWallet): boolean {
  return w.chains.some((c) => c.startsWith("solana:"));
}

export function truncatePubkey(addr: string): string {
  if (addr.length <= 12) return addr;
  return `${addr.slice(0, 4)}…${addr.slice(-4)}`;
}

export interface UseWallet {
  available: StandardWallet[];
  connected: boolean;
  connecting: boolean;
  address: string | null;
  publicKey: Uint8Array | null;
  walletName: string | null;
  error: string | null;
  canSignMessage: boolean;
  connect: (wallet: StandardWallet) => Promise<void>;
  disconnect: () => Promise<void>;
  signMessage: (message: string) => Promise<string>;
  refresh: () => void;
}

export function useWallet(): UseWallet {
  const [available, setAvailable] = useState<StandardWallet[]>([]);
  const [connecting, setConnecting] = useState(false);
  const [address, setAddress] = useState<string | null>(null);
  const [publicKey, setPublicKey] = useState<Uint8Array | null>(null);
  const [walletName, setWalletName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const activeWallet = useRef<StandardWallet | null>(null);
  const activeAccount = useRef<StandardAccount | null>(null);

  const refresh = useCallback(() => {
    if (typeof window === "undefined") return;
    const { get } = getWallets();
    setAvailable((get() as unknown as StandardWallet[]).filter(isSolanaWallet));
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    refresh();
    const { on } = getWallets();
    const offReg = on("register", refresh);
    const offUnreg = on("unregister", refresh);
    return () => {
      offReg?.();
      offUnreg?.();
    };
  }, [refresh]);

  const connect = useCallback(async (wallet: StandardWallet) => {
    setError(null);
    setConnecting(true);
    try {
      const feature = wallet.features["standard:connect"] as ConnectFeature | undefined;
      if (!feature?.connect) throw new Error(`${wallet.name} does not support standard connect.`);
      const { accounts } = await feature.connect();
      const acct = accounts[0];
      if (!acct) throw new Error("No account returned by the wallet.");
      setAddress(acct.address);
      setPublicKey(acct.publicKey);
      setWalletName(wallet.name);
      activeWallet.current = wallet;
      activeAccount.current = acct;

      // Track account changes (e.g. user switches accounts).
      const events = wallet.features["standard:events"] as EventsFeature | undefined;
      events?.on("change", (props) => {
        const next = props.accounts?.[0];
        if (next) {
          setAddress(next.address);
          setPublicKey(next.publicKey);
          activeAccount.current = next;
        } else {
          setAddress(null);
          setPublicKey(null);
          setWalletName(null);
          activeAccount.current = null;
        }
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to connect.");
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(async () => {
    const wallet = activeWallet.current;
    try {
      const feature = wallet?.features["standard:disconnect"] as DisconnectFeature | undefined;
      await feature?.disconnect?.();
    } catch {
      /* ignore */
    }
    setAddress(null);
    setPublicKey(null);
    setWalletName(null);
    activeWallet.current = null;
    activeAccount.current = null;
  }, []);

  const signMessage = useCallback(async (message: string) => {
    const wallet = activeWallet.current;
    const account = activeAccount.current;
    if (!wallet || !account) throw new Error("Connect a wallet first.");
    const feature = wallet.features["solana:signMessage"] as SignMessageFeature | undefined;
    if (!feature?.signMessage) {
      throw new Error(`${wallet.name} does not support Solana message signing.`);
    }
    const encoded = new TextEncoder().encode(message);
    const { signature } = await feature.signMessage({ account, message: encoded });
    return Array.from(signature)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }, []);

  return {
    available,
    connected: address !== null,
    connecting,
    address,
    publicKey,
    walletName,
    error,
    canSignMessage: Boolean(activeWallet.current?.features["solana:signMessage"]),
    connect,
    disconnect,
    signMessage,
    refresh,
  };
}
