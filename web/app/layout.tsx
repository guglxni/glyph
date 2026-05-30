import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const sans = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "GLYPH — Verifiable guardrail layer for autonomous agents on Solana",
  description:
    "One policy, any program. GLYPH cryptographically binds an AI agent's allowed actions to an on-chain Groth16 verifier. Live on Solana devnet.",
  openGraph: {
    title: "GLYPH — Verifiable guardrail layer for autonomous agents on Solana",
    description:
      "One policy, any program. Cryptographically enforced agent guardrails, verified on-chain. Live on devnet.",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
