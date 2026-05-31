import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const sans = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

const SITE = "https://web-lovat-seven-23.vercel.app";

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: "GLYPH — Verifiable guardrails for autonomous AI agents on Solana",
  description:
    "One policy. Any program. Cryptographically proven, on-chain. GLYPH is the horizontal trust layer that checks an agent's action against a declarative policy, proves the decision in zero-knowledge, and verifies the proof on-chain before the action executes.",
  keywords: [
    "Solana",
    "AI agents",
    "zero-knowledge",
    "RISC Zero",
    "TEE",
    "Groth16",
    "BN254",
    "verifiable AI",
    "agent guardrails",
  ],
  authors: [{ name: "GLYPH" }],
  openGraph: {
    title: "GLYPH — The verifiable guardrail layer for AI agents on Solana",
    description:
      "One policy. Any program. Cryptographically proven, on-chain.",
    url: SITE,
    siteName: "GLYPH",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "GLYPH — Verifiable guardrails for AI agents on Solana",
    description: "One policy. Any program. Cryptographically proven, on-chain.",
  },
  icons: {
    icon: [
      {
        url:
          "data:image/svg+xml," +
          encodeURIComponent(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#050608"/><path d="M16 6l8 4.5v9L16 24l-8-4.5v-9L16 6z" fill="none" stroke="#14F195" stroke-width="2" stroke-linejoin="round"/><circle cx="16" cy="15" r="3" fill="#14F195"/></svg>'
          ),
      },
    ],
  },
};

export const viewport: Viewport = {
  themeColor: "#050608",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="min-h-screen bg-ink-950 text-white/90 antialiased selection:bg-glyph/25">
        {children}
      </body>
    </html>
  );
}
