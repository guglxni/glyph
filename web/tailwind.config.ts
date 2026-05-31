import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Base surfaces — near-black, slightly cool
        ink: {
          950: "#050608",
          900: "#0A0C10",
          850: "#0E1117",
          800: "#13161D",
          750: "#181C25",
          700: "#1F242E",
          600: "#2A303B",
        },
        // Solana green — used as the primary accent
        glyph: {
          DEFAULT: "#14F195",
          50: "#E9FFF6",
          100: "#BCFCE4",
          300: "#5BF5BE",
          400: "#2BF3A6",
          500: "#14F195",
          600: "#0FC97C",
          700: "#0B9C60",
        },
        // ZK violet — secondary accent for the proving layer
        zk: {
          DEFAULT: "#8A2BE2",
          300: "#C193F4",
          400: "#A45BEC",
          500: "#8A2BE2",
          600: "#7521C2",
        },
        // Deny / warning
        deny: {
          DEFAULT: "#FF5C6C",
          400: "#FF7A87",
          500: "#FF5C6C",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      letterSpacing: {
        tightest: "-0.045em",
      },
      maxWidth: {
        content: "76rem",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(20,241,149,0.12), 0 12px 40px -12px rgba(20,241,149,0.25)",
        "glow-zk": "0 0 0 1px rgba(138,43,226,0.18), 0 12px 40px -12px rgba(138,43,226,0.30)",
        card: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 24px 60px -24px rgba(0,0,0,0.8)",
      },
      backgroundImage: {
        "grid-fade":
          "linear-gradient(to bottom, transparent, rgba(5,6,8,0.9) 70%), radial-gradient(circle at 50% 0%, rgba(20,241,149,0.10), transparent 55%)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(14px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-dot": {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.4", transform: "scale(0.85)" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        "border-flow": {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.6s cubic-bezier(0.16,1,0.3,1) both",
        "pulse-dot": "pulse-dot 1.8s ease-in-out infinite",
        shimmer: "shimmer 2s infinite",
        "border-flow": "border-flow 6s ease infinite",
      },
    },
  },
  plugins: [],
};

export default config;
