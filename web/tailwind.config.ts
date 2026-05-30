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
        bg: "#07080a",
        panel: "#0d0f12",
        panel2: "#111418",
        line: "#1c2026",
        ink: "#e8eaed",
        sub: "#9aa1ab",
        faint: "#5c636e",
        accent: "#3dd68c",
        accentdim: "#1f7a4d",
        danger: "#ff5d5d",
        amber: "#e8b339",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      maxWidth: {
        page: "1080px",
      },
      keyframes: {
        pulseDot: {
          "0%, 100%": { opacity: "1", boxShadow: "0 0 0 0 rgba(61,214,140,0.5)" },
          "50%": { opacity: "0.7", boxShadow: "0 0 0 6px rgba(61,214,140,0)" },
        },
        fadeUp: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        pulseDot: "pulseDot 2s ease-in-out infinite",
        fadeUp: "fadeUp 0.5s ease both",
      },
    },
  },
  plugins: [],
};

export default config;
