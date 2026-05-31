"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import {
  clearSettings,
  DEFAULT_SETTINGS,
  isConfigured,
  loadSettings,
  PRESETS,
  saveSettings,
  type LlmSettings as Settings,
} from "@/lib/llm";

const COMPAT_NOTE =
  "Works with any OpenAI-compatible endpoint — OpenAI, Anthropic, Gemini, Groq, OpenRouter, xAI, Ollama, LM Studio, or a self-hosted LiteLLM proxy.";

export function LlmSettings({
  settings,
  onChange,
}: {
  settings: Settings;
  onChange: (s: Settings) => void;
}) {
  const [open, setOpen] = useState(false);
  const configured = isConfigured(settings);

  const set = (patch: Partial<Settings>) => {
    const next = { ...settings, ...patch };
    onChange(next);
    saveSettings(next);
  };

  const applyPreset = (id: string) => {
    const p = PRESETS.find((x) => x.id === id);
    if (!p) return;
    set({ baseUrl: p.baseUrl, model: p.models[0] });
  };

  const activePresetId = PRESETS.find((p) => p.baseUrl === settings.baseUrl)?.id ?? "";
  const activePreset = PRESETS.find((p) => p.id === activePresetId);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-sm transition-colors ${
          configured
            ? "border-glyph/35 bg-glyph/[0.06] text-glyph-300 hover:border-glyph/55"
            : "border-amber-400/35 bg-amber-400/[0.06] text-amber-300 hover:border-amber-400/55"
        }`}
        aria-label="LLM settings"
      >
        <KeyIcon />
        <span className="hidden sm:inline">{configured ? "LLM ready" : "Configure LLM"}</span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-start justify-center overflow-y-auto bg-ink-950/70 p-4 backdrop-blur-sm"
            onClick={() => setOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 16, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 16, scale: 0.98 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="card my-4 max-h-[calc(100svh-2rem)] w-full max-w-lg overflow-y-auto p-5 sm:my-6 sm:p-6"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
            >
              <div className="sticky -top-5 z-10 flex items-start justify-between bg-ink-850/95 pb-3 pt-1 backdrop-blur sm:-top-6">
                <div>
                  <h3 className="text-lg font-semibold text-white">LLM settings · bring your own key</h3>
                  <p className="mt-1 text-2xs leading-relaxed text-white/45">{COMPAT_NOTE}</p>
                </div>
                <button
                  onClick={() => setOpen(false)}
                  className="grid h-8 w-8 place-items-center rounded-full border border-white/10 text-white/60 hover:bg-white/[0.05]"
                  aria-label="Close"
                >
                  ✕
                </button>
              </div>

              {/* Presets */}
              <div className="mt-5">
                <Label>Provider preset</Label>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {PRESETS.map((p) => (
                    <button
                      key={p.id}
                      onClick={() => applyPreset(p.id)}
                      className={`rounded-full border px-2.5 py-1 text-xs transition-colors ${
                        activePresetId === p.id
                          ? "border-glyph/45 bg-glyph/[0.08] text-glyph-300"
                          : "border-white/10 bg-white/[0.02] text-white/65 hover:border-white/25"
                      }`}
                    >
                      {p.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Base URL */}
              <Field label="Base URL">
                <input
                  type="text"
                  value={settings.baseUrl}
                  onChange={(e) => set({ baseUrl: e.target.value })}
                  placeholder="https://api.openai.com/v1"
                  className={inputCls}
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>

              {/* API key */}
              <Field label="API key">
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={settings.apiKey}
                    onChange={(e) => set({ apiKey: e.target.value })}
                    placeholder={activePreset?.local ? "(not required for local)" : "sk-…"}
                    className={inputCls}
                    spellCheck={false}
                    autoComplete="off"
                  />
                  <button
                    onClick={() => {
                      clearSettings();
                      set({ apiKey: "" });
                    }}
                    className="shrink-0 rounded-lg border border-white/10 px-3 text-xs text-white/60 hover:border-deny/30 hover:text-deny-400"
                    title="Clear stored key"
                  >
                    Clear
                  </button>
                </div>
              </Field>

              {/* Model */}
              <Field label="Model">
                <input
                  type="text"
                  list="glyph-model-suggestions"
                  value={settings.model}
                  onChange={(e) => set({ model: e.target.value })}
                  placeholder="gpt-5"
                  className={inputCls}
                  spellCheck={false}
                  autoComplete="off"
                />
                <datalist id="glyph-model-suggestions">
                  {(activePreset?.models ?? []).map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              </Field>

              {/* Advanced */}
              <div className="mt-3 grid grid-cols-2 gap-3">
                <Field label="Temperature" tight>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="2"
                    value={settings.temperature}
                    onChange={(e) => set({ temperature: Number(e.target.value) })}
                    className={inputCls}
                  />
                </Field>
                <Field label="Max tokens" tight>
                  <input
                    type="number"
                    step="64"
                    min="64"
                    value={settings.maxTokens}
                    onChange={(e) => set({ maxTokens: Number(e.target.value) })}
                    className={inputCls}
                  />
                </Field>
              </div>

              {/* Disclosure */}
              <p className="mt-5 rounded-lg border border-white/[0.07] bg-white/[0.015] p-3 text-2xs leading-relaxed text-white/45">
                Your key is stored only in your browser and forwarded to the provider through a
                stateless proxy that never logs or stores it.
              </p>

              <div className="mt-4 flex items-center justify-between">
                <button
                  onClick={() => {
                    clearSettings();
                    onChange(DEFAULT_SETTINGS);
                  }}
                  className="text-2xs text-white/45 hover:text-white/70"
                >
                  Reset to defaults
                </button>
                <button onClick={() => setOpen(false)} className="btn-primary !px-4 !py-2 text-sm">
                  Done
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

const inputCls =
  "w-full rounded-lg border border-white/12 bg-white/[0.02] px-3 py-2 font-mono text-sm text-white/90 outline-none transition-colors placeholder:text-white/30 focus:border-glyph/45";

function Label({ children }: { children: React.ReactNode }) {
  return <span className="text-2xs uppercase tracking-wider text-white/45">{children}</span>;
}

function Field({
  label,
  children,
  tight,
}: {
  label: string;
  children: React.ReactNode;
  tight?: boolean;
}) {
  return (
    <div className={tight ? "" : "mt-4"}>
      <Label>{label}</Label>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

function KeyIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden>
      <circle cx="8" cy="15" r="4" />
      <path d="M10.85 12.15 19 4m-3 0 3 3m-6 0 2 2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Hook that owns the LLM settings state + persistence. */
export function useLlmSettings(): [Settings, (s: Settings) => void] {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  useEffect(() => {
    setSettings(loadSettings());
  }, []);
  const update = (s: Settings) => {
    setSettings(s);
    saveSettings(s);
  };
  return [settings, update];
}
