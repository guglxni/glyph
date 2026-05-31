/**
 * BYOK LLM client + provider presets.
 *
 * Every preset targets an OpenAI-compatible `/v1/chat/completions` style endpoint.
 * The settings (base URL, key, model, temperature, max_tokens) are fully editable
 * and persisted in localStorage. Requests are forwarded through the stateless
 * `/api/llm` proxy so the browser never hits a CORS wall and the key is never
 * stored server-side.
 */

export interface LlmSettings {
  baseUrl: string;
  apiKey: string;
  model: string;
  temperature: number;
  maxTokens: number;
}

export interface LlmPreset {
  id: string;
  name: string;
  baseUrl: string;
  models: string[];
  local?: boolean;
  hint?: string;
}

export const PRESETS: LlmPreset[] = [
  { id: "openai", name: "OpenAI", baseUrl: "https://api.openai.com/v1", models: ["gpt-5", "gpt-5-mini", "o3"] },
  { id: "anthropic", name: "Anthropic", baseUrl: "https://api.anthropic.com/v1", models: ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"], hint: "OpenAI-compatible endpoint at /v1/chat/completions" },
  { id: "gemini", name: "Google Gemini", baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai", models: ["gemini-2.5-pro", "gemini-2.5-flash"] },
  { id: "groq", name: "Groq", baseUrl: "https://api.groq.com/openai/v1", models: ["llama-3.3-70b-versatile"] },
  { id: "openrouter", name: "OpenRouter", baseUrl: "https://openrouter.ai/api/v1", models: ["anthropic/claude-opus-4-8", "openai/gpt-5"] },
  { id: "xai", name: "xAI", baseUrl: "https://api.x.ai/v1", models: ["grok-4"] },
  { id: "ollama", name: "Ollama (local)", baseUrl: "http://localhost:11434/v1", models: ["llama3.2"], local: true },
  { id: "lmstudio", name: "LM Studio (local)", baseUrl: "http://localhost:1234/v1", models: ["local-model"], local: true },
  { id: "litellm", name: "LiteLLM proxy (self-host)", baseUrl: "http://localhost:4000", models: ["your-alias"], local: true },
];

export const DEFAULT_SETTINGS: LlmSettings = {
  baseUrl: PRESETS[0].baseUrl,
  apiKey: "",
  model: PRESETS[0].models[0],
  temperature: 0.2,
  maxTokens: 1024,
};

const STORAGE_KEY = "glyph.llm.settings.v1";

export function loadSettings(): LlmSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const parsed = JSON.parse(raw) as Partial<LlmSettings>;
    return {
      baseUrl: typeof parsed.baseUrl === "string" ? parsed.baseUrl : DEFAULT_SETTINGS.baseUrl,
      apiKey: typeof parsed.apiKey === "string" ? parsed.apiKey : "",
      model: typeof parsed.model === "string" ? parsed.model : DEFAULT_SETTINGS.model,
      temperature: typeof parsed.temperature === "number" ? parsed.temperature : DEFAULT_SETTINGS.temperature,
      maxTokens: typeof parsed.maxTokens === "number" ? parsed.maxTokens : DEFAULT_SETTINGS.maxTokens,
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveSettings(s: LlmSettings): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  } catch {
    /* ignore quota errors */
  }
}

export function clearSettings(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

export function isConfigured(s: LlmSettings): boolean {
  if (!s.baseUrl || !s.model) return false;
  const isLocal = /localhost|127\.0\.0\.1|0\.0\.0\.0/.test(s.baseUrl);
  return isLocal || s.apiKey.trim().length > 0;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatResult {
  content: string;
}

export async function chat(
  settings: LlmSettings,
  messages: ChatMessage[],
  opts?: { jsonMode?: boolean; signal?: AbortSignal }
): Promise<ChatResult> {
  const res = await fetch("/api/llm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal: opts?.signal,
    body: JSON.stringify({
      baseUrl: settings.baseUrl,
      apiKey: settings.apiKey,
      model: settings.model,
      temperature: settings.temperature,
      max_tokens: settings.maxTokens,
      messages,
      ...(opts?.jsonMode ? { response_format: { type: "json_object" } } : {}),
    }),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const msg =
      (data && (data.error?.message || data.error || data.detail)) ||
      `Request failed (HTTP ${res.status}).`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }

  const content: unknown = data?.choices?.[0]?.message?.content;
  if (typeof content !== "string" || content.length === 0) {
    throw new Error("The provider returned an empty response.");
  }
  return { content };
}
