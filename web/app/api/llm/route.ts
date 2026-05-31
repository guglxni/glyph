/**
 * GLYPH BYOK LLM proxy — a stateless, LiteLLM-style OpenAI-compatible passthrough.
 *
 * Why this exists: most providers block direct browser calls (CORS) and we never
 * want the user's API key to touch GLYPH infrastructure beyond a single in-flight
 * request. This route forwards the OpenAI `chat/completions` body to the user's
 * chosen `baseUrl` with their `Authorization: Bearer <key>` header, then streams
 * the provider's JSON straight back.
 *
 * IMPORTANT: this handler is intentionally STATELESS. It never logs, never stores,
 * and never persists the API key or the message contents anywhere. Exactly the
 * "unified OpenAI-compatible passthrough" pattern that LiteLLM popularised — but
 * with zero retention. The key lives only in the browser's localStorage and in
 * the single forwarded request.
 */

import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface ProxyBody {
  baseUrl?: unknown;
  apiKey?: unknown;
  model?: unknown;
  messages?: unknown;
  temperature?: unknown;
  max_tokens?: unknown;
  response_format?: unknown;
}

/** Normalise a base URL into a full chat-completions endpoint. */
function resolveEndpoint(baseUrl: string): string {
  let b = baseUrl.trim().replace(/\/+$/, "");
  if (b.endsWith("/chat/completions")) return b;
  return `${b}/chat/completions`;
}

function isHttpUrl(u: string): boolean {
  try {
    const parsed = new URL(u);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export async function POST(req: NextRequest) {
  let body: ProxyBody;
  try {
    body = (await req.json()) as ProxyBody;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const baseUrl = typeof body.baseUrl === "string" ? body.baseUrl : "";
  const apiKey = typeof body.apiKey === "string" ? body.apiKey : "";
  const model = typeof body.model === "string" ? body.model : "";
  const messages = Array.isArray(body.messages) ? (body.messages as ChatMessage[]) : null;

  // Minimal, robust validation — reject obviously malformed / dangerous input.
  if (!baseUrl || !isHttpUrl(baseUrl)) {
    return NextResponse.json(
      { error: "A valid OpenAI-compatible base URL (http/https) is required." },
      { status: 400 }
    );
  }
  if (!model) {
    return NextResponse.json({ error: "A model id is required." }, { status: 400 });
  }
  if (!messages || messages.length === 0) {
    return NextResponse.json({ error: "messages[] is required." }, { status: 400 });
  }

  const endpoint = resolveEndpoint(baseUrl);

  // Build the OpenAI chat body. Only forward known-safe fields.
  const payload: Record<string, unknown> = { model, messages };
  if (typeof body.temperature === "number") payload.temperature = body.temperature;
  if (typeof body.max_tokens === "number") payload.max_tokens = body.max_tokens;
  if (body.response_format && typeof body.response_format === "object") {
    payload.response_format = body.response_format;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  // Local runtimes (Ollama / LM Studio) often need no key — only attach if present.
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  // Abort if the provider hangs.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60_000);

  try {
    const upstream = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const text = await upstream.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      // Provider returned non-JSON (HTML error page, etc.) — surface it cleanly.
      return NextResponse.json(
        {
          error: `Provider returned a non-JSON response (HTTP ${upstream.status}).`,
          detail: text.slice(0, 500),
        },
        { status: upstream.status >= 400 ? upstream.status : 502 }
      );
    }

    if (!upstream.ok) {
      return NextResponse.json(json, { status: upstream.status });
    }
    return NextResponse.json(json, { status: 200 });
  } catch (err) {
    const isAbort = err instanceof Error && err.name === "AbortError";
    return NextResponse.json(
      {
        error: isAbort
          ? "The provider request timed out."
          : `Could not reach the provider. ${
              err instanceof Error ? err.message : "Unknown network error."
            }`,
      },
      { status: 504 }
    );
  } finally {
    clearTimeout(timeout);
  }
}
