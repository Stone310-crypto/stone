import { loadSession, loadSettings } from "../store/session";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function nativeFetch(url: string, init: RequestInit): Promise<Response> {
  try {
    const { fetch: tauriFetch } = await import("@tauri-apps/plugin-http");
    return await tauriFetch(url, init as Parameters<typeof tauriFetch>[1]);
  } catch {
    return fetch(url, init);
  }
}

export async function apiFetch<T>(
  path: string,
  init?: RequestInit & { skipAuth?: boolean },
): Promise<T> {
  const { nodeUrl } = loadSettings();
  const session = loadSession();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };

  if (!init?.skipAuth && session) {
    headers["x-api-key"] = session.apiKey;
    headers["Authorization"] = `Bearer ${session.sessionToken}`;
    console.log("[api] auth:", {
      apiKeyLen: session.apiKey?.length ?? 0,
      apiKeyPreview: session.apiKey ? session.apiKey.substring(0, 12) + "…" : "MISSING",
      tokenLen: session.sessionToken?.length ?? 0,
      tokenPreview: session.sessionToken ? session.sessionToken.substring(0, 16) + "…" : "MISSING",
      wallet: session.walletAddress ?? "MISSING",
    });
  } else if (!session) {
    console.warn("[api] ⚠️ Kein Session-Objekt — Anfrage ohne Auth-Header");
  }

  const { skipAuth: _, ...rest } = init ?? {};
  void _;

  const fullUrl = `${nodeUrl}${path}`;
  const method = init?.method ?? "GET";
  console.log(`[api] → ${method} ${fullUrl}`);
  const res = await nativeFetch(fullUrl, { ...rest, headers });
  console.log(`[api] ← ${res.status} ${res.statusText || ""}`);

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    console.error(`[api] ❌ ${res.status} von ${fullUrl}:`, text.substring(0, 500));
    throw new ApiError(res.status, text);
  }

  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) return res.json() as Promise<T>;
  return res.text() as unknown as Promise<T>;
}