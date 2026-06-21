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
  }

  const { skipAuth: _, ...rest } = init ?? {};
  void _;

  const fullUrl = `${nodeUrl}${path}`;
  const method = init?.method ?? "GET";
  const isChat = path.includes("/chat/");

  if (isChat) {
    console.log(`[dashboard] 📡 ${method} ${path}`);
  }

  const res = await nativeFetch(fullUrl, { ...rest, headers });

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    console.error(`[dashboard] ❌ ${res.status} from ${path}:`, text.substring(0, 500));
    throw new ApiError(res.status, text);
  }

  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const json = await res.json() as Record<string, unknown>;

    if (isChat) {
      const convos = (json as any)?.conversations;
      const msgs = (json as any)?.messages;
      if (Array.isArray(convos)) {
        console.log(`[dashboard] 📥 conversations: ${convos.length}`, convos.length > 0 ? convos.map((c: any) => ({
          peer: c.peer_wallet?.slice(0, 12) + "…",
          name: c.peer_name,
          msgs: c.total_messages,
          last: c.last_timestamp ? new Date(c.last_timestamp * 1000).toISOString() : "none",
        })) : "(empty)");
      } else if (Array.isArray(msgs)) {
        console.log(`[dashboard] 📥 messages: ${msgs.length}`, msgs.length > 0 ? {
          first: (msgs[0] as any)?.msg_id?.slice(0, 16) + "…",
          last: (msgs[msgs.length - 1] as any)?.msg_id?.slice(0, 16) + "…",
          block_indices: [...new Set(msgs.map((m: any) => m.block_index))],
        } : "(empty)");
      } else {
        // Generic chat response
        const keys = Object.keys(json);
        const summary: Record<string, unknown> = {};
        for (const k of keys) {
          const v = json[k];
          if (Array.isArray(v)) summary[k] = `[${v.length} items]`;
          else if (typeof v === "object" && v !== null) summary[k] = `{${Object.keys(v as object).length} keys}`;
          else summary[k] = v;
        }
        console.log(`[dashboard] 📥 ${path} response:`, summary);
      }
    }

    return json as T;
  }
  return res.text() as unknown as T;
}