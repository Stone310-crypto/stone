import { useEffect, useRef } from "react";
import { useAuth } from "../auth/AuthContext";
import { loadSettings } from "../store/session";

type NotificationPrefs = {
  messages: boolean;
  calls: boolean;
};

let wsRef: WebSocket | null = null;

function loadNotifPrefs(): NotificationPrefs {
  try {
    const raw = localStorage.getItem("stone-notification-prefs");
    if (raw) return JSON.parse(raw);
  } catch {}
  return { messages: true, calls: true };
}

export function saveNotifPrefs(prefs: NotificationPrefs) {
  localStorage.setItem("stone-notification-prefs", JSON.stringify(prefs));
}

export function getNotifPrefs(): NotificationPrefs {
  return loadNotifPrefs();
}

export function useWebSocketEvents() {
  const { session } = useAuth();
  const lastMsgRef = useRef<string | null>(null);

  useEffect(() => {
    if (!session) return;

    const settings = loadSettings();
    const nodeUrl = (settings as any)?.nodeUrl ?? "http://127.0.0.1:3080";
    const wsUrl = nodeUrl
      .replace(/^http/, "ws")
      .replace(/\/$/, "") + `/ws?token=${encodeURIComponent(session.apiKey)}`;

    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (wsRef && wsRef.readyState === WebSocket.OPEN) return;
      try {
        wsRef = new WebSocket(wsUrl);
      } catch {
        scheduleReconnect();
        return;
      }

      wsRef.onopen = () => {
        console.log("[ws] Connected to node events");
      };

      wsRef.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const prefs = loadNotifPrefs();

          if (data.event === "ChatMessageReceived" && prefs.messages) {
            const payload = data.data ?? data;
            const from = payload.from_name ?? payload.from ?? payload.sender_name ?? "";
            const content = payload.content ?? payload.encrypted_content ?? "";
            if (!from) return;

            // Decode if base64
            let text = content;
            try { text = decodeURIComponent(escape(atob(content))); } catch {}

            const dedupKey = `${from}:${text}`;
            if (dedupKey === lastMsgRef.current) return;
            lastMsgRef.current = dedupKey;

            showNotification("Neue Nachricht", `${from}: ${text.slice(0, 100)}`);
          }

          if (data.event === "CallSignalReceived" && prefs.calls) {
            const payload = data.data ?? data;
            const from = payload.from ?? payload.caller ?? "";
            showNotification("Eingehender Anruf", `${from} ruft an…`);
          }
        } catch {}
      };

      wsRef.onclose = () => {
        wsRef = null;
        scheduleReconnect();
      };

      wsRef.onerror = () => {
        wsRef?.close();
      };
    }

    function scheduleReconnect() {
      if (reconnectTimer) return;
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, 10_000);
    }

    // Request notification permission on macOS
    requestPermission().then(connect);

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef) {
        wsRef.onclose = null;
        wsRef.onerror = null;
        wsRef.close();
        wsRef = null;
      }
    };
  }, [session?.apiKey]);
}

async function requestPermission() {
  try {
    const { isPermissionGranted, requestPermission } = await import("@tauri-apps/plugin-notification");
    let granted = await isPermissionGranted();
    if (!granted) {
      const perm = await requestPermission();
      granted = perm === "granted";
    }
  } catch {
    // Browser mode — use Web Notifications API
    if ("Notification" in window) {
      await Notification.requestPermission();
    }
  }
}

async function showNotification(title: string, body: string) {
  try {
    const { sendNotification } = await import("@tauri-apps/plugin-notification");
    sendNotification({ title, body, sound: "default" });
  } catch {
    // Browser fallback
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification(title, { body });
    }
  }
}