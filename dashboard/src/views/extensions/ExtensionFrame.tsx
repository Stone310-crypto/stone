import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Loader2 } from "lucide-react";

interface Props {
  extensionId: string;
}

/** Lädt und rendert eine beliebige Extension-UI in einem iframe. */
export default function ExtensionFrame({ extensionId }: Props) {
  const [ui, setUI] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    invoke<string | null>("get_extension_ui", { id: extensionId })
      .then((html) => setUI(html))
      .catch(() => setUI(null))
      .finally(() => setLoading(false));
  }, [extensionId]);

  // Message-Proxy für iframe↔Tauri
  useEffect(() => {
    const handler = async (e: MessageEvent) => {
      if (e.data?.type !== "tauri-invoke") return;
      try {
        const result = await invoke(e.data.cmd, e.data.args);
        (e.source as WindowProxy).postMessage(
          { id: e.data.id, ok: true, result },
          { targetOrigin: "*" }
        );
      } catch (err: any) {
        (e.source as WindowProxy).postMessage(
          { id: e.data.id, ok: false, error: String(err) },
          { targetOrigin: "*" }
        );
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, []);

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: "var(--text-muted)",
        }}
      >
        <Loader2 size={24} style={{ animation: "spin 1s linear infinite" }} />
      </div>
    );
  }

  if (!ui) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: "var(--text-muted)",
          flexDirection: "column",
          gap: 8,
        }}
      >
        <span style={{ fontSize: 32 }}>🧩</span>
        <span>Extension "{extensionId}" ist nicht installiert.</span>
        <span style={{ fontSize: 12 }}>
          Installiere sie im 🧩 Erweiterungen-Tab.
        </span>
      </div>
    );
  }

  return (
    <iframe
      srcDoc={ui}
      style={{
        width: "100%",
        height: "100%",
        border: "none",
        background: "var(--main-bg)",
      }}
      title={`Extension: ${extensionId}`}
      sandbox="allow-scripts"
    />
  );
}
