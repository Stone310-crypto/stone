import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

/** Lädt und rendert die Dashboard-Extension-UI in einem iframe. */
export default function DashboardExtView() {
  const [ui, setUI] = useState<string | null>(null);

  useEffect(() => {
    invoke<string | null>("get_extension_ui", { id: "dashboard" })
      .then(setUI)
      .catch(() => setUI(null));
  }, []);

  useEffect(() => {
    const handler = async (e: MessageEvent) => {
      if (e.data?.type !== "tauri-invoke") return;
      try {
        const result = await invoke(e.data.cmd, e.data.args);
        (e.source as WindowProxy).postMessage({ id: e.data.id, ok: true, result }, { targetOrigin: "*" });
      } catch (err: any) {
        (e.source as WindowProxy).postMessage({ id: e.data.id, ok: false, error: String(err) }, { targetOrigin: "*" });
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, []);

  if (!ui) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", flexDirection: "column", gap: 8 }}>
        <span style={{ fontSize: 32 }}>📊</span>
        <span>Dashboard-Modul ist nicht installiert.</span>
        <span style={{ fontSize: 12 }}>Installiere es im 🧩 Erweiterungen-Tab.</span>
      </div>
    );
  }

  return (
    <iframe
      srcDoc={ui}
      style={{ width: "100%", height: "100%", border: "none", background: "var(--main-bg)" }}
      title="Dashboard Extension"
      sandbox="allow-scripts"
    />
  );
}
