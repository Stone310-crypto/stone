import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function DashboardExtView() {
  const [ui, setUI] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    invoke<string | null>("get_extension_ui", { id: "dashboard" })
      .then(setUI)
      .catch(() => setUI(null));
  }, []);

  const handleLoad = useCallback(() => {
    const iframe = iframeRef.current;
    if (!iframe?.contentWindow) return;
    try {
      (iframe.contentWindow as any).__stone_invoke = async (cmd: string, args: any) => {
        return await invoke(cmd, args);
      };
    } catch (e) {}
  }, []);

  if (!ui) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", flexDirection: "column", gap: 8 }}>
        <span style={{ fontSize: 32 }}>📊</span>
        <span>Dashboard-Modul ist nicht installiert.</span>
      </div>
    );
  }

  return (
    <iframe
      ref={iframeRef}
      srcDoc={ui}
      onLoad={handleLoad}
      style={{ width: "100%", height: "100%", border: "none", background: "var(--main-bg)" }}
      title="Dashboard Extension"
      sandbox="allow-scripts allow-same-origin"
    />
  );
}
