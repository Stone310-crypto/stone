import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Loader2 } from "lucide-react";

interface Props {
  extensionId: string;
}

export default function ExtensionFrame({ extensionId }: Props) {
  const [ui, setUI] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    setLoading(true);
    invoke<string | null>("get_extension_ui", { id: extensionId })
      .then((html) => setUI(html))
      .catch(() => setUI(null))
      .finally(() => setLoading(false));
  }, [extensionId]);

  const handleLoad = useCallback(() => {
    const iframe = iframeRef.current;
    if (!iframe?.contentWindow) return;
    try {
      (iframe.contentWindow as any).__stone_invoke = async (cmd: string, args: any) => {
        return await invoke(cmd, args);
      };
    } catch (e) {}
  }, []);

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)" }}>
        <Loader2 size={24} style={{ animation: "spin 1s linear infinite" }} />
      </div>
    );
  }

  if (!ui) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", flexDirection: "column", gap: 8 }}>
        <span style={{ fontSize: 32 }}>🧩</span>
        <span>Extension "{extensionId}" ist nicht installiert.</span>
        <span style={{ fontSize: 12 }}>Installiere sie im 🧩 Erweiterungen-Tab.</span>
      </div>
    );
  }

  return (
    <iframe
      ref={iframeRef}
      srcDoc={ui}
      onLoad={handleLoad}
      style={{ width: "100%", height: "100%", border: "none", background: "var(--main-bg)" }}
      title={`Extension: ${extensionId}`}
      sandbox="allow-scripts allow-same-origin"
    />
  );
}
