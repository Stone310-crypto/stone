import { useState, useRef, useEffect } from "react";
import type { PluginInstance } from "../../types/plugin";

interface IframePluginProps {
  plugin: PluginInstance;
}

export default function IframePlugin({ plugin }: IframePluginProps) {
  const url = String(plugin.config.url ?? "");
  const h = Number(plugin.config.height ?? 600);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [debugOpen, setDebugOpen] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [loadState, setLoadState] = useState<"idle" | "loading" | "loaded" | "blocked" | "error">("idle");
  const [errorDetail, setErrorDetail] = useState<string>("");
  const [blame, setBlame] = useState<string>("");
  const [checkTimer, setCheckTimer] = useState<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onCsp = (e: SecurityPolicyViolationEvent) => {
      addLog(`🔒 CSP-Violation: ${e.blockedURI} (${e.violatedDirective})`);
    };
    document.addEventListener("securitypolicyviolation", onCsp);
    return () => {
      document.removeEventListener("securitypolicyviolation", onCsp);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => { if (checkTimer) clearTimeout(checkTimer); };
  }, [checkTimer]);

  function addLog(msg: string) {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev.slice(-49), `${time} ${msg}`]);
  }

  function handleIframeLoad() {
    addLog("✅ iFrame onLoad gefeuert");
    // Wait 500ms then inspect the document
    const timer = setTimeout(() => {
      try {
        const doc = iframeRef.current?.contentDocument;
        const win = iframeRef.current?.contentWindow;
        if (!doc || !win) {
          addLog("🔒 contentDocument/contentWindow = null → Cross-Origin-Block");
          setBlame("Die Seite verweigert Cross-Origin-Zugriff. Sie kann nicht im iFrame inspiziert werden.");
          setLoadState("blocked");
          return;
        }
        const bodyLen = doc.body?.innerHTML?.length ?? 0;
        const hasVisible = doc.body?.innerText?.trim().length ?? 0;
        addLog(`📄 body: ${bodyLen} bytes HTML, ${hasVisible} chars Text`);
        if (bodyLen < 200 || hasVisible < 10) {
          addLog("🚫 iFrame-Inhalt ist leer → X-Frame-Options oder frame-ancestors blockiert");
          setBlame("Die Ziel-Website verbietet das Einbetten in iFrames (X-Frame-Options: DENY / frame-ancestors 'none').");
          setLoadState("blocked");
        } else {
          addLog("✅ iFrame hat sichtbaren Inhalt");
          setLoadState("loaded");
        }
      } catch (err: any) {
        addLog(`🔒 Inspektion fehlgeschlagen: ${err.message}`);
        setBlame("Cross-Origin-Isolation: Die Seite kann nicht aus dem iFrame heraus inspiziert werden.");
        setLoadState("blocked");
      }
    }, 500);
    setCheckTimer(timer);
  }

  function handleIframeError() {
    setLoadState("error");
    setErrorDetail("iFrame onError ausgelöst");
    addLog("❌ iFrame-Fehler – Seite konnte nicht geladen werden");
  }

  async function openInWindow() {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("plugin_open_window", { url, title: plugin.name });
      addLog("🪟 Neues Fenster geöffnet");
    } catch {
      try {
        window.open(url, "_blank");
        addLog("🪟 window.open als Fallback");
      } catch {
        addLog("❌ Fenster konnte nicht geöffnet werden");
      }
    }
  }

  if (!url) {
    return (
      <div
        style={{
          background: "var(--bg-surface)",
          borderRadius: 12,
          padding: 24,
          textAlign: "center",
          color: "var(--text-muted)",
          fontSize: 13,
          border: "1px solid var(--border-subtle)",
        }}
      >
        ⚙️ Keine URL konfiguriert — in den Plugin-Einstellungen setzen.
      </div>
    );
  }

  if (loadState === "idle") {
    setLoadState("loading");
    addLog(`🔄 Lade: ${url}`);
  }

  const statusColor = loadState === "loaded" ? "var(--green)" : loadState === "blocked" ? "var(--yellow)" : loadState === "error" ? "var(--red)" : "var(--yellow)";
  const statusLabel = loadState === "loaded" ? "Geladen" : loadState === "blocked" ? "Geblockt" : loadState === "error" ? "Fehler" : "Lädt…";

  return (
    <div style={{ position: "relative", width: "100%" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 10px",
          background: "var(--bg-surface)",
          border: "1px solid var(--border-subtle)",
          borderBottom: "none",
          borderRadius: "8px 8px 0 0",
          fontSize: 11,
        }}
      >
        <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: statusColor }} />
        <span style={{ color: "var(--text-muted)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{url}</span>
        <span style={{ fontSize: 10, color: statusColor, fontWeight: 600 }}>{statusLabel}</span>
        <button onClick={openInWindow} style={{ padding: "3px 8px", borderRadius: 4, border: "none", background: "var(--accent)", color: "#fff", cursor: "pointer", fontSize: 10, fontWeight: 600 }}>🪟 Fenster</button>
        <button onClick={() => setDebugOpen(!debugOpen)} style={{ padding: "3px 8px", borderRadius: 4, border: "none", background: debugOpen ? "var(--accent)" : "var(--bg-hover)", color: debugOpen ? "#fff" : "var(--text-muted)", cursor: "pointer", fontSize: 10, fontWeight: 600 }}>{debugOpen ? "✕ Debug" : "🐛 Debug"}</button>
      </div>

      {debugOpen && (
        <div style={{ background: "#0d1117", border: "1px solid var(--border-subtle)", borderTop: "none", padding: 8, maxHeight: 200, overflowY: "auto", fontFamily: "'SF Mono', 'Fira Code', monospace", fontSize: 10, lineHeight: 1.5 }}>
          <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>
            Status: <span style={{ color: statusColor }}>{loadState}</span>
            {" · "}URL: <span style={{ wordBreak: "break-all" }}>{url}</span>
          </div>
          {errorDetail && <div style={{ color: "var(--red)", marginBottom: 4 }}>{errorDetail}</div>}
          {blame && <div style={{ color: "var(--yellow)", marginBottom: 4, background: "rgba(250,166,26,0.1)", padding: "4px 6px", borderRadius: 4 }}>{blame}</div>}
          <div style={{ color: "#8b949e" }}>
            <strong>Log:</strong>
            {logs.length === 0 && <div style={{ color: "#484f58", fontStyle: "italic" }}>Keine Einträge</div>}
            {logs.map((l, i) => (<div key={i}>{l}</div>))}
          </div>
        </div>
      )}

      <div style={{ borderRadius: debugOpen ? "0 0 8px 8px" : 8, overflow: "hidden", border: "1px solid var(--border-subtle)", borderTop: "none", background: "#fff", width: "100%" }}>
        {loadState === "loading" && <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, background: "rgba(0,0,0,0.02)" }}><span style={{ color: "var(--text-muted)", fontSize: 12 }}>Lade…</span></div>}
        {loadState === "blocked" && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: 200, gap: 12, padding: 24 }}>
            <div style={{ fontSize: 28 }}>🚫</div>
            <p style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", textAlign: "center" }}>Einbetten nicht möglich</p>
            <p style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center" }}>{blame || "Die Seite blockiert iFrame-Einbettung (X-Frame-Options / CSP frame-ancestors)."}</p>
            <button onClick={openInWindow} style={{ padding: "8px 20px", borderRadius: 8, border: "none", background: "var(--accent)", color: "#fff", cursor: "pointer", fontSize: 13, fontWeight: 600 }}>🪟 In eigenem Fenster öffnen</button>
          </div>
        )}
        <iframe
          ref={iframeRef}
          src={url}
          title={plugin.name}
          style={{ width: "100%", height: h > 0 ? h : 600, border: "none", display: loadState === "blocked" ? "none" : "block", position: "relative", zIndex: 0 }}
          onLoad={handleIframeLoad}
          onError={handleIframeError}
        />
      </div>
    </div>
  );
}
