import { useState, useEffect } from "react";
import { useAuth } from "../../auth/AuthContext";
import { Hash, Download, RefreshCw, Info } from "lucide-react";

export default function HomeView() {
  const { session } = useAuth();
  const [appVersion, setAppVersion] = useState("0.1.0");
  const [updateState, setUpdateState] = useState<"idle" | "checking" | "available" | "downloading" | "ready" | "error">("idle");
  const [updateInfo, setUpdateInfo] = useState<{ version: string; body: string } | null>(null);
  const [updateError, setUpdateError] = useState("");

  useEffect(() => {
    // App-Version aus dem Tauri-Package-Info lesen
    import("@tauri-apps/api/app").then(({ getVersion }) => {
      getVersion().then(v => setAppVersion(v)).catch(() => {});
    }).catch(() => {});
  }, []);

  async function checkForUpdate() {
    setUpdateState("checking");
    setUpdateError("");
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (update) {
        setUpdateInfo({ version: update.version, body: update.body || "" });
        setUpdateState("available");
      } else {
        setUpdateState("idle");
      }
    } catch (e: any) {
      setUpdateError(e?.message || String(e));
      setUpdateState("error");
    }
  }

  async function downloadAndInstall() {
    setUpdateState("downloading");
    setUpdateError("");
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (!update) {
        setUpdateState("idle");
        return;
      }
      await update.download();
      setUpdateState("ready");
      await update.install();
    } catch (e: any) {
      setUpdateError(e?.message || String(e));
      setUpdateState("error");
    }
  }

  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", height: "100%", gap: 24, padding: 48,
      background: "var(--main-bg)",
    }}>
      <Hash size={40} style={{ color: "var(--text-muted)", opacity: 0.3 }} />
      <div style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
          Willkommen zurück, {session?.username ?? "User"}
        </h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 8, lineHeight: 1.6 }}>
          Wähle links einen Server oder eine Direktnachricht.
          <br />
          Oben findest du Explorer, Spiele und Node.
        </p>
      </div>

      {/* ─── Version & Update ──────────────────────────────────── */}
      <div style={{
        background: "var(--bg-panel)", border: "1px solid var(--border)",
        borderRadius: 16, padding: "20px 24px", maxWidth: 400, width: "100%",
        display: "flex", flexDirection: "column", gap: 12,
      }}>
        {/* Version Row */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Info size={16} style={{ color: "var(--text-muted)" }} />
            <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Version</span>
          </div>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", fontFamily: "monospace" }}>
            v{appVersion}
          </span>
        </div>

        {/* Update Available Banner */}
        {updateState === "available" && updateInfo && (
          <div style={{
            background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.2)",
            borderRadius: 10, padding: "12px 16px",
          }}>
            <div style={{ fontWeight: 600, fontSize: 13, color: "#3b82f6", marginBottom: 4 }}>
              🆕 Update v{updateInfo.version} verfügbar
            </div>
            {updateInfo.body && (
              <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5, maxHeight: 60, overflow: "hidden" }}>
                {updateInfo.body.slice(0, 300)}
              </div>
            )}
          </div>
        )}

        {/* Downloading */}
        {updateState === "downloading" && (
          <div style={{
            background: "rgba(59,130,246,0.06)", border: "1px solid rgba(59,130,246,0.15)",
            borderRadius: 10, padding: "12px 16px", fontSize: 13, color: "#3b82f6",
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
            Update wird heruntergeladen…
          </div>
        )}

        {/* Ready */}
        {updateState === "ready" && (
          <div style={{
            background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.2)",
            borderRadius: 10, padding: "12px 16px", fontSize: 13, color: "#22c55e",
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <Download size={14} /> App startet neu für Installation…
          </div>
        )}

        {/* Error */}
        {updateState === "error" && (
          <div style={{
            background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)",
            borderRadius: 10, padding: "12px 16px", fontSize: 12, color: "#ef4444",
          }}>
            Fehler: {updateError}
          </div>
        )}

        {/* Update Button */}
        {updateState === "available" ? (
          <button onClick={downloadAndInstall}
            style={{
              width: "100%", padding: "10px", borderRadius: 10,
              background: "#3b82f6", color: "#fff", border: "none",
              fontSize: 13, fontWeight: 600, cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
            }}>
            <Download size={14} /> Update installieren
          </button>
        ) : (
          <button onClick={checkForUpdate} disabled={updateState === "checking"}
            style={{
              width: "100%", padding: "10px", borderRadius: 10,
              background: updateState === "checking" ? "var(--bg-input)" : "var(--border)",
              color: "var(--text-muted)", border: "none",
              fontSize: 13, fontWeight: 500, cursor: updateState === "checking" ? "wait" : "pointer",
              display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
            }}>
            <RefreshCw size={14} style={updateState === "checking" ? { animation: "spin 1s linear infinite" } : {}} />
            {updateState === "checking" ? "Suche Updates…" : "Nach Updates suchen"}
          </button>
        )}
      </div>
    </div>
  );
}