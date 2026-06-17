import { useState, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNodeHealth } from "../../hooks/useNodeHealth";
import { useSystemStats } from "../../hooks/useSystemStats";
import { getNotifPrefs, saveNotifPrefs } from "../../hooks/useWebSocketEvents";
import { nodeManager, type NodeConfig, type NodeStatus } from "../../api/node";
import {
  ArrowLeft, X, Search, Play, Square, RefreshCw,
  Wifi, WifiOff, Server, Palette, Globe, Shield, ChevronRight
} from "lucide-react";

interface SettingsOverlayProps {
  onClose: () => void;
}

function NotificationToggles() {
  const [prefs, setPrefs] = useState(getNotifPrefs());

  function toggle(key: keyof typeof prefs) {
    const next = { ...prefs, [key]: !prefs[key] };
    setPrefs(next);
    saveNotifPrefs(next);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <span style={{ fontSize: 12, color: "var(--text-primary)" }}>Nachrichten</span>
          <p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>Benachrichtigung bei neuen Direktnachrichten</p>
        </div>
        <button onClick={() => toggle("messages")}
          style={{
            width: 40, height: 22, borderRadius: 11, border: "none", cursor: "pointer",
            background: prefs.messages ? "var(--accent)" : "rgba(255,255,255,0.12)",
            position: "relative", transition: "background 0.2s",
          }}>
          <div style={{
            width: 18, height: 18, borderRadius: "50%", background: "#fff",
            position: "absolute", top: 2,
            left: prefs.messages ? 20 : 2,
            transition: "left 0.2s",
          }} />
        </button>
      </div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <span style={{ fontSize: 12, color: "var(--text-primary)" }}>Anrufe</span>
          <p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>Benachrichtigung bei eingehenden Anrufen</p>
        </div>
        <button onClick={() => toggle("calls")}
          style={{
            width: 40, height: 22, borderRadius: 11, border: "none", cursor: "pointer",
            background: prefs.calls ? "var(--accent)" : "rgba(255,255,255,0.12)",
            position: "relative", transition: "background 0.2s",
          }}>
          <div style={{
            width: 18, height: 18, borderRadius: "50%", background: "#fff",
            position: "absolute", top: 2,
            left: prefs.calls ? 20 : 2,
            transition: "left 0.2s",
          }} />
        </button>
      </div>
    </div>
  );
}

function NodeBadge({ status }: { status: NodeStatus | null }) {
  if (!status) return null;
  const map: Record<string, { color: string; bg: string; label: string }> = {
    stopped:          { color: "var(--text-muted)", bg: "rgba(255,255,255,0.05)", label: "Gestoppt" },
    starting:         { color: "#eab308",           bg: "rgba(250,166,26,0.1)",   label: "Startet…" },
    running:          { color: "var(--green)",       bg: "rgba(59,165,92,0.1)",    label: "Läuft" },
    error:            { color: "var(--red)",         bg: "rgba(237,66,69,0.1)",    label: "Fehler" },
    binary_not_found: { color: "var(--red)",         bg: "rgba(237,66,69,0.08)",   label: "Binary fehlt" },
  };
  const s = status.status;
  const cfg = map[s] ?? map.stopped;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 8, background: cfg.bg, fontSize: 11, fontWeight: 600, color: cfg.color }}>
      <div style={{
        width: 6, height: 6, borderRadius: "50%",
        background: s === "running" ? "var(--green)" : s === "starting" ? "#eab308" : "var(--text-muted)",
        animation: s === "starting" ? "pulse 1.2s ease-in-out infinite" : "none",
      }} />
      {cfg.label}
    </div>
  );
}

type SettingsCategory = "system" | "personalization" | "notifications" | "privacy";

interface SettingsSection {
  id: string;
  category: SettingsCategory;
  label: string;
  icon: React.ReactNode;
  keywords: string[];
}

const sections: SettingsSection[] = [
  { id: "node", category: "system", label: "Lokale Node", icon: <Server size={16} />, keywords: ["node", "start", "stop", "cpu", "leistung", "mining"] },
  { id: "appearance", category: "personalization", label: "Erscheinungsbild", icon: <Palette size={16} />, keywords: ["theme", "farbe", "dark", "light", "aussehen", "design"] },
  { id: "language", category: "personalization", label: "Sprache", icon: <Globe size={16} />, keywords: ["sprache", "language", "deutsch", "english", "übersetzung"] },
  { id: "privacy", category: "privacy", label: "Datenschutz", icon: <Shield size={16} />, keywords: ["privacy", "datenschutz", "daten", "tracking", "telemetrie"] },
];

const categoryLabels: Record<SettingsCategory, string> = {
  system: "System",
  personalization: "Personalisierung",
  notifications: "Benachrichtigungen",
  privacy: "Datenschutz",
};

export default function SettingsOverlay({ onClose }: SettingsOverlayProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const health = useNodeHealth();
  const sysStats = useSystemStats(3000);
  const qc = useQueryClient();

  // ── Node state ──────────────────────────────────────────────
  const [config, setConfig] = useState<NodeConfig>({
    enabled: false, port: 3080, cpu_pct: 25, binary_path: "", seed_peers: "",
  });
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [hasTauri, setHasTauri] = useState(false);

  useEffect(() => {
    import("@tauri-apps/api/core").then(() => setHasTauri(true)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!hasTauri) return;
    nodeManager.getConfig().then(setConfig).catch(() => {});
    nodeManager.getStatus().then(setStatus).catch(() => {});
    const id = setInterval(async () => {
      try { const s = await nodeManager.getStatus(); setStatus(s); } catch {}
    }, 3_000);
    return () => clearInterval(id);
  }, [hasTauri]);

  async function toggleNode() {
    setLoading(true); setError("");
    try {
      if (status?.status === "running") { await nodeManager.stop(); }
      else { await nodeManager.start(); }
      const s = await nodeManager.getStatus(); setStatus(s);
      qc.invalidateQueries({ queryKey: ["node-health"] });
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  const isRunning = status?.status === "running";
  const filtered = searchQuery.trim()
    ? sections.filter(s => s.keywords.some(kw => kw.includes(searchQuery.toLowerCase())) || s.label.toLowerCase().includes(searchQuery.toLowerCase()))
    : sections;

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 56,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "rgba(0,0,0,0.55)",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        background: "var(--bg-panel)",
        borderRadius: 16,
        width: 480,
        maxWidth: "94vw",
        maxHeight: "85vh",
        overflowY: "auto",
        border: "1px solid var(--border-strong)",
        boxShadow: "0 16px 48px rgba(0,0,0,0.5)",
        padding: 20,
      }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <button onClick={onClose} title="Zurück"
            style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(255,255,255,0.06)", border: "none", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <ArrowLeft size={16} />
          </button>
          <h2 style={{ fontSize: 16, fontWeight: 700, flex: 1 }}>Einstellungen</h2>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
            <X size={18} />
          </button>
        </div>

        {/* Search */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 16 }}>
          <Search size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Einstellungen durchsuchen…"
            style={{
              flex: 1, background: "var(--bg-input)", border: "1px solid var(--border-default)",
              borderRadius: 8, padding: "8px 10px", fontSize: 13, color: "var(--text-primary)",
              outline: "none", boxSizing: "border-box",
            }}
            autoFocus
          />
        </div>

        {/* ── Node Section (always visible when no search) ────────── */}
        {(!searchQuery.trim() || "node".includes(searchQuery.toLowerCase())) && hasTauri && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8, letterSpacing: "0.04em" }}>
              System
            </div>

            {/* Node Status Card */}
            <div style={{
              background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 12, padding: 14, display: "flex", alignItems: "center",
              justifyContent: "space-between", gap: 12, marginBottom: 10,
            }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>Lokale Node</span>
                <NodeBadge status={status} />
              </div>
              <button onClick={toggleNode} disabled={loading || status?.status === "starting"}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "7px 14px", borderRadius: 8,
                  background: isRunning ? "rgba(237,66,69,0.15)" : "rgba(59,165,92,0.15)",
                  color: isRunning ? "var(--red)" : "var(--green)",
                  border: `1px solid ${isRunning ? "rgba(237,66,69,0.3)" : "rgba(59,165,92,0.3)"}`,
                  fontSize: 12, fontWeight: 600, cursor: loading ? "wait" : "pointer",
                }}>
                {loading ? <RefreshCw size={13} style={{ animation: "spin 0.7s linear infinite" }} /> :
                 isRunning ? <Square size={13} /> : <Play size={13} />}
                {isRunning ? "Stoppen" : "Starten"}
              </button>
            </div>

            {error && (
              <div style={{ background: "rgba(237,66,69,0.08)", borderRadius: 8, padding: "8px 10px", fontSize: 11, color: "var(--red)", marginBottom: 10 }}>
                {error}
              </div>
            )}

            {/* CPU Slider */}
            <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 12, border: "1px solid rgba(255,255,255,0.05)", marginBottom: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)" }}>CPU-Leistung</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: "var(--accent)", background: "var(--accent-bg)", borderRadius: 6, padding: "1px 8px" }}>{config.cpu_pct}%</span>
              </div>
              <input type="range" min={5} max={100} step={5} value={config.cpu_pct}
                onChange={(e) => setConfig((c) => ({ ...c, cpu_pct: Number(e.target.value) }))}
                style={{ width: "100%", accentColor: "var(--accent)", height: 4, cursor: "pointer" }} />
            </div>

            {/* System Resources */}
            {sysStats && (
              <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 12, border: "1px solid rgba(255,255,255,0.05)", marginBottom: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", display: "block", marginBottom: 10 }}>System-Auslastung</span>

                {/* System CPU */}
                <div style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Gesamt CPU</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", fontFamily: "monospace" }}>{sysStats.system_cpu_pct.toFixed(1)}%</span>
                  </div>
                  <div style={{ height: 5, borderRadius: 3, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: sysStats.system_cpu_pct > 80 ? "var(--red)" : sysStats.system_cpu_pct > 50 ? "var(--accent)" : "var(--green)", width: `${Math.min(sysStats.system_cpu_pct, 100)}%`, transition: "width 0.5s" }} />
                  </div>
                </div>

                {/* App CPU */}
                <div style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Stone App CPU</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "var(--accent)", fontFamily: "monospace" }}>{sysStats.app_cpu_pct.toFixed(1)}%</span>
                  </div>
                  <div style={{ height: 5, borderRadius: 3, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: "var(--accent)", width: `${Math.min(sysStats.app_cpu_pct, 100)}%`, transition: "width 0.5s" }} />
                  </div>
                </div>

                {/* Memory */}
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>RAM</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", fontFamily: "monospace" }}>
                      {sysStats.system_memory_used_mb} MB / {sysStats.system_memory_total_mb} MB
                    </span>
                  </div>
                  <div style={{ height: 5, borderRadius: 3, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: "var(--info)", width: `${Math.min((sysStats.system_memory_used_mb / sysStats.system_memory_total_mb) * 100, 100)}%`, transition: "width 0.5s" }} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
                    <span style={{ fontSize: 10, color: "var(--text-muted)" }}>App: {sysStats.app_memory_mb} MB</span>
                    <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{((sysStats.system_memory_used_mb / sysStats.system_memory_total_mb) * 100).toFixed(1)}%</span>
                  </div>
                </div>
              </div>
            )}

            {/* Notification Settings */}
            {(!searchQuery.trim() || "benarichtigung notification".includes(searchQuery.toLowerCase())) && (
              <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 12, border: "1px solid rgba(255,255,255,0.05)", marginBottom: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", display: "block", marginBottom: 10 }}>Benachrichtigungen</span>
                <NotificationToggles />
              </div>
            )}

            {/* Network Info */}
            <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 12, border: "1px solid rgba(255,255,255,0.05)" }}>
              <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", display: "block", marginBottom: 8 }}>Netzwerk</span>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Status</span>
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    {health.connected ? <Wifi size={11} style={{ color: "var(--green)" }} /> : <WifiOff size={11} style={{ color: "var(--text-muted)" }} />}
                    <span style={{ fontSize: 11, fontWeight: 600, color: health.connected ? "var(--green)" : "var(--text-muted)" }}>
                      {health.connected ? "Verbunden" : "Getrennt"}
                    </span>
                  </div>
                </div>
                {health.connected && (
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Block-Höhe</span>
                    <span style={{ fontSize: 11, fontFamily: "monospace", fontWeight: 600, color: "var(--text-primary)" }}>#{health.blockHeight.toLocaleString()}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ── Settings List ────────────────────────────────────── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {/* Group by category */}
          {(["system", "personalization", "notifications", "privacy"] as SettingsCategory[]).map(cat => {
            const catSections = filtered.filter(s => s.category === cat && s.id !== "node");
            if (catSections.length === 0) return null;
            return (
              <div key={cat} style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 6, letterSpacing: "0.04em" }}>
                  {categoryLabels[cat]}
                </div>
                {catSections.map((section) => (
                  <button key={section.id}
                    style={{
                      display: "flex", alignItems: "center", gap: 10,
                      width: "100%", padding: "10px 12px", borderRadius: 10,
                      background: "transparent", border: "1px solid transparent",
                      color: "var(--text-secondary)", cursor: "pointer",
                      fontSize: 13, textAlign: "left",
                      transition: "all 0.12s",
                      marginBottom: 2,
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)";
                      (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.06)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "transparent";
                      (e.currentTarget as HTMLElement).style.borderColor = "transparent";
                    }}
                  >
                    <span style={{ opacity: 0.6 }}>{section.icon}</span>
                    <span style={{ flex: 1 }}>{section.label}</span>
                    <span style={{ fontSize: 10, color: "var(--text-muted)", opacity: 0.4 }}>Coming soon</span>
                    <ChevronRight size={13} style={{ opacity: 0.3 }} />
                  </button>
                ))}
              </div>
            );
          })}
        </div>

        {searchQuery.trim() && filtered.length === 0 && (
          <p style={{ fontSize: 12, color: "var(--text-muted)", textAlign: "center", padding: 24 }}>
            Keine Einstellungen gefunden für "{searchQuery}"
          </p>
        )}

        {/* Vorschläge */}
        {!searchQuery.trim() && (
          <div style={{
            marginTop: 12, padding: 12, borderRadius: 10,
            background: "rgba(212,168,83,0.05)", border: "1px solid rgba(212,168,83,0.12)",
          }}>
            <p style={{ fontSize: 10, fontWeight: 600, color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6 }}>
              💡 Geplante Einstellungen
            </p>
            <ul style={{ fontSize: 11, color: "var(--text-muted)", paddingLeft: 16, display: "flex", flexDirection: "column", gap: 3 }}>
              <li>Dark/Light Theme & Farbakzente</li>
              <li>Sprachauswahl (DE/EN/…)</li>
              <li>Benachrichtigungen: Sound, Desktop-Push</li>
              <li>Datenschutz: Telemetrie, Datenweitergabe</li>
              <li>Auto-Start Node beim App-Start</li>
              <li>Benachrichtigung bei neuen Freunden/Messages</li>
            </ul>
          </div>
        )}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } } @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }`}</style>
    </div>
  );
}