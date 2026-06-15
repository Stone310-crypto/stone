import { useState, useEffect, type ReactElement } from "react";
import { useAuth } from "../../auth/AuthContext";
import { loadSettings, saveSettings } from "../../store/session";
import { useQueryClient } from "@tanstack/react-query";
import Avatar from "../../components/ui/Avatar";
import { nodeManager, type NodeConfig, type NodeStatus } from "../../api/node";
import { useNodeHealth } from "../../hooks/useNodeHealth";
import { LogOut, Settings, Copy, Check, User, Server, Play, Square, RefreshCw, Wifi, WifiOff } from "lucide-react";

type Panel = "profile" | "settings" | "node";

// ── Shared sub-components ─────────────────────────────────────────────────────

function SectionTitle({ children }: { children: string }) {
  return (
    <h3 style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 12, letterSpacing: "0.05em" }}>
      {children}
    </h3>
  );
}

function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactElement;
  hint?: string;
}) {
  return (
    <div>
      <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: "var(--text-dim)", marginBottom: 6 }}>
        {label}
      </label>
      {children}
      {hint && <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{hint}</p>}
    </div>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
  mono,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        width: "100%",
        padding: "9px 12px",
        borderRadius: 10,
        background: "rgba(255,255,255,0.04)",
        border: `1px solid ${focused ? "var(--accent)" : "rgba(255,255,255,0.09)"}`,
        color: "var(--text)",
        fontSize: 13,
        outline: "none",
        fontFamily: mono ? "monospace" : "inherit",
        boxShadow: focused ? "0 0 0 3px rgba(91,138,238,0.1)" : "none",
        transition: "border-color 0.15s, box-shadow 0.15s",
        boxSizing: "border-box",
      }}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      autoComplete="off"
    />
  );
}

function SaveBtn({ saved, onClick }: { saved: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "9px 20px",
        borderRadius: 10,
        background: saved ? "var(--green)" : "var(--accent)",
        color: "#fff",
        fontSize: 13,
        fontWeight: 600,
        border: "none",
        cursor: "pointer",
        transition: "background 0.2s",
      }}
    >
      {saved ? "✓ Gespeichert" : "Speichern"}
    </button>
  );
}

// ── Node status badge ─────────────────────────────────────────────────────────

function NodeBadge({ status }: { status: NodeStatus | null }) {
  if (!status) return null;

  const map: Record<string, { color: string; bg: string; label: string; dot: string }> = {
    stopped:          { color: "var(--text-muted)", bg: "rgba(255,255,255,0.05)", label: "Gestoppt",      dot: "rgba(255,255,255,0.2)" },
    starting:         { color: "var(--yellow)",     bg: "rgba(250,166,26,0.1)",   label: "Startet…",      dot: "var(--yellow)" },
    running:          { color: "var(--green)",       bg: "rgba(59,165,92,0.1)",    label: "Läuft",         dot: "var(--green)" },
    error:            { color: "var(--red)",         bg: "rgba(237,66,69,0.1)",    label: "Fehler",        dot: "var(--red)" },
    binary_not_found: { color: "var(--red)",         bg: "rgba(237,66,69,0.08)",   label: "Binary fehlt", dot: "var(--red)" },
  };

  const s = status.status;
  const cfg = map[s] ?? map.stopped;
  const label = s === "running" ? `${cfg.label} · Port ${(status as { port: number }).port}` : cfg.label;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderRadius: 10, background: cfg.bg }}>
      <div
        style={{
          width: 7,
          height: 7,
          borderRadius: "50%",
          background: cfg.dot,
          animation: s === "starting" ? "pulse 1.2s ease-in-out infinite" : s === "running" ? "pulse 3s ease-in-out infinite" : "none",
        }}
      />
      <span style={{ fontSize: 12, fontWeight: 600, color: cfg.color }}>{label}</span>
    </div>
  );
}

// ── Node panel ────────────────────────────────────────────────────────────────

function NodePanel() {
  const [config, setConfig] = useState<NodeConfig>({
    enabled: false,
    port: 3080,
    cpu_pct: 25,
    binary_path: "",
    seed_peers: "/ip4/212.227.54.241/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
  });
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const qc = useQueryClient();
  const health = useNodeHealth();

  // Tauri available?
  const [hasTauri, setHasTauri] = useState(false);

  useEffect(() => {
    import("@tauri-apps/api/core").then(() => setHasTauri(true)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!hasTauri) return;
    nodeManager.getConfig().then(setConfig).catch(() => {});
    nodeManager.getStatus().then(setStatus).catch(() => {});

    const id = setInterval(async () => {
      try {
        const s = await nodeManager.getStatus();
        setStatus(s);
      } catch {}
    }, 3_000);
    return () => clearInterval(id);
  }, [hasTauri]);

  async function handleSave() {
    setError("");
    try {
      await nodeManager.setConfig(config);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setError(String(e));
    }
  }

  async function toggleNode() {
    setLoading(true);
    setError("");
    try {
      if (status?.status === "running") {
        await nodeManager.stop();
      } else {
        await nodeManager.start();
        // Don't auto-switch nodeUrl — user decides manually in Settings tab
        // to avoid breaking QR/Discord login which needs the main server
      }
      const s = await nodeManager.getStatus();
      setStatus(s);
      qc.invalidateQueries({ queryKey: ["node-health"] });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  if (!hasTauri) {
    return (
      <div style={{ padding: "24px 0" }}>
        <p style={{ fontSize: 13, color: "var(--text-muted)", textAlign: "center" }}>
          Node-Verwaltung ist nur in der Desktop-App verfügbar.
        </p>
      </div>
    );
  }

  const isRunning = status?.status === "running";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Status + Toggle */}
      <div
        style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 14,
          padding: 16,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <p style={{ fontSize: 14, fontWeight: 700, color: "var(--text)" }}>Lokale Node</p>
          <NodeBadge status={status} />
        </div>

        <button
          onClick={toggleNode}
          disabled={loading || status?.status === "starting"}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "9px 16px",
            borderRadius: 10,
            background: isRunning ? "rgba(237,66,69,0.15)" : "rgba(59,165,92,0.15)",
            color: isRunning ? "var(--red)" : "var(--green)",
            border: `1px solid ${isRunning ? "rgba(237,66,69,0.3)" : "rgba(59,165,92,0.3)"}`,
            fontSize: 13,
            fontWeight: 600,
            cursor: loading ? "wait" : "pointer",
            transition: "all 0.15s",
          }}
        >
          {loading ? (
            <RefreshCw size={14} style={{ animation: "spin 0.7s linear infinite" }} />
          ) : isRunning ? (
            <Square size={14} />
          ) : (
            <Play size={14} />
          )}
          {isRunning ? "Stoppen" : "Starten"}
        </button>
      </div>

      {error && (
        <div
          style={{
            background: "rgba(237,66,69,0.08)",
            border: "1px solid rgba(237,66,69,0.25)",
            borderRadius: 10,
            padding: "9px 12px",
            fontSize: 12,
            color: "var(--red)",
          }}
        >
          {error}
        </div>
      )}

      {status?.status === "binary_not_found" && (
        <div
          style={{
            background: "rgba(250,166,26,0.07)",
            border: "1px solid rgba(250,166,26,0.25)",
            borderRadius: 10,
            padding: "10px 13px",
            fontSize: 12,
            color: "var(--yellow)",
            lineHeight: 1.6,
          }}
        >
          <strong>stone-master Binary nicht gefunden.</strong><br />
          Baue das Binary mit <code style={{ fontFamily: "monospace", background: "rgba(255,255,255,0.07)", padding: "1px 5px", borderRadius: 4 }}>cargo build --release --bin stone-master</code> im stone-1 Verzeichnis und gib den Pfad unten an.
        </div>
      )}

      {/* CPU Slider */}
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-dim)" }}>
            CPU-Leistung
          </label>
          <span
            style={{
              fontSize: 13,
              fontWeight: 700,
              color: config.cpu_pct > 70 ? "var(--red)" : config.cpu_pct > 40 ? "var(--yellow)" : "var(--green)",
              background: "rgba(255,255,255,0.05)",
              borderRadius: 6,
              padding: "1px 8px",
            }}
          >
            {config.cpu_pct}%
          </span>
        </div>
        <input
          type="range"
          min={5}
          max={100}
          step={5}
          value={config.cpu_pct}
          onChange={(e) => setConfig((c) => ({ ...c, cpu_pct: Number(e.target.value) }))}
          style={{
            width: "100%",
            accentColor: "var(--accent)",
            height: 4,
            cursor: "pointer",
          }}
        />
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
          <span style={{ fontSize: 10, color: "var(--text-muted)" }}>Niedrig (5%)</span>
          <span style={{ fontSize: 10, color: "var(--text-muted)" }}>Voll (100%)</span>
        </div>
      </div>

      {/* Network connection info */}
      <div
        style={{
          background: "rgba(255,255,255,0.02)",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 12,
          padding: "12px 14px",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-dim)" }}>
            Netzwerkverbindung
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            {health.connected
              ? <Wifi size={13} style={{ color: "var(--green)" }} />
              : <WifiOff size={13} style={{ color: "var(--text-muted)" }} />}
            <span style={{ fontSize: 12, fontWeight: 600, color: health.connected ? "var(--green)" : "var(--text-muted)" }}>
              {health.connected ? "Verbunden" : "Getrennt"}
            </span>
          </div>
        </div>
        {health.connected && (
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Block-Höhe</span>
            <span style={{ fontSize: 11, fontFamily: "monospace", fontWeight: 700, color: "var(--text)" }}>
              #{health.blockHeight.toLocaleString()}
            </span>
          </div>
        )}
        {health.connected && health.network && (
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Netzwerk</span>
            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-dim)" }}>
              {health.network}
            </span>
          </div>
        )}
        {isRunning && (
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Lokale Node</span>
            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--green)" }}>
              127.0.0.1:{config.port}
            </span>
          </div>
        )}
        {isRunning && (
          <p style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5, marginTop: 2 }}>
            ℹ️ Auth (Login/QR) läuft weiterhin über den konfigurierten Node URL. Für lokale API-Nutzung die URL in den Einstellungen auf http://127.0.0.1:{config.port} ändern.
          </p>
        )}
      </div>

      {/* Port */}
      <Field label="Port" hint="Testnet: 3080 · Mainnet: 8080">
        <TextInput
          value={String(config.port)}
          onChange={(v) => setConfig((c) => ({ ...c, port: Number(v) || 3080 }))}
          placeholder="3080"
          mono
        />
      </Field>

      {/* Binary path */}
      <Field label="Binary-Pfad" hint="Leer = sucht automatisch in ~/stone-1/target/release/, neben App, im PATH">
        <TextInput
          value={config.binary_path}
          onChange={(v) => setConfig((c) => ({ ...c, binary_path: v }))}
          placeholder="~/stone-1/target/release/stone-master"
          mono
        />
      </Field>

      {/* Seed peers */}
      <Field label="Seed Peers" hint="libp2p Multiaddress, kommagetrennt">
        <TextInput
          value={config.seed_peers}
          onChange={(v) => setConfig((c) => ({ ...c, seed_peers: v }))}
          placeholder="/ip4/212.227.54.241/tcp/4001/p2p/12D3KooW…"
          mono
        />
      </Field>

      <SaveBtn saved={saved} onClick={handleSave} />
    </div>
  );
}

// ── Username Field (editable inline) ─────────────────────────────────────────

function UsernameField({ initial, session }: { initial: string; session: any }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function save() {
    if (!name.trim() || name.trim() === initial) { setEditing(false); return; }
    setSaving(true);
    setError("");
    try {
      const { apiFetch } = await import("../../api/client");
      const resp = await apiFetch<any>("/api/v1/auth/profile/update", {
        method: "POST",
        body: JSON.stringify({ name: name.trim() }),
      });
      if (resp.error) { setError(resp.error); return; }
      session.username = name.trim();
      setEditing(false);
    } catch (e: any) {
      setError(e?.message ?? "Fehler");
    } finally {
      setSaving(false);
    }
  }

  if (editing) return (
    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
      <input type="text" value={name} onChange={e => setName(e.target.value)} autoFocus
        onKeyDown={e => { if (e.key === "Enter") save(); if (e.key === "Escape") { setName(initial); setEditing(false); } }}
        style={{ flex: 1, background: "var(--bg-input)", border: "1px solid var(--accent)", borderRadius: 6, padding: "4px 8px", fontSize: 17, fontWeight: 700, color: "var(--text-primary)", outline: "none" }} />
      <button onClick={save} disabled={saving} style={{ padding: "4px 10px", borderRadius: 6, background: "var(--accent)", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>✓</button>
      <button onClick={() => { setName(initial); setEditing(false); }} style={{ padding: "4px 10px", borderRadius: 6, background: "var(--bg-surface-2)", color: "var(--text-secondary)", border: "none", cursor: "pointer", fontSize: 12 }}>✕</button>
    </div>
  );

  return (
    <div>
      <h2 onClick={() => setEditing(true)} style={{ fontSize: 17, fontWeight: 700, cursor: "pointer", display: "inline-block" }}
        title="Klicken zum Bearbeiten">{name} <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 4 }}>✎</span></h2>
      {error && <p style={{ fontSize: 11, color: "var(--red)", marginTop: 2 }}>{error}</p>}
    </div>
  );
}

// ── Profile panel ─────────────────────────────────────────────────────────────

export default function ProfileView() {
  const { session, logout } = useAuth();
  const qc = useQueryClient();
  const [panel, setPanel] = useState<Panel>("profile");
  const [copied, setCopied] = useState(false);
  const settings = loadSettings();
  const [nodeUrl, setNodeUrl] = useState(settings.nodeUrl);
  const [saved, setSaved] = useState(false);

  function copyWallet() {
    if (!session) return;
    navigator.clipboard.writeText(session.walletAddress);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleSaveSettings() {
    saveSettings({ nodeUrl });
    qc.invalidateQueries();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  const navItems: [Panel, ReactElement, string][] = [
    ["profile",  <User size={14} />,   "Profil"],
    ["settings", <Settings size={14} />, "Einstellungen"],
    ["node",     <Server size={14} />,   "Node"],
  ];

  return (
    <div style={{ display: "flex", height: "100%" }}>
      {/* Panel */}
      <div
        style={{
          width: "var(--panel-w)",
          display: "flex",
          flexDirection: "column",
          background: "var(--panel-bg)",
          borderRight: "1px solid var(--border)",
          paddingTop: 14,
          flexShrink: 0,
        }}
      >
        <p
          style={{
            fontSize: 11,
            fontWeight: 600,
            textTransform: "uppercase",
            color: "var(--text-muted)",
            padding: "0 14px 10px",
            letterSpacing: "0.05em",
          }}
        >
          Konto
        </p>

        <div style={{ padding: "0 8px" }}>
          {navItems.map(([id, icon, label]) => (
            <button
              key={id}
              onClick={() => setPanel(id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 9,
                width: "100%",
                padding: "8px 10px",
                borderRadius: 10,
                fontSize: 13,
                fontWeight: 500,
                textAlign: "left",
                background: panel === id ? "rgba(255,255,255,0.07)" : "transparent",
                border: panel === id ? "1px solid rgba(255,255,255,0.08)" : "1px solid transparent",
                color: panel === id ? "var(--text)" : "var(--text-dim)",
                cursor: "pointer",
                transition: "all 0.12s",
                marginBottom: 2,
              }}
              onMouseEnter={(e) => {
                if (panel !== id) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)";
              }}
              onMouseLeave={(e) => {
                if (panel !== id) (e.currentTarget as HTMLElement).style.background = "transparent";
              }}
            >
              <span style={{ opacity: 0.7 }}>{icon}</span>
              {label}
            </button>
          ))}
        </div>

        <div style={{ flex: 1 }} />

        <button
          onClick={logout}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            margin: "0 8px 12px",
            padding: "8px 10px",
            borderRadius: 10,
            fontSize: 13,
            color: "var(--red)",
            background: "transparent",
            border: "1px solid transparent",
            cursor: "pointer",
            transition: "all 0.12s",
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "rgba(237,66,69,0.1)";
            (e.currentTarget as HTMLElement).style.borderColor = "rgba(237,66,69,0.2)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "transparent";
            (e.currentTarget as HTMLElement).style.borderColor = "transparent";
          }}
        >
          <LogOut size={14} />
          Abmelden
        </button>
      </div>

      {/* Main */}
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "24px 28px",
          background: "var(--main-bg)",
        }}
      >
        {panel === "profile" && session && (
          <div style={{ maxWidth: 380 }}>
            <div style={{ borderRadius: 16, overflow: "hidden", border: "1px solid var(--border-strong)", background: "var(--bg-surface)" }}>
              <div style={{ height: 80, background: "linear-gradient(135deg, #d4a853, #c9953a)" }} />
              <div style={{ padding: "0 18px 18px" }}>
                <div style={{ marginTop: -28, marginBottom: 12 }}>
                  <Avatar name={session.username} size={52} online />
                </div>

                {/* Username — editable */}
                <UsernameField initial={session.username} session={session} />

                <p style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace", marginTop: 4 }}>{session.userId}</p>

                <div style={{ marginTop: 14, background: "var(--bg-input)", border: "1px solid var(--border-default)", borderRadius: 10, padding: "10px 12px" }}>
                  <p style={{ fontSize: 11, fontWeight: 500, color: "var(--text-muted)", marginBottom: 5 }}>Wallet Adresse</p>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <p style={{ fontFamily: "monospace", fontSize: 12, color: "var(--text-primary)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{session.walletAddress}</p>
                    <button onClick={copyWallet} style={{ flexShrink: 0, padding: 6, borderRadius: 8, background: "var(--bg-hover)", border: "1px solid var(--border-default)", color: copied ? "var(--green)" : "var(--text-muted)", cursor: "pointer" }}>
                      {copied ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {panel === "settings" && (
          <div style={{ maxWidth: 360, display: "flex", flexDirection: "column", gap: 20 }}>
            <SectionTitle>Verbindung</SectionTitle>

            <Field label="Node URL" hint="Standard: http://212.227.54.241:3080">
              <TextInput
                value={nodeUrl}
                onChange={(v) => { setNodeUrl(v); setSaved(false); }}
                mono
              />
            </Field>

            <SaveBtn saved={saved} onClick={handleSaveSettings} />
          </div>
        )}

        {panel === "node" && (
          <div style={{ maxWidth: 400 }}>
            <SectionTitle>Eingebettete Node</SectionTitle>
            <NodePanel />
          </div>
        )}
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(0.8); }
        }
      `}</style>
    </div>
  );
}
