import { useState, useEffect } from "react";
import { AlertTriangle, CheckCircle, ToggleLeft, ToggleRight } from "lucide-react";
import { getStoredNetwork } from "../../hooks/useNetwork";

export default function TestnetModeView() {
  const [network, setNetwork] = useState(getStoredNetwork());
  const [nodeStatus, setNodeStatus] = useState<string>("");
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const poll = async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const raw: any = await invoke("node_get_status");
        if (typeof raw === "string") setNodeStatus(raw);
        else if (raw?.running) setNodeStatus(`Running :${raw.running.port}`);
        else if (raw?.error) setNodeStatus(raw.error.message);
        else setNodeStatus(JSON.stringify(raw));
      } catch { setNodeStatus("Node-Manager nicht verfügbar"); }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  // Sync network from health API
  useEffect(() => {
    const poll = async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const h: any = await invoke("get_node_health");
        if (h?.network === "testnet" || h?.network === "mainnet") {
          setNetwork(h.network);
          try { localStorage.setItem("stone-network-mode", h.network); } catch {}
        }
      } catch {}
    };
    const id = setInterval(poll, 10000);
    return () => clearInterval(id);
  }, []);

  async function toggleNetwork() {
    if (switching) return;
    setSwitching(true);
    setError("");
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const result: string = await invoke("switch_node_network");
      const [net, url] = result.split("|");
      setNetwork(net as any);
      try { localStorage.setItem("stone-network-mode", net); } catch {}
      try {
        const s = localStorage.getItem("stone_settings");
        const cfg = s ? JSON.parse(s) : {};
        cfg.network = net;
        cfg.nodeUrl = url;
        localStorage.setItem("stone_settings", JSON.stringify(cfg));
      } catch {}
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setSwitching(false);
    }
  }

  const isTestnet = network === "testnet";

  return (
    <div style={{ height: "100%", overflow: "auto", background: "var(--main-bg)", padding: 24, color: "var(--text)" }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>🧪 Testnet Mode</h1>
      <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 20 }}>
        Node-Status: <span style={{ color: nodeStatus.startsWith("Running") ? "var(--green)" : "var(--text-muted)" }}>{nodeStatus}</span>
      </p>

      {/* Warning/Info Banner */}
      {isTestnet ? (
        <div style={{ background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.2)", borderRadius: 10, padding: 14, marginBottom: 16, display: "flex", gap: 10, alignItems: "flex-start" }}>
          <AlertTriangle size={20} color="#f59e0b" />
          <div>
            <strong style={{ color: "#f59e0b" }}>TESTNET aktiv</strong>
            <p style={{ fontSize: 11, color: "#f59e0b", marginTop: 4 }}>Coins, Firmen, NFTs und Items sind experimentell. Keine echten Werte!</p>
          </div>
        </div>
      ) : (
        <div style={{ background: "rgba(90,158,111,0.08)", border: "1px solid rgba(90,158,111,0.2)", borderRadius: 10, padding: 14, marginBottom: 16, display: "flex", gap: 10, alignItems: "flex-start" }}>
          <CheckCircle size={20} color="#5a9e6f" />
          <div>
            <strong style={{ color: "#5a9e6f" }}>MAINNET aktiv</strong>
            <p style={{ fontSize: 11, color: "#5a9e6f", marginTop: 4 }}>Stabiler Betrieb. Alle Features verfügbar.</p>
          </div>
        </div>
      )}

      {/* Toggle */}
      <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 12, padding: 16, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={toggleNetwork} disabled={switching}
            style={{ background: "transparent", border: "none", cursor: switching ? "wait" : "pointer", padding: 0, opacity: switching ? 0.5 : 1 }}>
            {isTestnet ? <ToggleRight size={48} color="#f59e0b" /> : <ToggleLeft size={48} color="#5a9e6f" />}
          </button>
          <div>
            <div style={{ fontWeight: 600, fontSize: 14 }}>
              {switching ? "⏳ Starte neu…" : isTestnet ? "🧪 Testnet" : "✅ Mainnet"}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
              {switching ? "Node wird neugestartet…" : isTestnet ? "Port 3080 · stone-testnet" : "Port 3180 · stone-mainnet"}
            </div>
          </div>
        </div>
        {error && <div style={{ marginTop: 8, fontSize: 11, color: "var(--red)", background: "rgba(239,68,68,0.1)", padding: "8px 12px", borderRadius: 6 }}>{error}</div>}
      </div>

      {/* Feature Grid */}
      <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>🎯 Feature-Status</h2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: 8 }}>
        <FeatureCard icon="💬" name="Messenger / Chat" always />
        <FeatureCard icon="📁" name="Dateien & Storage" always />
        <FeatureCard icon="🖥️" name="Server & Gruppen" always />
        <FeatureCard icon="💰" name="Wallet & Coins" testnetOnly={isTestnet} />
        <FeatureCard icon="🏢" name="Firmen registrieren" testnetOnly={isTestnet} />
        <FeatureCard icon="💸" name="Überweisungen" testnetOnly={isTestnet} />
        <FeatureCard icon="🎮" name="Gaming & Items" testnetOnly={isTestnet} />
        <FeatureCard icon="📊" name="Marktplatz" testnetOnly={isTestnet} />
      </div>
    </div>
  );
}

function FeatureCard({ icon, name, always, testnetOnly }: { icon: string; name: string; always?: boolean; testnetOnly?: boolean }) {
  const enabled = always || testnetOnly;
  return (
    <div style={{
      background: "var(--bg-panel)", border: `1px solid ${enabled ? "rgba(90,158,111,0.2)" : "rgba(255,255,255,0.04)"}`,
      borderRadius: 10, padding: 12, textAlign: "center",
    }}>
      <span style={{ fontSize: 24, display: "block", marginBottom: 4 }}>{icon}</span>
      <div style={{ fontSize: 12, fontWeight: 600 }}>{name}</div>
      <div style={{ fontSize: 10, marginTop: 4, color: always ? "#5a9e6f" : testnetOnly ? "#f59e0b" : "var(--text-muted)" }}>
        {always ? "✅ Immer" : testnetOnly ? "🧪 Experimentell" : "🔒 Nur Testnet"}
      </div>
    </div>
  );
}
