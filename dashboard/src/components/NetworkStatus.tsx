import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Activity, Server, Globe } from "lucide-react";

interface NetworkStatus {
  chain_id: string;
  network: string;
  block_height: number;
  peer_count: number;
  node_url: string;
  testnet_url: string;
}

/** Small network status indicator for the NavRail or toolbar. */
export default function NetworkStatusIndicator() {
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [expanded, setExpanded] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await invoke<NetworkStatus>("get_network_status"));
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, [load]);

  const isTestnet = status?.network === "testnet";
  const color = isTestnet ? "#f59e0b" : "var(--green)";
  const bg = isTestnet ? "rgba(245,158,11,0.12)" : "rgba(90,158,111,0.12)";
  const label = isTestnet ? "Testnet" : status?.network === "mainnet" ? "Mainnet" : "Offline";
  const icon = status?.peer_count ? <Activity size={10} /> : <Server size={10} />;

  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex", alignItems: "center", gap: 4,
          padding: "3px 8px", borderRadius: 10,
          background: bg, border: "none",
          color, fontSize: 10, fontWeight: 600,
          cursor: "pointer",
        }}
        title={status ? `${status.chain_id} · Block #${status.block_height} · ${status.peer_count} Peers` : "Netzwerk wird geladen..."}
      >
        {icon}
        {label}
        {status && <span style={{ opacity: 0.6 }}>·</span>}
        {status && <span style={{ opacity: 0.6 }}>#{status.block_height}</span>}
      </button>

      {expanded && status && (
        <div style={{
          position: "absolute", bottom: "100%", left: 0, marginBottom: 4,
          background: "var(--bg-panel)", border: "1px solid var(--border-default)",
          borderRadius: 8, padding: "10px 14px", fontSize: 11, minWidth: 200,
          zIndex: 50, boxShadow: "0 4px 16px rgba(0,0,0,0.3)",
          color: "var(--text-primary)",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
            <Globe size={12} style={{ color }} />
            <strong>{status.chain_id}</strong>
          </div>
          <div style={{ color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: 2 }}>
            <span>Block: #{status.block_height}</span>
            <span>Peers: {status.peer_count}</span>
            <span style={{ fontFamily: "monospace", fontSize: 10, opacity: 0.6 }}>{status.node_url}</span>
          </div>
          {isTestnet && (
            <div style={{ marginTop: 4, fontSize: 10, color: "#f59e0b", opacity: 0.8 }}>
              ⚠️ Experimentelle Features aktiv
            </div>
          )}
        </div>
      )}
    </div>
  );
}
