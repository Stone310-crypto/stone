import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, X } from "lucide-react";
import { getStoredNetwork, type NetworkMode } from "../hooks/useNetwork";

interface NetworkStatus {
  chain_id: string;
  network: string;
  block_height: number;
  peer_count: number;
  node_url: string;
  testnet_url: string;
}

export default function TestnetBanner() {
  const [mode, setMode] = useState<NetworkMode>(getStoredNetwork());
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [dismissed, setDismissed] = useState(false);

  const loadStatus = useCallback(async () => {
    try {
      const s = await invoke<NetworkStatus>("get_network_status");
      setStatus(s);
      if (s.network === "testnet" || s.network === "mainnet") {
        try { localStorage.setItem("stone-network-mode", s.network); } catch {}
        setMode(s.network as NetworkMode);
      }
    } catch {
      setMode(getStoredNetwork());
    }
  }, []);

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 30_000);
    return () => clearInterval(interval);
  }, [loadStatus]);

  // Poll localStorage for changes made by the extension
  useEffect(() => {
    const check = setInterval(() => {
      const stored = getStoredNetwork();
      if (stored !== mode) {
        setMode(stored);
        setDismissed(false);
      }
    }, 2000);
    return () => clearInterval(check);
  }, [mode]);

  if (mode !== "testnet" || dismissed) return null;

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10,
      padding: "6px 14px", minHeight: 32,
      background: "rgba(245,158,11,0.08)",
      borderBottom: "1px solid rgba(245,158,11,0.2)",
      color: "#f59e0b", fontSize: 11, fontWeight: 600,
      flexShrink: 0,
    }}>
      <AlertTriangle size={13} />
      <span style={{ flex: 1 }}>
        🧪 <strong>TESTNET</strong>
        {status && status.block_height > 0 ? (
          <span style={{ marginLeft: 10, fontWeight: 400, opacity: 0.75 }}>
            Chain: {status.chain_id} · Block: #{status.block_height} · Peers: {status.peer_count}
          </span>
        ) : (
          <span style={{ marginLeft: 10, fontWeight: 400, opacity: 0.6 }}>
            Experimentelle Features in Entwicklung
          </span>
        )}
      </span>
      <button onClick={() => setDismissed(true)}
        style={{ background: "none", border: "none", color: "#f59e0b", cursor: "pointer", padding: 2, opacity: 0.5, flexShrink: 0 }}
        title="Ausblenden">
        <X size={13} />
      </button>
    </div>
  );
}
