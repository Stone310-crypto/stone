import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useNodeHealth } from "../../hooks/useNodeHealth";
import { getStoredNetwork } from "../../hooks/useNetwork";
import { useAuth } from "../../auth/AuthContext";
import {
  X, Play, Square, Cpu, Hash, Zap, AlertTriangle,
  Loader2, ChevronDown, ChevronUp, Wallet, Edit3, Save, Check,
} from "lucide-react";

interface MinerStats {
  hashrate: number;
  blocks_found: number;
  earned: string;
  active: boolean;
  throttle_pct: number;
  cpu_cores: number;
  difficulty: number;
  block_height: number;
  autostart: boolean;
}

interface Props {
  onClose: () => void;
}

const STORAGE_KEY = "stone-miner-config";

interface MinerConfig {
  cpu_cores: number;
  priority: number; // 1-4 (niedrig → hoch)
  autostart: boolean;
  payout_wallet?: string;
}

function loadMinerConfig(): MinerConfig {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : { cpu_cores: 4, priority: 2, autostart: false };
  } catch {
    return { cpu_cores: 4, priority: 2, autostart: false };
  }
}

function saveMinerConfig(cfg: MinerConfig) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg)); } catch {}
}

function formatHashrate(h: number): string {
  if (h >= 1_000_000) return `${(h / 1_000_000).toFixed(1)} MH/s`;
  if (h >= 1_000) return `${(h / 1_000).toFixed(0)} kH/s`;
  return `${h.toFixed(0)} H/s`;
}

function formatEarned(s: string): string {
  if (!s || s === "0") return "0";
  const n = parseFloat(s);
  if (isNaN(n)) return s;
  return n < 0.001 ? n.toFixed(6) : n.toFixed(3);
}

export default function PowerUserPanel({ onClose }: Props) {
  const { connected, blockHeight } = useNodeHealth();
  const { session } = useAuth();
  const network = getStoredNetwork();
  const isTestnet = network === "testnet";
  const detectedWallet = session?.walletAddress ?? "";

  const [cfg, setCfg] = useState<MinerConfig>(loadMinerConfig);
  const [stats, setStats] = useState<MinerStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(true);

  // Payout wallet
  const [payoutWallet, setPayoutWallet] = useState(detectedWallet);
  const [editingWallet, setEditingWallet] = useState(false);
  const [walletInput, setWalletInput] = useState("");
  const [walletSaved, setWalletSaved] = useState(false);

  // Load miner config from backend on mount
  useEffect(() => {
    invoke<MinerConfig>("miner_get_config").then((c) => {
      if (c) {
        setCfg({ cpu_cores: c.cpu_cores || 4, priority: c.priority || 2, autostart: c.autostart || false, payout_wallet: c.payout_wallet });
        if (c.payout_wallet) setPayoutWallet(c.payout_wallet);
      }
    }).catch(() => {});
  }, []);

  const refreshStats = useCallback(async () => {
    try {
      const s = await invoke<MinerStats>("miner_status");
      setStats(s);
      setError(null);
    } catch {
      // Miner not running or command not available
      setStats(null);
    }
  }, []);

  useEffect(() => {
    refreshStats();
    const iv = setInterval(refreshStats, 5000);
    return () => clearInterval(iv);
  }, [refreshStats]);

  const handleStart = async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await invoke("miner_start", {
        config: {
          cpu_cores: cfg.cpu_cores,
          priority: cfg.priority,
          network: isTestnet ? "testnet" : "mainnet",
        },
      });
      setSuccessMsg("⛏️ Miner gestartet — suche nach Blöcken...");
      setTimeout(refreshStats, 2000);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await invoke("miner_stop");
      setSuccessMsg("⏹ Miner gestoppt");
      setTimeout(refreshStats, 2000);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleCfgChange = (partial: Partial<MinerConfig>) => {
    const updated = { ...cfg, ...partial };
    setCfg(updated);
    saveMinerConfig(updated);
  };

  const handleSaveWallet = async () => {
    const w = walletInput.trim();
    if (!w || w.length !== 64) {
      setError("Wallet-Adresse muss 64 Hex-Zeichen lang sein");
      return;
    }
    try {
      await invoke("miner_set_payout_wallet", { wallet: w });
      setPayoutWallet(w);
      setEditingWallet(false);
      setWalletSaved(true);
      setError(null);
      setTimeout(() => setWalletSaved(false), 2500);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  };

  const startEditWallet = () => {
    setWalletInput(payoutWallet);
    setEditingWallet(true);
  };

  const priorityLabels = ["Niedrig", "Mittel", "Hoch", "Maximal"];
  const priorityColors = ["var(--green)", "var(--blue)", "var(--amber)", "var(--red)"];

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "rgba(0,0,0,0.6)",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        background: "var(--bg-panel)",
        borderRadius: 16,
        width: 520,
        maxWidth: "94vw",
        maxHeight: "90vh",
        overflowY: "auto",
        border: "1px solid var(--border-strong)",
        boxShadow: "0 20px 60px rgba(0,0,0,0.6)",
      }}>
        {/* ── Header ─────────────────────────────────────── */}
        <div style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "16px 20px",
          borderBottom: "1px solid var(--border)",
          background: "rgba(255,255,255,0.02)",
        }}>
          <span style={{ fontSize: 20 }}>⚙️</span>
          <h2 style={{ fontSize: 16, fontWeight: 700, flex: 1 }}>PowerUser-Bereich</h2>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 10,
            background: isTestnet ? "rgba(245,158,11,0.15)" : "rgba(90,158,111,0.15)",
            color: isTestnet ? "#f59e0b" : "var(--green)",
            border: `1px solid ${isTestnet ? "rgba(245,158,11,0.3)" : "rgba(90,158,111,0.3)"}`,
          }}>
            {isTestnet ? "🧪 TESTNET" : "✅ MAINNET"}
          </span>
          <span style={{
            fontSize: 9, fontWeight: 700, padding: "2px 8px", borderRadius: 10,
            background: stats?.active ? "rgba(90,158,111,0.15)" : "rgba(255,255,255,0.06)",
            color: stats?.active ? "var(--green)" : "var(--text-muted)",
          }}>
            {stats?.active ? "⚡ AKTIV" : "⏸ INACTIVE"}
          </span>
          <button
            onClick={onClose}
            style={{
              width: 28, height: 28, borderRadius: 7,
              background: "rgba(255,255,255,0.06)", border: "none",
              color: "var(--text-muted)", cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            <X size={15} />
          </button>
        </div>

        <div style={{ padding: 20 }}>
          {/* ── Miner-Steuerung ──────────────────────────── */}
          <div style={{ marginBottom: 20 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
              <Cpu size={14} /> Miner-Steuerung
            </h3>
            <div style={{ display: "flex", gap: 10 }}>
              <button
                onClick={handleStart}
                disabled={loading || stats?.active}
                style={{
                  flex: 1, padding: "10px 16px", borderRadius: 10,
                  background: stats?.active ? "rgba(255,255,255,0.04)" : "var(--green)",
                  border: stats?.active ? "1px solid var(--border)" : "none",
                  color: stats?.active ? "var(--text-muted)" : "#fff",
                  cursor: stats?.active ? "default" : "pointer",
                  fontSize: 13, fontWeight: 600,
                  display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                  opacity: stats?.active ? 0.5 : (loading ? 0.6 : 1),
                }}
              >
                {loading ? <Loader2 size={15} style={{ animation: "spin 0.7s linear infinite" }} /> : <Play size={15} />}
                Starte Miner
              </button>
              <button
                onClick={handleStop}
                disabled={loading || !stats?.active}
                style={{
                  flex: 1, padding: "10px 16px", borderRadius: 10,
                  background: stats?.active ? "var(--red)" : "rgba(255,255,255,0.04)",
                  border: stats?.active ? "none" : "1px solid var(--border)",
                  color: stats?.active ? "#fff" : "var(--text-muted)",
                  cursor: stats?.active ? "pointer" : "default",
                  fontSize: 13, fontWeight: 600,
                  display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                  opacity: stats?.active ? (loading ? 0.6 : 1) : 0.5,
                }}
              >
                {loading ? <Loader2 size={15} style={{ animation: "spin 0.7s linear infinite" }} /> : <Square size={15} />}
                Stoppe Miner
              </button>
            </div>
            {error && (
              <div style={{ marginTop: 8, padding: "8px 12px", borderRadius: 8, background: "rgba(237,66,69,0.08)", border: "1px solid rgba(237,66,69,0.2)", fontSize: 11, color: "var(--red)" }}>
                {error}
              </div>
            )}
            {successMsg && (
              <div style={{ marginTop: 8, padding: "8px 12px", borderRadius: 8, background: "rgba(90,158,111,0.08)", border: "1px solid rgba(90,158,111,0.2)", fontSize: 11, color: "var(--green)" }}>
                {successMsg}
              </div>
            )}
          </div>

          {/* ── Auszahlungs-Wallet ───────────────────────── */}
          <div style={{ marginBottom: 20 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
              <Wallet size={14} /> Auszahlungs-Adresse
            </h3>
            <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 12, border: "1px solid var(--border)" }}>
              {editingWallet ? (
                <div style={{ display: "flex", gap: 6 }}>
                  <input
                    type="text"
                    value={walletInput}
                    onChange={(e) => setWalletInput(e.target.value)}
                    placeholder="64-stellige Hex-Wallet-Adresse…"
                    style={{
                      flex: 1, background: "var(--bg-input)", border: "1px solid var(--border-default)",
                      borderRadius: 8, padding: "8px 10px", fontSize: 12, fontFamily: "monospace",
                      color: "var(--text-primary)", outline: "none",
                    }}
                    autoFocus
                  />
                  <button
                    onClick={handleSaveWallet}
                    style={{
                      padding: "8px 12px", borderRadius: 8,
                      background: "var(--accent)", border: "none", color: "#fff",
                      cursor: "pointer", fontWeight: 600, fontSize: 11,
                      display: "flex", alignItems: "center", gap: 4,
                    }}
                  >
                    <Save size={12} /> Speichern
                  </button>
                </div>
              ) : (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    {payoutWallet ? (
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{
                          fontSize: 11, fontFamily: "monospace", color: "var(--text-primary)",
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                        }}>
                          {payoutWallet.slice(0, 16)}…{payoutWallet.slice(-8)}
                        </span>
                        {detectedWallet === payoutWallet && (
                          <span style={{ fontSize: 9, color: "var(--green)", fontWeight: 600, flexShrink: 0 }}>👤 Dein Profil</span>
                        )}
                        {walletSaved && (
                          <span style={{ fontSize: 9, color: "var(--green)", display: "flex", alignItems: "center", gap: 2, flexShrink: 0 }}>
                            <Check size={10} /> Gespeichert
                          </span>
                        )}
                      </div>
                    ) : (
                      <span style={{ fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}>
                        Keine Adresse konfiguriert
                      </span>
                    )}
                  </div>
                  <button
                    onClick={startEditWallet}
                    style={{
                      padding: "5px 10px", borderRadius: 6,
                      background: "rgba(255,255,255,0.06)", border: "1px solid var(--border-default)",
                      color: "var(--text-secondary)", cursor: "pointer", fontSize: 11,
                      display: "flex", alignItems: "center", gap: 4, flexShrink: 0,
                    }}
                  >
                    <Edit3 size={11} /> {payoutWallet ? "Ändern" : "Hinzufügen"}
                  </button>
                </div>
              )}
              {!payoutWallet && !editingWallet && (
                <div style={{ marginTop: 8, padding: "6px 10px", borderRadius: 6, background: "rgba(245,158,11,0.06)", fontSize: 10, color: "#f59e0b" }}>
                  ⚠️ Ohne Auszahlungs-Adresse können Mining-Rewards nicht gutgeschrieben werden.
                </div>
              )}
            </div>
          </div>

          {/* ── Einstellungen ────────────────────────────── */}
          <div style={{ marginBottom: 20 }}>
            <div
              onClick={() => setExpanded(!expanded)}
              style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: expanded ? 12 : 0, cursor: "pointer", userSelect: "none" }}
            >
              <h3 style={{ fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", gap: 6, flex: 1 }}>
                <Zap size={14} /> Einstellungen
              </h3>
              {expanded ? <ChevronUp size={14} style={{ color: "var(--text-muted)" }} /> : <ChevronDown size={14} style={{ color: "var(--text-muted)" }} />}
            </div>

            {expanded && (
              <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 14, border: "1px solid var(--border)" }}>
                {/* CPU-Kerne */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                  <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>CPU-Kerne</span>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <input
                      type="range"
                      min={1} max={16} value={cfg.cpu_cores}
                      onChange={(e) => handleCfgChange({ cpu_cores: parseInt(e.target.value) })}
                      style={{ width: 100, accentColor: "var(--accent)" }}
                    />
                    <span style={{ fontSize: 12, fontWeight: 700, fontFamily: "monospace", color: "var(--text-primary)", minWidth: 20, textAlign: "center" }}>
                      {cfg.cpu_cores}
                    </span>
                  </div>
                </div>

                {/* Mining-Priorität */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                  <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Mining-Priorität</span>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <div style={{ display: "flex", gap: 2 }}>
                      {[1, 2, 3, 4].map((p) => (
                        <div key={p} style={{
                          width: 18, height: 8, borderRadius: 4,
                          background: p <= cfg.priority ? priorityColors[p - 1] : "rgba(255,255,255,0.1)",
                          cursor: "pointer",
                          transition: "all 0.15s",
                        }}
                        onClick={() => handleCfgChange({ priority: p })}
                        title={`Priorität ${p}: ${priorityLabels[p - 1]}`}
                        />
                      ))}
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: priorityColors[cfg.priority - 1], minWidth: 60 }}>
                      {priorityLabels[cfg.priority - 1]}
                    </span>
                  </div>
                </div>

                {/* Autostart */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Autostart bei Systemstart</span>
                  <button
                    onClick={() => handleCfgChange({ autostart: !cfg.autostart })}
                    style={{
                      width: 40, height: 22, borderRadius: 11,
                      background: cfg.autostart ? "var(--green)" : "rgba(255,255,255,0.12)",
                      border: "none", cursor: "pointer",
                      position: "relative", transition: "background 0.2s",
                    }}
                  >
                    <div style={{
                      position: "absolute", top: 2,
                      left: cfg.autostart ? 20 : 2,
                      width: 18, height: 18, borderRadius: "50%",
                      background: "#fff",
                      transition: "left 0.2s",
                    }} />
                  </button>
                </div>

                {/* Testnet Hinweis */}
                {isTestnet && (
                  <div style={{ marginTop: 12, padding: "8px 12px", borderRadius: 8, background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.2)", fontSize: 11, color: "#f59e0b", display: "flex", alignItems: "flex-start", gap: 6 }}>
                    <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                    <span>🧪 Testnet-Mining: Keine echten Werte! Rewards sind experimentell.</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ── Statistiken ──────────────────────────────── */}
          {stats && (
            <div style={{ marginBottom: 16 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
                📊 Statistiken
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {/* Hashrate */}
                <div style={{ background: "rgba(255,255,255,0.03)", borderRadius: 10, padding: 12, border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}>⚡ Hashrate</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: "var(--text-primary)" }}>
                    {formatHashrate(stats.hashrate)}
                  </div>
                </div>

                {/* Gefundene Blöcke */}
                <div style={{ background: "rgba(255,255,255,0.03)", borderRadius: 10, padding: 12, border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}>🧱 Gefundene Blöcke</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: "var(--text-primary)" }}>
                    {stats.blocks_found}
                  </div>
                </div>

                {/* Verdient */}
                <div style={{ background: "rgba(255,255,255,0.03)", borderRadius: 10, padding: 12, border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}>💰 Verdient</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: "var(--accent)" }}>
                    {formatEarned(stats.earned)} STONE
                  </div>
                </div>

                {/* Difficulty */}
                <div style={{ background: "rgba(255,255,255,0.03)", borderRadius: 10, padding: 12, border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}>🎯 Difficulty</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: "var(--text-primary)" }}>
                    {stats.difficulty}
                  </div>
                </div>
              </div>

              {/* Network context */}
              <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--text-muted)" }}>
                <Hash size={12} />
                <span>Mining auf <strong style={{ color: isTestnet ? "#f59e0b" : "var(--green)" }}>{isTestnet ? "TESTNET" : "MAINNET"}</strong> · Block #{stats.block_height > 0 ? stats.block_height : blockHeight}</span>
              </div>
            </div>
          )}

          {/* No stats yet */}
          {!stats && !loading && (
            <div style={{ textAlign: "center", padding: 24, color: "var(--text-muted)", fontSize: 12 }}>
              <div style={{ fontSize: 32, marginBottom: 8 }}>⛏️</div>
              Miner ist nicht aktiv.<br />
              Starte den Miner um Statistiken zu sehen.
            </div>
          )}

          {loading && !stats && (
            <div style={{ textAlign: "center", padding: 24, color: "var(--text-muted)" }}>
              <Loader2 size={24} style={{ animation: "spin 0.7s linear infinite", marginBottom: 8 }} />
              <div style={{ fontSize: 12 }}>Starte Miner…</div>
            </div>
          )}

          {/* ── Warnung ──────────────────────────────────── */}
          <div style={{
            background: "rgba(245,158,11,0.06)",
            border: "1px solid rgba(245,158,11,0.2)",
            borderRadius: 10,
            padding: 12,
            display: "flex", alignItems: "flex-start", gap: 8,
          }}>
            <AlertTriangle size={14} style={{ color: "#f59e0b", flexShrink: 0, marginTop: 1 }} />
            <div style={{ fontSize: 11, color: "#f59e0b", lineHeight: 1.5 }}>
              <strong>Achtung:</strong> Mining verbraucht Energie und kann die CPU
              belasten. Nutze es mit Bedacht. Mining-Rewards werden täglich auf
              deine Payout-Wallet ausgezahlt.
            </div>
          </div>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
