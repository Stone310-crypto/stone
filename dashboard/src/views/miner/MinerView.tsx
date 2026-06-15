import { useQuery } from "@tanstack/react-query";
import { mining as miningApi, node } from "../../api/stone";
import { Coins, Link } from "lucide-react";
import { useEffect, useRef, useState } from "react";

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div
      className="rounded-xl p-4"
      style={{
        background: "var(--surface)",
        border: `1px solid ${accent ? "var(--accent)" : "var(--border)"}`,
      }}
    >
      <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>{label}</p>
      <p
        className="text-xl font-bold tabular-nums"
        style={{ color: accent ? "var(--accent)" : "var(--text)" }}
      >
        {value}
      </p>
    </div>
  );
}

// ── Node Terminal (Live-Console) ─────────────────────────────────────
function NodeTerminal() {
  const [logs, setLogs] = useState<string[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    pollingRef.current = setInterval(async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const newLogs: string[] = await invoke("node_get_logs");
        if (newLogs.length > 0) {
          setLogs((prev) => [...prev, ...newLogs].slice(-500));
        }
      } catch {
        // Tauri not available — ignore
      }
    }, 500);

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  return (
    <div className="mt-6">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold uppercase" style={{ color: "var(--text-muted)" }}>
          Node Console
        </p>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1 text-xs cursor-pointer" style={{ color: "var(--text-muted)" }}>
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={() => setAutoScroll(!autoScroll)}
              style={{ accentColor: "var(--accent)" }}
            />
            Auto-Scroll
          </label>
          <button
            onClick={() => setLogs([])}
            className="text-xs px-2 py-1 rounded hover:opacity-80"
            style={{ background: "var(--surface)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            Clear
          </button>
        </div>
      </div>
      <div
        className="rounded-lg p-4 overflow-y-auto font-mono text-xs leading-relaxed"
        style={{
          background: "#0a0b0f",
          border: "1px solid var(--border)",
          maxHeight: 320,
          minHeight: 120,
        }}
      >
        {logs.length === 0 && (
          <span style={{ color: "var(--text-muted)", opacity: 0.5 }}>
            Warte auf Node-Logs… (Node muss gestartet sein)
          </span>
        )}
        {logs.map((line, i) => {
          const isError = line.startsWith("[err]");
          const isOut = line.startsWith("[out]");
          return (
            <div
              key={i}
              style={{
                color: isError ? "#ef4444" : isOut ? "var(--text-dim)" : "var(--text-muted)",
                opacity: isOut ? 0.85 : 1,
              }}
            >
              {line}
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

export default function MinerView() {
  const miningQ = useQuery({
    queryKey: ["mining-status"],
    queryFn: miningApi.status,
    refetchInterval: 10_000,
  });

  const healthQ = useQuery({
    queryKey: ["health"],
    queryFn: node.health,
    refetchInterval: 10_000,
  });

  const m = miningQ.data?.mining;

  return (
    <div className="flex h-full">
      {/* Panel */}
      <div
        className="flex flex-col shrink-0"
        style={{
          width: "var(--panel-w)",
          background: "var(--panel-bg)",
          borderRight: "1px solid var(--border)",
          paddingTop: 16,
        }}
      >
        <p className="text-xs font-semibold uppercase px-4 mb-3" style={{ color: "var(--text-muted)" }}>
          Mining
        </p>
        <div className="px-4 py-3 mx-2 rounded-lg mb-2" style={{ background: "var(--surface)" }}>
          <div className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full"
              style={{ background: m?.is_mining ? "var(--green)" : "var(--text-muted)" }}
            />
            <span className="text-sm font-medium" style={{ color: "var(--text)" }}>
              {m?.is_mining ? "Mining aktiv" : "Mining inaktiv"}
            </span>
          </div>
          {m?.mining_wallet && (
            <p className="text-xs mono truncate mt-1" style={{ color: "var(--text-muted)" }}>
              {m.mining_wallet.slice(0, 20)}…
            </p>
          )}
        </div>
        <div className="flex-1" />
        {healthQ.data && (
          <div
            className="mx-3 mb-3 p-3 rounded-lg text-xs"
            style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
          >
            <p className="font-semibold mb-2" style={{ color: "var(--text-dim)" }}>Node</p>
            <p className="mono truncate" style={{ color: "var(--text-muted)" }}>
              {healthQ.data.node_id.slice(0, 24)}…
            </p>
          </div>
        )}
      </div>

      {/* Main */}
      <div className="flex-1 overflow-y-auto p-6" style={{ background: "var(--main-bg)" }}>
        <h2 className="text-xl font-bold mb-6">Mining Dashboard</h2>

        {!m && (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>Verbinden…</p>
        )}

        {m && (
          <div className="space-y-6 max-w-2xl">
            {/* Primary stats */}
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Stat label="Aktive Miner" value={m.active_miners.toString()} accent />
              <Stat label="Blocks Gemined" value={m.blocks_mined.toLocaleString()} />
              <Stat label="Throttle" value={`${m.throttle_pct}%`} />
              <Stat label="Difficulty" value={m.current_difficulty.toString()} />
            </div>

            {/* Chain */}
            <div>
              <p className="text-xs font-semibold uppercase mb-3 flex items-center gap-2" style={{ color: "var(--text-muted)" }}>
                <Link size={12} /> Chain
              </p>
              <div className="grid grid-cols-3 gap-3">
                <Stat label="Block Height" value={m.chain.block_height.toLocaleString()} />
                <Stat label="Dokumente" value={m.chain.total_documents.toLocaleString()} />
                <Stat label="Peers" value={m.network.total_peers.toString()} />
              </div>
              <div
                className="mt-3 rounded-lg px-4 py-3"
                style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
              >
                <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>Latest Hash</p>
                <p className="mono text-xs break-all" style={{ color: "var(--accent)" }}>
                  {m.chain.latest_hash}
                </p>
              </div>
            </div>

            {/* Token */}
            <div>
              <p className="text-xs font-semibold uppercase mb-3 flex items-center gap-2" style={{ color: "var(--text-muted)" }}>
                <Coins size={12} /> Token
              </p>
              <div className="grid grid-cols-2 gap-3">
                <Stat label="Total Supply" value={parseFloat(m.token.total_supply).toLocaleString(undefined, { maximumFractionDigits: 2 }) + " STONE"} />
                <Stat label="Circulating" value={parseFloat(m.token.circulating_supply).toLocaleString(undefined, { maximumFractionDigits: 2 }) + " STONE"} />
              </div>
            </div>
          </div>
        )}

        {/* ── Node Terminal ──────────────────────────────── */}
        <NodeTerminal />
      </div>
    </div>
  );
}