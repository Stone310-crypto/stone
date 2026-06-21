import { useQuery } from "@tanstack/react-query";
import { node } from "../../api/stone";
import { useEffect, useRef, useState } from "react";

export default function NodeView() {
  const healthQ = useQuery({
    queryKey: ["health"],
    queryFn: node.health,
    refetchInterval: 5_000,
  });

  const [updateState, setUpdateState] = useState<
    "idle" | "checking" | "downloading" | "restarting"
  >("idle");
  const [newVersion, setNewVersion] = useState<string | null>(null);
  const [dlResult, setDlResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const checkForUpdates = async () => {
    setError(null);
    setUpdateState("checking");
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const tag: string | null = await invoke("node_binary_check_updates");
      if (tag) {
        setNewVersion(tag);
      }
    } catch (e: any) {
      setError(e?.toString() ?? "Fehler beim Update-Check");
    } finally {
      setUpdateState("idle");
    }
  };

  const downloadUpdate = async () => {
    setError(null);
    setUpdateState("downloading");
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const results: [string, string][] =
        await invoke("node_binary_download_latest");
      const lines = results.map(([name, path]) => `${name} → ${path}`);
      setDlResult(lines.join("\n"));
      setNewVersion(null);
    } catch (e: any) {
      setError(e?.toString() ?? "Download fehlgeschlagen");
    } finally {
      setUpdateState("idle");
    }
  };

  const doRestart = async () => {
    setUpdateState("restarting");
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("node_stop");
      await new Promise((r) => setTimeout(r, 1000));
      await invoke("node_start");
      setDlResult(null);
    } catch (e: any) {
      setError(e?.toString() ?? "Restart fehlgeschlagen");
    } finally {
      setUpdateState("idle");
    }
  };

  return (
    <div
      className="flex-1 overflow-y-auto p-6"
      style={{ background: "var(--main-bg)" }}
    >
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Embedded Node</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={checkForUpdates}
            disabled={updateState === "checking"}
            className="text-xs px-3 py-1.5 rounded hover:opacity-80 disabled:opacity-50"
            style={{
              background: "var(--surface)",
              color: "var(--text-muted)",
              border: "1px solid var(--border)",
            }}
          >
            {updateState === "checking" ? "Prüfe…" : "🔍 Update prüfen"}
          </button>
        </div>
      </div>

      {/* Update-Banner */}
      {error && (
        <div
          className="mb-4 p-3 rounded-lg text-sm"
          style={{
            background: "rgba(239,68,68,0.1)",
            color: "#ef4444",
            border: "1px solid rgba(239,68,68,0.2)",
          }}
        >
          {error}
          <button
            onClick={() => setError(null)}
            className="ml-3 underline"
          >
            Ausblenden
          </button>
        </div>
      )}

      {newVersion && (
        <div
          className="mb-4 p-4 rounded-lg"
          style={{
            background: "rgba(250,166,26,0.1)",
            border: "1px solid rgba(250,166,26,0.2)",
            color: "var(--yellow)",
          }}
        >
          <p className="font-semibold mb-2">
            Neue Node-Version verfügbar: {newVersion}
          </p>
          <div className="flex gap-2">
            <button
              onClick={downloadUpdate}
              disabled={updateState === "downloading"}
              className="text-sm px-3 py-1 rounded font-medium hover:opacity-90 disabled:opacity-50"
              style={{
                background: "var(--yellow)",
                color: "#000",
              }}
            >
              {updateState === "downloading"
                ? "Lade herunter…"
                : "⬇ Jetzt aktualisieren"}
            </button>
            <button
              onClick={() => setNewVersion(null)}
              className="text-sm px-3 py-1 rounded"
              style={{
                background: "var(--surface)",
                color: "var(--text-muted)",
                border: "1px solid var(--border)",
              }}
            >
              Später
            </button>
          </div>
        </div>
      )}

      {dlResult && (
        <div
          className="mb-4 p-4 rounded-lg"
          style={{
            background: "rgba(34,197,94,0.1)",
            border: "1px solid rgba(34,197,94,0.2)",
            color: "#22c55e",
          }}
        >
          <p className="font-semibold mb-1">
            ✅ Binaries aktualisiert:
          </p>
          <pre className="text-xs font-mono opacity-80">{dlResult}</pre>
          <p className="text-xs mt-2">
            Starte den Node neu, um die neuen Binaries zu verwenden.
          </p>
          <button
            onClick={doRestart}
            disabled={updateState === "restarting"}
            className="mt-2 text-sm px-3 py-1 rounded font-medium hover:opacity-90 disabled:opacity-50"
            style={{
              background: "#22c55e",
              color: "#000",
            }}
          >
            {updateState === "restarting"
              ? "Starte neu…"
              : "🔄 Node neustarten"}
          </button>
        </div>
      )}

      {healthQ.data && (
        <div className="grid grid-cols-2 gap-3 mb-6">
          <div
            className="rounded-xl p-4"
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
            }}
          >
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Block Height
            </p>
            <p
              className="text-xl font-bold tabular-nums"
              style={{ color: "var(--text)" }}
            >
              #{healthQ.data.block_height}
            </p>
          </div>
          <div
            className="rounded-xl p-4"
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
            }}
          >
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Node ID
            </p>
            <p
              className="text-sm font-mono"
              style={{ color: "var(--text)" }}
            >
              {healthQ.data.node_id.slice(0, 24)}…
            </p>
          </div>
        </div>
      )}
      <NodeTerminal />
    </div>
  );
}

// ── Log-Filter Kategorien ─────────────────────────────────────────────
const LOG_CATEGORIES = [
  { key: "all", label: "Alle", color: "var(--text-muted)" },
  { key: "chat", label: "Chat", color: "#a78bfa" },
  { key: "sync", label: "Sync", color: "#60a5fa" },
  { key: "auto-mining", label: "AutoMining", color: "#fbbf24" },
  { key: "startup", label: "Startup", color: "#34d399" },
  { key: "p2p", label: "P2P", color: "#fb923c" },
  { key: "err", label: "Errors", color: "#ef4444" },
];

function extractCategory(line: string): string {
  const m = line.match(/^\[(err|out)\]\s*\[([a-z0-9_-]+)\]/);
  if (m) return m[2];
  if (line.startsWith("[err]")) return "err";
  return "other";
}

// ── Node Terminal (Live-Console) ─────────────────────────────────────
function NodeTerminal() {
  const [logs, setLogs] = useState<string[]>([]);
  const [paused, setPaused] = useState(false);
  const [copied, setCopied] = useState(false);
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterText, setFilterText] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pausedRef = useRef(false);

  // Keep pausedRef in sync
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  useEffect(() => {
    pollingRef.current = setInterval(async () => {
      if (pausedRef.current) return;
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const newLogs: string[] = await invoke("node_get_logs");
        if (newLogs.length > 0) {
          setLogs((prev) => [...prev, ...newLogs].slice(-1000));
        }
      } catch {
        // Tauri not available — ignore
      }
    }, 1000);

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  useEffect(() => {
    if (!paused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, paused]);

  // Filter
  const filteredLogs = logs.filter((line) => {
    if (filterCategory !== "all" && extractCategory(line) !== filterCategory) return false;
    if (filterText && !line.toLowerCase().includes(filterText.toLowerCase())) return false;
    return true;
  });

  const categoryCounts: Record<string, number> = {};
  for (const l of logs) { const c = extractCategory(l); categoryCounts[c] = (categoryCounts[c] || 0) + 1; }

  const clearLogs = () => setLogs([]);

  const copyLogs = async () => {
    const text = filteredLogs.join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="mt-6">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold uppercase" style={{ color: "var(--text-muted)" }}>
          Node Console ({filteredLogs.length}/{logs.length})
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPaused(!paused)}
            className="text-xs px-2 py-1 rounded hover:opacity-80"
            style={{ background: paused ? "rgba(250,166,26,0.15)" : "var(--surface)", color: paused ? "var(--yellow)" : "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            {paused ? "▶ Resume" : "⏸ Pause"}
          </button>
          <button
            onClick={copyLogs}
            className="text-xs px-2 py-1 rounded hover:opacity-80"
            style={{ background: "var(--surface)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            {copied ? "✓ Kopiert" : "📋 Kopieren"}
          </button>
          <button
            onClick={clearLogs}
            className="text-xs px-2 py-1 rounded hover:opacity-80"
            style={{ background: "var(--surface)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            Clear
          </button>
        </div>
      </div>

      {/* ── Filter Bar ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-1.5 mb-2 flex-wrap">
        {LOG_CATEGORIES.map((cat) => {
          const count = cat.key === "all" ? logs.length : (categoryCounts[cat.key] || 0);
          const active = filterCategory === cat.key;
          return (
            <button
              key={cat.key}
              onClick={() => setFilterCategory(cat.key)}
              className="text-xs px-2 py-0.5 rounded-full"
              style={{
                background: active ? cat.color + "22" : "var(--surface)",
                color: active ? cat.color : "var(--text-muted)",
                border: `1px solid ${active ? cat.color + "44" : "var(--border)"}`,
                fontWeight: active ? 600 : 400,
              }}
            >
              {cat.label}{count > 0 ? <span style={{ marginLeft: 3, opacity: 0.6 }}>{count}</span> : null}
            </button>
          );
        })}
        <input
          type="text"
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          placeholder="Filter…"
          className="text-xs px-2 py-1 rounded flex-1 min-w-[80px]"
          style={{ background: "var(--surface)", color: "var(--text)", border: "1px solid var(--border)", outline: "none" }}
        />
      </div>

      {/* Paused banner */}
      {paused && (
        <div className="text-xs mb-2 px-2 py-1 rounded" style={{ background: "rgba(250,166,26,0.1)", color: "var(--yellow)", border: "1px solid rgba(250,166,26,0.2)" }}>
          ⏸ Pausiert — {logs.length} Zeilen eingefroren
        </div>
      )}

      {/* Console */}
      <div
        className="rounded-lg p-4 overflow-y-auto font-mono text-xs leading-relaxed"
        style={{
          background: "#0a0b0f",
          border: "1px solid var(--border)",
          height: "calc(100vh - 340px)",
          minHeight: 200,
        }}
      >
        {filteredLogs.length === 0 && logs.length === 0 && (
          <span style={{ color: "var(--text-muted)", opacity: 0.5 }}>
            Warte auf Node-Logs… (Node muss gestartet sein)
          </span>
        )}
        {filteredLogs.length === 0 && logs.length > 0 && (
          <span style={{ color: "var(--text-muted)", opacity: 0.5 }}>
            Keine Logs für diesen Filter
          </span>
        )}
        {filteredLogs.map((line, i) => {
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