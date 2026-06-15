import { useQuery } from "@tanstack/react-query";
import { node } from "../../api/stone";
import { useEffect, useRef, useState } from "react";

export default function NodeView() {
  const healthQ = useQuery({
    queryKey: ["health"],
    queryFn: node.health,
    refetchInterval: 5_000,
  });

  return (
    <div className="flex-1 overflow-y-auto p-6" style={{ background: "var(--main-bg)" }}>
      <h2 className="text-xl font-bold mb-6">Embedded Node</h2>
      {healthQ.data && (
        <div className="grid grid-cols-2 gap-3 mb-6">
          <div className="rounded-xl p-4" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Block Height</p>
            <p className="text-xl font-bold tabular-nums" style={{ color: "var(--text)" }}>#{healthQ.data.block_height}</p>
          </div>
          <div className="rounded-xl p-4" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Node ID</p>
            <p className="text-sm font-mono" style={{ color: "var(--text)" }}>{healthQ.data.node_id.slice(0, 24)}…</p>
          </div>
        </div>
      )}
      <NodeTerminal />
    </div>
  );
}

// ── Node Terminal (Live-Console) ─────────────────────────────────────
function NodeTerminal() {
  const [logs, setLogs] = useState<string[]>([]);
  const [paused, setPaused] = useState(false);
  const [copied, setCopied] = useState(false);
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
          setLogs((prev) => [...prev, ...newLogs].slice(-500));
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

  const clearLogs = () => setLogs([]);

  const copyLogs = async () => {
    const text = logs.join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback: select + execCommand
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
          Node Console
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
      {paused && (
        <div className="text-xs mb-2 px-2 py-1 rounded" style={{ background: "rgba(250,166,26,0.1)", color: "var(--yellow)", border: "1px solid rgba(250,166,26,0.2)" }}>
          ⏸ Pausiert — {logs.length} Zeilen eingefroren
        </div>
      )}
      <div
        className="rounded-lg p-4 overflow-y-auto font-mono text-xs leading-relaxed"
        style={{
          background: "#0a0b0f",
          border: "1px solid var(--border)",
          height: "calc(100vh - 280px)",
          minHeight: 200,
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