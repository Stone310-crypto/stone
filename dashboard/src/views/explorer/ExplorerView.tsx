import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { blocks as blocksApi, node } from "../../api/stone";
import type { Block } from "../../types/api";
import { ChevronLeft, ChevronRight, Cpu, FileText, ArrowLeftRight } from "lucide-react";

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString([], {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function shortHash(h: string): string {
  return `${h.slice(0, 10)}…${h.slice(-8)}`;
}

function BlockListItem({
  block,
  active,
  onClick,
}: {
  block: Block;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-left transition-colors"
      style={{
        background: active ? "var(--surface-2)" : "transparent",
        borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
      }}
      onMouseEnter={(e) => {
        if (!active) (e.currentTarget as HTMLElement).style.background = "var(--surface)";
      }}
      onMouseLeave={(e) => {
        if (!active) (e.currentTarget as HTMLElement).style.background = "transparent";
      }}
    >
      <div
        className="flex items-center justify-center rounded-lg shrink-0"
        style={{
          width: 32,
          height: 32,
          background: active ? "var(--accent-dim)" : "var(--surface)",
        }}
      >
        <Cpu size={14} style={{ color: active ? "var(--accent)" : "var(--text-muted)" }} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold" style={{ color: active ? "var(--accent)" : "var(--text)" }}>
            #{block.index.toLocaleString()}
          </span>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            {block.transaction_count} TXs
          </span>
        </div>
        <p className="text-xs mono truncate mt-0.5" style={{ color: "var(--text-muted)" }}>
          {shortHash(block.hash)}
        </p>
      </div>
    </button>
  );
}

function BlockDetail({ block }: { block: Block }) {
  const fields: [string, string][] = [
    ["Index", block.index.toLocaleString()],
    ["Hash", block.hash],
    ["Previous Hash", block.previous_hash],
    ["Zeitstempel", fmtTime(block.timestamp)],
    ["Transaktionen", block.transaction_count.toString()],
    ["Dokumente", block.document_count.toString()],
    ...(block.chat_batch_count != null
      ? [["Chat Batches", block.chat_batch_count.toString()] as [string, string]]
      : []),
    ["Validator", block.validator_pub_key],
  ];

  return (
    <div className="p-6 max-w-2xl">
      <h2 className="text-xl font-bold mb-1">
        Block{" "}
        <span style={{ color: "var(--accent)" }}>#{block.index.toLocaleString()}</span>
      </h2>
      <p className="text-xs mono mb-6" style={{ color: "var(--text-muted)" }}>
        {fmtTime(block.timestamp)}
      </p>

      <div
        className="rounded-xl overflow-hidden"
        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
      >
        {fields.map(([label, value], i) => (
          <div
            key={label}
            className="flex gap-4 px-4 py-3"
            style={{
              borderTop: i > 0 ? "1px solid var(--border)" : "none",
            }}
          >
            <p
              className="text-xs font-medium shrink-0"
              style={{ color: "var(--text-muted)", width: 130 }}
            >
              {label}
            </p>
            <p
              className="text-sm mono break-all"
              style={{
                color:
                  label === "Hash" || label === "Previous Hash" || label === "Validator"
                    ? "var(--accent)"
                    : "var(--text)",
              }}
            >
              {value}
            </p>
          </div>
        ))}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3 mt-4">
        {[
          { icon: <ArrowLeftRight size={16} />, label: "Transaktionen", value: block.transaction_count },
          { icon: <FileText size={16} />, label: "Dokumente", value: block.document_count },
          { icon: <Cpu size={16} />, label: "Chat Batches", value: block.chat_batch_count ?? 0 },
        ].map(({ icon, label, value }) => (
          <div
            key={label}
            className="rounded-xl p-3 flex items-center gap-3"
            style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
          >
            <div style={{ color: "var(--accent)" }}>{icon}</div>
            <div>
              <p className="text-lg font-bold tabular-nums">{value}</p>
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>{label}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ExplorerView() {
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Block | null>(null);

  const blocksQ = useQuery({
    queryKey: ["blocks", page],
    queryFn: () => blocksApi.list(page, 30),
    refetchInterval: 15_000,
  });

  const healthQ = useQuery({
    queryKey: ["health"],
    queryFn: node.health,
    refetchInterval: 10_000,
  });

  const blockList = blocksQ.data?.blocks ?? [];
  const total = blocksQ.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / 30));

  return (
    <div className="flex h-full">
      {/* Panel */}
      <div
        className="flex flex-col shrink-0"
        style={{
          width: "var(--panel-w)",
          background: "var(--panel-bg)",
          borderRight: "1px solid var(--border)",
        }}
      >
        {/* Stats */}
        <div className="px-4 py-4 border-b" style={{ borderColor: "var(--border)" }}>
          <p className="text-xs font-semibold uppercase mb-3" style={{ color: "var(--text-muted)" }}>
            Netzwerk
          </p>
          <div className="space-y-2">
            {[
              ["Block Height", healthQ.data?.block_height?.toLocaleString() ?? "—"],
              ["Status", healthQ.data?.status ?? "—"],
              ["Network", healthQ.data?.network ?? "—"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs">
                <span style={{ color: "var(--text-muted)" }}>{k}</span>
                <span className="tabular-nums font-medium" style={{ color: "var(--text)" }}>
                  {v}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Block list */}
        <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
          {blockList.map((b) => (
            <BlockListItem
              key={b.hash}
              block={b}
              active={selected?.hash === b.hash}
              onClick={() => setSelected(b)}
            />
          ))}
        </div>

        {/* Pagination */}
        <div
          className="flex items-center justify-between px-3 py-2 border-t text-xs"
          style={{ borderColor: "var(--border)", color: "var(--text-muted)" }}
        >
          <span>
            {page + 1}/{totalPages}
          </span>
          <div className="flex gap-1">
            <button
              className="p-1 rounded disabled:opacity-30"
              style={{ color: "var(--text-dim)" }}
              disabled={page === 0}
              onClick={() => { setPage((p) => p - 1); setSelected(null); }}
            >
              <ChevronLeft size={14} />
            </button>
            <button
              className="p-1 rounded disabled:opacity-30"
              style={{ color: "var(--text-dim)" }}
              disabled={page >= totalPages - 1}
              onClick={() => { setPage((p) => p + 1); setSelected(null); }}
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 overflow-y-auto" style={{ background: "var(--main-bg)" }}>
        {selected ? (
          <BlockDetail block={selected} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-3">
            <Cpu size={48} style={{ color: "var(--text-muted)", opacity: 0.3 }} />
            <p className="text-base font-semibold" style={{ color: "var(--text-dim)" }}>
              Block auswählen
            </p>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Klicke einen Block in der Liste
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
