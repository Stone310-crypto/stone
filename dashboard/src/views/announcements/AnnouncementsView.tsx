import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { announcements as annoApi } from "../../api/stone";
import type { AnnouncementEntry } from "../../types/api";
import Avatar from "../../components/ui/Avatar";
import { ThumbsUp, ThumbsDown, Megaphone } from "lucide-react";

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString([], {
    weekday: "short", month: "short", day: "numeric", year: "numeric",
  });
}

const EMOJIS = ["👍", "❤️", "🚀", "🔥", "💎"];

function AnnoCard({ a }: { a: AnnouncementEntry }) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState(false);

  const voteMut = useMutation({
    mutationFn: (dir: "up" | "down") => annoApi.vote(a.id, dir),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["announcements"] }),
  });

  const reactMut = useMutation({
    mutationFn: (emoji: string) => annoApi.react(a.id, emoji),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["announcements"] }),
  });

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
    >
      {/* Header */}
      <div className="flex items-start gap-3 p-4">
        <Avatar name={a.author} size={38} />
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline justify-between gap-2">
            <p className="text-sm font-semibold" style={{ color: "var(--text)" }}>
              {a.author}
            </p>
            <time className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
              {fmtDate(a.created_at)}
            </time>
          </div>
          <h3 className="text-base font-bold mt-0.5" style={{ color: "var(--text)" }}>
            {a.title}
          </h3>
        </div>
      </div>

      {/* Body */}
      <div
        className="px-4 pb-3 text-sm leading-relaxed cursor-pointer"
        style={{ color: "var(--text-dim)" }}
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? (
          a.body
        ) : (
          <>
            {a.body.slice(0, 220)}
            {a.body.length > 220 && (
              <span style={{ color: "var(--accent)" }}> …mehr anzeigen</span>
            )}
          </>
        )}
      </div>

      {/* Poll */}
      {a.poll_options && a.poll_options.length > 0 && (
        <div className="px-4 pb-3 space-y-2">
          {a.poll_options.map((opt) => {
            const maxVotes = Math.max(...(a.poll_options?.map((o) => o.votes) ?? [1]));
            const pct = maxVotes > 0 ? (opt.votes / maxVotes) * 100 : 0;
            return (
              <div key={opt.id}>
                <div className="flex justify-between text-xs mb-1" style={{ color: "var(--text-dim)" }}>
                  <span>{opt.label}</span>
                  <span className="tabular-nums">{opt.votes}</span>
                </div>
                <div className="h-1.5 rounded-full" style={{ background: "var(--border)" }}>
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${pct}%`, background: "var(--accent)" }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Footer */}
      <div
        className="flex items-center gap-3 px-4 py-2.5 border-t"
        style={{ borderColor: "var(--border)" }}
      >
        {/* Votes */}
        {a.votes && (
          <div className="flex items-center gap-2">
            <button
              className="flex items-center gap-1 text-xs rounded-lg px-2 py-1 transition-colors"
              style={{ background: "var(--surface-2)", color: "var(--green)" }}
              onClick={() => voteMut.mutate("up")}
            >
              <ThumbsUp size={12} />
              {a.votes.up}
            </button>
            <button
              className="flex items-center gap-1 text-xs rounded-lg px-2 py-1 transition-colors"
              style={{ background: "var(--surface-2)", color: "var(--red)" }}
              onClick={() => voteMut.mutate("down")}
            >
              <ThumbsDown size={12} />
              {a.votes.down}
            </button>
          </div>
        )}

        <div className="flex-1" />

        {/* Emoji reactions */}
        <div className="flex items-center gap-1">
          {EMOJIS.map((emoji) => {
            const count = a.reactions?.[emoji] ?? 0;
            return (
              <button
                key={emoji}
                onClick={() => reactMut.mutate(emoji)}
                className="flex items-center gap-0.5 text-xs rounded-lg px-1.5 py-0.5 transition-colors"
                style={{
                  background: count > 0 ? "var(--accent-dim)" : "var(--surface-2)",
                  border: count > 0 ? "1px solid var(--accent)" : "1px solid transparent",
                  color: "var(--text)",
                }}
              >
                {emoji}
                {count > 0 && (
                  <span className="tabular-nums text-xs" style={{ color: "var(--text-dim)" }}>
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function AnnouncementsView() {
  const { data, isLoading } = useQuery({
    queryKey: ["announcements"],
    queryFn: annoApi.list,
    refetchInterval: 60_000,
  });

  const items = data?.announcements ?? [];

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
          Community
        </p>
        <div className="px-2 space-y-0.5">
          {[["announcements", "📣 Announcements"]].map(([, label]) => (
            <div
              key={label as string}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm"
              style={{ background: "var(--surface-2)", color: "var(--text)" }}
            >
              <span>{label as string}</span>
            </div>
          ))}
        </div>
        <div className="flex-1" />
        <p className="text-xs px-4 pb-4" style={{ color: "var(--text-muted)" }}>
          {items.length} Beiträge
        </p>
      </div>

      {/* Main */}
      <div
        className="flex-1 overflow-y-auto p-6"
        style={{ background: "var(--main-bg)" }}
      >
        {isLoading && (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>Laden…</p>
        )}

        {!isLoading && items.length === 0 && (
          <div className="flex flex-col items-center justify-center h-64 gap-3">
            <Megaphone size={40} style={{ color: "var(--text-muted)", opacity: 0.3 }} />
            <p style={{ color: "var(--text-dim)" }}>Noch keine Ankündigungen</p>
          </div>
        )}

        <div className="max-w-2xl space-y-4">
          {items.map((a) => (
            <AnnoCard key={a.id} a={a} />
          ))}
        </div>
      </div>
    </div>
  );
}
