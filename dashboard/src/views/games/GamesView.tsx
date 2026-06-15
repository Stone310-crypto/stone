import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { games as gamesApi } from "../../api/stone";
import { useAuth } from "../../auth/AuthContext";
import type { OnChainGame } from "../../types/api";
import { ShieldCheck, Gamepad2, Users, Coins } from "lucide-react";
import Avatar from "../../components/ui/Avatar";

function GameCard({
  game,
  active,
  onClick,
}: {
  game: OnChainGame;
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
      <Avatar name={game.name} size={32} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-medium truncate" style={{ color: "var(--text)" }}>
            {game.name}
          </span>
          {game.verified && (
            <ShieldCheck size={12} style={{ color: "var(--accent)", flexShrink: 0 }} />
          )}
        </div>
        <p className="text-xs truncate mt-0.5" style={{ color: "var(--text-muted)" }}>
          {game.player_count != null ? `${game.player_count} Spieler` : "—"}
        </p>
      </div>
    </button>
  );
}

function GameDetail({ game, myWallet }: { game: OnChainGame; myWallet: string }) {
  const balanceQ = useQuery({
    queryKey: ["game-balance", game.game_id, myWallet],
    queryFn: () => gamesApi.coinBalance(game.game_id, myWallet),
    enabled: !!myWallet,
  });

  const poolQ = useQuery({
    queryKey: ["game-pool", game.game_id],
    queryFn: () => gamesApi.poolStatus(game.game_id),
  });

  return (
    <div className="p-6 max-w-xl">
      <div className="flex items-center gap-4 mb-6">
        <Avatar name={game.name} size={56} />
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold">{game.name}</h2>
            {game.verified && (
              <span
                className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full"
                style={{ background: "var(--accent-dim)", color: "var(--accent)" }}
              >
                <ShieldCheck size={11} />
                Verifiziert
              </span>
            )}
          </div>
          <p className="text-xs mono mt-1" style={{ color: "var(--text-muted)" }}>
            {game.game_id}
          </p>
        </div>
      </div>

      {game.description && (
        <p className="text-sm mb-5 leading-relaxed" style={{ color: "var(--text-dim)" }}>
          {game.description}
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 mb-4">
        {[
          { icon: <Users size={16} />, label: "Spieler", value: game.player_count?.toString() ?? "—" },
          {
            icon: <Coins size={16} />,
            label: "Mein Guthaben",
            value: balanceQ.data ? `${parseFloat(balanceQ.data.balance).toFixed(2)} Coins` : "—",
          },
        ].map(({ icon, label, value }) => (
          <div
            key={label}
            className="rounded-xl p-4 flex items-center gap-3"
            style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
          >
            <div style={{ color: "var(--accent)" }}>{icon}</div>
            <div>
              <p className="text-base font-semibold tabular-nums">{value}</p>
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {poolQ.data && (
        <div
          className="rounded-xl p-4"
          style={{
            background: poolQ.data.configured ? "var(--accent-dim)" : "var(--surface)",
            border: `1px solid ${poolQ.data.configured ? "var(--accent)" : "var(--border)"}`,
          }}
        >
          <p className="text-sm font-semibold mb-2" style={{ color: poolQ.data.configured ? "var(--accent)" : "var(--text-dim)" }}>
            Gaming Pool
          </p>
          <div className="flex justify-between text-sm">
            <span style={{ color: "var(--text-dim)" }}>Balance</span>
            <span className="tabular-nums font-medium">
              {parseFloat(poolQ.data.pool_balance).toFixed(2)} STONE
            </span>
          </div>
          {poolQ.data.daily_limit && (
            <div className="flex justify-between text-sm mt-1">
              <span style={{ color: "var(--text-dim)" }}>Tageslimit</span>
              <span className="tabular-nums">{poolQ.data.daily_limit} STONE</span>
            </div>
          )}
        </div>
      )}

      <div className="mt-4 text-xs" style={{ color: "var(--text-muted)" }}>
        Owner:{" "}
        <span className="mono" style={{ color: "var(--text-dim)" }}>
          {game.owner_wallet}
        </span>
      </div>
    </div>
  );
}

export default function GamesView() {
  const { session } = useAuth();
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [selected, setSelected] = useState<OnChainGame | null>(null);

  const allQ = useQuery({
    queryKey: ["games-all"],
    queryFn: gamesApi.list,
    refetchInterval: 60_000,
  });

  const verifiedQ = useQuery({
    queryKey: ["games-verified"],
    queryFn: gamesApi.verified,
    enabled: verifiedOnly,
    refetchInterval: 60_000,
  });

  const gameList = (verifiedOnly ? verifiedQ.data?.games : allQ.data?.games) ?? [];

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
        {/* Filter */}
        <div className="px-4 py-4 border-b" style={{ borderColor: "var(--border)" }}>
          <div className="flex gap-1 p-0.5 rounded-lg" style={{ background: "var(--surface)" }}>
            {[
              [false, "Alle"],
              [true, "Verifiziert"],
            ].map(([val, label]) => (
              <button
                key={String(label)}
                onClick={() => setVerifiedOnly(val as boolean)}
                className="flex-1 py-1 rounded-md text-xs font-medium transition-colors"
                style={{
                  background: verifiedOnly === val ? "var(--accent)" : "transparent",
                  color: verifiedOnly === val ? "#fff" : "var(--text-dim)",
                }}
              >
                {label as string}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
          {gameList.map((g) => (
            <GameCard
              key={g.game_id}
              game={g}
              active={selected?.game_id === g.game_id}
              onClick={() => setSelected(g)}
            />
          ))}
          {gameList.length === 0 && (
            <p className="text-xs px-3 py-2" style={{ color: "var(--text-muted)" }}>
              Keine Games
            </p>
          )}
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 overflow-y-auto" style={{ background: "var(--main-bg)" }}>
        {selected ? (
          <GameDetail game={selected} myWallet={session?.walletAddress ?? ""} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-3">
            <Gamepad2 size={48} style={{ color: "var(--text-muted)", opacity: 0.3 }} />
            <p className="text-base font-semibold" style={{ color: "var(--text-dim)" }}>
              Game auswählen
            </p>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              {gameList.length} Games verfügbar
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
