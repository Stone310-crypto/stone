import type { ReactNode } from "react";
import { MessageSquare, Wallet, Blocks, Gamepad2, Megaphone, Server, User, Globe, Upload } from "lucide-react";
import { useNodeHealth } from "../../hooks/useNodeHealth";

export type NavSection =
  | "chat"
  | "wallet"
  | "explorer"
  | "games"
  | "servers"
  | "announcements"
  | "node"
  | "profile"
  | "files";

interface NavRailProps {
  active: NavSection;
  onChange: (s: NavSection) => void;
  unreadChat?: number;
}

interface NavItem {
  id: NavSection;
  icon: ReactNode;
  label: string;
  badge?: number;
}

function RailButton({
  item,
  active,
  onClick,
}: {
  item: NavItem;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <div className="relative flex justify-center" title={item.label}>
      {/* Active pill indicator */}
      <div
        className="absolute left-0 top-1/2 -translate-y-1/2 w-1 rounded-r-full transition-all"
        style={{
          height: active ? 28 : 8,
          background: active ? "#fff" : "transparent",
          opacity: active ? 1 : 0,
        }}
      />

      <button
        onClick={onClick}
        className="relative flex items-center justify-center transition-all"
        style={{
          width: 48,
          height: 48,
          background: active ? "var(--accent)" : "var(--surface)",
          color: active ? "#fff" : "var(--text-dim)",
          borderRadius: active ? "16px" : "24px",
          border: "none",
          cursor: "pointer",
        }}
        onMouseEnter={(e) => {
          if (!active) {
            (e.currentTarget as HTMLButtonElement).style.borderRadius = "16px";
            (e.currentTarget as HTMLButtonElement).style.background = "var(--accent)";
            (e.currentTarget as HTMLButtonElement).style.color = "#fff";
          }
        }}
        onMouseLeave={(e) => {
          if (!active) {
            (e.currentTarget as HTMLButtonElement).style.borderRadius = "24px";
            (e.currentTarget as HTMLButtonElement).style.background = "var(--surface)";
            (e.currentTarget as HTMLButtonElement).style.color = "var(--text-dim)";
          }
        }}
      >
        {item.icon}
        {!!item.badge && (
          <span
            className="absolute flex items-center justify-center text-white font-bold rounded-full"
            style={{
              background: "var(--red)",
              fontSize: 9,
              minWidth: 16,
              height: 16,
              top: -2,
              right: -2,
              padding: "0 3px",
            }}
          >
            {item.badge > 99 ? "99+" : item.badge}
          </span>
        )}
      </button>
    </div>
  );
}

// ── Network status widget ─────────────────────────────────────────────────────

function NetworkStatus() {
  const { connected, blockHeight, network } = useNodeHealth();

  return (
    <div
      title={
        connected
          ? `Verbunden · ${network} · Block #${blockHeight.toLocaleString()}`
          : "Keine Verbindung zum Netzwerk"
      }
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 4,
        padding: "8px 0",
        cursor: "default",
        userSelect: "none",
      }}
    >
      {/* Status dot */}
      <div
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: connected ? "var(--green)" : "rgba(255,255,255,0.18)",
          boxShadow: connected ? "0 0 6px var(--green)" : "none",
          animation: connected ? "pulse-glow 2.5s ease-in-out infinite" : "none",
          transition: "background 0.4s",
        }}
      />
      {/* Block height (compact) */}
      {connected && blockHeight > 0 && (
        <span
          style={{
            fontSize: 9,
            fontWeight: 700,
            fontFamily: "monospace",
            color: "var(--text-muted)",
            letterSpacing: "0.01em",
            lineHeight: 1,
          }}
        >
          #{blockHeight > 9999 ? `${Math.floor(blockHeight / 1000)}k` : blockHeight}
        </span>
      )}
    </div>
  );
}

export default function NavRail({ active, onChange, unreadChat }: NavRailProps) {
  const topItems: NavItem[] = [
    { id: "chat",          icon: <MessageSquare size={22} strokeWidth={1.8} />, label: "Chat",         badge: unreadChat },
    { id: "wallet",        icon: <Wallet        size={22} strokeWidth={1.8} />, label: "Wallet" },
    { id: "explorer",      icon: <Blocks        size={22} strokeWidth={1.8} />, label: "Blockchain" },
    { id: "files",         icon: <Upload        size={22} strokeWidth={1.8} />, label: "Dateien" },
    { id: "games",         icon: <Gamepad2      size={22} strokeWidth={1.8} />, label: "Games" },
    { id: "servers",       icon: <Globe         size={22} strokeWidth={1.8} />, label: "Server" },
    { id: "announcements", icon: <Megaphone     size={22} strokeWidth={1.8} />, label: "News" },
    { id: "node",          icon: <Server        size={22} strokeWidth={1.8} />, label: "Node" },
  ];

  return (
    <div
      className="flex flex-col items-center py-3 gap-2 shrink-0"
      style={{
        width: "var(--rail-w)",
        background: "var(--rail-bg)",
        paddingTop: 52,
      }}
    >
      {/* App icon */}
      <div
        className="flex items-center justify-center font-bold mb-2"
        style={{
          width: 48,
          height: 48,
          borderRadius: 16,
          background: "var(--accent)",
          color: "#fff",
          fontSize: 20,
          flexShrink: 0,
        }}
      >
        S
      </div>

      <div className="w-8 my-1" style={{ height: 1, background: "var(--border)" }} />

      {topItems.map((item) => (
        <RailButton
          key={item.id}
          item={item}
          active={active === item.id}
          onClick={() => onChange(item.id)}
        />
      ))}

      <div className="flex-1" />

      {/* Network status */}
      <NetworkStatus />

      <div className="w-8" style={{ height: 1, background: "var(--border)" }} />

      {/* Profile */}
      <RailButton
        item={{ id: "profile", icon: <User size={22} strokeWidth={1.8} />, label: "Profil" }}
        active={active === "profile"}
        onClick={() => onChange("profile")}
      />

      <style>{`
        @keyframes pulse-glow {
          0%, 100% { opacity: 1; box-shadow: 0 0 6px var(--green); }
          50%       { opacity: 0.6; box-shadow: 0 0 2px var(--green); }
        }
      `}</style>
    </div>
  );
}
