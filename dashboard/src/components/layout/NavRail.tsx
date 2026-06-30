import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { orgs } from "../../api/stone";
import { useAuth } from "../../auth/AuthContext";
import {
  Blocks, Gamepad2, Server, User, Home as HomeIcon, Wallet,
  ChevronUp, ChevronDown,
  Plus, Hash, UserPlus, Settings,
  Loader2, LogOut, Circle, Moon, MinusCircle, Download, Puzzle, Palette,
} from "lucide-react";
import { useNodeHealth } from "../../hooks/useNodeHealth";
import { useModules, type ModuleInfo } from "../../hooks/useModules";
import { useTheme } from "../../hooks/useTheme";
import { invoke } from "@tauri-apps/api/core";
import { chat, groups } from "../../api/stone";

export interface SelectedServer {
  type: "server";
  orgId: string;
  name: string;
}

export interface SelectedDM {
  type: "dm";
  wallet: string;
  name: string;
}

export interface SelectedGroup {
  type: "group";
  id: string;
  name: string;
}

export type ActiveConversation = SelectedServer | SelectedDM | SelectedGroup;

interface NavRailProps {
  selectedServer: string | null;
  onSelectServer: (orgId: string) => void;
  activeConversation: ActiveConversation | null;
  onSelectConversation: (conv: ActiveConversation) => void;
  onCreateServer: () => void;
  onAddFriend: () => void;
}

interface Org {
  org_id: string;
  name: string;
  member_count: number;
  channel_count: number;
}

function shortAddr(addr: string): string {
  return addr.length > 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;
}

function NetworkStatus() {
  const { connected, blockHeight, network } = useNodeHealth();
  return (
    <div
      title={connected ? `Verbunden · ${network} · Block #${blockHeight.toLocaleString()}` : "Keine Verbindung"}
      style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 4px", cursor: "default" }}
    >
      <div style={{
        width: 7, height: 7, borderRadius: "50%",
        background: connected ? "var(--green)" : "rgba(255,255,255,0.18)",
        boxShadow: connected ? "0 0 5px var(--green)" : "none",
        animation: connected ? "pulse-glow 2.5s ease-in-out infinite" : "none",
        flexShrink: 0,
      }} />
      {connected && blockHeight > 0 && (
        <span style={{ fontSize: 10, fontWeight: 600, fontFamily: "monospace", color: "var(--text-muted)" }}>
          #{blockHeight > 9999 ? `${Math.floor(blockHeight / 1000)}k` : blockHeight}
        </span>
      )}
    </div>
  );
}

// ─── Top Navigation Bar (dynamisch, basierend auf Modulen) ──────────────────

const navIcons: Record<string, ReactNode> = {
  explorer: <Blocks size={16} />,
  games: <Gamepad2 size={16} />,
  node: <Server size={16} />,
  gaming: <Gamepad2 size={16} />,
  dashboard: <Blocks size={16} />,
};

const navLabels: Record<string, string> = {
  explorer: "Blockchain",
  games: "Spiele",
  node: "Node",
  gaming: "Gaming",
  dashboard: "Dashboard",
};

function TopNavBar({ onNavigate }: { onNavigate: (section: string) => void }) {
  const [collapsed, setCollapsed] = useState(false);
  const { optionalModules } = useModules();
  const { activeTheme, applyTheme, loadInstalledThemes } = useTheme();
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [themes, setThemes] = useState<{ id: string; name: string; icon: string }[]>([]);
  const [editorInstalled, setEditorInstalled] = useState(false);

  // Baue Nav-Items aus verfügbaren Modulen: Core (explorer) + optionals
  const navItems: { id: string; icon: ReactNode; label: string; available: boolean; mod?: ModuleInfo }[] = [
    { id: "explorer", icon: <Blocks size={16} />, label: "Blockchain", available: true },
    ...optionalModules.map((mod) => ({
      id: mod.name,
      icon: navIcons[mod.name] ?? <Puzzle size={16} />,
      label: navLabels[mod.name] ?? mod.display_name,
      available: mod.available,
      mod,
    })),
  ];

  return (
    <div style={{
      background: "var(--bg-panel)",
      borderBottom: "1px solid var(--border)",
      flexShrink: 0,
      transition: "height 0.2s ease",
      overflow: "visible",
      height: collapsed ? 32 : 40,
      position: "relative",
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 4,
        padding: "0 12px", height: "100%",
      }}>
        {/* Home */}
        <button
          onClick={() => onNavigate("home")}
          title="Startseite"
          style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "4px 10px", borderRadius: 6,
            background: "transparent", border: "none",
            color: "var(--text-secondary)", cursor: "pointer",
            fontSize: 12, fontWeight: 500,
            transition: "all 0.12s",
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.05)";
            (e.currentTarget as HTMLElement).style.color = "var(--text-primary)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "transparent";
            (e.currentTarget as HTMLElement).style.color = "var(--text-secondary)";
          }}
        >
          <HomeIcon size={16} />
          {!collapsed && "Start"}
        </button>

        <div style={{ width: 1, height: 18, background: "var(--border)", margin: "0 4px" }} />

        {/* Nav items (dynamic) */}
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => {
              if (item.available) {
                onNavigate(item.id === "gaming" ? "games" : item.id === "node" ? "node" : item.id);
              } else {
                // Nicht installiert → zum Erweiterungen-Tab
                onNavigate("extensions");
              }
            }}
            title={item.available ? item.label : `${item.label} — Nicht installiert (klicken zum Installieren)`}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "4px 10px", borderRadius: 6,
              background: "transparent", border: "none",
              color: item.available ? "var(--text-secondary)" : "var(--text-muted)",
              cursor: item.available ? "pointer" : "pointer",
              fontSize: 12, fontWeight: 500,
              transition: "all 0.12s",
              opacity: item.available ? 1 : 0.55,
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.05)";
              (e.currentTarget as HTMLElement).style.color = "var(--text-primary)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "transparent";
              (e.currentTarget as HTMLElement).style.color = item.available ? "var(--text-secondary)" : "var(--text-muted)";
            }}
          >
            {item.icon}
            {!collapsed && (
              <>
                {item.label}
                {!item.available && item.mod && (
                  <span
                    onClick={(e) => {
                      e.stopPropagation();
                      import("../../hooks/useModules").then(({ downloadModule }) => downloadModule(item.mod!));
                    }}
                    title={`${item.mod.display_name} herunterladen (${item.mod.size_mb} MB)`}
                    style={{
                      display: "inline-flex", alignItems: "center", gap: 2,
                      padding: "1px 6px", borderRadius: 8,
                      background: "var(--accent)", color: "var(--text-inverse)",
                      fontSize: 9, fontWeight: 700, cursor: "pointer",
                    }}
                  >
                    <Download size={10} />
                    {item.mod.size_mb}MB
                  </span>
                )}
              </>
            )}
          </button>
        ))}

        <div style={{ flex: 1 }} />

        {/* ➕ Erweiterungen-Button */}
        <button
          onClick={() => onNavigate("extensions")}
          title="Erweiterungen"
          style={{
            display: "flex", alignItems: "center", gap: 5,
            padding: "4px 10px", borderRadius: 8,
            background: "rgba(212,168,83,0.08)", border: "1px solid rgba(212,168,83,0.2)",
            color: "var(--accent)", cursor: "pointer",
            fontSize: 12, fontWeight: 600,
            transition: "all 0.15s",
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "rgba(212,168,83,0.15)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "rgba(212,168,83,0.08)";
          }}
        >
          <Puzzle size={14} />
          {!collapsed && "Erweiterungen"}
        </button>

        {/* 🎨 Theme-Button */}
        <div style={{ position: "relative" }}>
          <button
            onClick={async () => {
              setShowThemeMenu(!showThemeMenu);
              if (!showThemeMenu) {
                const t = await loadInstalledThemes();
                setThemes(t);
                const ui = await invoke<string | null>("get_extension_ui", { id: "theme-editor" }).catch(() => null);
                setEditorInstalled(!!ui);
              }
            }}
            title="Design ändern"
            style={{
              display: "flex", alignItems: "center", gap: 5,
              padding: "4px 10px", borderRadius: 8,
              background: showThemeMenu ? "rgba(212,168,83,0.15)" : "transparent",
              border: "1px solid transparent",
              color: activeTheme ? "var(--accent)" : "var(--text-secondary)",
              cursor: "pointer", fontSize: 12, fontWeight: 500,
              transition: "all 0.15s",
            }}
            onMouseEnter={(e) => {
              if (!showThemeMenu) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.05)";
            }}
            onMouseLeave={(e) => {
              if (!showThemeMenu) (e.currentTarget as HTMLElement).style.background = "transparent";
            }}
          >
            <Palette size={14} />
          </button>
          {showThemeMenu && (
            <div style={{
              position: "absolute", top: "100%", right: 0, marginTop: 6,
              background: "var(--bg-panel)", border: "1px solid var(--border)",
              borderRadius: 10, padding: 8, minWidth: 180, zIndex: 50,
              boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
            }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", padding: "4px 8px", marginBottom: 4 }}>
                🎨 Themes
              </div>
              <button
                onClick={() => { applyTheme(null); setShowThemeMenu(false); }}
                style={{
                  display: "flex", alignItems: "center", gap: 8, width: "100%",
                  padding: "6px 8px", borderRadius: 6, border: "none",
                  background: !activeTheme ? "rgba(255,255,255,0.08)" : "transparent",
                  color: "var(--text-primary)", cursor: "pointer", fontSize: 12,
                }}
              >
                <span>🌙</span> Standard
                {!activeTheme && <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--green)" }}>✓</span>}
              </button>
              {themes.map((t) => (
                <button
                  key={t.id}
                  onClick={() => { applyTheme(t.id); setShowThemeMenu(false); }}
                  style={{
                    display: "flex", alignItems: "center", gap: 8, width: "100%",
                    padding: "6px 8px", borderRadius: 6, border: "none",
                    background: activeTheme === t.id ? "rgba(255,255,255,0.08)" : "transparent",
                    color: "var(--text-primary)", cursor: "pointer", fontSize: 12,
                  }}
                >
                  <span>{t.icon || "🎨"}</span> {t.name}
                  {activeTheme === t.id && <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--green)" }}>✓</span>}
                </button>
              ))}
              {themes.length === 0 && !editorInstalled && (
                <div style={{ fontSize: 11, color: "var(--text-muted)", padding: "4px 8px" }}>
                  Keine Themes installiert
                </div>
              )}
              {editorInstalled && (
                <button
                  onClick={() => { onNavigate("theme-editor"); setShowThemeMenu(false); }}
                  style={{
                    display: "flex", alignItems: "center", gap: 8, width: "100%",
                    padding: "6px 8px", borderRadius: 6, border: "none",
                    background: "rgba(212,168,83,0.1)", color: "var(--accent)",
                    cursor: "pointer", fontSize: 12, fontWeight: 600,
                  }}
                >
                  🎨 Editor öffnen
                </button>
              )}
              <div style={{ borderTop: "1px solid var(--border)", margin: "4px 0" }} />
              <button
                onClick={() => { onNavigate("extensions"); setShowThemeMenu(false); }}
                style={{
                  display: "flex", alignItems: "center", gap: 8, width: "100%",
                  padding: "6px 8px", borderRadius: 6, border: "none",
                  background: "transparent", color: "var(--text-secondary)",
                  cursor: "pointer", fontSize: 11,
                }}
              >
                🧩 Mehr im Store…
              </button>
            </div>
          )}
        </div>

        <NetworkStatus />

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? "Leiste ausklappen" : "Leiste einklappen"}
          style={{
            width: 22, height: 22, borderRadius: 4,
            background: "rgba(255,255,255,0.04)", border: "none",
            color: "var(--text-muted)", cursor: "pointer",
            display: "flex", alignItems: "center", justifyContent: "center",
            flexShrink: 0,
          }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.08)"; }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)"; }}
        >
          {collapsed ? <ChevronDown size={12} /> : <ChevronUp size={12} />}
        </button>
      </div>
    </div>
  );
}

// ── DM List Panel ─────────────────────────────────────────────────────────────

function DMPanel({
  activeConversation,
  onSelectConversation,
  onAddFriend,
}: {
  activeConversation: ActiveConversation | null;
  onSelectConversation: (conv: ActiveConversation) => void;
  onAddFriend: () => void;
}) {
  const convQuery = useQuery({
    queryKey: ["conversations"],
    queryFn: chat.conversations,
    refetchInterval: 8_000,
  });
  const groupQuery = useQuery({
    queryKey: ["groups"],
    queryFn: groups.list,
    refetchInterval: 30_000,
  });
  const conversations = convQuery.data?.conversations ?? [];
  const grps = groupQuery.data?.groups ?? [];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 10px 6px", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <input
            type="text"
            placeholder="Gespräche suchen…"
            style={{
              flex: 1, background: "var(--bg-input)", border: "1px solid var(--border-default)",
              borderRadius: 6, padding: "5px 8px", fontSize: 11, color: "var(--text-primary)",
              outline: "none",
            }}
          />
          <button
            onClick={onAddFriend}
            title="Freunde hinzufügen"
            style={{
              width: 26, height: 26, borderRadius: 6,
              background: "rgba(255,255,255,0.04)", border: "none",
              color: "var(--text-muted)", cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
              flexShrink: 0,
            }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.08)"; (e.currentTarget as HTMLElement).style.color = "var(--accent)"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)"; (e.currentTarget as HTMLElement).style.color = "var(--text-muted)"; }}
          >
            <UserPlus size={14} />
          </button>
        </div>
      </div>

      {/* List */}
      <div style={{ flex: 1, overflowY: "auto", padding: "6px 4px" }}>
        {/* Groups */}
        {grps.length > 0 && (
          <div style={{ marginBottom: 6 }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", padding: "4px 8px 4px", letterSpacing: "0.04em" }}>
              Gruppen
            </div>
            {grps.map((g: any) => {
              const isActive = activeConversation?.type === "group" && (activeConversation as SelectedGroup).id === (g.group_id ?? g.id);
              return (
                <button
                  key={g.group_id ?? g.id}
                  onClick={() => onSelectConversation({ type: "group", id: g.group_id ?? g.id, name: g.name })}
                  style={{
                    display: "flex", alignItems: "center", gap: 8,
                    width: "100%", padding: "5px 8px", borderRadius: 6,
                    background: isActive ? "rgba(255,255,255,0.07)" : "transparent",
                    border: "none", color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
                    cursor: "pointer", fontSize: 12, textAlign: "left",
                    transition: "all 0.12s",
                  }}
                  onMouseEnter={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)"; }}
                  onMouseLeave={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                >
                  <Hash size={12} style={{ flexShrink: 0, color: "var(--text-muted)" }} />
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g.name}</span>
                  {g.unread_count > 0 && (
                    <span style={{ fontSize: 10, fontWeight: 700, background: "var(--accent)", color: "#fff", borderRadius: 20, padding: "1px 5px", minWidth: 14, textAlign: "center" }}>
                      {g.unread_count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}

        {/* DMs */}
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", padding: "4px 8px 4px", letterSpacing: "0.04em" }}>
            Direktnachrichten
          </div>
          {conversations.map((c: any) => {
            const wallet = c.peer_wallet ?? "";
            const name = c.peer_name || shortAddr(wallet);
            const isActive = activeConversation?.type === "dm" && (activeConversation as SelectedDM).wallet === wallet;
            let preview = c.last_message ?? "";
            try { preview = decodeURIComponent(escape(atob(preview))); } catch { /* raw */ }
            return (
              <button
                key={wallet}
                onClick={() => onSelectConversation({ type: "dm", wallet, name })}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  width: "100%", padding: "6px 8px", borderRadius: 6,
                  background: isActive ? "rgba(255,255,255,0.07)" : "transparent",
                  border: "none", color: "var(--text-primary)", cursor: "pointer",
                  textAlign: "left", transition: "all 0.12s",
                }}
                onMouseEnter={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)"; }}
                onMouseLeave={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: "50%",
                  background: "var(--accent)", display: "flex",
                  alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, color: "#fff",
                  flexShrink: 0, position: "relative",
                }}>
                  {name[0]?.toUpperCase() ?? "?"}
                  <div style={{
                    position: "absolute", bottom: -1, right: -1,
                    width: 9, height: 9, borderRadius: "50%",
                    background: "var(--bg-panel)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <div style={{
                      width: 5, height: 5, borderRadius: "50%",
                      background: c.online !== false ? "var(--green)" : "var(--text-muted)",
                    }} />
                  </div>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontSize: 12, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {name}
                    </span>
                    {c.unread_count > 0 && (
                      <span style={{ fontSize: 10, fontWeight: 700, background: "var(--accent)", color: "#fff", borderRadius: 20, padding: "1px 5px", marginLeft: 4, minWidth: 14, textAlign: "center" }}>
                        {c.unread_count}
                      </span>
                    )}
                  </div>
                  <p style={{ fontSize: 10, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 1 }}>
                    {preview || "Keine Nachrichten"}
                  </p>
                </div>
              </button>
            );
          })}
          {conversations.length === 0 && !convQuery.isLoading && (
            <p style={{ fontSize: 10, padding: "6px 8px", color: "var(--text-muted)" }}>
              Keine Gespräche — füge Freunde hinzu!
            </p>
          )}
          {convQuery.isLoading && (
            <div style={{ display: "flex", justifyContent: "center", padding: 12 }}>
              <Loader2 size={14} style={{ animation: "spin 0.7s linear infinite", color: "var(--text-muted)" }} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Server List Panel ─────────────────────────────────────────────────────────

function ServerPanel({
  selectedServer, onSelectServer,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  activeConversation: _activeConversation,
  onSelectConversation,
  onCreateServer,
}: {
  selectedServer: string | null;
  onSelectServer: (orgId: string) => void;
  activeConversation: ActiveConversation | null;
  onSelectConversation: (conv: ActiveConversation) => void;
  onCreateServer: () => void;
}) {
  const orgsQ = useQuery({
    queryKey: ["orgs"],
    queryFn: () => orgs.list(),
    refetchInterval: 15_000,
  });
  const orgsList: Org[] = ((orgsQ.data as any)?.orgs ?? []).map((o: any) => ({
    org_id: o.id ?? "",
    name: o.name ?? "",
    member_count: o.members ?? 0,
    channel_count: o.channels ?? 0,
  }));

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 10px 6px", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", flex: 1, letterSpacing: "0.04em" }}>
            Server
          </span>
          <button
            onClick={onCreateServer}
            title="Neuen Server erstellen"
            style={{
              width: 22, height: 22, borderRadius: 5,
              background: "rgba(255,255,255,0.04)", border: "1px dashed var(--border-strong)",
              color: "var(--accent)", cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            <Plus size={12} />
          </button>
        </div>
      </div>

      {/* Server list */}
      <div style={{ flex: 1, overflowY: "auto", padding: "6px 4px", display: "flex", flexDirection: "column", gap: 2 }}>
        {orgsList.map((org) => {
          const isActive = selectedServer === org.org_id;
          return (
            <button
              key={org.org_id}
              onClick={() => {
                onSelectServer(org.org_id);
                onSelectConversation({ type: "server", orgId: org.org_id, name: org.name });
              }}
              title={org.name}
              style={{
                display: "flex", alignItems: "center", gap: 8,
                width: "100%", padding: "6px 8px", borderRadius: 6,
                background: isActive ? "rgba(255,255,255,0.07)" : "transparent",
                border: "none", cursor: "pointer",
                textAlign: "left", transition: "all 0.12s",
              }}
              onMouseEnter={(e) => {
                if (!isActive) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)";
              }}
              onMouseLeave={(e) => {
                if (!isActive) (e.currentTarget as HTMLElement).style.background = "transparent";
              }}
            >
              <div style={{
                width: 28, height: 28, borderRadius: isActive ? 10 : 16,
                background: isActive ? "var(--accent)" : "var(--bg-surface)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 13, fontWeight: 700,
                color: isActive ? "var(--text-inverse)" : "var(--text-muted)",
                flexShrink: 0, transition: "all 0.2s",
              }}>
                {org.name[0]?.toUpperCase() ?? "S"}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: isActive ? "var(--accent)" : "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {org.name}
                </div>
                <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                  {org.member_count} Mitglieder
                </div>
              </div>
            </button>
          );
        })}
        {orgsList.length === 0 && !orgsQ.isLoading && (
          <p style={{ fontSize: 10, padding: "6px 8px", color: "var(--text-muted)" }}>
            Noch keine Server
          </p>
        )}
        {orgsQ.isLoading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 12 }}>
            <Loader2 size={14} style={{ animation: "spin 0.7s linear infinite", color: "var(--text-muted)" }} />
          </div>
        )}
      </div>
    </div>
  );
}

// ── Bottom User Bar ──────────────────────────────────────────────────────────

type OnlineStatus = "online" | "idle" | "dnd" | "offline";

const statusConfig: Record<OnlineStatus, { icon: ReactNode; label: string; color: string }> = {
  online:  { icon: <Circle size={9} fill="#22c55e" color="#22c55e" />, label: "Online", color: "#22c55e" },
  idle:    { icon: <Moon size={9} fill="#eab308" color="#eab308" />, label: "Abwesend", color: "#eab308" },
  dnd:     { icon: <MinusCircle size={9} fill="#ef4444" color="#ef4444" />, label: "Nicht stören", color: "#ef4444" },
  offline: { icon: <Circle size={9} fill="transparent" color="var(--text-muted)" />, label: "Offline", color: "var(--text-muted)" },
};

function UserBar() {
  const { session, logout } = useAuth();
  const [showMenu, setShowMenu] = useState(false);
  const [showStatusMenu, setShowStatusMenu] = useState(false);
  const [status, setStatus] = useState<OnlineStatus>("online");
  if (!session) return null;

  const currentStatus = statusConfig[status];

  const navigate = (section: string) => {
    setShowMenu(false);
    setShowStatusMenu(false);
    window.dispatchEvent(new CustomEvent("stone-navigate", { detail: { section } }));
  };

  return (
    <div style={{ position: "relative", borderTop: "1px solid var(--border)", background: "rgba(0,0,0,0.15)", flexShrink: 0 }}>
      <div
        onClick={() => setShowMenu(!showMenu)}
        style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "8px 10px", cursor: "pointer",
          background: showMenu ? "rgba(255,255,255,0.06)" : "transparent",
          transition: "background 0.15s",
        }}
        onMouseEnter={(e) => { if (!showMenu) (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.03)"; }}
        onMouseLeave={(e) => { if (!showMenu) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
      >
        <div style={{
          width: 28, height: 28, borderRadius: "50%",
          background: "var(--accent)", display: "flex",
          alignItems: "center", justifyContent: "center",
          fontSize: 12, fontWeight: 700, color: "#fff", flexShrink: 0,
          position: "relative",
        }}>
          {session.username?.[0]?.toUpperCase() ?? "?"}
          <div style={{
            position: "absolute", bottom: -1, right: -1,
            width: 13, height: 13, borderRadius: "50%",
            background: "var(--bg-panel)", display: "flex",
            alignItems: "center", justifyContent: "center",
          }}>
            {currentStatus.icon}
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: 12, fontWeight: 600, color: "var(--text-primary)",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {session.username}
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
            {currentStatus.label}
          </div>
        </div>
      </div>
      {showMenu && (
        <>
          <div onClick={() => { setShowMenu(false); setShowStatusMenu(false); }} style={{ position: "fixed", inset: 0, zIndex: 98 }} />
          <div style={{
            position: "absolute", bottom: "100%", left: 8, right: 8, zIndex: 99,
            background: "var(--bg-panel)", borderRadius: 12,
            border: "1px solid var(--border-strong)", padding: "6px 4px",
            boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          }}>
            {/* Status selector */}
            <div style={{ position: "relative", marginBottom: 2 }}>
              <button
                onClick={() => setShowStatusMenu(!showStatusMenu)}
                style={{
                  display: "flex", alignItems: "center", gap: 10,
                  width: "100%", padding: "8px 10px", borderRadius: 6,
                  background: showStatusMenu ? "rgba(255,255,255,0.06)" : "transparent",
                  border: "none", color: currentStatus.color, cursor: "pointer",
                  fontSize: 13, textAlign: "left",
                }}
              >
                {currentStatus.icon}
                <span style={{ flex: 1, color: "var(--text-primary)" }}>{currentStatus.label}</span>
                <span style={{ fontSize: 10, color: "var(--text-muted)" }}>▸</span>
              </button>
              {showStatusMenu && (
                <div style={{ marginLeft: 12, marginBottom: 2, display: "flex", flexDirection: "column", gap: 1 }}>
                  {(Object.entries(statusConfig) as [OnlineStatus, typeof currentStatus][]).map(([key, cfg]) => (
                    <button
                      key={key}
                      onClick={() => { setStatus(key); setShowStatusMenu(false); }}
                      style={{
                        display: "flex", alignItems: "center", gap: 8,
                        width: "100%", padding: "6px 10px", borderRadius: 4,
                        background: status === key ? "rgba(255,255,255,0.06)" : "transparent",
                        border: "none", color: cfg.color, cursor: "pointer",
                        fontSize: 12, textAlign: "left",
                      }}
                    >
                      {cfg.icon} {cfg.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div style={{ height: 1, background: "var(--border)", margin: "2px 8px" }} />
            <button onClick={() => navigate("profile")} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "8px 10px", borderRadius: 6, background: "transparent", border: "none", color: "var(--text-primary)", cursor: "pointer", fontSize: 13, textAlign: "left" }}>
              <User size={15} /> Profil bearbeiten
            </button>
            <button onClick={() => navigate("wallet")} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "8px 10px", borderRadius: 6, background: "transparent", border: "none", color: "var(--text-primary)", cursor: "pointer", fontSize: 13, textAlign: "left" }}>
              <Wallet size={15} /> Wallet anzeigen
            </button>
            <div style={{ height: 1, background: "var(--border)", margin: "2px 8px" }} />
            <button onClick={() => navigate("settings")} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "8px 10px", borderRadius: 6, background: "transparent", border: "none", color: "var(--text-primary)", cursor: "pointer", fontSize: 13, textAlign: "left" }}>
              <Settings size={15} /> Einstellungen
            </button>
            <div style={{ height: 1, background: "var(--border)", margin: "2px 8px" }} />
            <button
              onClick={() => { setShowMenu(false); logout(); }}
              style={{
                display: "flex", alignItems: "center", gap: 8,
                width: "100%", padding: "8px 10px", borderRadius: 6,
                background: "transparent", border: "none",
                color: "#ef4444", cursor: "pointer", fontSize: 13, textAlign: "left",
              }}
            >
              <LogOut size={15} /> Abmelden
            </button>
          </div>
        </>
      )}
      <style>{`@keyframes pulse-glow { 0%,100%{opacity:1;box-shadow:0 0 5px var(--green)}50%{opacity:0.6;box-shadow:0 0 2px var(--green)} }`}</style>
    </div>
  );
}

// ── Main Layout ──────────────────────────────────────────────────────────────

export default function NavRail(props: NavRailProps) {
  const { selectedServer, onSelectServer, activeConversation, onSelectConversation, onCreateServer, onAddFriend } = props;

  const navigate = (section: string) => {
    window.dispatchEvent(new CustomEvent("stone-navigate", { detail: { section } }));
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden" }}>
      {/* ── Top Navigation Bar ──────────────────────────────── */}
      <TopNavBar onNavigate={navigate} />

      {/* ── Main area: Server Panel | DM Panel | Content ──── */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Server Panel (left) — scrollable list + collapsible profile */}
        <div style={{
          width: 180, flexShrink: 0,
          background: "var(--rail-bg)",
          borderRight: "1px solid var(--border)",
          display: "flex", flexDirection: "column",
          overflow: "hidden",
        }}>
          <ServerPanel
            selectedServer={selectedServer}
            onSelectServer={onSelectServer}
            activeConversation={activeConversation}
            onSelectConversation={onSelectConversation}
            onCreateServer={onCreateServer}
          />
          {/* Collapsible profile at bottom of server panel */}
          <UserBar />
        </div>

        {/* DM Panel (middle) */}
        <div style={{
          width: 220, flexShrink: 0,
          background: "var(--bg-panel)",
          borderRight: "1px solid var(--border)",
          display: "flex", flexDirection: "column",
          overflow: "hidden",
        }}>
          <DMPanel
            activeConversation={activeConversation}
            onSelectConversation={onSelectConversation}
            onAddFriend={onAddFriend}
          />
        </div>

        {/* Content area is rendered by App.tsx as sibling */}
      </div>
    </div>
  );
}