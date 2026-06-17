import { useState, type ReactElement, useEffect } from "react";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import LoginView from "./auth/LoginView";
import NavRail, { type ActiveConversation } from "./components/layout/NavRail";

import HomeView from "./views/home/HomeView";
import ExplorerView from "./views/explorer/ExplorerView";
import GamesView from "./views/games/GamesView";
import ServerView from "./views/servers/ServerView";
import NodeView from "./views/node/NodeView";
import ProfileView from "./views/profile/ProfileView";
import ChatView from "./views/chat/ChatView";
import WalletView from "./views/wallet/WalletView";
import ProfileEditOverlay from "./views/profile/ProfileEditOverlay";
import FriendAddOverlay from "./views/chat/FriendAddOverlay";
import SettingsOverlay from "./views/profile/SettingsOverlay";
import { useWebSocketEvents } from "./hooks/useWebSocketEvents";

declare global {
  interface WindowEventMap {
    "stone-navigate": CustomEvent<{ section: string }>;
  }
}

function CreateServerDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const handleCreate = async () => {
    if (!name.trim()) return;
    setLoading(true);
    try {
      const { orgs } = await import("./api/stone");
      await orgs.create(name.trim());
      onClose();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };
  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100,
    }}>
      <div style={{
        background: "var(--bg-panel)", borderRadius: 16, padding: 24, width: 400,
        border: "1px solid var(--border-strong)",
      }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Server erstellen</h2>
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", marginBottom: 6, display: "block" }}>
            Server-Name
          </label>
          <input
            type="text" value={name} onChange={(e) => setName(e.target.value)}
            placeholder="Mein Server" autoFocus
            style={{
              width: "100%", background: "var(--bg-input)", border: "1px solid var(--border-default)",
              borderRadius: 8, padding: "10px 12px", fontSize: 13, color: "var(--text-primary)", outline: "none",
            }}
          />
        </div>
        {error && (
          <div style={{ background: "var(--red-bg)", borderRadius: 8, padding: 8, fontSize: 12, color: "var(--red)", marginBottom: 12 }}>
            {error}
          </div>
        )}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button onClick={onClose} style={{ padding: "10px 20px", borderRadius: 8, border: "1px solid var(--border-default)", color: "var(--text-secondary)", cursor: "pointer", fontSize: 13, background: "transparent" }}>
            Abbrechen
          </button>
          <button onClick={handleCreate} disabled={!name.trim() || loading} style={{ padding: "10px 20px", borderRadius: 8, background: (!name.trim() || loading) ? "rgba(212,168,83,0.3)" : "var(--accent)", color: "var(--text-inverse)", cursor: (!name.trim() || loading) ? "not-allowed" : "pointer", border: "none", fontSize: 13, fontWeight: 600 }}>
            {loading ? "Erstelle…" : "Erstellen"}
          </button>
        </div>
      </div>
    </div>
  );
}

function MainApp() {
  const { session } = useAuth();
  useWebSocketEvents();
  const [activeSection, setActiveSection] = useState<string>("home");
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [activeConversation, setActiveConversation] = useState<ActiveConversation | null>(null);
  const [showCreateServer, setShowCreateServer] = useState(false);
  const [showWalletOverlay, setShowWalletOverlay] = useState(false);
  const [showProfileOverlay, setShowProfileOverlay] = useState(false);
  const [showFriendOverlay, setShowFriendOverlay] = useState(false);
  const [showSettingsOverlay, setShowSettingsOverlay] = useState(false);

  // Listen for stone-navigate events from UserBar etc.
  useEffect(() => {
    const handler = (e: CustomEvent<{ section: string }>) => {
      const s = e.detail.section;
      if (s === "wallet") {
        setShowWalletOverlay((prev) => !prev);
        return;
      }
      if (s === "profile") {
        setShowProfileOverlay(true);
        return;
      }
      if (s === "settings") {
        setShowSettingsOverlay(true);
        return;
      }
      if (["home", "explorer", "games", "node"].includes(s)) {
        setActiveSection(s);
        setActiveConversation(null);
        setSelectedServer(null);
      }
    };
    window.addEventListener("stone-navigate", handler as EventListener);
    return () => window.removeEventListener("stone-navigate", handler as EventListener);
  }, []);

  if (!session) return <LoginView />;

  const showServer = !!selectedServer && activeConversation?.type === "server";
  const showDm = activeConversation?.type === "dm" || activeConversation?.type === "group";

  const views: Record<string, ReactElement> = {
    home: <HomeView />,
    explorer: <ExplorerView />,
    games: <GamesView />,
    node: <NodeView />,
    profile: <ProfileView />,
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden", background: "var(--main-bg)" }}>
      {/* macOS Title Bar Area */}
      {/Mac|iPhone|iPad|iPod/.test(navigator.platform) && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, height: 44,
          WebkitAppRegion: "drag", zIndex: 100, pointerEvents: "none",
        } as React.CSSProperties} />
      )}

      {showCreateServer && <CreateServerDialog onClose={() => setShowCreateServer(false)} />}

      {/* ── Top Nav + Left Panels (NavRail) + Bottom UserBar ── */}
      <NavRail
        selectedServer={selectedServer}
        onSelectServer={setSelectedServer}
        activeConversation={activeConversation}
        onSelectConversation={(conv) => {
          setActiveConversation(conv);
          if (conv) {
            if (conv.type === "server") {
              setSelectedServer(conv.orgId);
            } else {
              setSelectedServer(null);
            }
          }
        }}
        onCreateServer={() => setShowCreateServer(true)}
        onAddFriend={() => setShowFriendOverlay(true)}
      />

      {/* ── Main Content overlaid to the right of the panels ── */}
      <div style={{ position: "absolute", top: 40, left: 400, right: 0, bottom: 0, overflow: "hidden" }}>
        {showServer ? (
          <ServerView selectedOrg={selectedServer} />
        ) : showDm ? (
          <ChatView initialActive={activeConversation} />
        ) : views[activeSection] || <HomeView />}
      </div>

      {/* ── Wallet Overlay ───────────────────────────────── */}
      {showWalletOverlay && (
        <WalletView onClose={() => setShowWalletOverlay(false)} />
      )}

      {/* ── Profile Edit Overlay ──────────────────────────── */}
      {showProfileOverlay && (
        <ProfileEditOverlay onClose={() => setShowProfileOverlay(false)} />
      )}

      {/* ── Friend Add Overlay ───────────────────────────── */}
      {showFriendOverlay && (
        <FriendAddOverlay onClose={() => setShowFriendOverlay(false)} />
      )}

      {/* ── Settings Overlay ──────────────────────────────── */}
      {showSettingsOverlay && (
        <SettingsOverlay onClose={() => setShowSettingsOverlay(false)} />
      )}
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}