import { useState, type ReactElement } from "react";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import LoginView from "./auth/LoginView";
import NavRail, { type NavSection } from "./components/layout/NavRail";
import { useQuery } from "@tanstack/react-query";
import { chat as chatApi } from "./api/stone";

import ChatView from "./views/chat/ChatView";
import WalletView from "./views/wallet/WalletView";
import ExplorerView from "./views/explorer/ExplorerView";
import FileUploadView from "./views/files/FileUploadView";
import GamesView from "./views/games/GamesView";
import ServerView from "./views/servers/ServerView";
import AnnouncementsView from "./views/announcements/AnnouncementsView";
import NodeView from "./views/node/NodeView";
import ProfileView from "./views/profile/ProfileView";

function MainApp() {
  const { session } = useAuth();
  const [section, setSection] = useState<NavSection>("servers");

  const convQuery = useQuery({
    queryKey: ["conversations"],
    queryFn: chatApi.conversations,
    refetchInterval: 15_000,
    enabled: !!session,
  });

  const totalUnread = (convQuery.data?.conversations ?? []).reduce(
    (s, c) => s + c.unread_count,
    0,
  );

  if (!session) return <LoginView />;

  const views: Record<NavSection, ReactElement> = {
    chat: <ChatView />,
    wallet: <WalletView />,
    explorer: <ExplorerView />,
    files: <FileUploadView />,
    games: <GamesView />,
    servers: <ServerView />,
    announcements: <AnnouncementsView />,
    node: <NodeView />,
    profile: <ProfileView />,
  };

  return (
    <div
      className="flex h-screen overflow-hidden"
      style={{ background: "var(--main-bg)" }}
    >
      {/* macOS traffic light drag region — only on macOS */}
      {/Mac|iPhone|iPad|iPod/.test(navigator.platform) && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            height: 44,
            WebkitAppRegion: "drag",
            zIndex: 100,
            pointerEvents: "none",
          } as React.CSSProperties}
        />
      )}

      <NavRail
        active={section}
        onChange={setSection}
        unreadChat={totalUnread || undefined}
      />

      <main className="flex-1 overflow-hidden">
        {views[section]}
      </main>
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
