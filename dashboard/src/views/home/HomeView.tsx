import { useAuth } from "../../auth/AuthContext";
import { Hash } from "lucide-react";

export default function HomeView() {
  const { session } = useAuth();

  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", height: "100%", gap: 16, padding: 48,
      background: "var(--main-bg)",
    }}>
      <Hash size={40} style={{ color: "var(--text-muted)", opacity: 0.3 }} />
      <div style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
          Willkommen zurück, {session?.username ?? "User"}
        </h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 8, lineHeight: 1.6 }}>
          Wähle links einen Server oder eine Direktnachricht.
          <br />
          Oben findest du Explorer, Spiele und Node.
        </p>
      </div>
    </div>
  );
}