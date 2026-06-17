import { useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import Avatar from "../../components/ui/Avatar";
import { ArrowLeft, X, Camera, Loader2 } from "lucide-react";

interface ProfileEditOverlayProps {
  onClose: () => void;
}

export default function ProfileEditOverlay({ onClose }: ProfileEditOverlayProps) {
  const { session } = useAuth();
  const [username, setUsername] = useState(session?.username ?? "");
  const [bio, setBio] = useState("");
  const [serverTag, setServerTag] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    if (!username.trim()) return;
    setSaving(true);
    setError("");
    try {
      const { apiFetch } = await import("../../api/client");
      const resp = await apiFetch<any>("/api/v1/auth/profile/update", {
        method: "POST",
        body: JSON.stringify({ name: username.trim(), bio: bio.trim() }),
      });
      if (resp.error) { setError(resp.error); return; }
      if (session) session.username = username.trim();
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e: any) {
      setError(e?.message ?? "Fehler beim Speichern");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 55,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "rgba(0,0,0,0.55)",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        background: "var(--bg-panel)",
        borderRadius: 16,
        width: 460,
        maxWidth: "94vw",
        maxHeight: "85vh",
        overflowY: "auto",
        border: "1px solid var(--border-strong)",
        boxShadow: "0 16px 48px rgba(0,0,0,0.5)",
      }}>
        {/* Banner */}
        <div style={{
          height: 80,
          background: "linear-gradient(135deg, #d4a853 0%, #c9953a 40%, #b8862d 100%)",
          borderRadius: "16px 16px 0 0",
          position: "relative",
        }}>
          <button
            title="Banner ändern"
            style={{
              position: "absolute", bottom: 8, right: 8,
              width: 28, height: 28, borderRadius: 8,
              background: "rgba(0,0,0,0.3)", border: "none",
              color: "rgba(255,255,255,0.7)", cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
              opacity: 0.7,
            }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.opacity = "1"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.opacity = "0.7"; }}
          >
            <Camera size={14} />
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: "0 20px 20px" }}>
          {/* Header */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16, marginTop: -36 }}>
            <button onClick={onClose} title="Zurück"
              style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(0,0,0,0.3)", border: "none", color: "#fff", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <ArrowLeft size={16} />
            </button>

            {/* Avatar with edit button */}
            <div style={{ position: "relative", flexShrink: 0 }}>
              <Avatar name={session?.username ?? "?"} size={56} />
              <button
                title="Profilbild ändern"
                style={{
                  position: "absolute", bottom: 0, right: 0,
                  width: 22, height: 22, borderRadius: 7,
                  background: "var(--accent)", border: "2px solid var(--bg-panel)",
                  color: "#fff", cursor: "pointer",
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}
              >
                <Camera size={11} />
              </button>
            </div>

            <div style={{ flex: 1 }} />
            <button onClick={onClose} style={{ background: "rgba(0,0,0,0.3)", border: "none", color: "#fff", cursor: "pointer", borderRadius: 8, padding: 6, display: "flex" }}>
              <X size={16} />
            </button>
          </div>

          {/* Form */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {/* Username */}
            <div>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                Anzeigename
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Dein Name"
                style={{
                  width: "100%", padding: "10px 12px", borderRadius: 10,
                  background: "var(--bg-input)", border: "1px solid var(--border-default)",
                  color: "var(--text-primary)", fontSize: 14, fontWeight: 600,
                  outline: "none", boxSizing: "border-box",
                }}
                autoComplete="off"
              />
            </div>

            {/* Bio */}
            <div>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                Über mich
              </label>
              <textarea
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                placeholder="Erzähle etwas über dich…"
                rows={3}
                style={{
                  width: "100%", padding: "10px 12px", borderRadius: 10,
                  background: "var(--bg-input)", border: "1px solid var(--border-default)",
                  color: "var(--text-primary)", fontSize: 13,
                  outline: "none", resize: "vertical",
                  fontFamily: "inherit", boxSizing: "border-box",
                }}
              />
            </div>

            {/* Server Tag */}
            <div>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                Server Tag
              </label>
              <input
                type="text"
                value={serverTag}
                onChange={(e) => setServerTag(e.target.value)}
                placeholder="#0000 · Kommt bald"
                disabled
                style={{
                  width: "100%", padding: "10px 12px", borderRadius: 10,
                  background: "var(--bg-surface)", border: "1px solid var(--border-default)",
                  color: "var(--text-muted)", fontSize: 13,
                  outline: "none", opacity: 0.5, cursor: "not-allowed",
                  boxSizing: "border-box",
                }}
              />
              <p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                Server-Tags werden in zukünftigen Updates verfügbar sein.
              </p>
            </div>

            {/* Error */}
            {error && (
              <div style={{ background: "var(--red-bg)", border: "1px solid rgba(217,91,91,0.3)", borderRadius: 8, padding: "9px 12px", fontSize: 12, color: "var(--red)" }}>
                {error}
              </div>
            )}

            {/* Save */}
            <button
              onClick={handleSave}
              disabled={!username.trim() || saving}
              style={{
                width: "100%", padding: 12, borderRadius: 10,
                background: saved ? "var(--green)" : (!username.trim() || saving) ? "rgba(212,168,83,0.3)" : "var(--accent)",
                color: saved ? "#fff" : "var(--text-inverse)",
                fontWeight: 600, fontSize: 14, border: "none",
                cursor: (!username.trim() || saving) ? "not-allowed" : "pointer",
                display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
              }}
            >
              {saving ? <Loader2 size={18} style={{ animation: "spin 0.7s linear infinite" }} /> : saved ? "✓ Gespeichert" : "Speichern"}
            </button>
          </div>
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}