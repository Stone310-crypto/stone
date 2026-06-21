import {
  useState,
  useEffect,
  useRef,
  useCallback,
  type FormEvent,
  type ReactNode,
} from "react";
import QRCode from "qrcode";
import { useAuth } from "./AuthContext";
import { auth as authApi } from "../api/stone";
import { loadSettings, saveSettings } from "../store/session";

async function openExternal(url: string) {
  try {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(url);
  } catch {
    window.open(url, "_blank");
  }
}

function Background() {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none" style={{ zIndex: 0 }}>
      <div style={{ position: "absolute", top: "-20%", left: "-10%", width: 600, height: 600, borderRadius: "50%", background: "radial-gradient(circle, rgba(91,138,238,0.12) 0%, transparent 70%)", filter: "blur(40px)" }} />
      <div style={{ position: "absolute", bottom: "-20%", right: "-5%", width: 500, height: 500, borderRadius: "50%", background: "radial-gradient(circle, rgba(168,85,247,0.10) 0%, transparent 70%)", filter: "blur(60px)" }} />
      <div style={{ position: "absolute", inset: 0, backgroundImage: `linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)`, backgroundSize: "48px 48px", maskImage: "radial-gradient(ellipse at center, black 30%, transparent 80%)", WebkitMaskImage: "radial-gradient(ellipse at center, black 30%, transparent 80%)" }} />
    </div>
  );
}

function Card({ children }: { children: ReactNode }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.035)", backdropFilter: "blur(24px)", WebkitBackdropFilter: "blur(24px)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 20, boxShadow: "0 0 0 1px rgba(255,255,255,0.04), 0 24px 64px rgba(0,0,0,0.6)", padding: "32px 28px", width: 400, position: "relative", zIndex: 1 }}>
      {children}
    </div>
  );
}

function Logo() {
  return (
    <div className="flex flex-col items-center mb-7">
      <div style={{ width: 52, height: 52, borderRadius: 16, background: "linear-gradient(135deg, #5b8aee, #7c6df5)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, fontWeight: 800, color: "#fff", marginBottom: 14, boxShadow: "0 8px 24px rgba(91,138,238,0.35)" }}>S</div>
      <p style={{ fontSize: 18, fontWeight: 700, color: "var(--text)", marginBottom: 3 }}>Stone Chain</p>
      <p style={{ fontSize: 13, color: "var(--text-muted)" }}>Blockchain · Wallet · Chat</p>
    </div>
  );
}

function Tabs({ active, onChange }: { active: "login" | "register"; onChange: (t: "login" | "register") => void }) {
  return (
    <div className="flex relative mb-6 rounded-xl p-0.5" style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)" }}>
      <div style={{ position: "absolute", top: 2, left: active === "login" ? 2 : "calc(50% + 1px)", width: "calc(50% - 3px)", bottom: 2, borderRadius: 10, background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.1)", transition: "left 0.2s cubic-bezier(0.4,0,0.2,1)" }} />
      {(["login", "register"] as const).map((t) => (
        <button key={t} onClick={() => onChange(t)} className="flex-1 py-2 text-sm font-medium relative z-10 transition-colors rounded-xl" style={{ color: active === t ? "var(--text)" : "var(--text-muted)" }}>{t === "login" ? "Anmelden" : "Registrieren"}</button>
      ))}
    </div>
  );
}

function Input({ label, value, onChange, placeholder, type = "text", hint, badge, textarea, mono }:
  { label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string; hint?: string; badge?: ReactNode; textarea?: boolean; mono?: boolean }) {
  const [focused, setFocused] = useState(false);
  const baseStyle: React.CSSProperties = { width: "100%", background: "rgba(255,255,255,0.04)", border: `1px solid ${focused ? "rgba(91,138,238,0.7)" : "rgba(255,255,255,0.08)"}`, borderRadius: 10, padding: "10px 13px", fontSize: 13, color: "var(--text)", outline: "none", fontFamily: mono ? "'SF Mono', 'Fira Code', monospace" : "inherit", lineHeight: 1.6, resize: "none" as const, transition: "border-color 0.15s", boxShadow: focused ? "0 0 0 3px rgba(91,138,238,0.12)" : "none" };
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-dim)" }}>{label}</label>
        {badge}
      </div>
      {textarea ? <textarea value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} rows={3} style={baseStyle} onFocus={() => setFocused(true)} onBlur={() => setFocused(false)} autoComplete="off" spellCheck={false} autoCorrect="off" autoCapitalize="off" />
        : <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} style={baseStyle} onFocus={() => setFocused(true)} onBlur={() => setFocused(false)} autoComplete="off" />}
      {hint && <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{hint}</p>}
    </div>
  );
}

function PrimaryBtn({ children, onClick, disabled, loading, type = "button", color }:
  { children: ReactNode; onClick?: () => void; disabled?: boolean; loading?: boolean; type?: "button" | "submit"; color?: string }) {
  return (
    <button type={type} onClick={onClick} disabled={disabled || loading} style={{ width: "100%", padding: "11px 0", borderRadius: 10, background: disabled || loading ? "rgba(255,255,255,0.06)" : color ?? "linear-gradient(135deg, #5b8aee, #7c6df5)", color: disabled || loading ? "var(--text-muted)" : "#fff", fontSize: 14, fontWeight: 600, cursor: disabled || loading ? "not-allowed" : "pointer", border: "none", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, transition: "opacity 0.15s, transform 0.1s", transform: "scale(1)", boxShadow: disabled || loading ? "none" : "0 4px 20px rgba(91,138,238,0.3)" }}>
      {loading ? <span style={{ width: 16, height: 16, border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "#fff", borderRadius: "50%", display: "inline-block", animation: "spin 0.7s linear infinite" }} /> : children}
    </button>
  );
}

function ErrorBox({ msg }: { msg: string }) {
  return <div style={{ background: "rgba(237,66,69,0.1)", border: "1px solid rgba(237,66,69,0.3)", borderRadius: 8, padding: "9px 12px", fontSize: 12, color: "var(--red)" }}>{msg}</div>;
}

function Divider({ label }: { label: string }) {
  return <div style={{ display: "flex", alignItems: "center", gap: 10 }}><div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} /><span style={{ fontSize: 11, color: "var(--text-muted)" }}>{label}</span><div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} /></div>;
}

function AltBtn({ icon, label, onClick }: { icon: ReactNode; label: string; onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)} style={{ flex: 1, padding: "10px 8px", borderRadius: 10, background: hovered ? "rgba(255,255,255,0.07)" : "rgba(255,255,255,0.03)", border: `1px solid ${hovered ? "rgba(255,255,255,0.14)" : "rgba(255,255,255,0.07)"}`, color: hovered ? "var(--text)" : "var(--text-dim)", fontSize: 12, fontWeight: 500, cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", gap: 5, transition: "all 0.15s" }}>
      {icon}
      {label}
    </button>
  );
}

// ── LOGIN FORM ────────────────────────────────────────────────────────────────

function LoginForm({ onSwitchToQr, onSwitchToDiscord }: { onSwitchToQr: () => void; onSwitchToDiscord: () => void }) {
  const { login } = useAuth();
  const [phrase, setPhrase] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const wordCount = phrase.trim().split(/\s+/).filter(Boolean).length;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (wordCount !== 12) return;
    setError("");
    setLoading(true);
    try { await login(phrase.trim()); }
    catch (err) { setError(err instanceof Error ? err.message : "Anmeldung fehlgeschlagen"); }
    finally { setLoading(false); }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Input label="Recovery Phrase" value={phrase} onChange={setPhrase} placeholder="word1 word2 word3 …" textarea mono badge={<span style={{ fontSize: 11, fontWeight: 600, color: wordCount === 12 ? "var(--green)" : "var(--text-muted)", background: wordCount === 12 ? "rgba(59,165,92,0.15)" : "rgba(255,255,255,0.05)", borderRadius: 20, padding: "1px 8px", transition: "all 0.2s" }}>{wordCount}/12</span>} />
      {error && <ErrorBox msg={error} />}
      <PrimaryBtn type="submit" disabled={wordCount !== 12} loading={loading}>Anmelden</PrimaryBtn>
      <Divider label="oder anmelden mit" />
      <div style={{ display: "flex", gap: 8 }}>
        <AltBtn icon={<span style={{ fontSize: 18 }}>📱</span>} label="Stonechain App" onClick={onSwitchToQr} />
        <AltBtn icon={<svg width="18" height="18" viewBox="0 0 127.14 96.36" fill="#5865f2"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z" /></svg>} label="Discord" onClick={onSwitchToDiscord} />
      </div>
    </form>
  );
}

// ── REGISTER FORM ─────────────────────────────────────────────────────────────

function RegisterForm() {
  const { signup } = useAuth();
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [savedPhrase, setSavedPhrase] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [copied, setCopied] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setError("");
    setLoading(true);
    try { const phrase = await signup(name.trim()); setSavedPhrase(phrase); }
    catch (err) { setError(err instanceof Error ? err.message : "Registrierung fehlgeschlagen"); }
    finally { setLoading(false); }
  }

  function copyPhrase() { navigator.clipboard.writeText(savedPhrase); setCopied(true); setTimeout(() => setCopied(false), 2000); }

  if (savedPhrase && !confirmed) {
    const words = savedPhrase.trim().split(/\s+/);
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ background: "rgba(250,166,26,0.08)", border: "1px solid rgba(250,166,26,0.25)", borderRadius: 10, padding: "10px 13px" }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: "var(--yellow)", marginBottom: 3 }}>⚠️ Nur einmal sichtbar!</p>
          <p style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5 }}>Notiere diese 12 Wörter. Ohne sie ist dein Konto nicht wiederherstellbar.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
          {words.map((w, i) => (
            <div key={i} style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "6px 10px", display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, color: "var(--text-muted)", width: 16 }}>{i + 1}.</span>
              <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text)", fontFamily: "monospace" }}>{w}</span>
            </div>
          ))}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={copyPhrase} style={{ flex: 1, padding: "10px", borderRadius: 10, background: copied ? "rgba(59,165,92,0.15)" : "rgba(255,255,255,0.04)", border: `1px solid ${copied ? "rgba(59,165,92,0.4)" : "rgba(255,255,255,0.08)"}`, color: copied ? "var(--green)" : "var(--text-dim)", fontSize: 13, fontWeight: 500, cursor: "pointer", transition: "all 0.15s" }}>{copied ? "✓ Kopiert" : "Kopieren"}</button>
          <button onClick={() => setConfirmed(true)} style={{ flex: 1, padding: "10px", borderRadius: 10, background: "linear-gradient(135deg, #5b8aee, #7c6df5)", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer", border: "none", boxShadow: "0 4px 16px rgba(91,138,238,0.3)" }}>Gesichert →</button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Input label="Benutzername" value={name} onChange={setName} placeholder="z.B. Leon" hint="Wallet und Recovery Phrase werden automatisch generiert." />
      {error && <ErrorBox msg={error} />}
      <PrimaryBtn type="submit" disabled={!name.trim()} loading={loading}>Konto erstellen</PrimaryBtn>
    </form>
  );
}

// ── STONECHAIN APP LOGIN (QR-Code — kein forge-nomad, lokale Session + VPS-Push) ──

function StonechainAppLoginView({ onBack }: { onBack: () => void }) {
  const { applySession } = useAuth();
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [status, setStatus] = useState<"loading" | "waiting" | "approved" | "expired" | "error">("loading");
  const [timeLeft, setTimeLeft] = useState(0);
  const [error, setError] = useState("");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const createSession = useCallback(async () => {
    setStatus("loading"); setQrDataUrl(""); setError("");
    if (pollRef.current) clearInterval(pollRef.current);
    if (timerRef.current) clearInterval(timerRef.current);
    try {
      const res = await authApi.qrCreate();
      const s = loadSettings();
      const nodes: string[] = [];
      try { const { invoke } = await import("@tauri-apps/api/core"); const ip: string = await invoke("get_local_ip"); nodes.push(`http://${ip}:${new URL(s.nodeUrl).port || "3080"}`); } catch { nodes.push(s.nodeUrl); }
      nodes.push("http://212.227.54.241:3080");
      const payload = JSON.stringify({ type: "stone_login", token: res.login_token, nodes });
      const dataUrl = await QRCode.toDataURL(payload, { width: 200, margin: 2, color: { dark: "#e2e8f0", light: "#161920" } });
      setQrDataUrl(dataUrl); setTimeLeft(res.expires_in); setStatus("waiting");
      timerRef.current = setInterval(() => setTimeLeft((t) => { if (t <= 1) { clearInterval(timerRef.current!); setStatus("expired"); return 0; } return t - 1; }), 1000);
      pollRef.current = setInterval(async () => {
        try {
          const poll = await authApi.qrStatus(res.login_token);
          if (poll.status === "approved" && poll.session_token && poll.user) {
            clearInterval(pollRef.current!); clearInterval(timerRef.current!); setStatus("approved");
            applySession({ sessionToken: poll.session_token, apiKey: poll.api_key ?? poll.session_token, userId: poll.user.id, walletAddress: poll.user.wallet_address, username: poll.user.name, phrase: poll.phrase ?? undefined });
          } else if (poll.status === "expired") { clearInterval(pollRef.current!); clearInterval(timerRef.current!); setStatus("expired"); }
        } catch {}
      }, 2000);
    } catch (err) { setError(err instanceof Error ? err.message : "Verbindung fehlgeschlagen"); setStatus("error"); }
  }, [applySession]);

  useEffect(() => { createSession(); return () => { if (pollRef.current) clearInterval(pollRef.current); if (timerRef.current) clearInterval(timerRef.current); }; }, [createSession]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ textAlign: "center" }}><p style={{ fontSize: 16, fontWeight: 700, color: "var(--text)", marginBottom: 5 }}>Login mit Stonechain App</p><p style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>Öffne die <strong style={{ color: "var(--text-dim)" }}>Stonechain App</strong> auf deinem Handy und scanne diesen QR-Code. Keine Seed-Phrase nötig.</p></div>
      <div style={{ alignSelf: "center", position: "relative", borderRadius: 16, overflow: "hidden", background: "#161920", border: "1px solid rgba(255,255,255,0.1)", boxShadow: "0 8px 32px rgba(0,0,0,0.4)" }}>
        {status === "loading" && <div style={{ width: 200, height: 200, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ width: 28, height: 28, border: "2px solid rgba(91,138,238,0.3)", borderTopColor: "var(--accent)", borderRadius: "50%", display: "block", animation: "spin 0.7s linear infinite" }} /></div>}
        {qrDataUrl &&<img src={qrDataUrl} alt="QR Code" style={{ width: 200, height: 200, display: "block", opacity: status === "waiting" ? 1 : 0.2, transition: "opacity 0.3s" }} />}
        {status === "approved" && <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", background: "rgba(59,165,92,0.92)", gap: 6 }}><span style={{ fontSize: 36 }}>✓</span><p style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>Eingeloggt!</p></div>}
        {status === "expired" && <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", background: "rgba(20,23,32,0.92)", gap: 10 }}><p style={{ fontSize: 13, color: "var(--text-dim)" }}>Code abgelaufen</p><button onClick={createSession} style={{ padding: "6px 16px", borderRadius: 8, background: "var(--accent)", color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none" }}>Neu laden</button></div>}
      </div>
      {status === "waiting" && <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, fontSize: 12, color: "var(--text-muted)" }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent)", animation: "pulse 1.5s ease-in-out infinite" }} />Warte auf Bestätigung… <span style={{ fontFamily: "monospace", color: timeLeft < 30 ? "var(--yellow)" : "var(--text-dim)" }}>{timeLeft}s</span></div>}
      {status === "error" && <ErrorBox msg={error} />}
      <button onClick={onBack} style={{ fontSize: 12, color: "var(--text-muted)", textAlign: "center", cursor: "pointer", background: "none", border: "none", textDecoration: "underline", textDecorationColor: "transparent" }} onMouseEnter={(e) => (e.currentTarget.style.textDecorationColor = "var(--text-muted)")} onMouseLeave={(e) => (e.currentTarget.style.textDecorationColor = "transparent")}>← Zurück zur Anmeldung</button>
    </div>
  );
}

// ── DISCORD LOGIN ─────────────────────────────────────────────────────────────

const DISCORD_CLIENT_ID = "1504220990484385883";
const DISCORD_REDIRECT = "https://www.unrooted.dev/management/login/discord/callback";

function DiscordLoginView({ onBack }: { onBack: () => void }) {
  const [loading, setLoading] = useState(false);
  const discordUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT)}&response_type=code&scope=identify&state=desktop_app`;

  function openDiscord() {
    setLoading(true);
    openExternal(discordUrl);
    setTimeout(() => setLoading(false), 2000);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ textAlign: "center" }}>
        <p style={{ fontSize: 16, fontWeight: 700, color: "var(--text)", marginBottom: 5 }}>Mit Discord anmelden</p>
        <p style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>Du wirst zu Discord weitergeleitet. Nach der Bestätigung wird dein Account erstellt.</p>
      </div>
      <PrimaryBtn onClick={openDiscord} loading={loading} color="#5865f2">
        <svg width="20" height="16" viewBox="0 0 127.14 96.36" fill="white"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z" /></svg>
        Mit Discord fortfahren
      </PrimaryBtn>
      <button onClick={onBack} style={{ fontSize: 12, color: "var(--text-muted)", textAlign: "center", cursor: "pointer", background: "none", border: "none" }}>← Zurück</button>
    </div>
  );
}

// ── Advanced ──────────────────────────────────────────────────────────────────

function AdvancedSettings() {
  const s = loadSettings();
  const [url, setUrl] = useState(s.nodeUrl);
  const [saved, setSaved] = useState(false);
  const [nodeStatus, setNodeStatus] = useState<string>("");
  const [nodeLoading, setNodeLoading] = useState(false);

  useEffect(() => {
    let i: ReturnType<typeof setInterval>;
    const poll = async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const raw: unknown = await invoke("node_get_status");
        if (typeof raw === "string") setNodeStatus(raw);
        else if (typeof raw === "object" && raw !== null) {
          const obj = raw as Record<string, unknown>;
          if (obj.running && typeof obj.running === "object") {
            const r = obj.running as { port?: number; pid?: number };
            setNodeStatus(`Running :${r.port ?? "?"}`);
          } else if (obj.error && typeof obj.error === "object") {
            const e = obj.error as { message?: string };
            setNodeStatus(e.message ?? "Error");
          } else setNodeStatus(JSON.stringify(raw));
        }
      } catch { setNodeStatus(""); }
    };
    poll(); i = setInterval(poll, 3000);
    return () => clearInterval(i);
  }, []);

  function save() { saveSettings({ ...s, nodeUrl: url }); setSaved(true); setTimeout(() => setSaved(false), 1500); }

  async function toggleNode() {
    setNodeLoading(true);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      if (nodeStatus.startsWith("Running")) await invoke("node_stop");
      else { const result: string = await invoke("node_start"); setUrl(result); saveSettings({ ...s, nodeUrl: result }); setSaved(true); setTimeout(() => setSaved(false), 1500); }
    } catch (e: unknown) { setNodeStatus(`Error: ${e instanceof Error ? e.message : String(e)}`); }
    setNodeLoading(false);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", gap: 8 }}>
        <input type="text" value={url} onChange={(e) => { setUrl(e.target.value); setSaved(false); }} style={{ flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "8px 10px", fontSize: 11, color: "var(--text)", outline: "none", fontFamily: "monospace" }} />
        <button onClick={save} style={{ padding: "8px 12px", borderRadius: 8, background: saved ? "rgba(59,165,92,0.25)" : "rgba(91,138,238,0.25)", color: saved ? "var(--green)" : "var(--accent)", fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none", transition: "all 0.15s" }}>{saved ? "✓" : "OK"}</button>
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <div style={{ flex: 1, fontSize: 11, color: nodeStatus.startsWith("Running") ? "var(--green)" : "var(--text-muted)" }}>Node: {nodeStatus || "Kein Node-Manager"}</div>
        <button onClick={toggleNode} disabled={nodeLoading || !nodeStatus} style={{ padding: "6px 14px", borderRadius: 8, background: nodeStatus.startsWith("Running") ? "rgba(237,66,69,0.2)" : "rgba(59,165,92,0.2)", color: nodeStatus.startsWith("Running") ? "var(--red)" : "var(--green)", fontSize: 11, fontWeight: 600, cursor: "pointer", border: "none", opacity: nodeLoading ? 0.5 : 1 }}>{nodeLoading ? "⏳" : nodeStatus.startsWith("Running") ? "Stop Node" : "Start Node"}</button>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

type View = "main" | "stonechain" | "discord";

export default function LoginView() {
  const [tab, setTab] = useState<"login" | "register">("login");
  const [view, setView] = useState<View>("main");
  const [showAdvanced, setShowAdvanced] = useState(false);

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0a0b0f", position: "relative", paddingTop: 44 }}>
      <Background />
      <Card>
        {view === "main" && (<><Logo /><Tabs active={tab} onChange={(t) => setTab(t)} />{tab === "login" ? <LoginForm onSwitchToQr={() => setView("stonechain")} onSwitchToDiscord={() => setView("discord")} /> : <RegisterForm />}</>)}
        {view === "stonechain" && <StonechainAppLoginView onBack={() => setView("main")} />}
        {view === "discord" && <DiscordLoginView onBack={() => setView("main")} />}
        <div style={{ marginTop: 20, textAlign: "center" }}>
          <button onClick={() => setShowAdvanced((v) => !v)} style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", cursor: "pointer", background: "none", border: "none", transition: "color 0.15s" }} onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--text-muted)")} onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.2)")}>{showAdvanced ? "▲" : "▼"} Node URL</button>
          {showAdvanced && <div style={{ marginTop: 8 }}><AdvancedSettings /></div>}
          <button onClick={() => { localStorage.clear(); window.location.reload(); }} style={{ fontSize: 10, color: "rgba(237,66,69,0.3)", cursor: "pointer", background: "none", border: "none", marginTop: 14, transition: "color 0.15s" }} onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--red)")} onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "rgba(237,66,69,0.3)")}>Session löschen (bei Login-Problemen)</button>
        </div>
      </Card>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } } @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.85); } }`}</style>
    </div>
  );
}