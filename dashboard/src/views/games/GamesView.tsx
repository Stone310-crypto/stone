import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { games as gamesApi } from "../../api/stone";
import { useAuth } from "../../auth/AuthContext";
import { getStoredNetwork } from "../../hooks/useNetwork";
import type { OnChainGame } from "../../types/api";
import { ShieldCheck, Gamepad2, Users, Coins, Plus, Building, AlertTriangle, ArrowLeft } from "lucide-react";
import Avatar from "../../components/ui/Avatar";

function GameCard({ game, active, onClick }: { game: OnChainGame; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick}
      style={{
        display: "flex", alignItems: "center", gap: 10, width: "100%",
        padding: "10px 12px", borderRadius: 8, textAlign: "left",
        background: active ? "var(--surface-2)" : "transparent",
        border: "none", cursor: "pointer",
        borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
        transition: "background 0.12s",
      }}
      onMouseEnter={(e) => { if (!active) (e.currentTarget as HTMLElement).style.background = "var(--surface)"; }}
      onMouseLeave={(e) => { if (!active) (e.currentTarget as HTMLElement).style.background = "transparent"; }}>
      <Avatar name={game.name} size={32} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <span style={{ fontSize: 13, fontWeight: 500, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{game.name}</span>
          {game.verified && <ShieldCheck size={12} style={{ color: "var(--accent)", flexShrink: 0 }} />}
        </div>
        <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{game.player_count != null ? `${game.player_count} Spieler` : "—"}</p>
      </div>
    </button>
  );
}

function GameDetail({ game, myWallet }: { game: OnChainGame; myWallet: string }) {
  const balanceQ = useQuery({ queryKey: ["game-balance", game.game_id, myWallet], queryFn: () => gamesApi.coinBalance(game.game_id, myWallet), enabled: !!myWallet });
  const poolQ = useQuery({ queryKey: ["game-pool", game.game_id], queryFn: () => gamesApi.poolStatus(game.game_id) });
  return (
    <div style={{ padding: 32, maxWidth: 560 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
        <Avatar name={game.name} size={56} />
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>{game.name}</h2>
            {game.verified && <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 10, background: "var(--accent-dim)", color: "var(--accent)", display: "flex", alignItems: "center", gap: 4 }}><ShieldCheck size={11} />Verifiziert</span>}
          </div>
          <p style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace", marginTop: 4 }}>{game.game_id}</p>
        </div>
      </div>
      {game.description && <p style={{ fontSize: 13, color: "var(--text-dim)", lineHeight: 1.6, marginBottom: 20 }}>{game.description}</p>}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, padding: 16, display: "flex", alignItems: "center", gap: 12 }}>
          <Users size={20} style={{ color: "var(--accent)" }} />
          <div><div style={{ fontSize: 18, fontWeight: 700 }}>{game.player_count ?? "—"}</div><div style={{ fontSize: 11, color: "var(--text-muted)" }}>Spieler</div></div>
        </div>
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, padding: 16, display: "flex", alignItems: "center", gap: 12 }}>
          <Coins size={20} style={{ color: "var(--accent)" }} />
          <div><div style={{ fontSize: 18, fontWeight: 700 }}>{balanceQ.data ? `${parseFloat(balanceQ.data.balance).toFixed(2)}` : "—"}</div><div style={{ fontSize: 11, color: "var(--text-muted)" }}>Mein Guthaben</div></div>
        </div>
      </div>
      {poolQ.data && (
        <div style={{ background: poolQ.data.configured ? "var(--accent-dim)" : "var(--surface)", border: `1px solid ${poolQ.data.configured ? "var(--accent)" : "var(--border)"}`, borderRadius: 12, padding: 16 }}>
          <p style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: poolQ.data.configured ? "var(--accent)" : "var(--text-dim)" }}>Gaming Pool</p>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}><span style={{ color: "var(--text-dim)" }}>Balance</span><span style={{ fontWeight: 500 }}>{parseFloat(poolQ.data.pool_balance).toFixed(2)} STONE</span></div>
        </div>
      )}
    </div>
  );
}

function FormField({ label, value, onChange, placeholder, hint }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; hint?: string }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>{label}</label>
      <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        style={{ width: "100%", padding: "10px 12px", borderRadius: 8, background: "var(--bg-input)", border: "1px solid var(--border)", color: "var(--text)", fontSize: 13, outline: "none" }} />
      {hint && <p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>{hint}</p>}
    </div>
  );
}

export default function GamesView() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const network = getStoredNetwork();
  const isTestnet = network === "testnet";
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [selected, setSelected] = useState<OnChainGame | null>(null);
  const [tab, setTab] = useState<"games"|"companies"|"register-game"|"register-company">("games");

  const allQ = useQuery({ queryKey: ["games-all"], queryFn: gamesApi.list, refetchInterval: 60_000, enabled: isTestnet });
  const verifiedQ = useQuery({ queryKey: ["games-verified"], queryFn: gamesApi.verified, enabled: verifiedOnly && isTestnet, refetchInterval: 60_000 });

  const [companies, setCompanies] = useState<any[]>([]);
  useEffect(() => { if (isTestnet) invoke<any[]>("list_companies").then(setCompanies).catch(() => setCompanies([])); }, [tab, isTestnet]);

  const [regForm, setRegForm] = useState<any>({});
  const [regError, setRegError] = useState("");
  const [regOk, setRegOk] = useState("");
  const [regLoading, setRegLoading] = useState(false);

  async function handleRegisterGame() {
    setRegLoading(true); setRegError(""); setRegOk("");
    try {
      await invoke("register_game", { req: { game_id: regForm.gameId || "", name: regForm.name || "", version: regForm.version || "1.0.0", owner_company: regForm.ownerCompany || session?.walletAddress || "", genres: (regForm.genres || "").split(",").map((s: string) => s.trim()).filter(Boolean) } });
      setRegForm({}); setRegOk("Spiel registriert!");
      qc.invalidateQueries({ queryKey: ["games-all"] });
      setTimeout(() => setRegOk(""), 3000);
      setTab("games");
    } catch (e: any) { setRegError(e?.message || String(e)); }
    finally { setRegLoading(false); }
  }

  async function handleRegisterCompany() {
    setRegLoading(true); setRegError(""); setRegOk("");
    try {
      await invoke("create_company", { req: { name: regForm.companyName || "", country: regForm.country || "", website: regForm.website || "", owner_wallet: regForm.ownerWallet || session?.walletAddress || "" } });
      setRegForm({}); setRegOk("Firma registriert!");
      setTimeout(() => setRegOk(""), 3000);
      setTab("companies");
    } catch (e: any) { setRegError(e?.message || String(e)); }
    finally { setRegLoading(false); }
  }

  // Not testnet → show warning
  if (!isTestnet) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--main-bg)" }}>
        <div style={{ textAlign: "center", maxWidth: 420, padding: 40 }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🧪</div>
          <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Nur im Testnet verfügbar</h2>
          <p style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 20 }}>
            Das Gaming-Modul (Firmen & Spiele registrieren) ist nur im Stone-Testnet aktiv.
            Wechsle in den Testnet-Mode, um es zu nutzen.
          </p>
          <div style={{ background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.2)", borderRadius: 10, padding: "12px 16px", display: "inline-flex", alignItems: "center", gap: 8 }}>
            <AlertTriangle size={16} color="#f59e0b" />
            <span style={{ fontSize: 12, color: "#f59e0b" }}>Du bist im <strong>Mainnet</strong>. Öffne 🧪 Testnet Mode zum Wechseln.</span>
          </div>
        </div>
      </div>
    );
  }

  const gameList = (verifiedOnly ? verifiedQ.data?.games : allQ.data?.games) ?? [];

  return (
    <div style={{ display: "flex", height: "100%", background: "var(--main-bg)" }}>
      {/* Left Panel */}
      <div style={{ width: 200, flexShrink: 0, background: "var(--panel-bg)", borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column" }}>
        <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--border)" }}>
          <div style={{ display: "flex", gap: 2, padding: 2, borderRadius: 8, background: "var(--surface)", marginBottom: 8 }}>
            {[[false, "Alle"], [true, "Verifiziert"]].map(([val, label]) => (
              <button key={String(label)} onClick={() => setVerifiedOnly(val as boolean)}
                style={{ flex: 1, padding: "4px 0", borderRadius: 6, border: "none", cursor: "pointer",
                  background: verifiedOnly === val ? "var(--accent)" : "transparent",
                  color: verifiedOnly === val ? "#000" : "var(--text-dim)", fontSize: 11, fontWeight: 500 }}>
                {label as string}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <button onClick={() => { setTab("register-game"); setRegForm({}); setRegError(""); setRegOk(""); }}
              style={{ padding: "6px 10px", borderRadius: 6, border: "none", cursor: "pointer", background: "var(--accent)", color: "#000", fontSize: 11, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}>
              <Plus size={12} /> Spiel registrieren
            </button>
            <button onClick={() => { setTab("register-company"); setRegForm({}); setRegError(""); setRegOk(""); }}
              style={{ padding: "6px 10px", borderRadius: 6, border: "none", cursor: "pointer", background: "var(--border)", color: "var(--text)", fontSize: 11, fontWeight: 500, display: "flex", alignItems: "center", gap: 6 }}>
              <Building size={12} /> Firma registrieren
            </button>
            {tab !== "games" && (
              <button onClick={() => { setTab("games"); setSelected(null); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "none", cursor: "pointer", background: "transparent", color: "var(--text-muted)", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}>
                <ArrowLeft size={12} /> Zurück zur Liste
              </button>
            )}
          </div>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "4px 6px" }}>
          {gameList.map((g) => (
            <GameCard key={g.game_id} game={g} active={selected?.game_id === g.game_id} onClick={() => { setSelected(g); setTab("games"); }} />
          ))}
          {gameList.length === 0 && !allQ.isLoading && (
            <p style={{ fontSize: 11, color: "var(--text-muted)", padding: "8px 12px", textAlign: "center" }}>Keine Spiele registriert</p>
          )}
          {allQ.isLoading && (
            <p style={{ fontSize: 11, color: "var(--text-muted)", padding: "8px 12px", textAlign: "center" }}>Lade…</p>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, overflowY: "auto", padding: 24 }}>
        {/* Testnet Banner */}
        <div style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)", borderRadius: 10, padding: "8px 14px", marginBottom: 20, display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "#f59e0b" }}>
          <AlertTriangle size={14} /> 🧪 Testnet — Firmen & Spiele sind experimentell.
        </div>

        {tab === "games" && selected && <GameDetail game={selected} myWallet={session?.walletAddress ?? ""} />}
        {tab === "games" && !selected && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60%", gap: 12, color: "var(--text-muted)" }}>
            <Gamepad2 size={48} style={{ opacity: 0.2 }} />
            <p style={{ fontSize: 14, fontWeight: 600, color: "var(--text-dim)" }}>Game auswählen</p>
            <p style={{ fontSize: 12 }}>{gameList.length} Games verfügbar</p>
          </div>
        )}

        {/* Companies Tab */}
        {tab === "companies" && (
          <div>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>🏢 Registrierte Firmen</h2>
            {companies.length === 0 ? (
              <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Noch keine Firmen registriert.</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {companies.map((c: any, i: number) => (
                  <div key={i} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 14 }}>{c.name}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{c.country}{c.website ? ` · ${c.website}` : ""}</div>
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>{c.owner_wallet?.slice(0, 12)}…</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Register Game Form */}
        {tab === "register-game" && (
          <div style={{ maxWidth: 480 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 20 }}>➕ Neues Spiel registrieren</h2>
            {regError && <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 8, fontSize: 12, background: "rgba(239,68,68,0.08)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.2)" }}>{regError}</div>}
            {regOk && <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 8, fontSize: 12, background: "rgba(34,197,94,0.08)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.2)" }}>{regOk}</div>}
            <FormField label="Game-ID" value={regForm.gameId || ""} onChange={v => setRegForm({ ...regForm, gameId: v })} placeholder="mein-spiel" hint="3-64 Zeichen: a-z, 0-9, _, -" />
            <FormField label="Name" value={regForm.name || ""} onChange={v => setRegForm({ ...regForm, name: v })} placeholder="Mein Spiel" />
            <FormField label="Version" value={regForm.version || ""} onChange={v => setRegForm({ ...regForm, version: v })} placeholder="1.0.0" />
            <FormField label="Company-Wallet (Owner)" value={regForm.ownerCompany || session?.walletAddress || ""} onChange={v => setRegForm({ ...regForm, ownerCompany: v })} placeholder={session?.walletAddress || ""} />
            <FormField label="Genres" value={regForm.genres || ""} onChange={v => setRegForm({ ...regForm, genres: v })} placeholder="RPG, Adventure" hint="Kommagetrennt" />
            <button onClick={handleRegisterGame} disabled={regLoading}
              style={{ width: "100%", padding: "12px", borderRadius: 10, border: "none", cursor: regLoading ? "wait" : "pointer",
                background: regLoading ? "rgba(212,168,83,0.3)" : "var(--accent)", color: regLoading ? "var(--text-muted)" : "#000",
                fontSize: 13, fontWeight: 600, marginTop: 8 }}>
              {regLoading ? "Registriere…" : "📝 Spiel registrieren"}
            </button>
          </div>
        )}

        {/* Register Company Form */}
        {tab === "register-company" && (
          <div style={{ maxWidth: 480 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 20 }}>🏗️ Neue Firma registrieren</h2>
            {regError && <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 8, fontSize: 12, background: "rgba(239,68,68,0.08)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.2)" }}>{regError}</div>}
            {regOk && <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 8, fontSize: 12, background: "rgba(34,197,94,0.08)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.2)" }}>{regOk}</div>}
            <FormField label="Firmenname" value={regForm.companyName || ""} onChange={v => setRegForm({ ...regForm, companyName: v })} placeholder="Mein Studio" hint="2-64 Zeichen" />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <FormField label="Land (ISO)" value={regForm.country || ""} onChange={v => setRegForm({ ...regForm, country: v })} placeholder="DE" />
              <FormField label="Website" value={regForm.website || ""} onChange={v => setRegForm({ ...regForm, website: v })} placeholder="https://..." />
            </div>
            <FormField label="Owner-Wallet" value={regForm.ownerWallet || session?.walletAddress || ""} onChange={v => setRegForm({ ...regForm, ownerWallet: v })} placeholder={session?.walletAddress || ""} />
            <button onClick={handleRegisterCompany} disabled={regLoading}
              style={{ width: "100%", padding: "12px", borderRadius: 10, border: "none", cursor: regLoading ? "wait" : "pointer",
                background: regLoading ? "rgba(212,168,83,0.3)" : "var(--accent)", color: regLoading ? "var(--text-muted)" : "#000",
                fontSize: 13, fontWeight: 600, marginTop: 8 }}>
              {regLoading ? "Registriere…" : "🏗️ Firma registrieren"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
