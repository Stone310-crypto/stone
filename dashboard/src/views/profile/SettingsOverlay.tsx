import { useState, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNodeHealth } from "../../hooks/useNodeHealth";
import { useSystemStats } from "../../hooks/useSystemStats";
import { getNotifPrefs, saveNotifPrefs } from "../../hooks/useWebSocketEvents";
import { nodeManager, type NodeConfig, type NodeStatus } from "../../api/node";
import {
  ArrowLeft, X, Play, Square, RefreshCw, Download, AlertTriangle,
  Wifi, WifiOff, Server, Palette, Shield, ChevronRight,
} from "lucide-react";

type SettingsPage = "main" | "system" | "personalization" | "privacy" | "updates";
interface SettingsOverlayProps { onClose: () => void; }

const card: React.CSSProperties = { background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 12, border: "1px solid rgba(255,255,255,0.05)", marginBottom: 10 };
const secHdr: React.CSSProperties = { fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", display: "block", marginBottom: 10 };
const spin: React.CSSProperties = { animation: "spin 1s linear infinite" };
const btnSm: React.CSSProperties = { padding: "5px 10px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.1)", background: "rgba(255,255,255,0.04)", color: "var(--text-muted)", fontSize: 11, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, whiteSpace: "nowrap" as const };
const banner = (rgb: string): React.CSSProperties => ({ background: `rgba(${rgb},0.08)`, border: `1px solid rgba(${rgb},0.2)`, borderRadius: 8, padding: "10px 12px" });

// ── ToggleRow ───────────────────────────────────────────────────
function ToggleRow({ label, sub, checked, loading, onToggle }: { label: string; sub: string; checked: boolean; loading?: boolean; onToggle: () => void }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <div><span style={{ fontSize: 12, color: "var(--text-primary)" }}>{label}</span><p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>{sub}</p></div>
      <button onClick={onToggle} disabled={loading} style={{ width: 40, height: 22, borderRadius: 11, border: "none", cursor: loading ? "wait" : "pointer", background: checked ? "var(--accent)" : "rgba(255,255,255,0.12)", position: "relative", transition: "background 0.2s", opacity: loading ? 0.5 : 1, flexShrink: 0 }}>
        <div style={{ width: 18, height: 18, borderRadius: "50%", background: "#fff", position: "absolute", top: 2, left: checked ? 20 : 2, transition: "left 0.2s" }} />
      </button>
    </div>
  );
}

// ── AutoStartToggle ─────────────────────────────────────────────
function AutoStartToggle() {
  const [on, setOn] = useState(false); const [ld, setLd] = useState(true);
  useEffect(() => { import("@tauri-apps/api/core").then(({ invoke }) => { invoke<boolean>("get_auto_launch").then(setOn).catch(() => {}).finally(() => setLd(false)); }).catch(() => setLd(false)); }, []);
  async function toggle() { if (ld) return; setLd(true); try { const { invoke } = await import("@tauri-apps/api/core"); setOn(await invoke<boolean>("set_auto_launch", { enable: !on })); } catch {} setLd(false); }
  return <ToggleRow label="Auto-Start" sub="App automatisch beim System-Login starten" checked={on} loading={ld} onToggle={toggle} />;
}

// ── NotificationToggles ─────────────────────────────────────────
function NotificationToggles() {
  const [prefs, setPrefs] = useState(getNotifPrefs());
  const toggle = (k: keyof typeof prefs) => { const n = { ...prefs, [k]: !prefs[k] }; setPrefs(n); saveNotifPrefs(n); };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <ToggleRow label="Nachrichten" sub="Benachrichtigung bei neuen Direktnachrichten" checked={prefs.messages} onToggle={() => toggle("messages")} />
      <ToggleRow label="Anrufe" sub="Benachrichtigung bei eingehenden Anrufen" checked={prefs.calls} onToggle={() => toggle("calls")} />
    </div>
  );
}

// ── NodeBadge ───────────────────────────────────────────────────
function NodeBadge({ status }: { status: NodeStatus | null }) {
  if (!status) return null;
  const m: Record<string, { c: string; bg: string; l: string }> = { stopped: { c: "var(--text-muted)", bg: "rgba(255,255,255,0.05)", l: "Gestoppt" }, starting: { c: "#eab308", bg: "rgba(250,166,26,0.1)", l: "Startet…" }, running: { c: "var(--green)", bg: "rgba(59,165,92,0.1)", l: "Läuft" }, error: { c: "var(--red)", bg: "rgba(237,66,69,0.1)", l: "Fehler" }, binary_not_found: { c: "var(--red)", bg: "rgba(237,66,69,0.08)", l: "Binary fehlt" } };
  const x = m[status.status] ?? m.stopped;
  return <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 8, background: x.bg, fontSize: 11, fontWeight: 600, color: x.c }}><div style={{ width: 6, height: 6, borderRadius: "50%", background: status.status === "running" ? "var(--green)" : status.status === "starting" ? "#eab308" : "var(--text-muted)", animation: status.status === "starting" ? "pulse 1.2s ease-in-out infinite" : "none" }} />{x.l}</div>;
}

// ── AppUpdatePanel ──────────────────────────────────────────────
function AppUpdatePanel() {
  const [v, sv] = useState("…"); const [st, sst] = useState<"idle"|"checking"|"available"|"downloading"|"ready"|"error">("idle"); const [inf, si] = useState<{version:string;body:string}|null>(null); const [err, se] = useState(""); const [pct, sp] = useState(0);
  useEffect(() => { import("@tauri-apps/api/app").then(({getVersion})=>getVersion().then(sv).catch(()=>sv("?"))).catch(()=>sv("?")); }, []);
  async function check() { sst("checking"); se(""); try { const {check} = await import("@tauri-apps/plugin-updater"); const u = await check({timeout:15000}); if(u){si({version:u.version,body:u.body||""});sst("available");}else sst("idle"); } catch(e:any){se(e?.message||String(e));sst("error");} }
  async function install() { sst("downloading"); se(""); sp(0); try { try { const {invoke}=await import("@tauri-apps/api/core"); await invoke("node_stop"); await new Promise(r=>setTimeout(r,800)); console.log("[updater] Node gestoppt."); } catch(e){ console.warn("[updater] Node-Stop fehlgeschlagen:",e); } const {check}=await import("@tauri-apps/plugin-updater"); const u = await check({timeout:15000}); if(!u){sst("idle");return;} si({version:u.version,body:u.body||""}); await u.downloadAndInstall((e)=>{if(e.event==="Progress")sp(p=>Math.min(99,p+5));else if(e.event==="Finished"){sp(100);sst("ready");}},{timeout:120000}); try{const {relaunch}=await import("@tauri-apps/plugin-process");await relaunch();}catch{} } catch(e:any){se(e?.message||String(e));sst("error");} }
  return (
    <div style={{display:"flex",flexDirection:"column",gap:8}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <div><span style={{fontSize:12,color:"var(--text-primary)"}}>Dashboard</span><p style={{fontSize:10,color:"var(--text-muted)",marginTop:1}}>Installiert: v{v}</p></div>
        {st==="idle"&&<button onClick={check} style={btnSm}><RefreshCw size={12}/> Prüfen</button>}
        {st==="checking"&&<span style={{fontSize:11,color:"var(--text-muted)",display:"flex",alignItems:"center",gap:4}}><RefreshCw size={12} style={spin}/> Suche…</span>}
      </div>
      {st==="available"&&inf&&<div style={banner("59,130,246")}><div style={{fontWeight:600,fontSize:12,color:"#3b82f6",marginBottom:2}}>🆕 v{inf.version} verfügbar</div>{inf.body&&<div style={{fontSize:10,color:"var(--text-muted)",lineHeight:1.4,maxHeight:36,overflow:"hidden",marginBottom:8}}>{inf.body.slice(0,200)}</div>}<button onClick={install} style={{...btnSm,background:"#3b82f6",color:"#fff",border:"none"}}><Download size={12}/> Installieren</button></div>}
      {st==="downloading"&&<div style={banner("59,130,246")}><div style={{fontSize:12,color:"#3b82f6",display:"flex",alignItems:"center",gap:6,marginBottom:6}}><RefreshCw size={12} style={spin}/> Download {pct}%</div><div style={{height:4,borderRadius:2,background:"rgba(59,130,246,0.15)",overflow:"hidden"}}><div style={{height:"100%",width:`${pct}%`,background:"#3b82f6",borderRadius:2,transition:"width 0.3s"}}/></div></div>}
      {st==="ready"&&<div style={banner("34,197,94")}><span style={{fontSize:12,color:"#22c55e",display:"flex",alignItems:"center",gap:6}}><Download size={12}/> Installiert – App startet neu…</span></div>}
      {st==="error"&&<div style={banner("239,68,68")}><div style={{fontSize:11,color:"#ef4444",display:"flex",alignItems:"center",gap:4,marginBottom:6}}><AlertTriangle size={12}/> {err}</div><button onClick={check} style={{...btnSm,border:"1px solid rgba(239,68,68,0.3)",background:"transparent",color:"#ef4444"}}>Wiederholen</button></div>}
    </div>
  );
}

// ── NodeBinaryPanel ─────────────────────────────────────────────
function NodeBinaryPanel() {
  const [tag, st] = useState<string|null>(null); const [chk, sc] = useState(false); const [dld, sd] = useState(false); const [err, se] = useState(""); const [done, sdone] = useState(false); const [restarting, srestart] = useState(false);
  async function check() { sc(true); se(""); sdone(false); try { const {invoke}=await import("@tauri-apps/api/core"); st(await invoke<string|null>("node_binary_check_updates")); } catch(e:any){se(e?.message||String(e));} sc(false); }
  async function download() { sd(true); se(""); srestart(false); try { const {invoke}=await import("@tauri-apps/api/core"); await invoke("node_binary_download_latest"); sdone(true); st(null); srestart(true); } catch(e:any){se(e?.message||String(e));} sd(false); }
  return (
    <div style={{display:"flex",flexDirection:"column",gap:8}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <div><span style={{fontSize:12,color:"var(--text-primary)"}}>Node-Binaries</span><p style={{fontSize:10,color:"var(--text-muted)",marginTop:1}}>stone-app-node, stone-master, stonevpn</p></div>
        {!tag&&!done&&<button onClick={check} disabled={chk} style={btnSm}><RefreshCw size={12} style={chk?spin:undefined}/> {chk?"Prüfe…":"Prüfen"}</button>}
        {done&&<span style={{fontSize:11,color:"#22c55e",fontWeight:600}}>✅ Aktuell{restarting?" – Node wurde neugestartet":""}</span>}
      </div>
      {tag&&<div style={banner("59,130,246")}><div style={{fontWeight:600,fontSize:12,color:"#3b82f6",marginBottom:8}}>🆕 Neue Version: {tag}</div><button onClick={download} disabled={dld} style={{...btnSm,background:"#3b82f6",color:"#fff",border:"none"}}><Download size={12}/> {dld?"Download & Neustart…":"Herunterladen & Node neustarten"}</button></div>}
      {err&&<div style={banner("239,68,68")}><div style={{fontSize:11,color:"#ef4444",display:"flex",alignItems:"center",gap:4,marginBottom:6}}><AlertTriangle size={12}/> {err}</div><button onClick={check} style={{...btnSm,border:"1px solid rgba(239,68,68,0.3)",background:"transparent",color:"#ef4444"}}>Wiederholen</button></div>}
    </div>
  );
}

// ── StatBar ─────────────────────────────────────────────────────
function StatBar({ label, value, total, max, color }: { label: string; value: number; total?: number; max: number; color?: string }) {
  const dm = total ?? max; const pct = Math.min((value / dm) * 100, 100);
  const bc = color ?? (value > 80 ? "var(--red)" : value > 50 ? "var(--accent)" : "var(--green)");
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{label}</span>
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", fontFamily: "monospace" }}>{value}{total ? ` / ${total} MB` : "%"}</span>
      </div>
      <div style={{ height: 5, borderRadius: 3, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
        <div style={{ height: "100%", borderRadius: 3, background: bc, width: `${pct}%`, transition: "width 0.5s" }} />
      </div>
    </div>
  );
}

// ── Categories ──────────────────────────────────────────────────
const categories = [
  { id: "system" as const, icon: <Server size={20}/>, label: "System", desc: "Node, Netzwerk, Auto-Start" },
  { id: "personalization" as const, icon: <Palette size={20}/>, label: "Personalisierung", desc: "Theme, Sprache, Benachrichtigungen" },
  { id: "privacy" as const, icon: <Shield size={20}/>, label: "Datenschutz", desc: "Tracking, Telemetrie, Daten" },
  { id: "updates" as const, icon: <Download size={20}/>, label: "Updates", desc: "Dashboard & Node-Binaries aktualisieren" },
];

// ── Main ────────────────────────────────────────────────────────
export default function SettingsOverlay({ onClose }: SettingsOverlayProps) {
  const [page, setPage] = useState<SettingsPage>("main");
  const health = useNodeHealth(); const sys = useSystemStats(3000); const qc = useQueryClient();
  const [cfg, setCfg] = useState<NodeConfig>({ enabled: false, port: 3080, cpu_pct: 25, binary_path: "", seed_peers: "" });
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [nl, snl] = useState(false); const [ne, sne] = useState("");
  const [hasTauri, sht] = useState(false);

  useEffect(() => { import("@tauri-apps/api/core").then(() => sht(true)).catch(() => {}); }, []);
  useEffect(() => { if (!hasTauri) return; nodeManager.getConfig().then(setCfg).catch(()=>{}); nodeManager.getStatus().then(setStatus).catch(()=>{}); const id = setInterval(async () => { try { setStatus(await nodeManager.getStatus()); } catch {} }, 3000); return () => clearInterval(id); }, [hasTauri]);

  async function toggleNode() { snl(true); sne(""); try { if (status?.status === "running") await nodeManager.stop(); else await nodeManager.start(); setStatus(await nodeManager.getStatus()); qc.invalidateQueries({ queryKey: ["node-health"] }); } catch (e) { sne(String(e)); } snl(false); }
  const isRunning = status?.status === "running";

  function back() { setPage("main"); }
  const title = page === "main" ? "Einstellungen" : categories.find(c => c.id === page)?.label ?? "Einstellungen";

  function header(showBack: boolean) {
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <button onClick={showBack ? back : onClose} style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(255,255,255,0.06)", border: "none", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><ArrowLeft size={16}/></button>
        <h2 style={{ fontSize: 16, fontWeight: 700, flex: 1 }}>{title}</h2>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}><X size={18}/></button>
      </div>
    );
  }

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 56, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,0,0,0.55)" }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{ background: "var(--bg-panel)", borderRadius: 16, width: 480, maxWidth: "94vw", maxHeight: "85vh", overflowY: "auto", border: "1px solid var(--border-strong)", boxShadow: "0 16px 48px rgba(0,0,0,0.5)", padding: 20 }}>
        {header(page !== "main")}

        {page === "main" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {categories.map(cat => (
              <button key={cat.id} onClick={() => setPage(cat.id)}
                style={{ display: "flex", alignItems: "center", gap: 14, width: "100%", padding: "14px 16px", borderRadius: 12, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", color: "var(--text-primary)", cursor: "pointer", textAlign: "left", transition: "all 0.15s" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.background = "rgba(255,255,255,0.05)"; el.style.borderColor = "rgba(255,255,255,0.1)"; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.background = "rgba(255,255,255,0.02)"; el.style.borderColor = "rgba(255,255,255,0.05)"; }}
              >
                <span style={{ opacity: 0.6 }}>{cat.icon}</span>
                <div style={{ flex: 1 }}><div style={{ fontSize: 14, fontWeight: 600 }}>{cat.label}</div><div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{cat.desc}</div></div>
                <ChevronRight size={16} style={{ opacity: 0.3 }}/>
              </button>
            ))}
          </div>
        )}

        {page === "system" && (
          <div>
            <div style={{ ...card, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>Lokale Node</span><NodeBadge status={status}/></div>
              <button onClick={toggleNode} disabled={nl || status?.status === "starting"} style={{ display: "flex", alignItems: "center", gap: 5, padding: "7px 14px", borderRadius: 8, background: isRunning ? "rgba(237,66,69,0.15)" : "rgba(59,165,92,0.15)", color: isRunning ? "var(--red)" : "var(--green)", border: `1px solid ${isRunning ? "rgba(237,66,69,0.3)" : "rgba(59,165,92,0.3)"}`, fontSize: 12, fontWeight: 600, cursor: nl ? "wait" : "pointer" }}>
                {nl ? <RefreshCw size={13} style={{ animation: "spin 0.7s linear infinite" }}/> : isRunning ? <Square size={13}/> : <Play size={13}/>}{isRunning ? "Stoppen" : "Starten"}
              </button>
            </div>
            {ne && <div style={{ ...card, background: "rgba(237,66,69,0.08)", border: "1px solid rgba(237,66,69,0.15)", fontSize: 11, color: "var(--red)" }}>{ne}</div>}

            <div style={card}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}><span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)" }}>CPU-Leistung</span><span style={{ fontSize: 12, fontWeight: 700, color: "var(--accent)", background: "var(--accent-bg)", borderRadius: 6, padding: "1px 8px" }}>{cfg.cpu_pct}%</span></div>
              <input type="range" min={5} max={100} step={5} value={cfg.cpu_pct} onChange={e => setCfg(c => ({ ...c, cpu_pct: Number(e.target.value) }))} style={{ width: "100%", accentColor: "var(--accent)", height: 4, cursor: "pointer" }}/>
            </div>

            {sys && (
              <div style={card}>
                <span style={secHdr}>System-Auslastung</span>
                <StatBar label="Gesamt CPU" value={sys.system_cpu_pct} max={100}/>
                <StatBar label="Stone App CPU" value={sys.app_cpu_pct} max={100} color="var(--accent)"/>
                <StatBar label="RAM" value={sys.system_memory_used_mb} total={sys.system_memory_total_mb} max={sys.system_memory_total_mb} color="var(--info)"/>
                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}><span style={{ fontSize: 10, color: "var(--text-muted)" }}>App: {sys.app_memory_mb} MB</span><span style={{ fontSize: 10, color: "var(--text-muted)" }}>{((sys.system_memory_used_mb / sys.system_memory_total_mb) * 100).toFixed(1)}%</span></div>
              </div>
            )}

            <div style={card}><AutoStartToggle/></div>

            <div style={card}>
              <span style={secHdr}>Netzwerk</span>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}><span style={{ fontSize: 11, color: "var(--text-muted)" }}>Status</span><div style={{ display: "flex", alignItems: "center", gap: 4 }}>{health.connected ? <Wifi size={11} style={{ color: "var(--green)" }}/> : <WifiOff size={11} style={{ color: "var(--text-muted)" }}/>}<span style={{ fontSize: 11, fontWeight: 600, color: health.connected ? "var(--green)" : "var(--text-muted)" }}>{health.connected ? "Verbunden" : "Getrennt"}</span></div></div>
                {health.connected && <div style={{ display: "flex", justifyContent: "space-between" }}><span style={{ fontSize: 11, color: "var(--text-muted)" }}>Block-Höhe</span><span style={{ fontSize: 11, fontFamily: "monospace", fontWeight: 600, color: "var(--text-primary)" }}>#{health.blockHeight.toLocaleString()}</span></div>}
              </div>
            </div>
          </div>
        )}

        {page === "personalization" && (
          <div>
            <div style={card}><div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}><div><span style={{ fontSize: 12, color: "var(--text-primary)" }}>Erscheinungsbild</span><p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>Dark/Light Theme & Farbakzente</p></div><span style={{ fontSize: 10, color: "var(--text-muted)", opacity: 0.5 }}>Coming soon</span></div></div>
            <div style={card}><div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}><div><span style={{ fontSize: 12, color: "var(--text-primary)" }}>Sprache</span><p style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>Deutsch, English, …</p></div><span style={{ fontSize: 10, color: "var(--text-muted)", opacity: 0.5 }}>Coming soon</span></div></div>
            <div style={card}><span style={secHdr}>Benachrichtigungen</span><NotificationToggles/></div>
          </div>
        )}

        {page === "privacy" && (
          <div style={card}><span style={secHdr}>Datenschutz</span><p style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>Einstellungen für Telemetrie, Diagnosedaten und Datenweitergabe folgen in einem kommenden Update.</p></div>
        )}

        {page === "updates" && (
          <div>
            <div style={card}><span style={secHdr}>App-Update</span><AppUpdatePanel/></div>
            <div style={card}><span style={secHdr}>Node-Binaries</span><NodeBinaryPanel/></div>
          </div>
        )}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } } @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }`}</style>
    </div>
  );
}
