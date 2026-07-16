import { useState, useEffect, useRef } from "react";
import { useSystemStats } from "../../hooks/useSystemStats";
import { Cpu, Database, Clock, Users, Server, Terminal, Save, RefreshCw, Download, Shield } from "lucide-react";

export default function DashboardView() {
  const stats = useSystemStats(3000);
  const [health, setHealth] = useState<{block_height:number;peer_count:number;uptime_secs:number;mempool_size:number;network:string;node_id:string}|null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [config, setConfig] = useState<any>({});
  const [logPaused, setLogPaused] = useState(false);
  const [cfgSaved, setCfgSaved] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(false);
  useEffect(()=>{pausedRef.current=logPaused},[logPaused]);

  // ─── VPN Status (integrierter VPN) ───────────────────────────────
  const [vpnStatus, setVpnStatus] = useState<{active:boolean;installed:boolean;vpn_id?:string;vpn_ip:string|null;peer_count:number;peers:string[];mode:string;tun_active?:boolean}|null>(null);
  const [vpnAction, setVpnAction] = useState<string|null>(null);
  const [vpnResult, setVpnResult] = useState<string|null>(null);

  useEffect(() => {
    const poll = async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        // Integrierten VPN-Status abrufen
        const vs: any = await invoke("vpn_status");
        if (vs) {
          setVpnStatus({
            active: vs.mode !== "stopped" && vs.mode !== "error",
            installed: false,
            vpn_ip: vs.vpn_ip,
            vpn_id: vs.vpn_ip, // Nutzer-ID = VPN-IP für Anzeige
            peer_count: vs.peer_count ?? 0,
            peers: [],
            mode: vs.mode === "relay" ? "Relay" : vs.mode === "client" ? "Client" : vs.mode,
            tun_active: vs.tun_active,
          });
        }
      } catch(e) {
        // Fallback: alten Befehl probieren
        try {
          const { invoke } = await import("@tauri-apps/api/core");
          const vs: any = await invoke("get_vpn_status");
          if (vs) setVpnStatus(vs);
        } catch {}
      }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  async function vpnActionHandler(action: string) {
    setVpnAction(action);
    setVpnResult(null);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      // Neue integrierte VPN-Commands bevorzugen
      if (action === "start_vpn") {
        const result: any = await invoke("vpn_start");
        setVpnResult(`VPN gestartet — IP: ${result?.vpn_ip ?? 'warte…'}`);
      } else if (action === "stop_vpn") {
        await invoke("vpn_stop");
        setVpnResult("VPN gestoppt");
      } else {
        // Alle anderen Actions (install/uninstall service) via altem Befehl
        const result: string = await invoke(action);
        setVpnResult(result);
      }
    } catch(e: any) {
      setVpnResult("❌ " + (e?.toString() ?? "Fehler"));
    } finally {
      setVpnAction(null);
    }
  }

  // ─── Updater ──────────────────────────────────────────────────────
  const [updateState, setUpdateState] = useState<"idle"|"checking"|"available"|"downloading"|"ready">("idle");
  const [updateInfo, setUpdateInfo] = useState<{version:string;body:string}|null>(null);

  async function checkForUpdate() {
    setUpdateState("checking");
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (update) {
        setUpdateInfo({ version: update.version, body: update.body || "" });
        setUpdateState("available");
      } else {
        setUpdateState("idle");
      }
    } catch (e) { setUpdateState("idle"); }
  }

  async function downloadAndInstall() {
    setUpdateState("downloading");
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (!update) { setUpdateState("idle"); return; }
      await update.download();
      setUpdateState("ready");
      await update.install();
    } catch (e) { setUpdateState("idle"); }
  }

  // Auto-check on mount
  useEffect(() => { checkForUpdate(); }, []);

  // Node Health polling
  useEffect(()=>{
    let active=true;
    const poll=async()=>{
      try{const{invoke}=await import("@tauri-apps/api/core");const h:any=await invoke("get_node_health");if(active)setHealth(h)}catch(e){if(active)setHealth(null)}
    };
    poll();const id=setInterval(poll,5000);return()=>{active=false;clearInterval(id)};
  },[]);

  // Logs polling
  useEffect(()=>{
    const id=setInterval(async()=>{
      if(pausedRef.current)return;
      try{const{invoke}=await import("@tauri-apps/api/core");const lines:string[]=await invoke("node_get_logs");if(lines.length>0)setLogs(prev=>[...prev,...lines].slice(-500))}catch(e){}
    },1500);
    return()=>clearInterval(id);
  },[]);

  // Config polling
  useEffect(()=>{
    const load=async()=>{
      try{const{invoke}=await import("@tauri-apps/api/core");const c:any=await invoke("node_get_config");setConfig(c||{})}catch(e){}
    };
    load();
  },[]);

  // Auto-scroll logs
  useEffect(()=>{if(!logPaused&&logRef.current)logRef.current.scrollTop=logRef.current.scrollHeight},[logs,logPaused]);

  async function saveConfig(){
    try{const{invoke}=await import("@tauri-apps/api/core");await invoke("node_set_config",{config});setCfgSaved(true);setTimeout(()=>setCfgSaved(false),2000)}catch(e){}
  }

  const fmtUptime=(s:number)=>{if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m'}
  const fmtMB=(m:number)=>{if(m==null)return'—';return m>1024?(m/1024).toFixed(1)+' GB':m.toFixed(0)+' MB'}

  return (
    <div style={{height:"100%",overflow:"auto",background:"var(--main-bg)",padding:24,color:"var(--text)"}}>
      <h1 style={{fontSize:20,fontWeight:700,marginBottom:4}}>📊 Node Dashboard</h1>
      <p style={{fontSize:12,color:"var(--text-muted)",marginBottom:16}}>
        {health?.network ? (health.network[0]?.toUpperCase() ?? '') + health.network.slice(1) : '—'} · Port {config?.port||'—'} · Node {health?.node_id?.slice(0,16)||'—'}…
      </p>

      {/* Update Banner */}
      {updateState === "available" && updateInfo && (
        <div style={{background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",borderRadius:10,padding:"12px 16px",marginBottom:16,display:"flex",alignItems:"center",gap:12}}>
          <div style={{flex:1}}>
            <div style={{fontWeight:600,fontSize:13,color:"#3b82f6"}}>🆕 Update verfügbar: v{updateInfo.version}</div>
            {updateInfo.body && <div style={{fontSize:11,color:"var(--text-muted)",marginTop:2}}>{updateInfo.body.slice(0,200)}</div>}
          </div>
          <button onClick={downloadAndInstall}
            style={{padding:"8px 16px",borderRadius:8,background:"#3b82f6",color:"#fff",border:"none",cursor:"pointer",fontSize:12,fontWeight:600,display:"flex",alignItems:"center",gap:6,whiteSpace:"nowrap"}}>
            <Download size={14}/> Update installieren
          </button>
        </div>
      )}
      {updateState === "downloading" && (
        <div style={{background:"rgba(59,130,246,0.06)",border:"1px solid rgba(59,130,246,0.15)",borderRadius:10,padding:"10px 16px",marginBottom:16,fontSize:12,color:"#3b82f6",display:"flex",alignItems:"center",gap:8}}>
          <RefreshCw size={14} style={{animation:"spin 1s linear infinite"}}/> Update wird heruntergeladen…
        </div>
      )}
      {updateState === "checking" && (
        <div style={{fontSize:11,color:"var(--text-muted)",marginBottom:16}}>🔍 Suche nach Updates…</div>
      )}

      {/* Stats Grid */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:8,marginBottom:16}}>
        <StatCard icon={<Server size={16}/>} label="Block Height" value={health?'#'+health.block_height:'—'} color="var(--accent)"/>
        <StatCard icon={<Users size={16}/>} label="Peers" value={health?.peer_count??'—'} color="var(--green)"/>
        <StatCard icon={<Clock size={16}/>} label="Uptime" value={health?fmtUptime(health.uptime_secs):'—'} color="var(--blue)"/>
        <StatCard icon={<Database size={16}/>} label="Mempool" value={health?.mempool_size??'—'} color="var(--amber)"/>
        <StatCard icon={<Shield size={16}/>} label="VPN" value={vpnStatus?.active ? (vpnStatus.vpn_ip ?? 'verbunden') : 'inaktiv'} color={vpnStatus?.active ? 'var(--green)' : 'var(--text-muted)'} subtitle={vpnStatus?.active ? `${vpnStatus.peer_count} peers` : undefined}/>
      </div>

      {/* VPN Status & Controls */}
      <div style={{background:"var(--bg-panel)",border:"1px solid var(--border)",borderRadius:10,padding:"12px 16px",marginBottom:16}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <Shield size={18} style={{color: vpnStatus?.active ? "var(--green)" : "var(--text-muted)"}}/>
          <div style={{flex:1}}>
            <div style={{fontWeight:600,fontSize:13}}>
              VPN {vpnStatus?.active ? `🟢 ${vpnStatus.vpn_ip ?? 'verbunden'}` : '⚫ inaktiv'}
              {vpnStatus?.tun_active && <span style={{fontSize:10,color:"var(--green)",marginLeft:6}}>TUN</span>}
            </div>
            <div style={{fontSize:11,color:"var(--text-muted)"}}>
              {vpnStatus?.active
                ? `${vpnStatus.peer_count} Peers · ${vpnStatus.mode || 'aktiv'}`
                : 'Nicht gestartet'}
            </div>
          </div>
          <div style={{display:"flex",gap:6}}>
            {!vpnStatus?.active && (
              <button onClick={() => vpnActionHandler("start_vpn")} disabled={vpnAction !== null}
                style={{padding:"5px 12px",borderRadius:6,background:"var(--green)",color:"#fff",border:"none",cursor:"pointer",fontSize:11,fontWeight:600,whiteSpace:"nowrap",opacity:vpnAction?0.6:1}}>
                ▶ Start
              </button>
            )}
            {vpnStatus?.active && (
              <button onClick={() => vpnActionHandler("stop_vpn")} disabled={vpnAction !== null}
                style={{padding:"5px 12px",borderRadius:6,background:"var(--amber)",color:"#000",border:"none",cursor:"pointer",fontSize:11,fontWeight:600,whiteSpace:"nowrap",opacity:vpnAction?0.6:1}}>
                ⏹ Stop
              </button>
            )}
            {!vpnStatus?.installed && (
              <button onClick={() => vpnActionHandler("install_vpn_service")} disabled={vpnAction !== null}
                style={{padding:"5px 12px",borderRadius:6,background:"var(--accent)",color:"#fff",border:"none",cursor:"pointer",fontSize:11,fontWeight:600,whiteSpace:"nowrap",opacity:vpnAction?0.6:1}}>
                🔧 Installieren
              </button>
            )}
            {vpnStatus?.installed && (
              <>
                <button onClick={() => vpnActionHandler("stop_vpn_service")} disabled={vpnAction !== null}
                  style={{padding:"5px 12px",borderRadius:6,background:"var(--border)",color:"var(--text)",border:"none",cursor:"pointer",fontSize:10,whiteSpace:"nowrap",opacity:vpnAction?0.6:1}}>
                  ⏸ Dienst Stop
                </button>
                <button onClick={() => vpnActionHandler("uninstall_vpn_service")} disabled={vpnAction !== null}
                  style={{padding:"5px 12px",borderRadius:6,background:"rgba(239,68,68,0.1)",color:"#ef4444",border:"1px solid rgba(239,68,68,0.2)",cursor:"pointer",fontSize:10,whiteSpace:"nowrap",opacity:vpnAction?0.6:1}}>
                  🗑 Deinstallieren
                </button>
              </>
            )}
          </div>
        </div>
        {vpnAction && (
          <div style={{fontSize:11,color:"var(--text-muted)",marginTop:6}}>⏳ {vpnAction === "start_vpn" ? "Starte VPN…" : vpnAction === "stop_vpn" ? "Stoppe…" : vpnAction === "install_vpn_service" ? "Installiere…" : vpnAction === "uninstall_vpn_service" ? "Deinstalliere…" : "Bitte warten…"}</div>
        )}
        {vpnResult && (
          <div style={{marginTop:6,fontSize:11,color: vpnResult.startsWith("❌") ? "#ef4444" : "var(--green)",whiteSpace:"pre-wrap"}}>{vpnResult}</div>
        )}
      </div>

      {/* System Stats */}
      <h2 style={{fontSize:14,fontWeight:600,marginBottom:8}}><Cpu size={14} style={{marginRight:6}}/>System</h2>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:8,marginBottom:16}}>
        <StatCard label="CPU Gesamt" value={stats?stats.system_cpu_pct.toFixed(1)+'%':'—'} color="var(--blue)" bar={stats?.system_cpu_pct??0} barColor="var(--blue)"/>
        <StatCard label="RAM Gesamt" value={stats?fmtMB(stats.system_memory_used_mb)+' / '+fmtMB(stats.system_memory_total_mb):'—'} color="var(--amber)" bar={stats?((stats.system_memory_used_mb/(stats.system_memory_total_mb||1))*100):0} barColor="var(--amber)"/>
        <StatCard label="App CPU" value={stats?stats.app_cpu_pct.toFixed(1)+'%':'—'} color="var(--accent)"/>
        <StatCard label="App RAM" value={stats?fmtMB(stats.app_memory_mb):'—'} color="var(--green)"/>
      </div>

      {/* Settings */}
      <h2 style={{fontSize:14,fontWeight:600,marginBottom:8}}>⚙️ Einstellungen</h2>
      <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:16,alignItems:"center"}}>
        <label style={{fontSize:12,color:"var(--text-muted)"}}>Storage (GB):<br/>
          <input type="number" value={config.storage_offered_gb??100} onChange={e=>setConfig({...config,storage_offered_gb:parseInt(e.target.value)||100})}
            style={{width:80,padding:"6px 8px",borderRadius:6,background:"var(--bg-input)",border:"1px solid var(--border)",color:"var(--text)",fontSize:13,marginTop:4}}/>
        </label>
        <label style={{fontSize:12,color:"var(--text-muted)"}}>Auto-Mining:<br/>
          <select value={String(config.auto_mining_enabled??true)} onChange={e=>setConfig({...config,auto_mining_enabled:e.target.value==='true'})}
            style={{padding:"6px 8px",borderRadius:6,background:"var(--bg-input)",border:"1px solid var(--border)",color:"var(--text)",fontSize:13,marginTop:4}}>
            <option value="true">An</option><option value="false">Aus</option>
          </select>
        </label>
        <label style={{fontSize:12,color:"var(--text-muted)"}}>Reward/Tag:<br/>
          <input type="number" value={config.reward_per_day??0} onChange={e=>setConfig({...config,reward_per_day:parseFloat(e.target.value)||0})}
            style={{width:80,padding:"6px 8px",borderRadius:6,background:"var(--bg-input)",border:"1px solid var(--border)",color:"var(--text)",fontSize:13,marginTop:4}} step="0.1"/>
        </label>
        <button onClick={saveConfig} style={{marginTop:18,padding:"8px 16px",borderRadius:8,background:cfgSaved?"rgba(34,197,94,0.2)":"var(--accent)",color:cfgSaved?"var(--green)":"#000",border:"none",cursor:"pointer",fontSize:12,fontWeight:600}}>
          <Save size={14} style={{marginRight:4}}/>{cfgSaved?"Gespeichert":"Speichern"}
        </button>
      </div>

      {/* Logs */}
      <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
        <h2 style={{fontSize:14,fontWeight:600,margin:0}}><Terminal size={14} style={{marginRight:6}}/>Node Logs ({logs.length})</h2>
        <button onClick={()=>{setLogPaused(!logPaused)}} style={{padding:"4px 12px",borderRadius:6,fontSize:11,background:logPaused?"rgba(250,166,26,0.15)":"var(--border)",color:logPaused?"var(--amber)":"var(--text-muted)",border:"none",cursor:"pointer"}}>
          {logPaused?"▶ Resume":"⏸ Pause"}
        </button>
        <button onClick={()=>setLogs([])} style={{padding:"4px 12px",borderRadius:6,fontSize:11,background:"var(--border)",color:"var(--text-muted)",border:"none",cursor:"pointer"}}>Clear</button>
      </div>
      <div ref={logRef} style={{background:"#0a0b0f",border:"1px solid var(--border)",borderRadius:10,padding:12,fontFamily:"'SF Mono',Menlo,monospace",fontSize:11,color:"#a0a0a0",height:200,overflowY:"auto",whiteSpace:"pre-wrap",lineHeight:1.5}}>
        {logs.length===0&&<span style={{opacity:0.5}}>Warte auf Node-Logs…</span>}
        {logs.map((l,i)=><div key={i} style={{color:l.startsWith('[err]')?'#ef4444':l.startsWith('[vpn]')?'#22c55e':l.startsWith('[out]')?'var(--text-dim)':'var(--text-muted)'}}>{l}</div>)}
      </div>
    </div>
  );
}

function StatCard({icon,label,value,color,bar,barColor,subtitle}:{icon?:any;label:string;value:string|number;color:string;bar?:number;barColor?:string;subtitle?:string}){
  return(
    <div style={{background:"var(--bg-panel)",border:"1px solid var(--border)",borderRadius:10,padding:14}}>
      <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:4,color:"var(--text-muted)"}}>{icon}<span style={{fontSize:12,fontWeight:600}}>{label}</span></div>
      <div style={{fontSize:22,fontWeight:700,fontFamily:"monospace",color}}>{value}</div>
      {subtitle && <div style={{fontSize:10,color:"var(--text-muted)",marginTop:2}}>{subtitle}</div>}
      {bar!==undefined&&<div style={{height:6,background:"rgba(255,255,255,0.06)",borderRadius:3,overflow:"hidden",marginTop:8}}><div style={{height:"100%",borderRadius:3,background:barColor||color,width:Math.min(100,bar)+"%",transition:"width .3s"}}/></div>}
    </div>
  );
}
