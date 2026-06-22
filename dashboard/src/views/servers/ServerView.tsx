import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { orgs } from "../../api/stone";
import { loadSettings } from "../../store/session";
import { useAuth } from "../../auth/AuthContext";
import {
  Plus, Users, Hash, UserPlus, Copy, Check,
  Loader2, Settings as SettingsIcon, Trash2,
  FolderPlus, Send, Plug, Download,
} from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import PluginSettingsView from "./PluginSettingsView";
import { getPluginByChannel } from "../../store/plugins";
import PluginRenderer from "../../components/plugins/PluginRenderer";

interface OrgDetail { org_id: string; name: string; owner_name: string; owner_wallet: string; member_count: number; channel_count: number; members: { wallet: string; name: string; role: string }[]; channels: { id: string; name: string; category_id: string }[]; categories: { category_id: string; name: string }[]; invite_code?: string; }

function fmtTime(ts: number): string { const d = new Date(ts*1000); const now = new Date(); if (d.toDateString()===now.toDateString()) return d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}); return d.toLocaleDateString([],{month:"short",day:"numeric"}); }

function getFileExtension(filename: string): string { const p=filename.split('.');return p.length>1?p[p.length-1].toLowerCase():''; }
function isImage(fn: string):boolean{ return ['png','jpg','jpeg','gif','webp','svg','bmp'].includes(getFileExtension(fn)); }
function isVideo(fn: string):boolean{ return ['mp4','webm','mov','avi','mkv'].includes(getFileExtension(fn)); }
function isAudio(fn: string):boolean{ return ['mp3','wav','ogg','flac','m4a'].includes(getFileExtension(fn)); }
function getFileIcon(fn: string):string{ if(isImage(fn))return'🖼️';if(isVideo(fn))return'🎬';if(isAudio(fn))return'🎵';const e=getFileExtension(fn);if(['zip','rar','7z','tar','gz'].includes(e))return'📦';if(['pdf'].includes(e))return'📄';if(['js','ts','rs','py','java'].includes(e))return'💻';return'📎'; }
function docDataUrl(docId: string): string { return `http://127.0.0.1:3080/api/v1/documents/${docId}/data`; }

interface FileAttachmentMeta { fileName:string;fileSize:string;docId:string;blockIndex:string;fileHash:string; }

function parseFileAttachment(text: string): FileAttachmentMeta|null {
  const m=text.match(/📎 Datei gesendet:\s*(.+?)\s*\(([^)]+)\)\nDoc:\s*(\S+)\nBlock:\s*#(\S+)\nSHA-256:\s*(\S+)/);
  if(!m)return null;
  return {fileName:m[1],fileSize:m[2],docId:m[3],blockIndex:m[4],fileHash:m[5]};
}

function FileAttachmentCard({ meta, size=260 }:{meta:FileAttachmentMeta;size?:number}) {
  const img=isImage(meta.fileName); const vid=isVideo(meta.fileName); const aud=isAudio(meta.fileName); const url=docDataUrl(meta.docId);
  function openFile(){ window.open(url,'_blank'); }
  return (
    <div style={{borderRadius:12,overflow:'hidden',background:'rgba(255,255,255,0.04)',border:'1px solid rgba(255,255,255,0.08)',maxWidth:size,width:'100%'}}>
      {(img||vid||aud)&&(<div style={{background:'#000',display:'flex',alignItems:'center',justifyContent:'center',minHeight:img?160:80}}>
        {img&&<img src={url} alt={meta.fileName} style={{width:'100%',maxHeight:280,objectFit:'contain',cursor:'pointer'}} onClick={openFile} />}
        {vid&&<video controls preload="metadata" style={{width:'100%',maxHeight:280,background:'#000'}}><source src={url} />Video nicht verfügbar</video>}
        {aud&&<audio controls preload="metadata" style={{width:'100%',padding:'16px 0'}}><source src={url} />Audio nicht verfügbar</audio>}
      </div>)}
      <div style={{display:'flex',alignItems:'center',gap:10,padding:'10px 12px',cursor:'pointer'}} onClick={openFile}>
        <span style={{fontSize:22}}>{getFileIcon(meta.fileName)}</span>
        <div style={{flex:1,minWidth:0}}>
          <div style={{fontSize:12,fontWeight:600,color:'var(--text-primary)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{meta.fileName}</div>
          <div style={{fontSize:10,color:'var(--text-muted)'}}>{meta.fileSize}</div>
        </div>
        <button onClick={(e)=>{e.stopPropagation();openFile();}} title="Herunterladen" style={{width:28,height:28,borderRadius:8,background:'var(--accent)',border:'none',color:'#fff',cursor:'pointer',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}><Download size={14} /></button>
      </div>
    </div>
  );
}

type ViewMode = "chat" | "settings";

function ChannelChat({ orgId, channelId, channelName }: { orgId: string; channelId: string; channelName: string }) {
  const { session } = useAuth();
  const userApiKey = session?.apiKey ?? "";
  const userToken = session?.sessionToken ?? "";
  const nodeUrl = loadSettings().nodeUrl;
  const bottomRef = useRef<HTMLDivElement>(null);
  const [input, setInput] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadToast, setUploadToast] = useState<{msg:string;ok:boolean}|null>(null);
  const qc = useQueryClient();
  const msgQ = useQuery({ queryKey: ["channel-msgs", orgId, channelId], queryFn: () => orgs.getMessages(orgId, channelId), refetchInterval: 3_000, enabled: !!orgId && !!channelId });
  const messages = msgQ.data?.messages ?? [];
  const sendMt = useMutation({ mutationFn: (text: string) => { const enc = btoa(unescape(encodeURIComponent(text))); const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12)))); return orgs.sendMessage(orgId, channelId, enc, nonce); }, onSuccess: () => { qc.invalidateQueries({ queryKey: ["channel-msgs"] }); } });
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages.length]);
  useEffect(() => { if (!uploadToast) return; const t = setTimeout(() => setUploadToast(null), 5000); return () => clearTimeout(t); }, [uploadToast]);
  function handleSend(e: React.FormEvent) { e.preventDefault(); const text = input.trim(); if(!text||sendMt.isPending)return; setInput(""); sendMt.mutate(text); }
  const myWallet = session?.walletAddress ?? "";
  const plugin = getPluginByChannel(channelId);

  function handleDragOver(e: React.DragEvent) { e.preventDefault(); e.stopPropagation(); setDragOver(true); }
  function handleDragLeave(e: React.DragEvent) { e.preventDefault(); e.stopPropagation(); setDragOver(false); }
  function handleDrop(e: React.DragEvent) { e.preventDefault(); e.stopPropagation(); setDragOver(false); const file = e.dataTransfer.files?.[0]; if(file) uploadFile(file); }

  async function uploadFile(file: File) {
    setUploading(true);
    try {
      const result: any = await invoke("upload_file", { path: (file as any).path ?? file.name, masterUrl: nodeUrl, apiKey: userApiKey, sessionToken: userToken });
      if (result?.success) {
        const fileName = file.name; const docId = result.doc_id ? result.doc_id.slice(0, 8) : "?"; const blockInfo = result.block_index != null ? `Block #${result.block_index}` : "";
        setUploadToast({ msg: `📎 "${fileName}" hochgeladen — Doc #${docId} ${blockInfo}${result.shards_distributed?" · ✓ Shards verteilt":""}`, ok: true });
        const chatMsg = `📎 Datei gesendet: ${fileName}\nDoc: ${result.doc_id??"?"}\nBlock: #${result.block_index??"?"}\nSHA-256: ${(result.file_hash??"").slice(0,16)}…`;
        const enc = btoa(unescape(encodeURIComponent(chatMsg))); const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))));
        await orgs.sendMessage(orgId, channelId, enc, nonce);
        qc.invalidateQueries({ queryKey: ["channel-msgs"] });
      } else { setUploadToast({ msg: `❌ Upload fehlgeschlagen: ${result?.error??"Unbekannter Fehler"}`, ok: false }); }
    } catch (err) { setUploadToast({ msg: `❌ Fehler: ${String(err)}`, ok: false }); }
    finally { setUploading(false); }
  }

  async function handleFileUpload() {
    try {
      const selected = await open({ multiple: false, title: "Datei auswählen – Hochladen in diesen Channel" });
      if (!selected) return;
      const fp = Array.isArray(selected) ? selected[0] : selected; if (!fp) return;
      setUploading(true);
      const result: any = await invoke("upload_file", { path: fp, masterUrl: nodeUrl, apiKey: userApiKey, sessionToken: userToken });
      if (result?.success) {
        const parts = fp.replace(/\\/g, "/").split("/"); const fileName = parts[parts.length-1]||fp; const docId = result.doc_id ? result.doc_id.slice(0,8) : "?"; const blockInfo = result.block_index != null ? `Block #${result.block_index}` : "";
        setUploadToast({ msg: `📎 "${fileName}" hochgeladen — Doc #${docId} ${blockInfo}${result.shards_distributed?" · ✓ Shards verteilt":""}`, ok: true });
        const chatMsg = `📎 Datei gesendet: ${fileName}\nDoc: ${result.doc_id??"?"}\nBlock: #${result.block_index??"?"}\nSHA-256: ${(result.file_hash??"").slice(0,16)}…`;
        const enc = btoa(unescape(encodeURIComponent(chatMsg))); const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))));
        await orgs.sendMessage(orgId, channelId, enc, nonce); qc.invalidateQueries({ queryKey: ["channel-msgs"] });
      } else { setUploadToast({ msg: `❌ Upload fehlgeschlagen: ${result?.error??"Unbekannter Fehler"}`, ok: false }); }
    } catch (err) { setUploadToast({ msg: `❌ Fehler: ${String(err)}`, ok: false }); }
    finally { setUploading(false); }
  }

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100%" }}>
      <div style={{ display:"flex", alignItems:"center", gap:8, padding:"10px 16px", borderBottom:"1px solid var(--border)", background:"rgba(255,255,255,0.01)", flexShrink:0 }}><Hash size={16} style={{ color:"var(--text-muted)" }} /><strong style={{ fontSize:14 }}>{channelName}</strong></div>
      {plugin && (<div style={{ padding:12, borderBottom:"1px solid var(--border)", flexShrink:0 }}><div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:8 }}><Plug size={12} style={{ color:"var(--accent)" }} /><span style={{ fontSize:11, fontWeight:600, color:"var(--accent)" }}>{plugin.name}</span></div><PluginRenderer plugin={plugin} /></div>)}
      {uploadToast && (
        <div style={{ margin:"0 12px", padding:"10px 14px", borderRadius:10, background:uploadToast.ok?"rgba(34,197,94,0.08)":"rgba(239,68,68,0.08)", border:`1px solid ${uploadToast.ok?"rgba(34,197,94,0.25)":"rgba(239,68,68,0.25)"}`, fontSize:12, color:uploadToast.ok?"#22c55e":"#ef4444", position:"absolute", top:56, left:12, right:12, zIndex:10, backdropFilter:"blur(12px)" }}>{uploadToast.msg}</div>
      )}
      <div style={{ flex:1, overflowY:"auto", padding:"8px 12px" }}>
        {messages.map((m: any, i: number) => {
          const isOwn = m.sender_wallet === myWallet;
          const prevSender = i > 0 ? messages[i-1].sender_wallet : "";
          const showSender = prevSender !== m.sender_wallet;
          let content = m.content;
          try { content = decodeURIComponent(escape(atob(content))); } catch {}
          const fileMeta = parseFileAttachment(content);
          return (<div key={m.msg_id ?? i} className={`flex gap-2 px-1 py-0.5 ${isOwn?"flex-row-reverse":""}`} style={{ alignItems:"flex-start" }}>{showSender ? <div style={{ width:28, height:28, borderRadius:"50%", background:isOwn?"var(--accent-bg)":"var(--bg-surface-2)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, flexShrink:0, color:isOwn?"var(--accent)":"var(--text-secondary)" }}>{m.sender_name?.[0]?.toUpperCase()??"?"}</div>:<div style={{ width:28, flexShrink:0 }} />}<div style={{ maxWidth:"70%" }}>{showSender && <div style={{ display:"flex", alignItems:"baseline", gap:6, marginBottom:2 }}><span style={{ fontSize:12, fontWeight:600, color:"var(--accent)" }}>{m.sender_name}</span><span style={{ fontSize:10, color:"var(--text-muted)" }}>{fmtTime(m.timestamp)}</span></div>}{fileMeta ? <FileAttachmentCard meta={fileMeta} size={220} /> : <div style={{ background:isOwn?"var(--accent)":"rgba(255,255,255,0.07)", color:isOwn?"#fff":"var(--text)", borderRadius:isOwn?"12px 12px 4px 12px":"12px 12px 12px 4px", padding:"6px 10px", fontSize:13, lineHeight:1.4, wordBreak:"break-word" }}>{content}</div>}</div></div>);
        })}
        {messages.length===0 && !msgQ.isLoading && <div style={{ textAlign:"center", padding:"48px 24px", color:"var(--text-muted)", fontSize:13 }}>Noch keine Nachrichten. Schreibe die erste!</div>}
        <div ref={bottomRef} />
      </div>
      <form onSubmit={handleSend} style={{ padding:"8px 12px 12px", flexShrink:0 }}>
        <div
          onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
          style={{ display:"flex", flexDirection:"column", gap:0, background:dragOver?"rgba(34,197,94,0.08)":"rgba(255,255,255,0.05)", border:`1px solid ${dragOver?"rgba(34,197,94,0.4)":"rgba(255,255,255,0.08)"}`, borderRadius:12, transition:"all 0.15s" }}>
          {dragOver && <div style={{ color:"#22c55e", fontSize:11, fontWeight:600, padding:"6px 12px 0", textAlign:"center" }}>📁 Datei loslassen zum Hochladen</div>}
          <div style={{ display:"flex", alignItems:"flex-end", gap:6, padding:"7px 10px" }}>
            <button type="button" onClick={handleFileUpload} disabled={uploading} title="Datei hochladen"
              style={{ width:28, height:28, borderRadius:8, background:uploading?"rgba(34,197,94,0.15)":"rgba(255,255,255,0.05)", color:uploading?"#22c55e":"var(--text-muted)", border:"none", display:"flex", alignItems:"center", justifyContent:"center", cursor:uploading?"not-allowed":"pointer", flexShrink:0 }}
              onMouseEnter={e=>{if(!uploading){(e.currentTarget as HTMLElement).style.background="rgba(34,197,94,0.12)";(e.currentTarget as HTMLElement).style.color="#22c55e"}}}
              onMouseLeave={e=>{if(!uploading){(e.currentTarget as HTMLElement).style.background="rgba(255,255,255,0.05)";(e.currentTarget as HTMLElement).style.color="var(--text-muted)"}}}
            ><Plus size={14} /></button>
            <input value={input} onChange={e=>setInput(e.target.value)} placeholder={dragOver?"Datei loslassen…":`Nachricht in #${channelName}`} style={{ flex:1, background:"transparent", border:"none", outline:"none", color:"var(--text)", fontSize:13 }} />
            <button type="submit" disabled={!input.trim()||sendMt.isPending} style={{ width:28, height:28, borderRadius:8, background:input.trim()&&!sendMt.isPending?"var(--accent)":"rgba(255,255,255,0.05)", color:input.trim()&&!sendMt.isPending?"#fff":"var(--text-muted)", border:"none", display:"flex", alignItems:"center", justifyContent:"center", cursor:input.trim()?"pointer":"not-allowed", flexShrink:0 }}><Send size={12} /></button>
          </div>
        </div>
      </form>
    </div>
  );
}

type SettingsTab = "overview" | "plugins";

function ServerSettings({ orgId }: { orgId: string }) {
  const [tab, setTab] = useState<SettingsTab>("overview");
  const detailQ = useQuery({ queryKey:["org",orgId], queryFn:()=>orgs.detail(orgId), enabled:!!orgId });
  const name = (detailQ.data as any)?.org?.name ?? "Server";
  const tabs: { id: SettingsTab; label: string; icon: any }[] = [
    { id:"overview", label:"Übersicht", icon:<SettingsIcon size={14} /> },
    { id:"plugins", label:"Plugins", icon:<Plug size={14} /> },
  ];
  return (
    <div style={{ height:"100%", display:"flex", flexDirection:"column", overflow:"hidden" }}>
      <div style={{ padding:"12px 16px", borderBottom:"1px solid var(--border)", flexShrink:0 }}><h2 style={{ fontSize:16, fontWeight:700 }}>Server-Einstellungen — {name}</h2></div>
      <div style={{ display:"flex", gap:0, borderBottom:"1px solid var(--border-default)", padding:"0 16px", flexShrink:0 }}>
        {tabs.map(t => <button key={t.id} onClick={()=>setTab(t.id)} style={{ padding:"10px 18px", border:"none", background:"transparent", color:tab===t.id?"var(--accent)":"var(--text-muted)", borderBottom:tab===t.id?"2px solid var(--accent)":"2px solid transparent", cursor:"pointer", fontSize:13, fontWeight:600, display:"flex", alignItems:"center", gap:6 }}>{t.icon} {t.label}</button>)}
      </div>
      <div style={{ flex:1, overflowY:"auto", padding:16 }}>
        {tab === "overview" ? <>
          <div style={{ marginBottom:24 }}>
            <h3 style={{ fontSize:13, fontWeight:600, color:"var(--accent)", marginBottom:4 }}>Personen</h3>
            <p style={{ fontSize:11, color:"var(--text-muted)", marginBottom:12 }}>Verwalte Rollen und deren Berechtigungen.</p>
            <div style={{ background:"var(--bg-surface)", borderRadius:10, border:"1px solid var(--border-default)", padding:12 }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                <span style={{ fontSize:11, fontWeight:600, textTransform:"uppercase", color:"var(--text-muted)" }}>Rollen</span>
                <button style={{ padding:"4px 10px", borderRadius:6, background:"var(--accent-bg)", border:"1px solid rgba(212,168,83,0.3)", color:"var(--accent)", cursor:"pointer", fontSize:11, fontWeight:500 }}>Rolle erstellen</button>
              </div>
              <p style={{ fontSize:11, color:"var(--text-muted)", fontStyle:"italic" }}>Jeder Nutzer ohne Rolle ist standardmäßig "Member".</p>
            </div>
          </div>
          <div>
            <h3 style={{ fontSize:13, fontWeight:600, color:"var(--accent)", marginBottom:4 }}>Moderation</h3>
            <p style={{ fontSize:11, color:"var(--text-muted)", marginBottom:12 }}>Gefährlichere Einstellungen.</p>
            <div style={{ background:"var(--bg-surface)", borderRadius:10, border:"1px solid var(--border-default)", padding:12 }}>
              <p style={{ fontSize:10, color:"var(--text-muted)", marginBottom:8 }}>⚠️ Das Löschen des Servers ist endgültig.</p>
              <button style={{ padding:"6px 12px", borderRadius:8, background:"rgba(237,66,69,0.1)", border:"1px solid rgba(237,66,69,0.3)", color:"var(--red)", cursor:"pointer", fontSize:11, fontWeight:600, display:"flex", alignItems:"center", gap:4 }}><Trash2 size={12} /> Server löschen</button>
            </div>
          </div>
        </> : <PluginSettingsView orgId={orgId} />}
      </div>
    </div>
  );
}

function EmptyRightPanel() {
  return (<div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color:"var(--text-muted)", fontSize:13, flexDirection:"column", gap:8 }}><Hash size={40} style={{ opacity:0.15 }} /><span>Wähle einen Channel aus der Liste.</span></div>);
}

function CreateDialog({ title, label, placeholder, onSave, onClose }: { title: string; label: string; placeholder: string; onSave: (name: string) => Promise<void>; onClose: () => void }) {
  const [name, setName] = useState(""); const [loading, setLoading] = useState(false);
  return (<div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.6)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:100 }}><div style={{ background:"var(--bg-panel)", borderRadius:16, padding:24, width:400, border:"1px solid var(--border-strong)" }}><h2 style={{ fontSize:18, fontWeight:700, marginBottom:16 }}>{title}</h2><div style={{ marginBottom:16 }}><label style={{ fontSize:12, fontWeight:500, color:"var(--text-secondary)", marginBottom:6, display:"block" }}>{label}</label><input type="text" value={name} onChange={e=>setName(e.target.value)} placeholder={placeholder} autoFocus style={{ width:"100%", background:"var(--bg-input)", border:"1px solid var(--border-default)", borderRadius:8, padding:"10px 12px", fontSize:13, color:"var(--text-primary)", outline:"none" }} /></div><div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}><button onClick={onClose} style={{ padding:"10px 20px", borderRadius:8, border:"1px solid var(--border-default)", color:"var(--text-secondary)", cursor:"pointer", fontSize:13, background:"transparent" }}>Abbrechen</button><button onClick={async ()=>{ setLoading(true); try { await onSave(name.trim()); } finally { setLoading(false); } }} disabled={!name.trim()||loading} style={{ padding:"10px 20px", borderRadius:8, background:(!name.trim()||loading)?"rgba(212,168,83,0.3)":"var(--accent)", color:"var(--text-inverse)", cursor:(!name.trim()||loading)?"not-allowed":"pointer", border:"none", fontSize:13, fontWeight:600 }}>{loading?<Loader2 size={16} style={{ animation:"spin 0.7s linear infinite" }}/>:"Erstellen"}</button></div></div></div>);
}

export default function ServerView({ selectedOrg: initialSelectedOrg }: { selectedOrg?: string | null }) {
  const [selectedOrg, setSelectedOrg] = useState<string|null>(initialSelectedOrg ?? null);
  const [activeChannel, setActiveChannel] = useState<{id:string;name:string}|null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>("chat");
  const [showCreateCat, setShowCreateCat] = useState(false);
  const [showCreateCh, setShowCreateCh] = useState(false);
  const [copiedId, setCopiedId] = useState<string|null>(null);
  const qc = useQueryClient();
  const detailQ = useQuery({ queryKey:["org",selectedOrg], queryFn:()=>orgs.detail(selectedOrg!), enabled:!!selectedOrg, refetchInterval:10_000 });
  const raw = detailQ.data as any;
  const d: OrgDetail | undefined = (selectedOrg && raw) ? { org_id: raw.org?.id ?? selectedOrg, name: raw.org?.name ?? "", owner_name: (raw.members??[]).find((m:any)=>m.role==="owner")?.display_name??"", owner_wallet: (raw.members??[]).find((m:any)=>m.role==="owner")?.user_id??"", member_count: (raw.members??[]).length, channel_count: (raw.channels??[]).length, members: (raw.members??[]).map((m:any)=>({wallet:m.user_id??"",name:m.display_name??"",role:m.role??""})), channels: (raw.channels??[]).map((c:any)=>({id:c.id??"",name:c.name??"",category_id:c.category_id??""})), categories: (raw.categories??[]).map((c:any)=>({category_id:c.category_id??"",name:c.name??""})), invite_code: (raw.invites?.length>0)?raw.invites[0].invite_id:undefined } : undefined;
  const inviteMt = useMutation({ mutationFn:()=>orgs.invite(selectedOrg!), onSuccess:()=>{qc.invalidateQueries({queryKey:["org",selectedOrg]});} });
  function copyChannelId(chid: string) { navigator.clipboard.writeText(chid); setCopiedId(chid); setTimeout(()=>setCopiedId(null),2000); }

  useEffect(() => {
    if (initialSelectedOrg !== undefined && initialSelectedOrg !== selectedOrg) {
      setSelectedOrg(initialSelectedOrg);
      setActiveChannel(null);
    }
  }, [initialSelectedOrg]);

  if (showCreateCat) return <CreateDialog title="Kategorie erstellen" label="Kategorie-Name" placeholder="Allgemein" onSave={async(n)=>{await orgs.createCategory(selectedOrg!,n);qc.invalidateQueries({queryKey:["org",selectedOrg]});setShowCreateCat(false);}} onClose={()=>setShowCreateCat(false)} />;
  if (showCreateCh) return <CreateDialog title="Text-Channel erstellen" label="Channel-Name" placeholder="allgemein" onSave={async(n)=>{await orgs.createChannel(selectedOrg!,n,"","text");qc.invalidateQueries({queryKey:["org",selectedOrg]});setShowCreateCh(false);}} onClose={()=>setShowCreateCh(false)} />;

  if (!selectedOrg) {
    return (
      <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color:"var(--text-muted)", fontSize:13, flexDirection:"column", gap:8 }}>
        <Hash size={40} style={{ opacity:0.15 }} />
        <span>Wähle einen Server aus der linken Leiste.</span>
      </div>
    );
  }

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden" }}>
      <div style={{ width:220, flexShrink:0, background:"var(--bg-surface)", borderRight:"1px solid var(--border)", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {d ? (<>
          <div style={{ padding:"10px 12px", borderBottom:"1px solid var(--border)", flexShrink:0 }}>
            <strong style={{ fontSize:13, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{d.name}</strong>
            <div style={{ display:"flex", gap:6, marginTop:6 }}>
              <button onClick={()=>{setViewMode("chat");setActiveChannel(null)}} style={{ flex:1, padding:"4px 6px", borderRadius:6, border:"none", background:viewMode==="chat"?"var(--accent-bg)":"transparent", color:viewMode==="chat"?"var(--accent)":"var(--text-muted)", cursor:"pointer", fontSize:10, fontWeight:600 }}><Hash size={10}/> Chat</button>
              <button onClick={()=>{setViewMode("settings");setActiveChannel(null)}} style={{ flex:1, padding:"4px 6px", borderRadius:6, border:"none", background:viewMode==="settings"?"var(--accent-bg)":"transparent", color:viewMode==="settings"?"var(--accent)":"var(--text-muted)", cursor:"pointer", fontSize:10, fontWeight:600 }}><SettingsIcon size={10}/> Einstellungen</button>
            </div>
          </div>
          <div style={{ flex:1, overflowY:"auto", padding:"6px 8px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
              <span style={{ fontSize:10, fontWeight:600, textTransform:"uppercase", color:"var(--text-muted)", letterSpacing:"0.05em" }}>Kanäle</span>
              <div style={{ display:"flex", gap:2 }}>
                <button onClick={()=>setShowCreateCat(true)} title="Kategorie" style={{ background:"none", border:"none", color:"var(--text-muted)", cursor:"pointer", padding:2 }}><FolderPlus size={12} /></button>
                <button onClick={()=>setShowCreateCh(true)} title="Channel" style={{ background:"none", border:"none", color:"var(--text-muted)", cursor:"pointer", padding:2 }}><Plus size={12} /></button>
              </div>
            </div>
            {(d.channels??[]).filter(ch=>!ch.category_id).map(ch=>(<div key={ch.id} onClick={()=>{setActiveChannel({id:ch.id,name:ch.name});setViewMode("chat")}} style={{ display:"flex", alignItems:"center", gap:6, padding:"6px 8px", borderRadius:6, marginBottom:2, background:activeChannel?.id===ch.id?"var(--accent-bg)":"transparent", color:activeChannel?.id===ch.id?"var(--accent)":"var(--text-secondary)", cursor:"pointer", fontSize:12 }} onMouseEnter={e=>{if(activeChannel?.id!==ch.id){e.currentTarget.style.background="var(--bg-hover)"}}} onMouseLeave={e=>{if(activeChannel?.id!==ch.id){e.currentTarget.style.background="transparent"}}}><Hash size={12} style={{ flexShrink:0 }} /><span style={{ flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{ch.name}</span><button onClick={(e)=>{e.stopPropagation();copyChannelId(ch.id)}} style={{ background:"none", border:"none", cursor:"pointer", padding:1, color:copiedId===ch.id?"var(--green)":"var(--text-muted)", opacity:0.5 }} title="Channel-ID kopieren">{copiedId===ch.id?<Check size={11}/>:<Copy size={11}/>}</button></div>))}
            {(d.categories??[]).map(cat=>{const catChs=(d.channels??[]).filter(ch=>ch.category_id===cat.category_id);if(catChs.length===0)return null;return(<div key={cat.category_id} style={{ marginTop:6 }}><div style={{ fontSize:10, fontWeight:600, textTransform:"uppercase", color:"var(--text-muted)", padding:"4px 6px 2px", letterSpacing:"0.05em" }}>{cat.name}</div>{catChs.map(ch=>(<div key={ch.id} onClick={()=>{setActiveChannel({id:ch.id,name:ch.name});setViewMode("chat")}} style={{ display:"flex", alignItems:"center", gap:6, padding:"6px 8px", borderRadius:6, marginBottom:2, background:activeChannel?.id===ch.id?"var(--accent-bg)":"transparent", color:activeChannel?.id===ch.id?"var(--accent)":"var(--text-secondary)", cursor:"pointer", fontSize:12 }} onMouseEnter={e=>{if(activeChannel?.id!==ch.id){e.currentTarget.style.background="var(--bg-hover)"}}} onMouseLeave={e=>{if(activeChannel?.id!==ch.id){e.currentTarget.style.background="transparent"}}}><Hash size={12} style={{ flexShrink:0 }} /><span style={{ flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{ch.name}</span><button onClick={(e)=>{e.stopPropagation();copyChannelId(ch.id)}} style={{ background:"none", border:"none", cursor:"pointer", padding:1, color:copiedId===ch.id?"var(--green)":"var(--text-muted)", opacity:0.5 }} title="Channel-ID kopieren">{copiedId===ch.id?<Check size={11}/>:<Copy size={11}/>}</button></div>))}</div>);})}
          </div>
          <div style={{ padding:"8px", borderTop:"1px solid var(--border)", flexShrink:0 }}>
            <button onClick={()=>inviteMt.mutate()} disabled={inviteMt.isPending} style={{ width:"100%", padding:"6px", borderRadius:6, background:"var(--accent-bg)", border:"1px solid rgba(212,168,83,0.3)", color:"var(--accent)", cursor:"pointer", display:"flex", alignItems:"center", gap:6, fontSize:11, fontWeight:500, justifyContent:"center" }}><UserPlus size={12}/> Mitglied einladen</button>
            <div style={{ marginTop:6, display:"flex", alignItems:"center", gap:6, fontSize:10, color:"var(--text-muted)", padding:"0 4px" }}><Users size={10}/> {(d.members??[]).length} Mitglieder</div>
          </div>
        </>) : (
          <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color:"var(--text-muted)", fontSize:12, textAlign:"center", padding:16 }}>
            {detailQ.isLoading ? <Loader2 size={20} style={{ animation:"spin 0.7s linear infinite" }}/> : "Server wird geladen…"}
          </div>
        )}
      </div>
      <div style={{ flex:1, overflow:"hidden", background:"var(--main-bg)" }}>
        {viewMode==="settings" ? <ServerSettings orgId={selectedOrg} /> : activeChannel ? <ChannelChat orgId={selectedOrg} channelId={activeChannel.id} channelName={activeChannel.name} /> : <EmptyRightPanel />}
      </div>
    </div>
  );
}