import { useState, useRef, useEffect, type FormEvent } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { chat as chatApi, groups as groupsApi } from "../../api/stone";
import { useAuth } from "../../auth/AuthContext";
import { loadSettings } from "../../store/session";
import Avatar from "../../components/ui/Avatar";
import { useWebRTC } from "../../hooks/useWebRTC";
import CallUI from "../../components/calls/CallUI";
import type { ChatEntry, GroupMessage } from "../../types/api";
import { Send, Hash, KeyRound, Plus, MessageCircle, Download, Phone } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ── Decode encrypted_content from server (base64 plaintext or raw) ────────────

function decodeMsg(entry: ChatEntry): string {
  const raw = entry.encrypted_content ?? entry.content ?? "";
  if (!raw) return "";
  try { return decodeURIComponent(escape(atob(raw))); } catch { return raw; }
}

function getMsgContent(msg: ChatEntry | GroupMessage): string {
  if ("encrypted_content" in msg && msg.encrypted_content) return decodeMsg(msg as ChatEntry);
  if ("content" in msg && msg.content) return decodeMsg(msg as ChatEntry);
  return "";
}

// ── File attachment detection ─────────────────────────────────────────────

interface FileAttachmentMeta {
  fileName: string;
  fileSize: string;
  docId: string;
  blockIndex: string;
  fileHash: string;
}

function parseFileAttachment(text: string): FileAttachmentMeta | null {
  const match = text.match(/📎 Datei gesendet:\s*(.+?)\s*\(([^)]+)\)\nDoc:\s*(\S+)\nBlock:\s*#(\S+)\nSHA-256:\s*(\S+)/);
  if (!match) return null;
  return { fileName: match[1], fileSize: match[2], docId: match[3], blockIndex: match[4], fileHash: match[5] };
}

function getFileExtension(filename: string): string {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

function isImage(filename: string): boolean {
  return ['png','jpg','jpeg','gif','webp','svg','bmp'].includes(getFileExtension(filename));
}

function isVideo(filename: string): boolean {
  return ['mp4','webm','mov','avi','mkv'].includes(getFileExtension(filename));
}

function isAudio(filename: string): boolean {
  return ['mp3','wav','ogg','flac','m4a'].includes(getFileExtension(filename));
}

function getFileIcon(filename: string): string {
  if (isImage(filename)) return '🖼️';
  if (isVideo(filename)) return '🎬';
  if (isAudio(filename)) return '🎵';
  const ext = getFileExtension(filename);
  if (['zip','rar','7z','tar','gz'].includes(ext)) return '📦';
  if (['pdf'].includes(ext)) return '📄';
  if (['js','ts','rs','py','java','c','cpp','h','json','yaml','toml','xml'].includes(ext)) return '💻';
  return '📎';
}

function FileAttachmentCard({ meta, size = 260 }: { meta: FileAttachmentMeta; size?: number }) {
  const { session } = useAuth();
  const apiKey = session?.apiKey ?? "";
  const nodeUrl = loadSettings().nodeUrl;
  const img = isImage(meta.fileName);
  const vid = isVideo(meta.fileName);
  const aud = isAudio(meta.fileName);
  const pdf = getFileExtension(meta.fileName) === 'pdf';
  const authParam = `token=${encodeURIComponent(apiKey)}`;
  const url = `${nodeUrl}/api/v1/documents/${meta.docId}/data?inline=1&${authParam}`;

  function openFile() { window.open(url, '_blank'); }

  // Blob download with Auth
  async function downloadFile() {
    try {
      const resp = await fetch(`${nodeUrl}/api/v1/documents/${meta.docId}/data`, {
        headers: { "x-api-key": apiKey },
      });
      if (!resp.ok) throw new Error("Download fehlgeschlagen");
      const blob = await resp.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = meta.fileName;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch (e) {
      console.error("[download]", e);
      window.open(url, '_blank');
    }
  }

  return (
    <div style={{ borderRadius: 12, overflow: 'hidden', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', maxWidth: size, width: '100%' }}>
      {/* Media preview */}
      {/* Media / PDF preview */}
      {(img || vid || aud || pdf) && (
        <div style={{ background: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: img ? 160 : pdf ? 200 : 80 }}>
          {img && <img src={url} alt={meta.fileName} style={{ width: '100%', maxHeight: 280, objectFit: 'contain', cursor: 'pointer' }} onClick={openFile} />}
          {vid && (
            <video controls preload="metadata" style={{ width: '100%', maxHeight: 280, background: '#000' }}>
              <source src={url} /> Video nicht verfügbar
            </video>
          )}
          {aud && (
            <audio controls preload="metadata" style={{ width: '100%', padding: '16px 0' }}>
              <source src={url} /> Audio nicht verfügbar
            </audio>
          )}
          {pdf && (
            <iframe src={url} style={{ width: '100%', height: 200, border: 'none', background: '#fff' }} title={meta.fileName} />
          )}
        </div>
      )}
      {/* Info bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', cursor: 'pointer' }} onClick={openFile}>
        <span style={{ fontSize: 22 }}>{getFileIcon(meta.fileName)}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{meta.fileName}</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{meta.fileSize}</div>
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); downloadFile(); }}
          title="Herunterladen"
          style={{ width: 28, height: 28, borderRadius: 8, background: 'var(--accent)', border: 'none', color: '#fff', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <Download size={14} />
        </button>
      </div>
    </div>
  );
}

function getSenderWallet(msg: ChatEntry | GroupMessage): string {
  if ("from_wallet" in msg && msg.from_wallet) return msg.from_wallet as string;
  if ("sender_wallet" in msg && msg.sender_wallet) return msg.sender_wallet as string;
  return "";
}

function getSenderName(msg: ChatEntry | GroupMessage): string {
  if ("from_name" in msg && (msg as ChatEntry).from_name) return (msg as ChatEntry).from_name!;
  if ("sender_name" in msg && msg.sender_name) return msg.sender_name!;
  return "";
}

function getMsgId(msg: ChatEntry | GroupMessage, i: number): string {
  if ("msg_id" in msg && msg.msg_id) return msg.msg_id;
  if ("id" in msg && msg.id) return msg.id;
  return String(i);
}

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function shortAddr(addr: string): string {
  return addr.length > 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;
}

function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

// ── Message bubble ────────────────────────────────────────────────────────────

function MessageBubble({ msg, isOwn, showSender, senderName }: { msg: ChatEntry | GroupMessage; isOwn: boolean; showSender: boolean; senderName: string }) {
  const isCoin = "type" in msg && (msg.type === "send_coins" || msg.type === "request_coins");
  const content = getMsgContent(msg);
  const fileMeta = parseFileAttachment(content);
  return (
    <div className={`flex gap-3 px-4 py-0.5 group hover:bg-white/[0.02] ${isOwn ? "flex-row-reverse" : ""}`}>
      {showSender ? <Avatar name={senderName} size={34} /> : <div style={{ width: 34, flexShrink: 0 }} />}
      <div className={`flex flex-col max-w-lg ${isOwn ? "items-end" : ""}`}>
        {showSender && <div className="flex items-baseline gap-2 mb-1"><span className="text-sm font-semibold" style={{ color: "var(--text)" }}>{senderName}</span><span className="text-xs" style={{ color: "var(--text-muted)" }}>{fmtTime(msg.timestamp)}</span></div>}
        {fileMeta ? (
          <FileAttachmentCard meta={fileMeta} />
        ) : isCoin ? (
          <div style={{ background: "var(--accent-dim)", border: "1px solid var(--accent)", borderRadius: 14, padding: "8px 14px", fontSize: 13, color: "var(--text)" }}>
            {"type" in msg && msg.type === "send_coins" ? "💸" : "🪙"} <strong>{"amount" in msg ? (msg as ChatEntry).amount : ""} STONE</strong> — {content}
          </div>
        ) : (
          <div style={{ background: isOwn ? "var(--accent)" : "rgba(255,255,255,0.07)", color: isOwn ? "#fff" : "var(--text)", borderRadius: isOwn ? "18px 18px 6px 18px" : "18px 18px 18px 6px", padding: "9px 14px", fontSize: 13, lineHeight: 1.5, border: isOwn ? "none" : "1px solid rgba(255,255,255,0.06)", maxWidth: "100%", wordBreak: "break-word" }}>
            {content || <span style={{ opacity: 0.5, fontStyle: "italic" }}>[Verschlüsselte Nachricht]</span>}
          </div>
        )}
        {!showSender && <span className="text-xs opacity-0 group-hover:opacity-100 transition-opacity mt-0.5" style={{ color: "var(--text-muted)" }}>{fmtTime(msg.timestamp)}</span>}
      </div>
    </div>
  );
}

// ── Message thread ────────────────────────────────────────────────────────────

type ActiveChat = { type: "dm"; wallet: string; name: string } | { type: "group"; id: string; name: string };

function PhrasePrompt({ onSave }: { onSave: (p: string) => void }) {
  const [val, setVal] = useState("");
  const words = val.trim().split(/\s+/).filter(Boolean).length;
  return (
    <div style={{ margin: "0 12px 12px", background: "rgba(250,166,26,0.07)", border: "1px solid rgba(250,166,26,0.25)", borderRadius: 12, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}><KeyRound size={14} style={{ color: "var(--yellow)", flexShrink: 0 }} /><p style={{ fontSize: 12, fontWeight: 600, color: "var(--yellow)" }}>Recovery Phrase benötigt</p></div>
      <p style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5 }}>Du hast dich per QR/Discord angemeldet. Für verschlüsselte Nachrichten einmalig die 12-Wort Phrase eingeben — wird lokal gespeichert.</p>
      <div style={{ display: "flex", gap: 8 }}>
        <textarea value={val} onChange={(e) => setVal(e.target.value)} placeholder="word1 word2 word3 …" rows={2} style={{ flex: 1, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "7px 10px", fontSize: 12, color: "var(--text)", outline: "none", resize: "none", fontFamily: "monospace" }} autoComplete="off" spellCheck={false} autoCorrect="off" autoCapitalize="off" />
        <button onClick={() => { if (words === 12) onSave(val.trim()); }} disabled={words !== 12} style={{ padding: "0 14px", borderRadius: 8, background: words === 12 ? "var(--accent)" : "rgba(255,255,255,0.06)", color: words === 12 ? "#fff" : "var(--text-muted)", fontSize: 12, fontWeight: 600, border: "none", cursor: words === 12 ? "pointer" : "not-allowed", flexShrink: 0, transition: "all 0.15s" }}>{words}/12</button>
      </div>
    </div>
  );
}

function MessageThread({ active, myWallet }: { active: ActiveChat; myWallet: string }) {
  const { session, storePhrase } = useAuth();
  const phrase = session?.phrase ?? "";
  const userApiKey = session?.apiKey ?? "";
  const userToken = session?.sessionToken ?? "";
  const nodeUrl = loadSettings().nodeUrl;

  // ═══ WebRTC Voice Calling ═══
  const rtc = useWebRTC({
    localWallet: myWallet,
    apiKey: userApiKey,
    nodeUrl,
  });

  // ═══ Auth-Token für Media-URLs (<img>/<video>/<audio> können keine Headers setzen) ═══
  const qc = useQueryClient();
  const bottomRef = useRef<HTMLDivElement>(null);
  const [input, setInput] = useState("");
  const [showPhrasePrompt, setShowPhrasePrompt] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadToast, setUploadToast] = useState<{ msg: string; ok: boolean } | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const dmQuery = useQuery({ queryKey: ["chat-messages", active.type === "dm" ? active.wallet : null], queryFn: () => active.type === "dm" ? chatApi.messages(active.wallet) : Promise.resolve({ messages: [], peer_name: "" }), enabled: active.type === "dm", refetchInterval: 4_000 });
  const groupQuery = useQuery({ queryKey: ["group-messages", active.type === "group" ? active.id : null], queryFn: () => active.type === "group" ? groupsApi.messages(active.id) : Promise.resolve({ messages: [], group_name: "" }), enabled: active.type === "group", refetchInterval: 4_000 });
  const messages: Array<ChatEntry | GroupMessage> = active.type === "dm" ? (dmQuery.data?.messages ?? []) : (groupQuery.data?.messages ?? []);

  const sendMutation = useMutation({
    mutationFn: (text: string) => active.type === "dm" ? chatApi.send(active.wallet, text, phrase) : groupsApi.send(active.id, text),
    onSuccess: () => { qc.invalidateQueries({ queryKey: active.type === "dm" ? ["chat-messages", active.wallet] : ["group-messages", active.id] }); },
  });

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages.length]);
  useEffect(() => {
    if (!uploadToast) return;
    const t = setTimeout(() => setUploadToast(null), 5000);
    return () => clearTimeout(t);
  }, [uploadToast]);

  function handleSend(e: FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text) return;
    if (!phrase && active.type === "dm") { setShowPhrasePrompt(true); return; }
    setShowPhrasePrompt(false); setInput(""); sendMutation.mutate(text);
  }

  function handleDragOver(e: React.DragEvent) { e.preventDefault(); e.stopPropagation(); setDragOver(true); }
  function handleDragLeave(e: React.DragEvent) { e.preventDefault(); e.stopPropagation(); setDragOver(false); }
  function handleDrop(e: React.DragEvent) {
    e.preventDefault(); e.stopPropagation(); setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    uploadFile(file);
  }

  async function uploadFile(file: File) {
    setUploading(true);
    try {
      const result: any = await invoke("upload_file", {
        path: (file as any).path ?? file.name,
        masterUrl: nodeUrl,
        apiKey: userApiKey,
        sessionToken: userToken,
      });
      if (result?.success) {
        const fileName = file.name;
        const docId = result.doc_id ? result.doc_id.slice(0, 8) : "?";
        const blockInfo = result.block_index != null ? `Block #${result.block_index}` : "";
        setUploadToast({ msg: `📎 "${fileName}" hochgeladen — Doc #${docId} ${blockInfo}${result.shards_distributed ? " · ✓ Shards verteilt" : ""}`, ok: true });
        const chatMsg = `📎 Datei gesendet: ${fileName} (${formatSize(result.file_size)})\nDoc: ${result.doc_id ?? "?"}\nBlock: #${result.block_index ?? "?"}\nSHA-256: ${(result.file_hash ?? "").slice(0, 16)}…`;
        if (active.type === "dm") { await chatApi.send(active.wallet, chatMsg, phrase); }
        else { await groupsApi.send(active.id, chatMsg); }
        qc.invalidateQueries({ queryKey: active.type === "dm" ? ["chat-messages", active.wallet] : ["group-messages", active.id] });
      } else {
        setUploadToast({ msg: `❌ Upload fehlgeschlagen: ${result?.error ?? "Unbekannter Fehler"}`, ok: false });
      }
    } catch (err) { setUploadToast({ msg: `❌ Fehler: ${String(err)}`, ok: false }); }
    finally { setUploading(false); }
  }

  async function handleFileUpload() {
    try {
      const selected = await open({
        multiple: false,
        title: "Datei auswählen – Hochladen in diesen Chat",
      });
      if (!selected) return;
      const filePath = Array.isArray(selected) ? selected[0] : selected;
      if (!filePath) return;

      setUploading(true);
      const result: any = await invoke("upload_file", {
        path: filePath,
        masterUrl: nodeUrl,
        apiKey: userApiKey,
        sessionToken: userToken,
      });

      if (result?.success) {
        const parts = filePath.replace(/\\/g, "/").split("/");
        const fileName = parts[parts.length - 1] || filePath;
        const docId = result.doc_id ? result.doc_id.slice(0, 8) : "?";
        const blockInfo = result.block_index != null ? `Block #${result.block_index}` : "";
        setUploadToast({
          msg: `📎 "${fileName}" hochgeladen — Doc #${docId} ${blockInfo}${result.shards_distributed ? " · ✓ Shards verteilt" : ""}`,
          ok: true,
        });

        const chatMsg = `📎 Datei gesendet: ${fileName} (${formatSize(result.file_size)})\nDoc: ${result.doc_id ?? "?"}\nBlock: #${result.block_index ?? "?"}\nSHA-256: ${(result.file_hash ?? "").slice(0, 16)}…`;
        if (active.type === "dm") {
          await chatApi.send(active.wallet, chatMsg, phrase);
        } else {
          await groupsApi.send(active.id, chatMsg);
        }
        qc.invalidateQueries({ queryKey: active.type === "dm" ? ["chat-messages", active.wallet] : ["group-messages", active.id] });
      } else {
        setUploadToast({ msg: `❌ Upload fehlgeschlagen: ${result?.error ?? "Unbekannter Fehler"}`, ok: false });
      }
    } catch (err) {
      setUploadToast({ msg: `❌ Fehler: ${String(err)}`, ok: false });
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", background: "rgba(255,255,255,0.01)" }}>
        {active.type === "dm" ? <Avatar name={active.name} size={30} /> : <div style={{ width: 30, height: 30, borderRadius: 10, background: "var(--surface-2)", display: "flex", alignItems: "center", justifyContent: "center" }}><Hash size={14} style={{ color: "var(--text-dim)" }} /></div>}
        <div style={{ flex: 1 }}><p style={{ fontSize: 14, fontWeight: 600, color: "var(--text)" }}>{active.name}</p>{active.type === "dm" && <p style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-muted)" }}>{shortAddr(active.wallet)}</p>}</div>
        {active.type === "dm" && (
          <button
            onClick={() => rtc.startCall(active.wallet, active.name)}
            title="Anrufen"
            style={{
              width: 32, height: 32, borderRadius: 8,
              background: "rgba(34,197,94,0.1)",
              border: "1px solid rgba(34,197,94,0.2)",
              color: "#22c55e",
              cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
              transition: "all 0.15s",
            }}
          >
            <Phone size={14} />
          </button>
        )}
      </div>

      {uploadToast && (
        <div style={{
          margin: "0 12px", padding: "10px 14px", borderRadius: 10,
          background: uploadToast.ok ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)",
          border: `1px solid ${uploadToast.ok ? "rgba(34,197,94,0.25)" : "rgba(239,68,68,0.25)"}`,
          fontSize: 12, color: uploadToast.ok ? "#22c55e" : "#ef4444",
          position: "absolute", top: 56, left: 12, right: 12, zIndex: 10,
          backdropFilter: "blur(12px)",
        }}>
          {uploadToast.msg}
        </div>
      )}

      <div style={{ flex: 1, overflowY: "auto", paddingTop: 12, paddingBottom: 8 }}>
        {messages.map((msg, i) => {
          const prevMsg = messages[i - 1]; const currSender = getSenderWallet(msg); const prevSender = prevMsg ? getSenderWallet(prevMsg) : "";
          const isOwn = ("is_own" in msg && msg.is_own) || currSender === myWallet || ("from_wallet" in msg && (msg as ChatEntry).from_wallet === myWallet);
          const senderName = getSenderName(msg) || (currSender ? shortAddr(currSender) : active.name);
          const showSender = !prevSender || prevSender !== currSender || msg.timestamp - (prevMsg?.timestamp ?? 0) > 300;
          return <MessageBubble key={getMsgId(msg, i)} msg={msg} isOwn={isOwn} showSender={showSender} senderName={senderName} />;
        })}
        {messages.length === 0 && !dmQuery.isLoading && !groupQuery.isLoading && <div style={{ textAlign: "center", padding: "48px 24px" }}><p style={{ fontSize: 13, color: "var(--text-muted)" }}>Noch keine Nachrichten. Schreib als erstes!</p></div>}
        <div ref={bottomRef} />
      </div>
      {showPhrasePrompt && <PhrasePrompt onSave={(p) => { storePhrase(p); setShowPhrasePrompt(false); }} />}
      {sendMutation.isError && !showPhrasePrompt && <div style={{ padding: "0 12px 8px" }}><div style={{ background: "rgba(237,66,69,0.1)", border: "1px solid rgba(237,66,69,0.3)", borderRadius: 10, padding: "7px 12px", fontSize: 12, color: "var(--red)" }}>{sendMutation.error instanceof Error ? sendMutation.error.message : "Fehler beim Senden"}</div></div>}
      {/* ═══ Voice Call UI ═══ */}
      <CallUI
        callState={rtc.callState}
        callDuration={rtc.formattedDuration}
        remoteName={rtc.remoteName}
        isMuted={rtc.isMuted}
        onAccept={() => {
          const id = (rtc as any).callId;
          rtc.acceptCall(id, rtc.remoteWallet, rtc.remoteName);
        }}
        onHangup={rtc.hangup}
        onMute={rtc.toggleMute}
      />

      <form onSubmit={handleSend} style={{ padding: "0 12px 12px" }}>
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          style={{
            display: "flex", flexDirection: "column", gap: 0,
            background: dragOver ? "rgba(34,197,94,0.08)" : "rgba(255,255,255,0.05)",
            border: `1px solid ${dragOver ? "rgba(34,197,94,0.4)" : "rgba(255,255,255,0.08)"}`,
            borderRadius: 14, transition: "all 0.15s",
          }}>
          {dragOver && (
            <div style={{
              color: "#22c55e", fontSize: 11, fontWeight: 600,
              padding: "6px 12px 0", textAlign: "center",
            }}>
              📁 Datei loslassen zum Hochladen
            </div>
          )}
          <div style={{ display: "flex", alignItems: "flex-end", gap: 6, padding: "6px 8px" }}>
            <button
              type="button" onClick={handleFileUpload} disabled={uploading} title="Datei hochladen"
              style={{
                width: 32, height: 32, borderRadius: 10,
                background: uploading ? "rgba(34,197,94,0.15)" : "rgba(255,255,255,0.05)",
                color: uploading ? "#22c55e" : "var(--text-muted)",
                border: "none", display: "flex", alignItems: "center", justifyContent: "center",
                cursor: uploading ? "not-allowed" : "pointer", transition: "all 0.15s", flexShrink: 0,
              }}
              onMouseEnter={(e) => { if (!uploading) { (e.currentTarget as HTMLElement).style.background = "rgba(34,197,94,0.12)"; (e.currentTarget as HTMLElement).style.color = "#22c55e"; } }}
              onMouseLeave={(e) => { if (!uploading) { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.05)"; (e.currentTarget as HTMLElement).style.color = "var(--text-muted)"; } }}
            >
              <Plus size={16} />
            </button>
            <textarea value={input} onChange={(e) => { setInput(e.target.value); e.currentTarget.style.height = "auto"; e.currentTarget.style.height = Math.min(e.currentTarget.scrollHeight, 120) + "px"; }} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(e as unknown as FormEvent); } }} placeholder={dragOver ? "Datei loslassen…" : `Nachricht an ${active.name}…`} rows={1} style={{ flex: 1, background: "transparent", border: "none", outline: "none", resize: "none", color: "var(--text)", fontSize: 13, minHeight: 22, maxHeight: 120, paddingTop: 2, lineHeight: 1.5 }} autoComplete="off" spellCheck={false} />
            <button type="submit" disabled={!input.trim() || sendMutation.isPending} style={{ width: 32, height: 32, borderRadius: 10, background: input.trim() && !sendMutation.isPending ? "var(--accent)" : "rgba(255,255,255,0.05)", color: input.trim() && !sendMutation.isPending ? "#fff" : "var(--text-muted)", border: "none", display: "flex", alignItems: "center", justifyContent: "center", cursor: input.trim() ? "pointer" : "not-allowed", transition: "all 0.15s", flexShrink: 0 }}><Send size={14} /></button>
          </div>
        </div>
      </form>
    </div>
  );
}

// ── Main ChatView ─────────────────────────────────────────────────────────────

interface ChatViewProps {
  initialActive?: { type: "dm"; wallet: string; name: string } | { type: "group"; id: string; name: string } | null;
}

export default function ChatView({ initialActive }: ChatViewProps) {
  const { session } = useAuth();

  if (!initialActive) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12, background: "var(--main-bg)" }}>
        <div style={{ width: 64, height: 64, borderRadius: 20, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <MessageCircle size={28} style={{ color: "var(--text-muted)", opacity: 0.5 }} />
        </div>
        <p style={{ fontSize: 15, fontWeight: 600, color: "var(--text-dim)" }}>Wähle ein Gespräch</p>
        <p style={{ fontSize: 12, color: "var(--text-muted)" }}>Klicke links auf einen Kontakt um zu schreiben</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", height: "100%", background: "var(--main-bg)" }}>
      <div style={{ flex: 1, overflow: "hidden" }}>
        <MessageThread active={initialActive as ActiveChat} myWallet={session?.walletAddress ?? ""} />
      </div>
    </div>
  );
}