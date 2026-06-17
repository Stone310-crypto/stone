import { useState, useEffect, type ReactElement } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { wallet as walletApi, staking as stakingApi, games as gamesApi } from "../../api/stone";
import { useAuth } from "../../auth/AuthContext";
import type { TokenTransaction } from "../../types/api";
import {
  ArrowUpRight, ArrowDownLeft, TrendingUp, Copy, Check,
  Send, QrCode, ArrowLeft, X, Loader2, Package,
} from "lucide-react";

interface WalletViewProps {
  onClose: () => void;
}

function fmtStone(v: string | undefined): string {
  if (!v) return "0.00";
  const n = parseFloat(v);
  return n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 });
}
function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function shortAddr(a: string): string {
  return a.length > 14 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a;
}
function CopyAddr({ addr }: { addr: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={async () => { await navigator.clipboard.writeText(addr); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      style={{ background:"none", border:"none", cursor:"pointer", color:copied?"var(--green)":"var(--text-muted)", display:"flex", alignItems:"center", gap:4, fontSize:12 }}>
      {copied ? <Check size={14} /> : <Copy size={14} />}{copied ? "Kopiert" : ""}
    </button>
  );
}

type Panel = "transactions" | "staking" | "items";
const PANELS: { id: Panel; label: string; icon: ReactElement }[] = [
  { id: "transactions", label: "Transaktionen", icon: <ArrowDownLeft size={16} /> },
  { id: "staking", label: "Staking", icon: <TrendingUp size={16} /> },
  { id: "items", label: "Items", icon: <Package size={16} /> },
];

// ── Send ──────────────────────────────────────────────────────────────────────
function SendPanel({ onClose, walletAddr }: { onClose: () => void; walletAddr: string }) {
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [error, setError] = useState("");
  const [step, setStep] = useState<"form" | "confirm">("form");
  const queryClient = useQueryClient();
  const sendMt = useMutation({
    mutationFn: () => walletApi.sendAuthenticated(to.trim(), amount.trim()),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["balance", walletAddr] }); queryClient.invalidateQueries({ queryKey: ["history", walletAddr] }); onClose(); },
    onError: (e: Error) => setError(e.message),
  });
  const valid = parseFloat(amount) > 0;
  if (step === "confirm") return (
    <div style={{ display:"flex", flexDirection:"column", gap:18 }}>
      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
        <button onClick={()=>setStep("form")} style={{ background:"none", border:"none", color:"var(--text-muted)", cursor:"pointer" }}><ArrowLeft size={18} /></button>
        <h3 style={{ fontSize:15, fontWeight:600 }}>Transaktion bestätigen</h3>
      </div>
      <div style={{ background:"var(--bg-surface)", borderRadius:12, padding:16, border:"1px solid var(--border-default)" }}>
        <p style={{ fontSize:12, color:"var(--text-muted)", marginBottom:4 }}>Empfänger</p>
        <p className="mono" style={{ fontSize:12, wordBreak:"break-all" }}>{to}</p>
        <div style={{ marginTop:14 }}><p style={{ fontSize:12, color:"var(--text-muted)", marginBottom:4 }}>Betrag</p>
        <p style={{ fontSize:22, fontWeight:700, color:"var(--accent)" }}>{amount} STONE</p></div>
      </div>
      {error && <div style={{ background:"var(--red-bg)", border:"1px solid rgba(217,91,91,0.3)", borderRadius:8, padding:"9px 12px", fontSize:12, color:"var(--red)" }}>{error}</div>}
      <button onClick={()=>sendMt.mutate()} disabled={sendMt.isPending}
        style={{ width:"100%", padding:12, borderRadius:10, background:sendMt.isPending?"rgba(212,168,83,0.3)":"var(--accent)", color:"var(--text-inverse)", fontWeight:600, fontSize:14, border:"none", cursor:sendMt.isPending?"not-allowed":"pointer" }}>
        {sendMt.isPending ? <Loader2 size={18} style={{ animation:"spin 0.7s linear infinite" }} /> : "Jetzt senden"}
      </button>
    </div>
  );
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <div style={{ display:"flex", alignItems:"center", gap:10 }}><button onClick={onClose} style={{ background:"none", border:"none", color:"var(--text-muted)", cursor:"pointer" }}><X size={18} /></button><h3 style={{ fontSize:15, fontWeight:600 }}>STONE senden</h3></div>
      <div><label style={{ fontSize:12, fontWeight:500, color:"var(--text-secondary)", marginBottom:6, display:"block" }}>Empfänger-Adresse</label>
        <input type="text" value={to} onChange={(e)=>setTo(e.target.value)} placeholder="0x… oder stone1…" style={{ width:"100%", background:"var(--bg-input)", border:"1px solid var(--border-default)", borderRadius:8, padding:"10px 12px", fontSize:13, outline:"none", fontFamily:"monospace", color:"var(--text-primary)" }} /></div>
      <div><label style={{ fontSize:12, fontWeight:500, color:"var(--text-secondary)", marginBottom:6, display:"block" }}>Betrag (STONE)</label>
        <input type="number" step="0.000001" min="0" value={amount} onChange={(e)=>setAmount(e.target.value)} placeholder="0.00" style={{ width:"100%", background:"var(--bg-input)", border:"1px solid var(--border-default)", borderRadius:8, padding:"10px 12px", fontSize:13, outline:"none", color:"var(--text-primary)" }} /></div>
      <button onClick={()=>setStep("confirm")} disabled={!to.trim()||!valid}
        style={{ width:"100%", padding:12, borderRadius:10, background:(!to.trim()||!valid)?"rgba(212,168,83,0.2)":"var(--accent)", color:(!to.trim()||!valid)?"var(--text-muted)":"var(--text-inverse)", fontWeight:600, fontSize:14, border:"none", cursor:(!to.trim()||!valid)?"not-allowed":"pointer" }}>Weiter</button>
    </div>
  );
}

// ── Receive ───────────────────────────────────────────────────────────────────
function ReceivePanel({ onClose, walletAddr }: { onClose: () => void; walletAddr: string }) {
  const [qrDataUrl, setQrDataUrl] = useState("");
  useEffect(() => { QRCode.toDataURL(`stone://${walletAddr}`, { width: 180, margin: 2, color: { dark: "#d4a853", light: "#1e202a" } }).then(setQrDataUrl); }, [walletAddr]);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16, alignItems:"center" }}>
      <div style={{ display:"flex", alignItems:"center", gap:10, alignSelf:"stretch" }}><button onClick={onClose} style={{ background:"none", border:"none", color:"var(--text-muted)", cursor:"pointer" }}><X size={18} /></button><h3 style={{ fontSize:15, fontWeight:600 }}>STONE empfangen</h3></div>
      <div style={{ background:"#1e202a", borderRadius:16, padding:16, border:"1px solid var(--border-default)" }}>{qrDataUrl ? <img src={qrDataUrl} alt="QR" style={{ width:180, height:180 }} /> : <Loader2 size={24} style={{ animation:"spin 0.7s linear infinite" }} />}</div>
      <div style={{ background:"var(--bg-surface)", borderRadius:8, padding:"10px 14px", border:"1px solid var(--border-default)", width:"100%" }}><p className="mono" style={{ fontSize:11, wordBreak:"break-all", textAlign:"center" }}>{walletAddr}</p></div>
      <CopyAddr addr={walletAddr} />
    </div>
  );
}

// ── TxRow ─────────────────────────────────────────────────────────────────────
function TxRow({ tx, myWallet }: { tx: TokenTransaction; myWallet: string }) {
  const incoming = tx.to === myWallet;
  return (
    <div style={{ background:"var(--bg-surface)", borderRadius:10, padding:"12px 16px", display:"flex", alignItems:"center", gap:12 }}
      onMouseEnter={(e)=>(e.currentTarget.style.background="var(--bg-surface-2)")} onMouseLeave={(e)=>(e.currentTarget.style.background="var(--bg-surface)")}>
      <div style={{ width:36, height:36, borderRadius:"50%", background:incoming?"var(--green-bg)":"var(--red-bg)", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
        {incoming ? <ArrowDownLeft size={16} style={{ color:"var(--green)" }} /> : <ArrowUpRight size={16} style={{ color:"var(--red)" }} />}
      </div>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ display:"flex", justifyContent:"space-between" }}><p style={{ fontSize:13, fontWeight:500 }}>{incoming?"Empfangen":"Gesendet"}</p><p className="mono" style={{ fontSize:13, fontWeight:600, color:incoming?"var(--green)":"var(--text-primary)" }}>{incoming?"+":"-"}{fmtStone(tx.amount)} STONE</p></div>
        <div style={{ display:"flex", justifyContent:"space-between", marginTop:2 }}><p className="mono" style={{ fontSize:11, color:"var(--text-muted)" }}>{incoming?shortAddr(tx.from):shortAddr(tx.to)}</p><p style={{ fontSize:11, color:"var(--text-muted)" }}>{fmtTime(tx.timestamp)}</p></div>
      </div>
    </div>
  );
}

// ── Items Tab ─────────────────────────────────────────────────────────────────
function ItemsTab({ walletAddr }: { walletAddr: string }) {
  const q = useQuery({
    queryKey: ["game-items", walletAddr],
    queryFn: async () => {
      const games = await gamesApi.list();
      const coins: { game_id: string; name: string; balance: string }[] = [];
      for (const g of games.games ?? []) {
        try { const bal = await gamesApi.coinBalance(g.game_id, walletAddr); if (parseFloat(bal.balance ?? "0") > 0) coins.push({ game_id: g.game_id, name: g.name, balance: bal.balance ?? "0" }); } catch {}
      }
      return coins;
    },
    enabled: !!walletAddr,
    refetchInterval: 30_000,
    retry: false,
  });
  const items = (q.data ?? []).map(c => ({ icon: "🪙", name: `${c.name} Coin`, game: c.game_id, quantity: c.balance }));
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {items.length===0 && <p style={{ fontSize:13, color:"var(--text-muted)", textAlign:"center", padding:24 }}>Keine Items oder Game-Coins vorhanden.</p>}
      {items.map((item,i)=>(
        <div key={i} style={{ background:"var(--bg-surface)", borderRadius:10, padding:"12px 16px", display:"flex", alignItems:"center", gap:12, border:"1px solid var(--border-subtle)" }}>
          <span style={{ fontSize:24 }}>{item.icon}</span><div style={{ flex:1 }}><p style={{ fontSize:13, fontWeight:500 }}>{item.name}</p><p style={{ fontSize:11, color:"var(--text-muted)" }}>{item.game}</p></div>
          <p className="mono" style={{ fontSize:13, fontWeight:600, color:"var(--accent)" }}>{item.quantity}</p>
        </div>
      ))}
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function WalletView({ onClose }: WalletViewProps) {
  const { session } = useAuth();
  const [panel, setPanel] = useState<Panel>("transactions");
  const [showSend, setShowSend] = useState(false);
  const [showReceive, setShowReceive] = useState(false);
  const addr = session?.walletAddress ?? "";

  const balQ = useQuery({ queryKey: ["balance", addr], queryFn: () => walletApi.balance(addr), enabled: !!addr, refetchInterval: 15_000 });
  const histQ = useQuery({ queryKey: ["history", addr], queryFn: () => walletApi.history(addr), enabled: !!addr, refetchInterval: 30_000 });
  const stkQ = useQuery({ queryKey: ["staking", addr], queryFn: () => stakingApi.stakerInfo(addr), enabled: !!addr, refetchInterval: 30_000 });

  const balance = balQ.data?.balance ?? "0";
  const txs: TokenTransaction[] = histQ.data?.transactions ?? [];
  const staker = stkQ.data?.staker;

  if (showSend) return (
    <div style={{ position:"fixed", inset:0, zIndex:60, display:"flex", alignItems:"center", justifyContent:"center", background:"rgba(0,0,0,0.6)" }}>
      <div style={{ background:"var(--bg-panel)", borderRadius:16, padding:24, width:420, maxHeight:"80vh", overflowY:"auto", border:"1px solid var(--border-strong)", boxShadow:"0 16px 48px rgba(0,0,0,0.5)" }}>
        <SendPanel onClose={() => setShowSend(false)} walletAddr={addr} />
      </div>
    </div>
  );
  if (showReceive) return (
    <div style={{ position:"fixed", inset:0, zIndex:60, display:"flex", alignItems:"center", justifyContent:"center", background:"rgba(0,0,0,0.6)" }}>
      <div style={{ background:"var(--bg-panel)", borderRadius:16, padding:24, width:420, maxHeight:"80vh", overflowY:"auto", border:"1px solid var(--border-strong)", boxShadow:"0 16px 48px rgba(0,0,0,0.5)" }}>
        <ReceivePanel onClose={() => setShowReceive(false)} walletAddr={addr} />
      </div>
    </div>
  );

  return (
    <div style={{ position:"fixed", inset:0, zIndex:55, display:"flex", alignItems:"center", justifyContent:"center", background:"rgba(0,0,0,0.55)" }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      {/* Wallet Card */}
      <div style={{
        background: "var(--bg-panel)",
        borderRadius: 16,
        width: 460,
        maxWidth: "94vw",
        maxHeight: "85vh",
        overflowY: "auto",
        border: "1px solid var(--border-strong)",
        boxShadow: "0 16px 48px rgba(0,0,0,0.5)",
        padding: 20,
      }}>
        {/* Header */}
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:20 }}>
          <button onClick={onClose} title="Zurück"
            style={{ width:30, height:30, borderRadius:8, background:"rgba(255,255,255,0.06)", border:"none", color:"var(--text-muted)", cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center" }}>
            <ArrowLeft size={16} />
          </button>
          <h2 style={{ fontSize:16, fontWeight:700, flex:1 }}>Wallet</h2>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"var(--text-muted)", cursor:"pointer" }}>
            <X size={18} />
          </button>
        </div>

        {/* Balance Card */}
        <div style={{ background:"linear-gradient(135deg, #1a1c26 0%, #242732 100%)", borderRadius:14, padding:20, border:"1px solid var(--border-strong)", marginBottom:16 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
            <div>
              <p style={{ fontSize:11, fontWeight:500, color:"var(--text-muted)", marginBottom:4 }}>Gesamtguthaben</p>
              <p style={{ fontSize:26, fontWeight:700, fontFamily:"monospace" }}>{fmtStone(balance)} <span style={{ fontSize:13, color:"var(--accent)" }}>STONE</span></p>
            </div>
            <div style={{ display:"flex", gap:6 }}>
              <button onClick={() => setShowReceive(true)} style={{ background:"var(--accent-bg)", border:"1px solid rgba(212,168,83,0.3)", borderRadius:8, padding:"7px 12px", color:"var(--accent)", cursor:"pointer", display:"flex", alignItems:"center", gap:5, fontSize:12, fontWeight:500 }}><QrCode size={14} /> Empfangen</button>
              <button onClick={() => setShowSend(true)} style={{ background:"var(--accent)", border:"none", borderRadius:8, padding:"7px 12px", color:"var(--text-inverse)", cursor:"pointer", display:"flex", alignItems:"center", gap:5, fontSize:12, fontWeight:600 }}><Send size={14} /> Senden</button>
            </div>
          </div>
          {addr && (
            <div style={{ marginTop:14, display:"flex", alignItems:"center", gap:8 }}>
              <p className="mono" style={{ fontSize:10, color:"var(--text-muted)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{addr}</p>
              <CopyAddr addr={addr} />
            </div>
          )}
        </div>

        {/* Tabs */}
        <div style={{ display:"flex", gap:4, marginBottom:14 }}>
          {PANELS.map(p => (
            <button key={p.id} onClick={() => setPanel(p.id)} style={{
              flex:1, padding:"9px 10px", borderRadius:10, background:panel===p.id?"var(--accent-bg)":"transparent",
              border:panel===p.id?"1px solid rgba(212,168,83,0.3)":"1px solid transparent",
              color:panel===p.id?"var(--accent)":"var(--text-muted)", cursor:"pointer",
              display:"flex", alignItems:"center", justifyContent:"center", gap:5, fontSize:12, fontWeight:500,
              transition:"all var(--transition-fast)",
            }}>{p.icon}{p.label}</button>
          ))}
        </div>

        {panel === "transactions" && (
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {txs.length===0 && <p style={{ fontSize:13, color:"var(--text-muted)", textAlign:"center", padding:24 }}>Keine Transaktionen vorhanden.</p>}
            {txs.map((tx,i)=><TxRow key={tx.tx_id||i} tx={tx} myWallet={addr} />)}
          </div>
        )}
        {panel === "staking" && (
          <div style={{ background:"var(--bg-surface)", borderRadius:14, padding:18, border:"1px solid var(--border-default)" }}>
            <h3 style={{ fontSize:14, fontWeight:600, marginBottom:12 }}>Staking</h3>
            {staker ? (
              <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                <div style={{ display:"flex", justifyContent:"space-between" }}><span style={{ color:"var(--text-muted)", fontSize:13 }}>Eingesetzt</span><span className="mono" style={{ fontSize:13, fontWeight:600 }}>{fmtStone(staker.staked_amount)} STONE</span></div>
                <div style={{ display:"flex", justifyContent:"space-between" }}><span style={{ color:"var(--text-muted)", fontSize:13 }}>Belohnung</span><span className="mono" style={{ color:"var(--green)", fontSize:13, fontWeight:600 }}>{fmtStone(staker.pending_reward)} STONE</span></div>
              </div>
            ) : <p style={{ color:"var(--text-muted)", fontSize:13 }}>Kein Staking aktiv.</p>}
          </div>
        )}
        {panel === "items" && <ItemsTab walletAddr={addr} />}
      </div>
    </div>
  );
}