import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { chat as chatApi } from "../../api/stone";
import { apiFetch } from "../../api/client";
import type { ContactRequestDetail, ChatResolveResult } from "../../types/api";
import { ArrowLeft, X, Search, UserPlus, Check, Loader2, Clock } from "lucide-react";

interface FriendAddOverlayProps {
  onClose: () => void;
}

function shortAddr(addr: string): string {
  return addr.length > 14 ? `${addr.slice(0, 8)}…${addr.slice(-6)}` : addr;
}

export default function FriendAddOverlay({ onClose }: FriendAddOverlayProps) {
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<ChatResolveResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState("");
  const [sentWallets, setSentWallets] = useState<Set<string>>(new Set());
  const qc = useQueryClient();

  // Pending contact requests
  const requestsQ = useQuery({
    queryKey: ["contact-requests"],
    queryFn: () => chatApi.contactRequests(),
    refetchInterval: 10_000,
  });
  const pendingRequests: ContactRequestDetail[] = requestsQ.data?.requests ?? [];

  // Accept / Decline mutations
  const acceptMt = useMutation({
    mutationFn: (id: string) => chatApi.acceptRequest(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["contact-requests"] }); qc.invalidateQueries({ queryKey: ["conversations"] }); },
  });
  const declineMt = useMutation({
    mutationFn: (id: string) => chatApi.declineRequest(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["contact-requests"] }); },
  });

  const handleSearch = async () => {
    const q = query.trim();
    if (!q) return;
    setSearching(true);
    setSearchError("");
    setSearchResults([]);
    try {
      const res = await chatApi.resolve(q);
      setSearchResults(res.results ?? []);
      if ((res.results ?? []).length === 0) setSearchError("Kein Nutzer gefunden");
    } catch (e: any) {
      setSearchError(e?.message ?? "Nicht gefunden");
    } finally {
      setSearching(false);
    }
  };

  const handleSendRequest = async (wallet: string) => {
    try {
      await apiFetch("/api/v1/chat/contacts/request", {
        method: "POST",
        body: JSON.stringify({ to: wallet }),
      });
      setSentWallets(prev => new Set([...prev, wallet]));
    } catch (e: any) {
      setSearchError(e?.message ?? "Fehler beim Senden");
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
        padding: 20,
      }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
          <button onClick={onClose} title="Zurück"
            style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(255,255,255,0.06)", border: "none", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <ArrowLeft size={16} />
          </button>
          <h2 style={{ fontSize: 16, fontWeight: 700, flex: 1 }}>Freunde hinzufügen</h2>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
            <X size={18} />
          </button>
        </div>

        {/* Search */}
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") handleSearch(); }}
            placeholder="Wallet-Adresse oder Benutzername…"
            style={{
              flex: 1, background: "var(--bg-input)", border: "1px solid var(--border-default)",
              borderRadius: 10, padding: "10px 12px", fontSize: 13, color: "var(--text-primary)",
              outline: "none", boxSizing: "border-box",
            }}
            autoFocus
            autoComplete="off"
          />
          <button
            onClick={handleSearch}
            disabled={!query.trim() || searching}
            style={{
              width: 42, height: 42, borderRadius: 10,
              background: "var(--accent)", border: "none", color: "var(--text-inverse)",
              cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
              opacity: (!query.trim() || searching) ? 0.5 : 1,
            }}
          >
            {searching ? <Loader2 size={16} style={{ animation: "spin 0.7s linear infinite" }} /> : <Search size={16} />}
          </button>
        </div>

        {/* Search Results */}
        {searchResults.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            {searchResults.map((r, idx) => (
              <div key={r.wallet || idx} style={{
                background: "var(--bg-surface)", borderRadius: 12, padding: 10,
                border: "1px solid var(--border-default)", marginBottom: 6,
                display: "flex", alignItems: "center", gap: 10,
              }}>
                <div style={{
                  width: 36, height: 36, borderRadius: "50%",
                  background: "var(--accent)", display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 15, fontWeight: 700, color: "#fff", flexShrink: 0,
                }}>
                  {(r.name || r.wallet)?.[0]?.toUpperCase() ?? "?"}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{r.name || "Unbekannt"}</p>
                  {r.bio ? (
                    <p style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.3, marginBottom: 2 }}>{r.bio}</p>
                  ) : null}
                  <p style={{ fontSize: 10, fontFamily: "monospace", color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {shortAddr(r.wallet)}
                  </p>
                </div>
                {sentWallets.has(r.wallet) ? (
                  <span style={{ fontSize: 11, color: "var(--green)", fontWeight: 600, flexShrink: 0, display: "flex", alignItems: "center", gap: 3 }}>
                    <Check size={12} /> Gesendet
                  </span>
                ) : (
                  <button
                    onClick={() => handleSendRequest(r.wallet)}
                    style={{
                      padding: "6px 12px", borderRadius: 8,
                      background: "var(--accent)", border: "none", color: "var(--text-inverse)",
                      cursor: "pointer", fontSize: 11, fontWeight: 600,
                      display: "flex", alignItems: "center", gap: 4, flexShrink: 0,
                    }}
                  >
                    <UserPlus size={12} /> Anfrage
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {searchError && searchResults.length === 0 && !searching && (
          <div style={{ background: "var(--red-bg)", border: "1px solid rgba(217,91,91,0.3)", borderRadius: 8, padding: "9px 12px", fontSize: 12, color: "var(--red)", marginBottom: 16 }}>
            {searchError}
          </div>
        )}

        {/* Pending Requests */}
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10 }}>
            <Clock size={14} style={{ color: "var(--text-muted)" }} />
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", letterSpacing: "0.04em" }}>
              Ausstehende Anfragen ({pendingRequests.length})
            </span>
          </div>

          {pendingRequests.length === 0 && !requestsQ.isLoading && (
            <p style={{ fontSize: 12, color: "var(--text-muted)", padding: "8px 0" }}>Keine ausstehenden Anfragen.</p>
          )}

          {requestsQ.isLoading && (
            <div style={{ display: "flex", justifyContent: "center", padding: 16 }}>
              <Loader2 size={16} style={{ animation: "spin 0.7s linear infinite", color: "var(--text-muted)" }} />
            </div>
          )}

          {pendingRequests.map((req) => (
            <div key={req.id} style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "10px 12px", borderRadius: 10,
              background: "var(--bg-surface)", border: "1px solid var(--border-default)",
              marginBottom: 6,
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: "50%",
                background: "var(--accent)", display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 13, fontWeight: 700, color: "#fff", flexShrink: 0,
              }}>
                {req.from_name?.[0]?.toUpperCase() ?? "?"}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{req.from_name}</p>
                <p style={{ fontSize: 10, fontFamily: "monospace", color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{shortAddr(req.from_wallet)}</p>
              </div>
              <button
                onClick={() => declineMt.mutate(req.id)}
                disabled={declineMt.isPending}
                style={{
                  padding: "5px 10px", borderRadius: 6,
                  background: "rgba(237,66,69,0.1)", border: "1px solid rgba(237,66,69,0.2)",
                  color: "var(--red)", cursor: "pointer", fontSize: 11, fontWeight: 600,
                }}
              >
                Ablehnen
              </button>
              <button
                onClick={() => acceptMt.mutate(req.id)}
                disabled={acceptMt.isPending}
                style={{
                  padding: "5px 10px", borderRadius: 6,
                  background: "var(--accent)", border: "none", color: "var(--text-inverse)",
                  cursor: "pointer", fontSize: 11, fontWeight: 600,
                }}
              >
                Annehmen
              </button>
            </div>
          ))}
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}