// ═══ CallUI — Voice Call Overlay ═══
//
// Handles: Ringing, Connected, Ended states
// with Mute, Duration, Hangup controls

import { Phone, PhoneOff, Mic, MicOff } from "lucide-react";
import type { CallState } from "../../hooks/useWebRTC";

interface CallUIProps {
  callState: CallState;
  callDuration: string;
  remoteName: string;
  isMuted: boolean;
  onAccept: () => void;
  onHangup: () => void;
  onMute: () => void;
  onReject?: () => void;
}

export default function CallUI({
  callState,
  callDuration,
  remoteName,
  isMuted,
  onAccept,
  onHangup,
  onMute,
  onReject,
}: CallUIProps) {
  if (callState === "idle" || callState === "ended") return null;

  const isIncoming = callState === "ringing";
  const isCalling = callState === "calling";
  const isConnected = callState === "connected";

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0,0,0,0.7)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div
        style={{
          background: "var(--bg-panel, #1a1a2e)",
          borderRadius: 24,
          border: "1px solid var(--border-strong, rgba(255,255,255,0.1))",
          padding: "40px 48px",
          textAlign: "center",
          minWidth: 320,
          maxWidth: 420,
          boxShadow: "0 24px 64px rgba(0,0,0,0.6)",
        }}
      >
        {/* Avatar */}
        <div
          style={{
            width: 80,
            height: 80,
            borderRadius: "50%",
            background: isConnected
              ? "linear-gradient(135deg, #22c55e 0%, #10b981 100%)"
              : "linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 32,
            fontWeight: 700,
            color: "#fff",
            margin: "0 auto 20px",
            animation: isCalling ? "pulse-ring 1.5s ease-in-out infinite" : "none",
          }}
        >
          {remoteName[0]?.toUpperCase() ?? "?"}
        </div>

        {/* Name + Status */}
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "#fff", marginBottom: 6 }}>
          {remoteName || "Unbekannt"}
        </h2>
        <p
          style={{
            fontSize: 13,
            color: isConnected ? "#22c55e" : isIncoming ? "#f59e0b" : "#94a3b8",
            marginBottom: 24,
            fontWeight: 500,
          }}
        >
          {isIncoming && "📞 Eingehender Anruf…"}
          {isCalling && "📞 Wähle…"}
          {isConnected && (
            <>
              🟢 Verbunden · {callDuration}
            </>
          )}
        </p>

        {/* Action Buttons */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 16,
          }}
        >
          {/* Mute — nur bei connected */}
          {isConnected && (
            <button
              onClick={onMute}
              title={isMuted ? "Mikrofon einschalten" : "Stummschalten"}
              style={{
                width: 52,
                height: 52,
                borderRadius: "50%",
                background: isMuted
                  ? "rgba(239,68,68,0.15)"
                  : "rgba(255,255,255,0.08)",
                border: isMuted
                  ? "2px solid rgba(239,68,68,0.4)"
                  : "2px solid rgba(255,255,255,0.1)",
                color: isMuted ? "#ef4444" : "var(--text-muted, #94a3b8)",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                transition: "all 0.15s",
              }}
            >
              {isMuted ? <MicOff size={20} /> : <Mic size={20} />}
            </button>
          )}

          {/* Accept — nur bei ringing */}
          {isIncoming && (
            <button
              onClick={onAccept}
              style={{
                width: 64,
                height: 64,
                borderRadius: "50%",
                background: "#22c55e",
                border: "none",
                color: "#fff",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "0 0 24px rgba(34,197,94,0.4)",
                transition: "all 0.15s",
              }}
            >
              <Phone size={28} />
            </button>
          )}

          {/* Hangup / Reject */}
          <button
            onClick={isIncoming ? (onReject ?? onHangup) : onHangup}
            style={{
              width: isIncoming ? 64 : 56,
              height: isIncoming ? 64 : 56,
              borderRadius: "50%",
              background: "var(--red, #ef4444)",
              border: "none",
              color: "#fff",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 24px rgba(239,68,68,0.3)",
              transition: "all 0.15s",
            }}
          >
            <PhoneOff size={isIncoming ? 28 : 22} />
          </button>
        </div>

        {/* Hint */}
        {isIncoming && (
          <p style={{ fontSize: 11, color: "var(--text-muted, #64748b)", marginTop: 16 }}>
            Annehmen oder Ablehnen
          </p>
        )}
        {isConnected && (
          <p style={{ fontSize: 11, color: "var(--text-muted, #64748b)", marginTop: 16 }}>
            Opus 48 kHz · End-to-End Encrypted
          </p>
        )}
      </div>

      <style>{`
        @keyframes pulse-ring {
          0% { box-shadow: 0 0 0 0 rgba(99,102,241,0.5); }
          50% { box-shadow: 0 0 0 20px rgba(99,102,241,0); }
          100% { box-shadow: 0 0 0 0 rgba(99,102,241,0); }
        }
      `}</style>
    </div>
  );
}