// ═══ useWebRTC — Voice/Video Calling Hook ═══
//
// WebRTC mit Opus-Codec (16-32 kbps wideband), STUN/TURN für NAT-Traversal,
// und server-seitigem Audio-Relay via WebSocket.
//
// Qualitätssicherung:
// - Opus codec: Fraunhofer IIS, 6-510 kbps, 48 kHz sampling
// - STUN: Google STUN (stun.l.google.com:19302) für P2P im LAN
// - TURN: Optional, für NAT-Traversal (eigener TURN-Server nötig)
// - Audio Constraints: noiseSuppression, echoCancellation, autoGainControl
// - JitterBuffer: built-in WebRTC (NetEQ)
// - Paketverlust-Kompensation: Opus FEC (Forward Error Correction)

import { useState, useRef, useCallback, useEffect } from "react";

export type CallState =
  | "idle"
  | "calling"      // Wir rufen an
  | "ringing"      // Wir werden angerufen
  | "connected"
  | "ended";

export interface UseWebRTCOptions {
  localWallet: string;
  apiKey: string;
  nodeUrl: string;
  onRemoteStream?: (stream: MediaStream) => void;
  onCallEnded?: () => void;
}

export function useWebRTC({
  localWallet,
  apiKey,
  nodeUrl,
  onRemoteStream,
  onCallEnded,
}: UseWebRTCOptions) {
  const [callState, setCallState] = useState<CallState>("idle");
  const [callDuration, setCallDuration] = useState(0);
  const [remoteName, setRemoteName] = useState("");
  const [remoteWallet, setRemoteWallet] = useState("");
  const [isMuted, setIsMuted] = useState(false);

  const pcRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const callIdRef = useRef<string>("");
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // STUN/TURN config — Google STUN + Coturn TURN für NAT-Traversal
  // Priorität: P2P (STUN) → TURN (Relay)
  const iceServers: RTCConfiguration = {
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" },
      {
        urls: "turn:127.0.0.1:3478",
        username: "stone",
        credential: "turn_stone_testnet_2024",
      },
      // Optional: Coturn auf dem VPS (externe IP statt localhost)
      {
        urls: "turn:212.227.54.241:3478",
        username: "stone",
        credential: "turn_stone_testnet_2024",
      },
    ],
    iceTransportPolicy: "all", // "relay" nur wenn TURN erzwingen will
  };

  // Cleanup
  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      hangup();
    };
  }, []);

  // ── Local Media ──────────────────────────────────────────────────
  const startLocalStream = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          sampleRate: 48000,
          channelCount: 1,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        },
      });
      localStreamRef.current = stream;
      return stream;
    } catch (e) {
      console.error("[WebRTC] Mikrofon-Zugriff:", e);
      throw new Error("Mikrofon-Zugriff verweigert oder nicht verfügbar");
    }
  }, []);

  // ── WebSocket Audio-Relay ────────────────────────────────────────
  const connectAudioRelay = useCallback((callId: string) => {
    const baseUrl = nodeUrl.replace(/^http/, "ws");
    const ws = new WebSocket(
      `${baseUrl}/api/v1/call/audio/${callId}?token=${encodeURIComponent(apiKey)}`
    );
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
      console.log("[WebRTC] Audio-Relay verbunden:", callId);
    };

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        // Audio-Frame vom Remote-Peer empfangen
        // (wird von WebRTC selbst verarbeitet, nicht über WS)
      }
    };

    ws.onerror = (e) => console.error("[WebRTC] Relay-Fehler:", e);
    ws.onclose = () => console.log("[WebRTC] Relay geschlossen");
    wsRef.current = ws;
  }, [nodeUrl, apiKey]);

  // ── PeerConnection Setup ──────────────────────────────────────────
  const createPeerConnection = useCallback((stream: MediaStream) => {
    const pc = new RTCPeerConnection(iceServers);

    // Lokalen Audio-Track hinzufügen
    stream.getTracks().forEach((track) => pc.addTrack(track, stream));

    // Remote-Stream empfangen
    pc.ontrack = (event) => {
      if (event.streams?.[0]) {
        onRemoteStream?.(event.streams[0]);
      }
    };

    // ICE Candidates → Signaling-Server senden
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        sendSignal("ice_candidate", JSON.stringify(event.candidate));
      }
    };

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "failed" || pc.connectionState === "disconnected") {
        hangup();
      }
    };

    pcRef.current = pc;
    return pc;
  }, []);

  // ── Signaling ────────────────────────────────────────────────────
  const sendSignal = useCallback(async (
    signalType: string,
    payload: string
  ) => {
    try {
      const nonce = btoa(
        String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12)))
      );
      await fetch(`${nodeUrl}/api/v1/call/signal`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
        },
        body: JSON.stringify({
          call_id: callIdRef.current,
          signal_type: signalType,
          to_wallet: remoteWallet,
          payload,
          nonce,
        }),
      });
    } catch (e) {
      console.error("[WebRTC] Signal senden fehlgeschlagen:", e);
    }
  }, [nodeUrl, apiKey, remoteWallet]);

  // ── Call starten (Anrufer) ───────────────────────────────────────
  const startCall = useCallback(async (toWallet: string, toName: string) => {
    // ═══ Sofortiges visuelles Feedback ═══
    setCallState("calling");
    setRemoteName(toName);
    setRemoteWallet(toWallet);
    const callId = `${localWallet.slice(0, 8)}-${Date.now()}`;
    callIdRef.current = callId;

    try {
      const stream = await startLocalStream();
      const pc = createPeerConnection(stream);
      connectAudioRelay(callId);

      // SDP-Offer erstellen
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      // Offer per Signaling senden
      await sendSignal("offer", JSON.stringify(offer));

      // Timer starten
      timerRef.current = setInterval(() => {
        setCallDuration((d) => d + 1);
      }, 1000);
    } catch (e: any) {
      console.error("[WebRTC] Anruf starten:", e);
      // ═══ Fehler unterscheiden ═══
      if (e?.message?.includes("Mikrofon") || e?.name === "NotAllowedError") {
        alert("Mikrofon-Zugriff verweigert. Bitte in den System-Einstellungen das Mikrofon für Stone freigeben.");
      } else if (e?.message?.includes("not supported") || e?.name === "TypeError") {
        alert("Anrufe werden in Tauri/Desktop noch nicht unterstützt. Bitte im Browser testen.");
      } else {
        alert(`Anruf konnte nicht gestartet werden: ${e?.message || e}`);
      }
      // Trotzdem calling zeigen, damit der Nutzer Feedback hat, dann nach 2s zurücksetzen
      setTimeout(() => setCallState("idle"), 3000);
    }
  }, [startLocalStream, createPeerConnection, connectAudioRelay, sendSignal]);

  // ── Call annehmen (Angerufener) ─────────────────────────────────
  const acceptCall = useCallback(async (
    callId: string,
    fromWallet: string,
    fromName: string
  ) => {
    try {
      const stream = await startLocalStream();
      const pc = createPeerConnection(stream);
      callIdRef.current = callId;
      setRemoteName(fromName);
      setRemoteWallet(fromWallet);
      setCallState("connected");

      connectAudioRelay(callId);

      // SDP-Answer erstellen
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      await sendSignal("answer", JSON.stringify(answer));

      timerRef.current = setInterval(() => {
        setCallDuration((d) => d + 1);
      }, 1000);
    } catch (e) {
      console.error("[WebRTC] Anruf annehmen:", e);
      setCallState("idle");
    }
  }, [startLocalStream, createPeerConnection, connectAudioRelay, sendSignal]);

  // ── Eingehender Anruf (wird vom Signaling-Event getriggert) ──────
  const incomingCall = useCallback((fromWallet: string, fromName: string, callId: string) => {
    setCallState("ringing");
    setRemoteWallet(fromWallet);
    setRemoteName(fromName);
    callIdRef.current = callId;
  }, []);

  // ── Auflegen ────────────────────────────────────────────────────
  const hangup = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (pcRef.current) {
      pcRef.current.close();
      pcRef.current = null;
    }
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((t) => t.stop());
      localStreamRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (callState !== "idle" && callState !== "ended") {
      sendSignal("hangup", "{}").catch(() => {});
    }
    setCallState("ended");
    setCallDuration(0);
    onCallEnded?.();
    // Auto-reset nach 2s
    setTimeout(() => {
      setCallState("idle");
      setRemoteName("");
      setRemoteWallet("");
    }, 2000);
  }, [callState, sendSignal, onCallEnded]);

  // ── Mute ────────────────────────────────────────────────────────
  const toggleMute = useCallback(() => {
    if (localStreamRef.current) {
      const audioTrack = localStreamRef.current.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsMuted(!audioTrack.enabled);
      }
    }
  }, []);

  // ── SDP verarbeiten (vom Signaling-Server) ─────────────────────
  const handleRemoteSDP = useCallback(async (sdpType: string, sdpPayload: string) => {
    const pc = pcRef.current;
    if (!pc) return;

    try {
      const desc = JSON.parse(sdpPayload) as RTCSessionDescriptionInit;
      await pc.setRemoteDescription(new RTCSessionDescription(desc));

      if (sdpType === "offer") {
        // SDP-Offer empfangen → Answer senden
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await sendSignal("answer", JSON.stringify(answer));
      }

      setCallState("connected");
    } catch (e) {
      console.error("[WebRTC] SDP verarbeiten:", e);
    }
  }, [sendSignal]);

  // ── ICE Candidate verarbeiten ──────────────────────────────────
  const handleRemoteICE = useCallback(async (icePayload: string) => {
    const pc = pcRef.current;
    if (!pc) return;

    try {
      const candidate = JSON.parse(icePayload) as RTCIceCandidateInit;
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (e) {
      console.error("[WebRTC] ICE verarbeiten:", e);
    }
  }, []);

  // Format duration as MM:SS
  const formattedDuration = `${Math.floor(callDuration / 60)
    .toString()
    .padStart(2, "0")}:${(callDuration % 60).toString().padStart(2, "0")}`;

  return {
    callState,
    callDuration,
    formattedDuration,
    remoteName,
    remoteWallet,
    isMuted,
    startCall,
    acceptCall,
    incomingCall,
    hangup,
    toggleMute,
    handleRemoteSDP,
    handleRemoteICE,
    callId: callIdRef.current,
    sendSignal,
  };
}
