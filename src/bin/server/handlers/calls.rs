//! Call-Signaling Handler – WebRTC-Signaling über den Stone Message Pool.
//!
//! Signaling-Nachrichten (Offer, Answer, ICE-Candidate, Hangup) werden
//! ephemeral gespeichert (TTL 60s) und NICHT in Blöcke gemined.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::chat::{CallSignal, SignalType};

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendSignalRequest {
    pub call_id: String,
    pub signal_type: String,
    pub to_wallet: String,
    /// Verschlüsselter SDP/ICE-Payload (AES-256-GCM, base64)
    pub payload: String,
    /// AES-256-GCM Nonce (base64)
    pub nonce: String,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/call/signal — Signaling-Nachricht senden
pub async fn handle_send_signal(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<SendSignalRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Pflichtfelder prüfen
    if req.call_id.is_empty() || req.to_wallet.is_empty() || req.payload.is_empty() || req.nonce.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "call_id, to_wallet, payload und nonce sind Pflichtfelder"})),
        ).into_response();
    }

    let signal_type = match req.signal_type.to_lowercase().as_str() {
        "offer" => SignalType::Offer,
        "answer" => SignalType::Answer,
        "ice_candidate" | "icecandidate" | "ice" => SignalType::IceCandidate,
        "hangup" => SignalType::Hangup,
        "busy" => SignalType::Busy,
        "ringing" => SignalType::Ringing,
        _ => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Ungültiger signal_type. Erlaubt: offer, answer, ice_candidate, hangup, busy, ringing"})),
        ).into_response(),
    };

    let now = chrono::Utc::now().timestamp();

    let signal = CallSignal {
        call_id: req.call_id.clone(),
        signal_type: signal_type.clone(),
        from_wallet: user.wallet_address.clone(),
        to_wallet: req.to_wallet.clone(),
        payload: req.payload,
        nonce: req.nonce,
        timestamp: now,
    };

    // GC bei jeder Nachricht
    state.call_signals.gc();
    state.call_signals.add_signal(signal);

    // WebSocket-Push ans Ziel
    state.node.events.publish(stone::master::NodeEvent::CallSignalReceived {
        call_id: req.call_id.clone(),
        signal_type: format!("{:?}", signal_type).to_lowercase(),
        from_wallet: user.wallet_address.clone(),
        to_wallet: req.to_wallet.clone(),
        timestamp: now,
    });

    // FCM-Push bei eingehendem Anruf (nur beim Offer)
    if matches!(signal_type, SignalType::Offer) {
        let push_store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let fcm = state.fcm_client.clone();
        let to_wallet = req.to_wallet.clone();
        let from_wallet = user.wallet_address.clone();
        let from_name = user.name.clone();
        let call_id = req.call_id.clone();
        tokio::spawn(async move {
            fcm.notify_wallet_incoming_call(&push_store, &to_wallet, &from_wallet, &from_name, &call_id).await;
        });
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "call_id": req.call_id,
            "signal_type": req.signal_type,
        })),
    ).into_response()
}

/// GET /api/v1/call/signal/:peer_wallet — Pending Signale für mich abrufen (drain)
pub async fn handle_get_signals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(peer_wallet): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Nur eigene Signale abrufen
    if peer_wallet != user.wallet_address {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"ok": false, "error": "Nur eigene Signale abrufbar"})),
        ).into_response();
    }

    let signals = state.call_signals.drain_for(&user.wallet_address);

    let data: Vec<_> = signals.iter().map(|s| json!({
        "call_id": s.call_id,
        "signal_type": s.signal_type,
        "from_wallet": s.from_wallet,
        "to_wallet": s.to_wallet,
        "payload": s.payload,
        "nonce": s.nonce,
        "timestamp": s.timestamp,
    })).collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "signals": data,
            "count": data.len(),
        })),
    ).into_response()
}
