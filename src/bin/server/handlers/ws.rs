//! WebSocket event-stream handler.
//!
//! SECURITY: Authentifizierung via `token` Query-Parameter erforderlich.
//! Unauthentifizierte Verbindungen werden mit 401 abgelehnt.
//! Origin-Header wird validiert wenn STONE_CORS_ORIGINS gesetzt ist.

use axum::{
    extract::{Query, State},
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::HeaderMap,
    response::IntoResponse,
};
use std::{sync::Arc, sync::atomic::Ordering};
use stone::master::{MasterNodeState, NodeEvent};
use tokio::sync::broadcast;

use super::super::auth_middleware::{resolve_user_by_key, resolve_user_by_session_token};
use super::super::state::AppState;

/// Maximale gleichzeitige WebSocket-Verbindungen
const MAX_WS_CONNECTIONS: u64 = 200;

#[derive(serde::Deserialize)]
pub struct WsQuery {
    /// Auth-Token (API-Key oder Session-Token)
    pub token: Option<String>,
}

/// GET /ws?token=... – WebSocket-Verbindung für Live-Events
pub async fn handle_websocket(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // SECURITY: Origin-Prüfung wenn STONE_CORS_ORIGINS konfiguriert
    if let Ok(allowed) = std::env::var("STONE_CORS_ORIGINS") {
        let origins: Vec<String> = allowed.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if !origins.is_empty() {
            let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
            if !origin.is_empty() && !origins.iter().any(|o| o == origin) {
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({"error": "Origin nicht erlaubt"})),
                ).into_response();
            }
        }
    }

    // SECURITY: Authentifizierung erforderlich
    let token = query.token.as_deref()
        .or_else(|| {
            // Fallback: Authorization-Header
            headers.get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
        })
        .or_else(|| {
            // Fallback: x-api-key Header
            headers.get("x-api-key").and_then(|v| v.to_str().ok())
        });

    let token = match token {
        Some(t) => t,
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "WebSocket erfordert Authentifizierung (?token=...)"})),
            ).into_response();
        }
    };

    // Token gegen User-DB validieren
    let is_valid = resolve_user_by_key(token, &state.users, &state.api_key, &state.admin_key).is_some()
        || resolve_user_by_session_token(token, &state.users, &state.api_key).is_some();

    if !is_valid {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Ungültiges Token"})),
        ).into_response();
    }

    // SECURITY: Max-Connections prüfen
    let current = state.node.metrics.ws_connections.load(Ordering::Relaxed);
    if current >= MAX_WS_CONNECTIONS {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "Max WebSocket-Verbindungen erreicht"})),
        ).into_response();
    }

    state
        .node
        .metrics
        .ws_connections
        .fetch_add(1, Ordering::Relaxed);
    let events = state.node.events.subscribe();
    let node = state.node.clone();
    ws.on_upgrade(move |socket| websocket_handler(socket, events, node))
        .into_response()
}

pub async fn websocket_handler(
    mut socket: WebSocket,
    mut events: broadcast::Receiver<NodeEvent>,
    node: Arc<MasterNodeState>,
) {
    let init = {
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let peers = node.peers.read().unwrap_or_else(|e| e.into_inner());
        let peers_healthy = peers.iter().filter(|p| p.is_healthy()).count();
        let documents_total = chain.list_all_documents().len() as u64;
        let now = chrono::Utc::now().timestamp();
        NodeEvent::InitialState {
            node_id: node.node_id.clone(),
            role: format!("{:?}", node.role),
            block_height: chain.blocks.len() as u64,
            latest_hash: chain.latest_hash.clone(),
            documents_total,
            peers_total: peers.len(),
            peers_healthy,
            requests_total: node.metrics.requests_total.load(Ordering::Relaxed),
            ws_connections: node.metrics.ws_connections.load(Ordering::Relaxed),
            uptime_seconds: now - node.started_at,
        }
    };
    if let Ok(msg) = serde_json::to_string(&init) {
        let _ = socket.send(Message::Text(msg.into())).await;
    }

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(ev) => {
                        if let Ok(msg) = serde_json::to_string(&ev) {
                            if socket.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    node.metrics.ws_connections.fetch_sub(1, Ordering::Relaxed);
}
