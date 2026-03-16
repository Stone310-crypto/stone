//! HTTP-Peer and manual-sync handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::master_node::{AddPeerRequest, PeerInfo, PeerStatus};

use super::super::auth_middleware::require_admin;
use super::super::state::{save_peers, AppState};
use super::super::sync::pull_from_peer;

/// GET /api/v1/peers (öffentlich)
pub async fn handle_list_peers(
    State(state): State<AppState>,
) -> impl IntoResponse {
    (StatusCode::OK, axum::Json(state.node.get_peers()))
}

/// POST /api/v1/peers
pub async fn handle_add_peer(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AddPeerRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let peer = PeerInfo {
        url: req.url.clone(),
        name: req.name,
        ca: req.ca,
        status: PeerStatus::Unreachable,
        last_seen: 0,
        last_hash: None,
        block_height: 0,
        latency_ms: None,
        sync_failures: 0,
    };

    state.node.upsert_peer(peer);
    let peers = state.node.get_peers();
    save_peers(&peers);

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "ok": true,
            "peers_total": peers.len(),
            "url": req.url,
        })),
    ))
}

/// DELETE /api/v1/peers/:idx
pub async fn handle_remove_peer(
    headers: HeaderMap,
    Path(idx): Path<usize>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let mut peers = state.node.get_peers();
    if idx >= peers.len() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Peer-Index nicht gefunden"})),
        )
            .into_response());
    }
    let removed = peers.remove(idx);
    state.node.replace_peers(peers.clone());
    save_peers(&peers);

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "removed": removed.url,
            "peers_remaining": peers.len(),
        })),
    ))
}

// ─── Peer Registration (public, kein Auth) ───────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterPeerRequest {
    pub url: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// POST /api/v1/peers/register — Öffentlich: Node meldet sich bei uns an.
///
/// Jeder Node kann sich ohne Auth registrieren. Die URL wird normalisiert
/// und validiert (muss http/https sein, kein localhost/127.x).
pub async fn handle_register_peer(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<RegisterPeerRequest>,
) -> impl IntoResponse {
    let url = req.url.trim().trim_end_matches('/').to_string();

    // Validierung: URL muss ein gültiges Schema haben
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "URL muss mit http:// oder https:// beginnen"})),
        );
    }

    // Keine localhost/loopback zulassen
    let host = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .and_then(|s| s.split(':').next())
        .unwrap_or("");
    if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::1" {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Localhost nicht erlaubt"})),
        );
    }

    // Duplikat-Check: Wenn URL schon bekannt, nur last_seen aktualisieren
    {
        let mut peers = state.node.peers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = peers.iter_mut().find(|p| p.url == url) {
            existing.last_seen = chrono::Utc::now().timestamp();
            existing.name = req.name.or_else(|| existing.name.clone());
            let total = peers.len();
            drop(peers);
            let all = state.node.get_peers();
            save_peers(&all);
            return (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "registered": false,
                    "message": "Peer bereits bekannt, last_seen aktualisiert",
                    "peers_total": total,
                })),
            );
        }
    }

    // Neuen Peer anlegen
    let peer = PeerInfo {
        url: url.clone(),
        name: req.name,
        ca: None,
        status: PeerStatus::Healthy, // Optimistisch: wenn er uns erreicht, ist er erreichbar
        last_seen: chrono::Utc::now().timestamp(),
        last_hash: None,
        block_height: 0,
        latency_ms: None,
        sync_failures: 0,
    };

    state.node.upsert_peer(peer);
    let peers = state.node.get_peers();
    save_peers(&peers);

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "ok": true,
            "registered": true,
            "url": url,
            "peers_total": peers.len(),
        })),
    )
}

// ─── Manual sync ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SyncRequest {
    #[serde(default)]
    pub peer_url: Option<String>,
}

/// POST /api/v1/sync – Manuelle Synchronisation
pub async fn handle_sync(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<SyncRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let peers = state.node.get_peers();
    let targets: Vec<String> = if let Some(url) = req.peer_url {
        vec![url]
    } else {
        peers.into_iter().map(|p| p.url).collect()
    };

    if targets.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Keine Peers konfiguriert"})),
        )
            .into_response());
    }

    let node = state.node.clone();
    let api_key = state.api_key.clone();
    tokio::spawn(async move {
        for peer_url in targets {
            pull_from_peer(&node, &peer_url, &api_key).await;
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        axum::Json(json!({"ok": true, "message": "Synchronisation gestartet"})),
    ))
}
