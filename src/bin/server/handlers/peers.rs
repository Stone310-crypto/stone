//! HTTP-Peer and manual-sync handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::master::{AddPeerRequest, PeerInfo, PeerStatus};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

use super::super::auth_middleware::require_admin;
use super::super::state::{save_peers, AppState};
use super::super::sync::pull_from_peer;

/// GET /api/v1/peers (öffentlich)
pub async fn handle_list_peers(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut peers = state.node.get_peers();
    if peers.is_empty() {
        return (StatusCode::OK, axum::Json(peers));
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(_) => return (StatusCode::OK, axum::Json(peers)),
    };

    let now = chrono::Utc::now().timestamp();
    let mut changed = false;

    let mut checks = JoinSet::new();
    for peer in &peers {
        let peer_url = peer.url.clone();
        let health_url = format!("{}/api/v1/health", peer_url.trim_end_matches('/'));
        let client = client.clone();
        checks.spawn(async move {
            let started = Instant::now();
            let is_healthy = match client.get(&health_url).send().await {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            };

            let discovered_peer_id = if is_healthy {
                let info_url = format!("{}/api/v1/p2p/info", peer_url.trim_end_matches('/'));
                match client.get(&info_url).send().await {
                    Ok(resp) if resp.status().is_success() => resp
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|v| v.get("peer_id").and_then(|p| p.as_str()).map(|s| s.to_string()))
                        .filter(|pid| pid.parse::<libp2p::PeerId>().is_ok()),
                    _ => None,
                }
            } else {
                None
            };

            (peer_url, is_healthy, started.elapsed().as_millis(), discovered_peer_id)
        });
    }

    while let Some(result) = checks.join_next().await {
        let Ok((peer_url, is_healthy, latency, discovered_peer_id)) = result else {
            continue;
        };
        let Some(peer) = peers.iter_mut().find(|p| p.url == peer_url) else {
            continue;
        };

        if is_healthy {
            if peer.status != PeerStatus::Healthy {
                peer.status = PeerStatus::Healthy;
                changed = true;
            }
            if peer.last_seen == 0 || now - peer.last_seen > 5 {
                peer.last_seen = now;
                changed = true;
            }
            if peer.latency_ms != Some(latency) {
                peer.latency_ms = Some(latency);
                changed = true;
            }
            if peer.sync_failures != 0 {
                peer.sync_failures = 0;
                changed = true;
            }
            if discovered_peer_id.is_some() && peer.peer_id != discovered_peer_id {
                peer.peer_id = discovered_peer_id;
                changed = true;
            }
        } else if peer.status == PeerStatus::Healthy {
            peer.status = PeerStatus::Unreachable;
            peer.sync_failures = peer.sync_failures.saturating_add(1);
            changed = true;
        }
    }

    if changed {
        state.node.replace_peers(peers.clone());
        save_peers(&peers);
    }

    (StatusCode::OK, axum::Json(peers))
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
        peer_id: req.peer_id.clone(),
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
    pub peer_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

fn normalize_peer_url_for_network(raw_url: &str) -> String {
    let url = raw_url.trim().trim_end_matches('/').to_string();
    let Some((scheme, rest)) = url.split_once("://") else {
        return url;
    };
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host = host_port.split(':').next().unwrap_or(host_port).trim();
    let port = host_port
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    if host.is_empty() {
        return url;
    }

    let default_http = if stone::network::is_mainnet() { 3180 } else { 3080 };
    let normalized_port = if port == 8080 { default_http } else { port };

    if normalized_port == 0 {
        format!("{}://{}", scheme, host)
    } else {
        format!("{}://{}:{}", scheme, host, normalized_port)
    }
}

/// POST /api/v1/peers/register — Öffentlich: Node meldet sich bei uns an.
///
/// Jeder Node kann sich ohne Auth registrieren. Die URL wird normalisiert
/// und validiert (muss http/https sein, kein localhost/127.x).
pub async fn handle_register_peer(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<RegisterPeerRequest>,
) -> impl IntoResponse {
    let url = normalize_peer_url_for_network(&req.url);

    // Optionales PeerId-Feld auf gültiges Format prüfen.
    if let Some(ref peer_id) = req.peer_id {
        if peer_id.parse::<libp2p::PeerId>().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "peer_id ist ungültig"})),
            );
        }
    }

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
            if let (Some(existing_pid), Some(incoming_pid)) = (&existing.peer_id, &req.peer_id) {
                if existing_pid.parse::<libp2p::PeerId>().is_ok() {
                    if existing_pid != incoming_pid {
                        return (
                            StatusCode::CONFLICT,
                            axum::Json(json!({
                                "error": "URL ist bereits mit einer anderen peer_id verknüpft",
                                "existing_peer_id": existing_pid,
                            })),
                        );
                    }
                } else {
                    // Altbestand bereinigen: früher gespeicherte ungültige peer_id (z.B. URL)
                    // durch eine jetzt gültig gelieferte PeerId ersetzen.
                    existing.peer_id = Some(incoming_pid.clone());
                }
            }
            if existing.peer_id.is_none() && req.peer_id.is_some() {
                existing.peer_id = req.peer_id.clone();
            }
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
        peer_id: req.peer_id,
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
