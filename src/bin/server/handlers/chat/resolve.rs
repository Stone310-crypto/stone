//! User-Suche: Lokal + On-Chain + Peer-Fallback.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

use crate::server::auth_middleware::require_user;
use crate::server::state::AppState;

use super::{resolve_local, resolve_from_peers};

/// GET /api/v1/chat/resolve/:identifier — User-ID / Name → Wallet-Adresse auflösen
///
/// Sucht erst lokal + on-chain, dann als Fallback auf allen Peer-Nodes.
pub async fn handle_chat_resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
) -> impl IntoResponse {
    let _user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let mut matches = resolve_local(&identifier, &state);

    // Peer-Fallback: Wenn lokal nichts gefunden, Peer-Nodes fragen
    if matches.is_empty() {
        let peer_results = resolve_from_peers(&identifier, &state).await;
        let known: std::collections::HashSet<String> = matches
            .iter()
            .filter_map(|m| m["wallet"].as_str().map(|s| s.to_string()))
            .collect();
        for r in peer_results {
            let w = r["wallet"].as_str().unwrap_or_default().to_string();
            if !w.is_empty() && !known.contains(&w) {
                matches.push(r);
            }
        }
    }

    if matches.is_empty() {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Kein User gefunden"})),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            axum::Json(json!({
                "ok": true,
                "results": matches,
            })),
        )
            .into_response()
    }
}

/// GET /api/v1/chat/resolve-public/:identifier — Öffentliche User-Suche (kein Auth)
///
/// Wird von Peer-Nodes aufgerufen um User cross-node aufzulösen.
/// Gibt nur lokale + on-chain Ergebnisse zurück (keine Peer-Weiterleitung).
pub async fn handle_chat_resolve_public(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
) -> impl IntoResponse {
    let matches = resolve_local(&identifier, &state);
    if matches.is_empty() {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Kein User gefunden"})),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            axum::Json(json!({
                "ok": true,
                "results": matches,
            })),
        )
            .into_response()
    }
}
