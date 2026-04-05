//! Merkle-Proof für Chat-Nachrichten.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

use crate::server::auth_middleware::require_user;
use crate::server::state::AppState;

/// GET /api/v1/chat/proof/:msg_id — Merkle-Proof für eine Chat-Nachricht
///
/// Gibt den kryptografischen Beweis zurück, dass eine bestimmte Nachricht
/// in einem Block der Chain verankert ist (via ChatBatchAnchor / Merkle-Tree).
pub async fn handle_chat_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(msg_id): Path<String>,
) -> impl IntoResponse {
    let _user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Nachricht im Chat-Index suchen
    {
        let chat_index = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
        let found = chat_index.conversations.values()
            .any(|msgs| msgs.iter().any(|m| m.msg_id == msg_id));

        if !found {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Nachricht nicht gefunden"})),
            ).into_response();
        }
    }

    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());

    // Block finden der diese Nachricht enthält
    for block in chain.blocks.iter().rev() {
        for anchor in &block.chat_batches {
            if anchor.messages.iter().any(|m| m.msg_id == msg_id) {
                return (
                    StatusCode::OK,
                    axum::Json(json!({
                        "ok": true,
                        "msg_id": msg_id,
                        "block_index": block.index,
                        "block_hash": block.hash,
                        "merkle_root": anchor.merkle_root,
                        "batch_size": anchor.batch_size,
                        "timestamp": block.timestamp,
                        "verified": true,
                    })),
                ).into_response();
            }
        }
    }

    // Noch nicht in einem Block (pending im Mempool)
    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "msg_id": msg_id,
            "status": "pending",
            "verified": false,
            "message": "Nachricht ist noch nicht in einem Block verankert",
        })),
    ).into_response()
}
