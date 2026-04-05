//! Admin: System-Nachrichten an User senden.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::server::auth_middleware::require_admin;
use crate::server::state::AppState;

use super::resolve_recipient;

#[derive(Deserialize)]
pub struct SystemMessageRequest {
    /// Empfänger: User-ID oder Wallet-Adresse
    pub to: String,
    /// Klartext-Nachricht
    pub message: String,
}

/// POST /api/v1/admin/system-message — System-Nachricht senden (Admin only)
pub async fn handle_system_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<SystemMessageRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&headers, &state) {
        return e.into_response();
    }

    let message = req.message.trim().to_string();
    let to = req.to.trim().to_string();
    if message.is_empty() || to.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "to und message sind Pflichtfelder"})),
        ).into_response();
    }

    // Empfänger-Wallet auflösen
    let to_wallet = resolve_recipient(&to, &state);
    let to_wallet = match to_wallet {
        Some(w) => w,
        None => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Empfänger nicht gefunden"})),
            ).into_response();
        }
    };

    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Klartext als base64 speichern
    let content_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        message.as_bytes(),
    );

    let entry = stone::chat::ChatEntry {
        msg_id: msg_id.clone(),
        from_wallet: "system:stoneteam".to_string(),
        to_wallet: to_wallet.clone(),
        from_user_id: "system".to_string(),
        from_name: "StoneTeam".to_string(),
        encrypted_content: content_b64,
        nonce: String::new(),
        content_hash: String::new(),
        timestamp: now,
        block_index: 0,
        tx_id: String::new(),
    };

    // In Chat-Index einfügen
    {
        let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
        idx.add_message(entry);
        stone::chat::save_chat_index(&idx);
    }

    println!("[system-msg] ✉ Nachricht an {} gesendet: {}",
        &to_wallet[..12.min(to_wallet.len())], &message[..50.min(message.len())]);

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "msg_id": msg_id,
            "to_wallet": to_wallet,
        })),
    ).into_response()
}
