//! Kontakte: Hinzufügen, Auflisten, Entfernen.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::server::auth_middleware::require_user;
use crate::server::state::AppState;

#[derive(Deserialize)]
pub struct AddContactRequest {
    /// Wallet-Adresse oder User-ID oder Name des Kontakts
    pub identifier: String,
    /// Optionaler Spitzname
    #[serde(default)]
    pub nickname: Option<String>,
}

/// POST /api/v1/chat/contacts — Kontakt hinzufügen
pub async fn handle_add_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<AddContactRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if user.wallet_address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Kein Wallet registriert"})),
        )
            .into_response();
    }

    // Kontakt auflösen (Wallet, User-ID oder Name)
    let (contact_wallet, contact_user_id, contact_name) = {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        let identifier = req.identifier.trim();

        // 1) Direkte Wallet-Adresse (64 hex)
        if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
            let info = users.iter()
                .find(|u| u.wallet_address == identifier)
                .map(|u| (u.id.clone(), u.name.clone()));
            match info {
                Some((uid, name)) => (identifier.to_string(), uid, name),
                None => {
                    // Im Ledger nachschauen
                    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                    let name = ledger.account_name(identifier)
                        .unwrap_or("Unbekannt").to_string();
                    (identifier.to_string(), String::new(), name)
                }
            }
        }
        // 2) User-ID
        else if let Some(u) = users.iter().find(|u| u.id == identifier) {
            if u.wallet_address.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"ok": false, "error": "User hat kein Wallet"})),
                ).into_response();
            }
            (u.wallet_address.clone(), u.id.clone(), u.name.clone())
        }
        // 3) Name-Suche (exakt, case-insensitive)
        else {
            let lower = identifier.to_lowercase();
            let found = users.iter()
                .find(|u| !u.wallet_address.is_empty() && u.name.to_lowercase() == lower);
            match found {
                Some(u) => (u.wallet_address.clone(), u.id.clone(), u.name.clone()),
                None => {
                    // Fallback: On-Chain Ledger
                    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                    let chain_match = ledger.all_registered_accounts().iter()
                        .find(|(_, name)| name.to_lowercase() == lower)
                        .map(|(w, n)| (w.clone(), n.clone()));
                    match chain_match {
                        Some((wallet, name)) => (wallet, String::new(), name),
                        None => return (
                            StatusCode::NOT_FOUND,
                            axum::Json(json!({"ok": false, "error": "Kontakt nicht gefunden"})),
                        ).into_response(),
                    }
                }
            }
        }
    };

    if contact_wallet == user.wallet_address {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Du kannst dich nicht selbst hinzufügen"})),
        ).into_response();
    }

    let nickname = req.nickname.unwrap_or_else(|| contact_name.clone());

    let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    if contacts.add_contact(&user.wallet_address, &contact_wallet, &contact_user_id, &nickname) {
        stone::chat::save_contacts(&contacts);
        (
            StatusCode::CREATED,
            axum::Json(json!({
                "ok": true,
                "contact": {
                    "wallet": contact_wallet,
                    "user_id": contact_user_id,
                    "nickname": nickname,
                    "name": contact_name,
                },
                "message": format!("{} wurde zu deinen Kontakten hinzugefügt", contact_name),
            })),
        ).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            axum::Json(json!({"ok": false, "error": "Kontakt bereits vorhanden"})),
        ).into_response()
    }
}

/// GET /api/v1/chat/contacts — Kontaktliste abrufen
pub async fn handle_list_contacts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if user.wallet_address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Kein Wallet registriert"})),
        ).into_response();
    }

    let contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    let my_contacts = contacts.get_contacts(&user.wallet_address);

    // Kontakte mit aktuellen User-Daten anreichern
    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let enriched: Vec<_> = my_contacts.iter().map(|c| {
        let current_name = users.iter()
            .find(|u| u.wallet_address == c.wallet)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| {
                let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                ledger.account_name(&c.wallet)
                    .unwrap_or("Unbekannt").to_string()
            });
        json!({
            "wallet": c.wallet,
            "user_id": c.user_id,
            "nickname": c.nickname,
            "name": current_name,
            "added_at": c.added_at,
            "is_contact": true,
        })
    }).collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "contacts": enriched,
            "count": enriched.len(),
        })),
    ).into_response()
}

/// DELETE /api/v1/chat/contacts/:wallet — Kontakt entfernen
pub async fn handle_remove_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(contact_wallet): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if user.wallet_address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Kein Wallet registriert"})),
        ).into_response();
    }

    let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    if contacts.remove_contact(&user.wallet_address, &contact_wallet) {
        stone::chat::save_contacts(&contacts);
        (
            StatusCode::OK,
            axum::Json(json!({"ok": true, "message": "Kontakt entfernt"})),
        ).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Kontakt nicht gefunden"})),
        ).into_response()
    }
}
