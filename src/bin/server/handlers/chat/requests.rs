//! Kontaktanfragen (Friend Request System): Senden, Auflisten, Akzeptieren, Ablehnen.

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
pub struct SendContactRequestBody {
    /// Empfänger: Wallet-Adresse, User-ID oder Name
    #[serde(alias = "identifier")]
    pub to: String,
}

/// POST /api/v1/chat/contacts/request — Kontaktanfrage senden
pub async fn handle_send_contact_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<SendContactRequestBody>,
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

    // Empfänger auflösen
    let (to_wallet, to_user_id, to_name) = {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        let identifier = req.to.trim();

        if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
            let info = users.iter()
                .find(|u| u.wallet_address == identifier)
                .map(|u| (u.id.clone(), u.name.clone()));
            match info {
                Some((uid, name)) => (identifier.to_string(), uid, name),
                None => return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({"ok": false, "error": "User nicht gefunden"})),
                ).into_response(),
            }
        } else if let Some(u) = users.iter().find(|u| u.id == identifier) {
            (u.wallet_address.clone(), u.id.clone(), u.name.clone())
        } else {
            let lower = identifier.to_lowercase();
            match users.iter().find(|u| !u.wallet_address.is_empty() && u.name.to_lowercase() == lower) {
                Some(u) => (u.wallet_address.clone(), u.id.clone(), u.name.clone()),
                None => return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({"ok": false, "error": "User nicht gefunden"})),
                ).into_response(),
            }
        }
    };

    if to_wallet == user.wallet_address {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Du kannst dir nicht selbst eine Anfrage senden"})),
        ).into_response();
    }

    // Bereits Kontakt?
    {
        let contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
        if contacts.is_contact(&user.wallet_address, &to_wallet) {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({"ok": false, "error": "Bereits in deiner Kontaktliste"})),
            ).into_response();
        }
    }

    let mut store = state.contact_requests.lock().unwrap_or_else(|e| e.into_inner());
    match store.add_request(
        &user.wallet_address, &user.name, &user.id,
        &to_wallet, &to_name, &to_user_id,
    ) {
        Ok(req) => {
            let req_json = json!({
                "id": req.id,
                "from_wallet": req.from_wallet,
                "from_name": req.from_name,
                "to_wallet": req.to_wallet,
                "to_name": req.to_name,
                "status": "pending",
                "created_at": req.created_at,
            });
            stone::chat::save_contact_requests(&store);
            (
                StatusCode::CREATED,
                axum::Json(json!({"ok": true, "request": req_json})),
            ).into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            axum::Json(json!({"ok": false, "error": e})),
        ).into_response(),
    }
}

/// GET /api/v1/chat/contacts/requests — Eingehende & ausgehende Kontaktanfragen
pub async fn handle_list_contact_requests(
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

    let store = state.contact_requests.lock().unwrap_or_else(|e| e.into_inner());
    let incoming: Vec<_> = store.incoming_for(&user.wallet_address).iter().map(|r| json!({
        "id": r.id,
        "from_wallet": r.from_wallet,
        "from_name": r.from_name,
        "from_user_id": r.from_user_id,
        "status": "pending",
        "created_at": r.created_at,
    })).collect();
    let outgoing: Vec<_> = store.outgoing_for(&user.wallet_address).iter().map(|r| json!({
        "id": r.id,
        "to_wallet": r.to_wallet,
        "to_name": r.to_name,
        "to_user_id": r.to_user_id,
        "status": "pending",
        "created_at": r.created_at,
    })).collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "incoming": incoming,
            "outgoing": outgoing,
        })),
    ).into_response()
}

/// POST /api/v1/chat/contacts/requests/:id/accept — Kontaktanfrage akzeptieren
pub async fn handle_accept_contact_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
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

    let (from_wallet, to_wallet, from_name, to_name) = {
        let mut store = state.contact_requests.lock().unwrap_or_else(|e| e.into_inner());
        match store.accept(&request_id, &user.wallet_address) {
            Ok((fw, tw)) => {
                let from_name = store.find(&request_id)
                    .map(|r| r.from_name.clone()).unwrap_or_default();
                stone::chat::save_contact_requests(&store);
                (fw, tw, from_name, user.name.clone())
            }
            Err(e) => return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": e})),
            ).into_response(),
        }
    };

    // Beide Seiten automatisch als Kontakt hinzufügen
    let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    contacts.add_contact(&to_wallet, &from_wallet, "", &from_name);
    contacts.add_contact(&from_wallet, &to_wallet, "", &to_name);
    stone::chat::save_contacts(&contacts);

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "message": format!("Kontaktanfrage akzeptiert – {} wurde hinzugefügt", from_name),
        })),
    ).into_response()
}

/// POST /api/v1/chat/contacts/requests/:id/decline — Kontaktanfrage ablehnen
pub async fn handle_decline_contact_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
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

    let mut store = state.contact_requests.lock().unwrap_or_else(|e| e.into_inner());
    match store.decline(&request_id, &user.wallet_address) {
        Ok(()) => {
            stone::chat::save_contact_requests(&store);
            (
                StatusCode::OK,
                axum::Json(json!({"ok": true, "message": "Kontaktanfrage abgelehnt"})),
            ).into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": e})),
        ).into_response(),
    }
}
