//! Push-Notification Endpoints — Token-Registrierung + Status.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::push::{Platform, hash_wallet, save_push_tokens};

use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterPushReq {
    /// SHA256 der Wallet-Adresse (oder Klartext → wird serverseitig gehasht)
    pub wallet: String,
    /// FCM-Token vom Android-Gerät
    pub fcm_token: String,
    /// Plattform: "android" oder "ios"
    #[serde(default = "default_platform")]
    pub platform: Platform,
}

fn default_platform() -> Platform { Platform::Android }

#[derive(Deserialize)]
pub struct UnregisterPushReq {
    pub wallet: String,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

/// POST /api/v1/push/register — FCM-Token registrieren
pub async fn handle_push_register(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<RegisterPushReq>,
) -> impl IntoResponse {
    let wallet = req.wallet.trim().to_string();
    if wallet.is_empty() || req.fcm_token.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false,
            "error": "wallet und fcm_token dürfen nicht leer sein",
        })))
        .into_response();
    }

    // FCM-Token Grundvalidierung (min. 100 Zeichen, typisch ~150-250)
    let fcm = req.fcm_token.trim();
    if fcm.len() < 50 || fcm.len() > 500 {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false,
            "error": "Ungültiger FCM-Token",
        })))
        .into_response();
    }

    let wallet_hash = hash_wallet(&wallet);

    let mut store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner());
    store.register(wallet_hash.clone(), fcm.to_string(), req.platform);
    save_push_tokens(&store);

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "wallet_hash": wallet_hash,
        "registered_tokens": store.token_count(),
    })))
    .into_response()
}

/// POST /api/v1/push/unregister — FCM-Token entfernen
pub async fn handle_push_unregister(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<UnregisterPushReq>,
) -> impl IntoResponse {
    let wallet = req.wallet.trim().to_string();
    if wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "wallet darf nicht leer sein",
        })))
        .into_response();
    }

    let wallet_hash = hash_wallet(&wallet);
    let mut store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner());
    let removed = store.unregister(&wallet_hash);
    save_push_tokens(&store);

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "removed": removed,
    })))
    .into_response()
}

/// GET /api/v1/push/status — Push-Status abfragen (für Debugging)
pub async fn handle_push_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner());
    let fcm_configured = state.fcm_client.is_configured();

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "fcm_configured": fcm_configured,
        "registered_tokens": store.token_count(),
    })))
    .into_response()
}

/// POST /api/v1/push/test — Test-Push an alle registrierten Geräte senden
pub async fn handle_push_test(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let fcm = state.fcm_client.clone();

    if !fcm.is_configured() {
        return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({
            "ok": false,
            "error": "FCM nicht konfiguriert",
        }))).into_response();
    }

    if store.token_count() == 0 {
        return (StatusCode::OK, axum::Json(json!({
            "ok": true,
            "sent": 0,
            "message": "Keine registrierten Tokens",
        }))).into_response();
    }

    let sent = fcm.broadcast_with_body(
        &store,
        &stone::push::PushType::Announcement,
        "Test-Push vom Server",
    ).await;

    println!("[push] 🧪 Test-Push: {sent}/{} Geräte erreicht", store.token_count());

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "sent": sent,
        "total_tokens": store.token_count(),
    }))).into_response()
}
