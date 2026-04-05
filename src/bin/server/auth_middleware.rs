//! API-Key & Session-Token authentication helpers.
//! Supports both `x-api-key` header (legacy) and `Authorization: Bearer <token>` (challenge-response).

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use stone::auth::{validate_session_token, User};

use super::state::AppState;

/// Constant-time string comparison to prevent timing attacks on API key checks.
/// Leaks only the string lengths (not content).
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    // Akzeptiere sowohl "x-api-key" (Legacy) als auch "X-Admin-Key" (Mac App)
    headers
        .get("x-api-key")
        .or_else(|| headers.get("x-admin-key"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Extrahiert einen Bearer-Token aus dem `Authorization`-Header.
/// Format: `Authorization: Bearer <session_token>`
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
        .map(|s| s.trim().to_string())
}

pub fn resolve_user_by_key(
    key: &str,
    users: &Arc<Mutex<Vec<User>>>,
    api_key: &str,
    admin_key: &str,
) -> Option<User> {
    // Prüfe ob der Key dem API-Key ODER dem Admin-Key entspricht
    if constant_time_eq(key, api_key) || constant_time_eq(key, admin_key) {
        return Some(User {
            id: "admin".into(),
            name: "admin".into(),
            api_key: key.to_string(),
            phrase_hash: String::new(),
            quota_bytes: u64::MAX,
            wallet_address: String::new(),
            account_type: "private".into(),
            org_id: String::new(),
            org_role: String::new(),
        });
    }
    let guard = users.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().find(|u| constant_time_eq(&u.api_key, key)).cloned()
}

/// Löst einen User anhand eines Session-Tokens auf (Challenge-Response Auth).
pub fn resolve_user_by_session_token(
    token: &str,
    users: &Arc<Mutex<Vec<User>>>,
    cluster_key: &str,
) -> Option<User> {
    let claims = validate_session_token(token, cluster_key)?;
    let guard = users.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().find(|u| u.wallet_address == claims.wallet_address).cloned()
}

pub fn require_user(headers: &HeaderMap, state: &AppState) -> Result<User, Response> {
    // 1. Versuche x-api-key (Legacy/Admin)
    if let Some(key) = extract_api_key(headers) {
        if let Some(user) = resolve_user_by_key(&key, &state.users, &state.api_key, &state.admin_key) {
            return Ok(user);
        }
    }

    

    // 2. Versuche Authorization: Bearer <session_token> (Challenge-Response)
    if let Some(token) = extract_bearer_token(headers) {
        if let Some(user) = resolve_user_by_session_token(&token, &state.users, &state.api_key) {            return Ok(user);
        }
        return Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Session-Token ungültig oder abgelaufen"})),
        )
            .into_response());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "Authentifizierung erforderlich (x-api-key Header oder Authorization: Bearer Token)"})),
    )
        .into_response())
}

pub fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<(), Response> {
    // Akzeptiere x-api-key, x-admin-key ODER x-node-secret Header
    let key = extract_api_key(headers)
        .or_else(|| headers.get("x-node-secret")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string()))
        .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    // Admin-Key, normaler API-Key (Node-Besitzer), oder NODE_SECRET (inter-node)
    let node_secret = std::env::var("NODE_SECRET").unwrap_or_default();
    if constant_time_eq(&key, state.admin_key.as_str())
        || constant_time_eq(&key, state.api_key.as_str())
        || (!node_secret.is_empty() && constant_time_eq(&key, &node_secret))
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Rechte erforderlich – verwende den API-Key aus token.bin oder den Admin-Key"})),
        )
            .into_response())
    }
}
