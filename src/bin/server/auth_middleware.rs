//! API-Key authentication helpers: extract_api_key, require_user, require_admin.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use stone::auth::User;

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
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
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
    let guard = users.lock().unwrap();
    guard.iter().find(|u| constant_time_eq(&u.api_key, key)).cloned()
}

pub fn require_user(headers: &HeaderMap, state: &AppState) -> Result<User, Response> {
    let key = extract_api_key(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    resolve_user_by_key(&key, &state.users, &state.api_key, &state.admin_key).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Ungültiger API-Key"})),
        )
            .into_response()
    })
}

pub fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<(), Response> {
    let key = extract_api_key(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    if constant_time_eq(&key, state.admin_key.as_str()) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Rechte erforderlich"})),
        )
            .into_response())
    }
}
