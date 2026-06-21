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

/// Vergleicht einen Kandidaten-Key gegen ZWEI Referenz-Keys in konstanter Zeit.
///
/// Im Gegensatz zu `a || b` (Short-Circuit) wird hier IMMER beide Vergleiche
/// ausgeführt, sodass ein Angreifer nicht aus der Antwortzeit ableiten kann,
/// welcher der beiden Keys getroffen wurde (oder ob überhaupt einer matched
/// und nur durch Zufall die Längen passten).
fn constant_time_eq_any(key: &str, a: &str, b: &str) -> bool {
    // bitor statt logischem OR → kein Short-Circuit auf bool-Ebene
    let m1 = constant_time_eq(key, a) as u8;
    let m2 = constant_time_eq(key, b) as u8;
    (m1 | m2) != 0
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
    // Prüfe ob der Key dem API-Key ODER dem Admin-Key entspricht.
    // `constant_time_eq_any` führt beide Vergleiche immer aus → kein Timing-Leak,
    // der verrät, welcher Key matched (oder ob nur einer der beiden überhaupt
    // die korrekte Länge hat).
    if constant_time_eq_any(key, api_key, admin_key) {
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
            discord_id: String::new(),
            discord_username: String::new(),
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
    let (_, wallet_addr, _) = validate_session_token(token, cluster_key)?;
    let guard = users.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().find(|u| u.wallet_address == wallet_addr).cloned()
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

// ─── Mnemonic-Auth Killswitch ────────────────────────────────────────────────
//
// 23 SDK-Endpoints akzeptieren den User-Mnemonic im Request-Body. Das ist
// fundamental unsicher (Mnemonic landet in HTTP-Logs, Proxies, Browser-DevTools).
// Migrationspfad: `/api/v1/sdk/tx/submit` für TXs + signaturbasierter Consent.
//
// Bis alle Clients migriert sind, kann der Operator über die Env-Variable
//   STONE_DISABLE_MNEMONIC_AUTH=1
// alle Mnemonic-akzeptierenden Endpoints in Produktion abschalten.

/// Prüft, ob Mnemonic-basierte Auth aktuell erlaubt ist.
///
/// Operator-Schalter: `STONE_DISABLE_MNEMONIC_AUTH=1` setzt globalen Killswitch.
/// Default = aktiviert (für Testnet/CLI). Operatoren MÜSSEN das in Produktion
/// auf `1` setzen.
pub fn mnemonic_auth_enabled() -> bool {
    !matches!(
        std::env::var("STONE_DISABLE_MNEMONIC_AUTH").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Liefert den 410-Gone-Body für einen abgeschalteten Mnemonic-Endpoint.
///
/// Aufrufer kombinieren das mit `StatusCode::GONE` zu einer Response in der
/// Form, die ihre Handler-Signatur ohnehin nutzt:
/// ```ignore
/// if !mnemonic_auth_enabled() {
///     return (StatusCode::GONE, Json(mnemonic_killswitch_body("op"))).into_response();
/// }
/// log_mnemonic_call("op");
/// ```
pub fn mnemonic_killswitch_body(operation: &str) -> serde_json::Value {
    json!({
        "ok": false,
        "error": "Mnemonic-basierte HTTP-Auth ist auf diesem Node deaktiviert. \
                  Migriere auf Client-Side-Signing: \
                  POST /api/v1/sdk/tx/submit mit signierter TokenTx.",
        "migration": "https://chain.unrooted.dev/sdk#client-side-signing",
        "deprecated_operation": operation,
    })
}

/// Loggt einen Deprecation-Hinweis für einen Mnemonic-Aufruf.
/// Erzeugt operativen Druck Richtung Migration.
pub fn log_mnemonic_call(operation: &str) {
    eprintln!(
        "[deprecation] {operation}: Mnemonic-Auth via HTTP. Killswitch: \
         STONE_DISABLE_MNEMONIC_AUTH=1"
    );
}
