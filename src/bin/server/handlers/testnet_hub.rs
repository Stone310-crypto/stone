//! Zentraler Testnet-Sammelpunkt für chain.unrooted.dev
//!
//! Endpoints:
//!   POST /stone/testnet/register        → Node meldet neuen Testnet-User (auth: NODE_SECRET)
//!   POST /stone/testnet/report          → Node leitet Bug-Report weiter  (auth: NODE_SECRET)
//!   POST /stone/testnet/support-reply   → Node leitet User-Antwort an Team weiter (auth: NODE_SECRET)
//!   GET  /stone/testnet/users           → Mac App holt alle Testnet-User (auth: admin)
//!   GET  /stone/testnet/bug-reports     → Mac App holt alle Bug-Reports  (auth: admin)
//!   GET  /stone/testnet/support-replies → Mac App holt Support-Antworten (auth: admin)

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Mutex as StdMutex, OnceLock};

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

// ── Daten-Strukturen ─────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CollectedTestnetUser {
    pub user_id: String,
    pub name: String,
    #[serde(default)]
    pub wallet_address: String,
    #[serde(default)]
    pub mainnet_wallet: String,
    #[serde(default)]
    pub node_url: String,
    #[serde(default)]
    pub created_at: f64,
    #[serde(default)]
    pub last_seen: f64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CollectedBugReport {
    pub report_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub wallet: String,
    #[serde(default)]
    pub mainnet_wallet: String,
    #[serde(default)]
    pub node_url: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub steps_to_reproduce: Vec<String>,
    #[serde(default)]
    pub device_info: String,
    #[serde(default)]
    pub app_version: String,
    #[serde(default)]
    pub logs: String,
    #[serde(default)]
    pub created_at: f64,
}

// ── Persistenz (JSON-Dateien) ────────────────────────────────────────────────

fn hub_users_file() -> String {
    format!("{}/testnet_hub_users.json", stone::blockchain::data_dir())
}

fn hub_reports_file() -> String {
    format!("{}/testnet_hub_reports.json", stone::blockchain::data_dir())
}

fn hub_user_store() -> &'static StdMutex<Vec<CollectedTestnetUser>> {
    static STORE: OnceLock<StdMutex<Vec<CollectedTestnetUser>>> = OnceLock::new();
    STORE.get_or_init(|| {
        let users = std::fs::read_to_string(hub_users_file())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        StdMutex::new(users)
    })
}

fn hub_report_store() -> &'static StdMutex<Vec<CollectedBugReport>> {
    static STORE: OnceLock<StdMutex<Vec<CollectedBugReport>>> = OnceLock::new();
    STORE.get_or_init(|| {
        let reports = std::fs::read_to_string(hub_reports_file())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        StdMutex::new(reports)
    })
}

fn save_hub_users(users: &[CollectedTestnetUser]) {
    if let Ok(json) = serde_json::to_string_pretty(users) {
        let _ = std::fs::write(hub_users_file(), json);
    }
}

fn save_hub_reports(reports: &[CollectedBugReport]) {
    if let Ok(json) = serde_json::to_string_pretty(reports) {
        let _ = std::fs::write(hub_reports_file(), json);
    }
}

// ── Auth: NODE_SECRET prüfen ─────────────────────────────────────────────────

fn require_node_secret(headers: &HeaderMap) -> Result<(), Response> {
    let expected = std::env::var("NODE_SECRET").unwrap_or_default();
    if expected.is_empty() {
        // Kein Secret konfiguriert → alles erlaubt (Entwicklung)
        return Ok(());
    }
    let provided = headers
        .get("x-node-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if provided == expected {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Ungültiges Node-Secret"})),
        )
            .into_response())
    }
}

/// Auth für GET-Endpoints: akzeptiert entweder admin API-Key ODER NODE_SECRET
/// So kann die Mac App das NODE_SECRET verwenden ohne den Node-API-Key zu kennen.
fn require_hub_read_auth(headers: &HeaderMap, state: &AppState) -> Result<(), Response> {
    // Erst Node-Secret prüfen (x-node-secret oder x-api-key oder x-admin-key)
    let node_secret = std::env::var("NODE_SECRET").unwrap_or_default();
    if !node_secret.is_empty() {
        for header_name in &["x-node-secret", "x-api-key", "x-admin-key"] {
            if let Some(val) = headers.get(*header_name).and_then(|v| v.to_str().ok()) {
                if val.trim() == node_secret {
                    return Ok(());
                }
            }
        }
    }
    // Fallback: normaler admin-Key des Nodes
    require_admin(headers, state)
}

// ── POST /stone/testnet/register ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub user_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub wallet_address: String,
    #[serde(default)]
    pub mainnet_wallet: String,
    #[serde(default)]
    pub node_url: String,
}

pub async fn handle_hub_register(
    headers: HeaderMap,
    axum::Json(body): axum::Json<RegisterRequest>,
) -> Response {
    if let Err(e) = require_node_secret(&headers) {
        return e;
    }

    let user_id = body.user_id.trim().to_string();
    let name = body.name.trim().to_string();
    if user_id.is_empty() || name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "user_id und name sind Pflichtfelder"})),
        )
            .into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut store = hub_user_store().lock().unwrap();
    // Upsert: gleicher user_id → Update (egal von welchem Node)
    if let Some(idx) = store.iter().position(|u| u.user_id == user_id) {
        store[idx].name = name.clone();
        store[idx].wallet_address = body.wallet_address.clone();
        if !body.mainnet_wallet.is_empty() {
            store[idx].mainnet_wallet = body.mainnet_wallet.clone();
        }
        store[idx].node_url = body.node_url.clone();
        store[idx].last_seen = now;
        save_hub_users(&store);
        println!("[hub] ✓ Testnet-User updated: {} ({})", name, user_id);
        return axum::Json(json!({"ok": true, "action": "updated"})).into_response();
    }

    store.push(CollectedTestnetUser {
        user_id: user_id.clone(),
        name: name.clone(),
        wallet_address: body.wallet_address.clone(),
        mainnet_wallet: body.mainnet_wallet.clone(),
        node_url: body.node_url.clone(),
        created_at: now,
        last_seen: now,
    });
    save_hub_users(&store);
    println!("[hub] ✓ Testnet-User created: {} ({}) von {}", name, user_id, body.node_url);

    axum::Json(json!({"ok": true, "action": "created"})).into_response()
}

// ── POST /stone/testnet/report ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ReportRequest {
    #[serde(alias = "id")]
    pub report_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub wallet: String,
    #[serde(default)]
    pub mainnet_wallet: String,
    #[serde(default)]
    pub node_url: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub steps_to_reproduce: Vec<String>,
    #[serde(default)]
    pub device_info: String,
    #[serde(default)]
    pub app_version: String,
    #[serde(default)]
    pub logs: String,
}

pub async fn handle_hub_report(
    headers: HeaderMap,
    axum::Json(body): axum::Json<ReportRequest>,
) -> Response {
    if let Err(e) = require_node_secret(&headers) {
        return e;
    }

    let report_id = body.report_id.trim().to_string();
    let description = body.description.trim().to_string();
    if report_id.is_empty() || description.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "report_id und description sind Pflichtfelder"})),
        )
            .into_response();
    }

    let mut store = hub_report_store().lock().unwrap();
    // Upsert: existierender Report → aktualisieren
    if let Some(idx) = store.iter().position(|r| r.report_id == report_id) {
        store[idx].description = description.clone();
        if !body.mainnet_wallet.is_empty() {
            store[idx].mainnet_wallet = body.mainnet_wallet.clone();
        }
        if !body.steps_to_reproduce.is_empty() {
            store[idx].steps_to_reproduce = body.steps_to_reproduce.clone();
        }
        save_hub_reports(&store);
        println!("[hub] ✓ Bug-Report {} aktualisiert", report_id);
        return axum::Json(json!({"ok": true, "action": "updated"})).into_response();
    }

    // Logs auf 500KB begrenzen
    let logs = if body.logs.len() > 500_000 {
        body.logs[..500_000].to_string()
    } else {
        body.logs.clone()
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    store.push(CollectedBugReport {
        report_id: report_id.clone(),
        user_id: body.user_id.clone(),
        user_name: body.user_name.clone(),
        wallet: body.wallet.clone(),
        mainnet_wallet: body.mainnet_wallet.clone(),
        node_url: body.node_url.clone(),
        network: if body.network.is_empty() { "testnet".into() } else { body.network.clone() },
        category: body.category.clone(),
        description,
        steps_to_reproduce: body.steps_to_reproduce.clone(),
        device_info: body.device_info.clone(),
        app_version: body.app_version.clone(),
        logs,
        created_at: now,
    });
    save_hub_reports(&store);
    println!("[hub] ✓ Bug-Report {} von '{}' gespeichert", report_id, body.user_name);

    (StatusCode::CREATED, axum::Json(json!({"ok": true, "action": "created"}))).into_response()
}

// ── GET /stone/testnet/users ─────────────────────────────────────────────────

pub async fn handle_hub_users(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    if let Err(e) = require_hub_read_auth(&headers, &state) {
        return e;
    }

    let store = hub_user_store().lock().unwrap();
    // Nur "Test-Net" User anzeigen (echte Testnet-Accounts)
    let filtered: Vec<_> = store.iter()
        .filter(|u| u.name.starts_with("Test-Net"))
        .collect();
    axum::Json(json!({
        "ok": true,
        "count": filtered.len(),
        "users": filtered.iter().map(|u| json!({
            "user_id": u.user_id,
            "name": u.name,
            "wallet_address": u.wallet_address,
            "mainnet_wallet": u.mainnet_wallet,
            "node_url": u.node_url,
            "created_at": u.created_at,
            "last_seen": u.last_seen,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

// ── GET /stone/testnet/bug-reports ───────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct BugReportQuery {
    pub user_id: Option<String>,
}

pub async fn handle_hub_bug_reports(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<BugReportQuery>,
) -> Response {
    if let Err(e) = require_hub_read_auth(&headers, &state) {
        return e;
    }

    let store = hub_report_store().lock().unwrap();

    // Wenn nach user_id gefiltert wird, auch nach wallet_address matchen
    // (Bug-Reports werden oft vom Wallet-Account eingereicht, nicht vom Test-Net Account)
    let wallet_prefix = if let Some(ref uid) = query.user_id {
        let users = hub_user_store().lock().unwrap();
        users.iter()
            .find(|u| u.user_id == *uid)
            .map(|u| u.wallet_address.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Neueste zuerst, optional nach user_id ODER wallet filtern
    let mut reports: Vec<_> = store.iter()
        .filter(|r| {
            if let Some(ref uid) = query.user_id {
                // Match by user_id directly
                if r.user_id == *uid { return true; }
                // Match by wallet address (first 8 chars)
                if !wallet_prefix.is_empty() && !r.wallet.is_empty() {
                    let wp = &wallet_prefix[..wallet_prefix.len().min(8)];
                    let rw = &r.wallet[..r.wallet.len().min(8)];
                    if wp == rw { return true; }
                }
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();
    reports.sort_by(|a, b| b.created_at.partial_cmp(&a.created_at).unwrap_or(std::cmp::Ordering::Equal));

    axum::Json(json!({
        "ok": true,
        "count": reports.len(),
        "reports": reports.iter().map(|r| json!({
            "report_id": r.report_id,
            "user_id": r.user_id,
            "user_name": r.user_name,
            "wallet": r.wallet,
            "mainnet_wallet": r.mainnet_wallet,
            "node_url": r.node_url,
            "network": r.network,
            "category": r.category,
            "description": r.description,
            "steps_to_reproduce": r.steps_to_reproduce,
            "device_info": r.device_info,
            "app_version": r.app_version,
            "logs": r.logs,
            "created_at": r.created_at,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

// ── POST /stone/testnet/sync-users  (Bulk-Sync aller User eines Nodes) ──────

#[derive(Deserialize)]
pub struct BulkSyncRequest {
    pub node_url: String,
    pub users: Vec<BulkSyncUser>,
}

#[derive(Deserialize)]
pub struct BulkSyncUser {
    pub user_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub wallet_address: String,
}

pub async fn handle_hub_bulk_sync(
    headers: HeaderMap,
    axum::Json(body): axum::Json<BulkSyncRequest>,
) -> Response {
    if let Err(e) = require_node_secret(&headers) {
        return e;
    }

    let node_url = body.node_url.trim().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut store = hub_user_store().lock().unwrap();
    let mut added = 0u32;
    let mut updated = 0u32;

    for u in &body.users {
        let uid = u.user_id.trim().to_string();
        let name = u.name.trim().to_string();
        if uid.is_empty() || name.is_empty() {
            continue;
        }

        if let Some(idx) = store.iter().position(|x| x.user_id == uid) {
            store[idx].name = name;
            store[idx].wallet_address = u.wallet_address.clone();
            store[idx].node_url = node_url.clone();
            store[idx].last_seen = now;
            updated += 1;
        } else {
            store.push(CollectedTestnetUser {
                user_id: uid,
                name,
                wallet_address: u.wallet_address.clone(),
                mainnet_wallet: String::new(),
                node_url: node_url.clone(),
                created_at: now,
                last_seen: now,
            });
            added += 1;
        }
    }

    save_hub_users(&store);
    println!("[hub] ✓ Bulk-Sync von {}: {} neu, {} aktualisiert (gesamt: {})",
        node_url, added, updated, store.len());

    axum::Json(json!({
        "ok": true,
        "added": added,
        "updated": updated,
        "total": store.len(),
    }))
    .into_response()
}

// ── POST /stone/testnet/send-coins ───────────────────────────────────────────
//
// Admin sendet Testnet-Coins an einen User via Faucet auf dessen Node.
// Leitet an POST /api/v1/token/faucet auf dem Ziel-Node weiter.
//

#[derive(Deserialize)]
pub struct HubSendCoinsRequest {
    /// Ziel User-ID
    pub to_user_id: String,
    /// Betrag in STONE (wird am Ziel-Node als Faucet-Request ausgeführt)
    pub amount: Option<String>,
}

pub async fn handle_hub_send_coins(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<HubSendCoinsRequest>,
) -> Response {
    if let Err(e) = require_hub_read_auth(&headers, &state) {
        return e;
    }

    let user_id = body.to_user_id.trim().to_string();
    if user_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "to_user_id ist ein Pflichtfeld"})),
        ).into_response();
    }

    // User im Hub finden → wallet + node_url
    let (wallet, node_url) = {
        let store = hub_user_store().lock().unwrap();
        match store.iter().find(|u| u.user_id == user_id) {
            Some(u) => (u.wallet_address.clone(), u.node_url.clone()),
            None => return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "User nicht im Hub gefunden"})),
            ).into_response(),
        }
    };

    if wallet.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "User hat keine Wallet-Adresse"})),
        ).into_response();
    }

    // Sicherheitscheck: Nur Testnet-Netzwerk
    let network = stone::token::NetworkMode::from_env();
    if !network.is_testnet() {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Coin-Send nur im Testnet erlaubt"})),
        ).into_response();
    }

    // Faucet lokal aufrufen (Hub ist selbst ein Testnet-Node)
    let faucet_url = if node_url.is_empty() || node_url.contains("100.90.28.68") {
        // Lokaler Node
        format!("http://127.0.0.1:{}/api/v1/token/faucet",
            std::env::var("API_PORT").unwrap_or_else(|_| "8080".into()))
    } else {
        format!("{}/api/v1/token/faucet", node_url.trim_end_matches('/'))
    };

    let node_secret = std::env::var("NODE_SECRET").unwrap_or_default();
    let client = reqwest::Client::new();
    match client.post(&faucet_url)
        .header("x-node-secret", &node_secret)
        .json(&json!({ "address": wallet }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                println!("[hub] ✓ Coins an {} ({}) gesendet via {}", user_id, &wallet[..16.min(wallet.len())], faucet_url);
                let parsed: serde_json::Value = serde_json::from_str(&body_text).unwrap_or(json!({"raw": body_text}));
                axum::Json(json!({
                    "ok": true,
                    "faucet_response": parsed,
                    "to_wallet": wallet,
                    "node_url": node_url,
                })).into_response()
            } else {
                let parsed: serde_json::Value = serde_json::from_str(&body_text).unwrap_or(json!({"raw": body_text}));
                (StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                 axum::Json(json!({
                    "ok": false,
                    "error": "Faucet-Request fehlgeschlagen",
                    "faucet_response": parsed,
                }))).into_response()
            }
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY, axum::Json(json!({
                "ok": false,
                "error": format!("Faucet nicht erreichbar: {}", e),
            }))).into_response()
        }
    }
}

// ── POST /stone/testnet/send-message ─────────────────────────────────────────
//
// Admin sendet eine System-Nachricht an einen Testnet-User.
// Der Hub leitet die Nachricht an den Node weiter, auf dem der User registriert ist.
//

#[derive(Deserialize)]
pub struct HubSendMessageRequest {
    /// Ziel User-ID
    pub to_user_id: String,
    /// Klartext-Nachricht
    pub message: String,
}

pub async fn handle_hub_send_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<HubSendMessageRequest>,
) -> Response {
    if let Err(e) = require_hub_read_auth(&headers, &state) {
        return e;
    }

    let user_id = body.to_user_id.trim().to_string();
    let message = body.message.trim().to_string();
    if user_id.is_empty() || message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "to_user_id und message sind Pflichtfelder"})),
        ).into_response();
    }

    // User finden → node_url ermitteln
    let node_url = {
        let store = hub_user_store().lock().unwrap();
        store.iter()
            .find(|u| u.user_id == user_id)
            .map(|u| u.node_url.clone())
    };

    let node_url = match node_url {
        Some(url) if !url.is_empty() => url,
        _ => {
            // Fallback: Nachricht lokal senden (Hub ist selbst ein Node)
            let entry = stone::chat::ChatEntry {
                msg_id: uuid::Uuid::new_v4().to_string(),
                from_wallet: "system:stoneteam".to_string(),
                to_wallet: user_id.clone(), // wird als User-ID resolve versucht
                from_user_id: "system".to_string(),
                from_name: "StoneTeam".to_string(),
                encrypted_content: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    message.as_bytes(),
                ),
                nonce: String::new(),
                content_hash: String::new(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                block_index: 0,
                tx_id: String::new(),
            };

            // Versuche wallet zu resolven
            let to_wallet = {
                let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
                users.iter()
                    .find(|u| u.id == user_id)
                    .map(|u| u.wallet_address.clone())
            };

            if let Some(wallet) = to_wallet {
                let mut corrected = entry;
                corrected.to_wallet = wallet;
                let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
                idx.add_message(corrected);
                stone::chat::save_chat_index(&idx);
                return axum::Json(json!({"ok": true, "delivered": "local"})).into_response();
            }

            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "User nicht gefunden und keine node_url bekannt"})),
            ).into_response();
        }
    };

    // An den Ziel-Node weiterleiten via POST /api/v1/admin/system-message
    let node_secret = std::env::var("NODE_SECRET").unwrap_or_default();
    let target_url = format!("{}/api/v1/admin/system-message", node_url.trim_end_matches('/'));

    let client = reqwest::Client::new();
    match client.post(&target_url)
        .header("x-node-secret", &node_secret)
        .header("x-api-key", &node_secret)
        .json(&json!({
            "to": user_id,
            "message": message,
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() {
                println!("[hub] ✉ System-Msg an {} via {} gesendet", user_id, node_url);
                axum::Json(json!({"ok": true, "delivered": "remote", "node": node_url})).into_response()
            } else {
                eprintln!("[hub] ✗ System-Msg Fehler von {}: {} {}", node_url, status, body);
                (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({"error": format!("Node antwortete mit {}: {}", status, body)})),
                ).into_response()
            }
        }
        Err(e) => {
            eprintln!("[hub] ✗ System-Msg Verbindungsfehler zu {}: {}", node_url, e);
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": format!("Verbindung zu {} fehlgeschlagen: {}", node_url, e)})),
            ).into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Support-Replies: User-Antworten an "Stonechain Team" (system:stoneteam)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SupportReply {
    pub from_user_id: String,
    pub from_name: String,
    pub from_wallet: String,
    pub message: String,
    pub node_url: String,
    pub timestamp: u64,
}

fn support_replies_file() -> std::path::PathBuf {
    let dir = stone::blockchain::data_dir();
    std::path::PathBuf::from(dir).join("hub_support_replies.json")
}

static SUPPORT_REPLIES_STORE: OnceLock<StdMutex<Vec<SupportReply>>> = OnceLock::new();

fn support_replies_store() -> &'static StdMutex<Vec<SupportReply>> {
    SUPPORT_REPLIES_STORE.get_or_init(|| {
        let path = support_replies_file();
        let list: Vec<SupportReply> = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        StdMutex::new(list)
    })
}

fn save_support_replies(replies: &[SupportReply]) {
    let path = support_replies_file();
    if let Ok(json) = serde_json::to_string_pretty(replies) {
        let _ = std::fs::write(path, json);
    }
}

/// POST /stone/testnet/support-reply  — Node meldet User-Antwort an StoneTeam
pub async fn handle_hub_support_reply(
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = require_node_secret(&headers) {
        return resp;
    }

    let from_user_id = body["from_user_id"].as_str().unwrap_or("").to_string();
    let from_name = body["from_name"].as_str().unwrap_or("").to_string();
    let from_wallet = body["from_wallet"].as_str().unwrap_or("").to_string();
    let message = body["message"].as_str().unwrap_or("").to_string();
    let timestamp = body["timestamp"].as_u64().unwrap_or(0);
    let node_url = std::env::var("PUBLIC_URL").unwrap_or_default();

    if message.is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "message leer"}))).into_response();
    }

    let reply = SupportReply {
        from_user_id,
        from_name,
        from_wallet,
        message,
        node_url,
        timestamp,
    };

    let store = support_replies_store();
    let count = {
        let mut list = store.lock().unwrap_or_else(|e| e.into_inner());
        list.push(reply);
        save_support_replies(&list);
        list.len()
    };

    println!("[hub] 💬 Support-Reply empfangen (gesamt: {})", count);
    axum::Json(json!({"ok": true, "count": count})).into_response()
}

/// GET /stone/testnet/support-replies  — Mac App holt alle Support-Antworten
pub async fn handle_hub_get_support_replies(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    if let Err(resp) = require_hub_read_auth(&headers, &state) {
        return resp;
    }

    let store = support_replies_store();
    let list = store.lock().unwrap_or_else(|e| e.into_inner());

    axum::Json(json!({
        "ok": true,
        "count": list.len(),
        "replies": *list,
    })).into_response()
}
