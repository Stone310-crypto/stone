//! Stone SDK – API Handler
//!
//! Alle Endpunkte für das Gaming-SDK:
//!
//! - Developer:  /api/v1/sdk/register, /api/v1/sdk/game/*
//! - Consent:    /api/v1/sdk/consent/*
//! - Wallet:     /api/v1/sdk/wallet/*
//! - TX:         /api/v1/sdk/tx/*
//! - Market:     /api/v1/sdk/market/*
//! - Game:       /api/v1/sdk/game/*
//! - Auth:       /api/v1/sdk/auth/*
//! - Player:     /api/v1/sdk/player/*

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use stone::token::{
    TokenTx, TxType, Wallet, compute_tx_id, default_chain_id,
    game_economy::{
        GameEconomyStore, GamePermission, MARKETPLACE_POOL, MAX_BATCH_SIZE,
        derive_game_wallet,
    },
};

use super::super::state::AppState;

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn read_game_store(state: &AppState) -> GameEconomyStore {
    state.node.game_economy.read().unwrap_or_else(|e| e.into_inner()).clone()
}

fn with_game_store_mut<F, R>(state: &AppState, f: F) -> R
where
    F: FnOnce(&mut GameEconomyStore) -> R,
{
    let mut store = state.node.game_economy.write().unwrap_or_else(|e| e.into_inner());
    let result = f(&mut store);
    if let Err(e) = store.persist() {
        eprintln!("[sdk-api] ⚠️  Persist fehlgeschlagen: {e}");
    }
    result
}

fn err_json(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": false, "error": msg }))
}

fn ok_json(data: serde_json::Value) -> Json<serde_json::Value> {
    let mut obj = data;
    obj.as_object_mut().map(|m| m.insert("ok".into(), serde_json::json!(true)));
    Json(obj)
}

/// TX über P2P broadcasten (fire-and-forget).
fn broadcast_tx(state: &AppState, tx: TokenTx) {
    if let Some(ref net) = state.network {
        let net = net.clone();
        tokio::spawn(async move { net.broadcast_tx(tx).await; });
    }
}

/// Validiert den X-SDK-Key Header und gibt das zugehörige RegisteredGame zurück.
fn validate_sdk_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let key = headers
        .get("X-SDK-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, err_json("X-SDK-Key Header fehlt")))?;

    let store = read_game_store(state);
    match store.validate_api_key(key) {
        Ok(game) => Ok(game.game_id.clone()),
        Err(e) => Err((StatusCode::FORBIDDEN, err_json(&e.to_string()))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §1 DEVELOPER – Spiel-Registrierung
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/quick-register ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct QuickRegisterReq {
    pub game_id: String,
    pub name: String,
    pub description: Option<String>,
    pub website: Option<String>,
    pub max_daily_limit: Option<String>,
    pub permissions: Option<Vec<GamePermission>>,
}

/// POST /api/v1/sdk/quick-register – Alles-in-einem: Wallet generieren,
/// Spiel registrieren, API-Key erstellen. Gibt Mnemonic + API-Key zurück.
pub async fn handle_sdk_quick_register(
    State(state): State<AppState>,
    Json(req): Json<QuickRegisterReq>,
) -> impl IntoResponse {
    // 1. Neues Wallet generieren
    let wallet = match Wallet::generate() {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            err_json(&format!("Wallet-Generierung fehlgeschlagen: {e}"))).into_response(),
    };

    // 2. Defaults setzen
    let description = req.description.unwrap_or_default();
    let website = req.website.unwrap_or_default();
    let max_limit: Decimal = req.max_daily_limit
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Decimal::new(1000, 0));
    let permissions = req.permissions.unwrap_or_else(|| vec![
        GamePermission::Basic,
        GamePermission::Marketplace,
        GamePermission::Assets,
    ]);

    if max_limit <= Decimal::ZERO {
        return (StatusCode::BAD_REQUEST, err_json("max_daily_limit muss > 0 sein")).into_response();
    }

    // 3. Spiel registrieren
    let result = with_game_store_mut(&state, |store| {
        store.register_game(
            &req.game_id, &req.name, &description, &website,
            &wallet.address(), max_limit, permissions.clone(),
        )
    });

    match result {
        Ok((game, api_key)) => Json(serde_json::json!({
            "ok": true,
            "game_id": game.game_id,
            "developer_wallet": wallet.address(),
            "mnemonic": wallet.mnemonic(),
            "api_key": api_key,
            "permissions": game.permissions,
            "max_daily_limit": game.max_wallet_limit.to_string(),
            "note": "⚠️ Mnemonic + API-Key NUR JETZT sichtbar! Sicher aufbewahren!"
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/register ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterGameReq {
    pub mnemonic: String,
    pub game_id: String,
    pub name: String,
    pub description: String,
    pub website: String,
    pub max_wallet_limit: String,
    pub permissions: Vec<GamePermission>,
}

/// POST /api/v1/sdk/register – Neues Spiel registrieren, API-Key erhalten
pub async fn handle_sdk_register(
    State(state): State<AppState>,
    Json(req): Json<RegisterGameReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let max_limit: Decimal = match req.max_wallet_limit.parse() {
        Ok(d) if d > Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges max_wallet_limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.register_game(
            &req.game_id, &req.name, &req.description, &req.website,
            &wallet.address(), max_limit, req.permissions.clone(),
        )
    });

    match result {
        Ok((game, api_key)) => Json(serde_json::json!({
            "ok": true,
            "game_id": game.game_id,
            "api_key": api_key,
            "note": "API-Key wird nur EINMAL angezeigt! Sicher aufbewahren.",
            "permissions": game.permissions,
            "max_wallet_limit": game.max_wallet_limit.to_string(),
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── GET /api/v1/sdk/game/:game_id ───────────────────────────────────────────

/// GET /api/v1/sdk/game/{game_id} – Spiel-Info abrufen (public)
pub async fn handle_sdk_game_info(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    match store.get_game(&game_id) {
        Some(game) => Json(serde_json::json!({
            "ok": true,
            "game": {
                "game_id": game.game_id,
                "name": game.name,
                "description": game.description,
                "website": game.website,
                "permissions": game.permissions,
                "max_wallet_limit": game.max_wallet_limit.to_string(),
                "status": game.status,
                "created_at": game.created_at,
            },
        })).into_response(),
        None => (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
    }
}

// ── POST /api/v1/sdk/game/:game_id/status ───────────────────────────────────

#[derive(Deserialize)]
pub struct GameStatusReq {
    pub action: String,   // "suspend", "blacklist", "reactivate"
    pub reason: Option<String>,
    pub until: Option<i64>,
}

/// POST /api/v1/sdk/game/{game_id}/status – Spiel suspendieren/blacklisten (Admin)
pub async fn handle_sdk_game_status(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
    Json(req): Json<GameStatusReq>,
) -> impl IntoResponse {
    let result = with_game_store_mut(&state, |store| {
        match req.action.as_str() {
            "suspend" => store.suspend_game(
                &game_id,
                req.reason.as_deref().unwrap_or("Admin-Entscheidung"),
                req.until,
            ),
            "blacklist" => store.blacklist_game(
                &game_id,
                req.reason.as_deref().unwrap_or("Admin-Entscheidung"),
            ),
            "reactivate" => store.reactivate_game(&game_id),
            _ => Err(stone::token::game_economy::GameEconomyError::InvalidInput {
                reason: "Aktion muss 'suspend', 'blacklist' oder 'reactivate' sein".into(),
            }),
        }
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({
            "game_id": game_id,
            "action": req.action,
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §2 CONSENT – Nutzer-Zustimmung
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/consent/request ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentRequestReq {
    pub player_wallet: String,
    pub requested_limit: String,
    pub requested_permissions: Vec<GamePermission>,
}

/// POST /api/v1/sdk/consent/request – Spiel fordert Nutzer-Consent an (API-Key Auth)
pub async fn handle_sdk_consent_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentRequestReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let limit: Decimal = match req.requested_limit.parse() {
        Ok(d) if d > Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges Limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.request_consent(&game_id, &req.player_wallet, limit, req.requested_permissions.clone())
    });

    match result {
        Ok(cr) => Json(serde_json::json!({
            "ok": true,
            "consent_request": {
                "request_id": cr.request_id,
                "game_id": cr.game_id,
                "game_name": cr.game_name,
                "player_wallet": cr.player_wallet,
                "requested_limit": cr.requested_limit.to_string(),
                "requested_permissions": cr.requested_permissions,
                "expires_at": cr.expires_at,
            },
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── GET /api/v1/sdk/consent/pending ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentPendingQuery {
    pub wallet: String,
}

/// GET /api/v1/sdk/consent/pending?wallet=... – Offene Consent-Anfragen anzeigen
pub async fn handle_sdk_consent_pending(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ConsentPendingQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let pending = store.pending_consents(&q.wallet);

    let items: Vec<serde_json::Value> = pending.iter().map(|cr| serde_json::json!({
        "request_id": cr.request_id,
        "game_id": cr.game_id,
        "game_name": cr.game_name,
        "requested_limit": cr.requested_limit.to_string(),
        "requested_permissions": cr.requested_permissions,
        "expires_at": cr.expires_at,
    })).collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": items.len(),
        "pending": items,
    }))
}

// ── POST /api/v1/sdk/consent/approve ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentApproveReq {
    pub mnemonic: String,
    pub request_id: String,
}

/// POST /api/v1/sdk/consent/approve – Nutzer genehmigt Consent-Anfrage
pub async fn handle_sdk_consent_approve(
    State(state): State<AppState>,
    Json(req): Json<ConsentApproveReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.approve_consent(&wallet.address(), &req.request_id)
    });

    match result {
        Ok(gw) => Json(serde_json::json!({
            "ok": true,
            "game_wallet": {
                "game_wallet": gw.game_wallet,
                "game_id": gw.game_id,
                "daily_limit": gw.daily_limit.to_string(),
                "allowed_permissions": gw.allowed_permissions,
            },
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/consent/reject ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentRejectReq {
    pub mnemonic: String,
    pub request_id: String,
}

/// POST /api/v1/sdk/consent/reject – Nutzer lehnt Consent-Anfrage ab
pub async fn handle_sdk_consent_reject(
    State(state): State<AppState>,
    Json(req): Json<ConsentRejectReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.reject_consent(&wallet.address(), &req.request_id)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "request_id": req.request_id, "status": "rejected" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §3 WALLET – Spiel-Wallets verwalten
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/wallet/create ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateGameWalletReq {
    pub mnemonic: String,
    pub game_id: String,
    pub display_name: String,
    pub daily_limit: String,
    pub permissions: Vec<GamePermission>,
}

/// POST /api/v1/sdk/wallet/create – Game-Wallet direkt erstellen (Nutzer-Aktion)
pub async fn handle_sdk_wallet_create(
    State(state): State<AppState>,
    Json(req): Json<CreateGameWalletReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let limit: Decimal = match req.daily_limit.parse() {
        Ok(d) if d > Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges daily_limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.create_game_wallet(
            &wallet.address(), &req.game_id, &req.display_name,
            limit, req.permissions.clone(),
        )
    });

    match result {
        Ok(gw) => Json(serde_json::json!({
            "ok": true,
            "game_wallet": gw,
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/link ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletLinkReq {
    pub mnemonic: String,
    pub game_id: String,
    pub display_name: Option<String>,
    pub daily_limit: Option<String>,
    pub permissions: Option<Vec<GamePermission>>,
}

/// POST /api/v1/sdk/wallet/link – Bestehende Stone-Wallet mit einem Spiel verknüpfen.
///
/// Erzeugt den User-Eintrag (falls nötig) und den Game-Wallet in einem Schritt.
/// Funktioniert für Wallets aus der Stonechain-App oder anderen Quellen.
pub async fn handle_sdk_wallet_link(
    State(state): State<AppState>,
    Json(req): Json<WalletLinkReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Ungültige Mnemonic: {e}"))).into_response(),
    };

    let wallet_addr = wallet.address();
    let display_name = req.display_name.unwrap_or_else(|| format!("Wallet-{}", &wallet_addr[..8]));
    let limit: Decimal = req.daily_limit.as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Decimal::new(500, 0));
    let permissions = req.permissions.unwrap_or_else(|| vec![
        GamePermission::Basic, GamePermission::Marketplace, GamePermission::Assets,
    ]);

    // On-chain Balance prüfen
    let main_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance(&wallet_addr)
    };

    // Game-Wallet erstellen (oder existierenden zurückgeben)
    let gw_result = with_game_store_mut(&state, |store| {
        // Prüfe ob bereits verknüpft
        if let Some(existing) = store.find_game_wallet(&wallet_addr, &req.game_id) {
            return Ok(existing.clone());
        }
        store.create_game_wallet(
            &wallet_addr, &req.game_id, &display_name,
            limit, permissions.clone(),
        )
    });

    match gw_result {
        Ok(gw) => Json(serde_json::json!({
            "ok": true,
            "wallet_address": wallet_addr,
            "main_balance": main_balance.to_string(),
            "game_wallet": gw.game_wallet,
            "game_id": gw.game_id,
            "daily_limit": gw.daily_limit.to_string(),
            "display_name": display_name,
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── GET /api/v1/sdk/wallet/balance ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletQuery {
    pub wallet: String,
    pub game_id: Option<String>,
}

/// GET /api/v1/sdk/wallet/balance?wallet=...&game_id=...
pub async fn handle_sdk_wallet_balance(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<WalletQuery>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let main_balance = ledger.balance(&q.wallet);

    let store = read_game_store(&state);

    if let Some(ref gid) = q.game_id {
        if let Some(gw) = store.find_game_wallet(&q.wallet, gid) {
            let game_balance = ledger.balance(&gw.game_wallet);
            return Json(serde_json::json!({
                "ok": true,
                "wallet": q.wallet,
                "main_balance": main_balance.to_string(),
                "game_id": gid,
                "game_wallet": gw.game_wallet,
                "game_balance": game_balance.to_string(),
                "daily_limit": gw.daily_limit.to_string(),
                "spent_today": gw.spent_today.to_string(),
                "frozen": gw.frozen,
            }));
        }
        return Json(serde_json::json!({
            "ok": true,
            "wallet": q.wallet,
            "main_balance": main_balance.to_string(),
            "game_id": gid,
            "game_balance": null,
        }));
    }

    // Alle Game-Wallets mit Balancen
    let game_wallets: Vec<serde_json::Value> = store.wallets_of(&q.wallet)
        .iter()
        .map(|gw| serde_json::json!({
            "game_id": gw.game_id,
            "game_wallet": gw.game_wallet,
            "balance": ledger.balance(&gw.game_wallet).to_string(),
            "daily_limit": gw.daily_limit.to_string(),
            "spent_today": gw.spent_today.to_string(),
            "frozen": gw.frozen,
        }))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "main_balance": main_balance.to_string(),
        "game_wallets": game_wallets,
    }))
}

// ── GET /api/v1/sdk/wallet/transactions ──────────────────────────────────────

#[derive(Deserialize)]
pub struct TxHistoryQuery {
    pub wallet: String,
    pub limit: Option<usize>,
}

/// GET /api/v1/sdk/wallet/transactions?wallet=...&limit=50
pub async fn handle_sdk_wallet_transactions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<TxHistoryQuery>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let limit = q.limit.unwrap_or(50).min(200);
    let mut txs: Vec<serde_json::Value> = Vec::new();

    for block in chain.blocks.iter().rev() {
        for tx in &block.transactions {
            if tx.from == q.wallet || tx.to == q.wallet {
                txs.push(serde_json::json!({
                    "tx_id": tx.tx_id,
                    "type": tx.tx_type.to_string(),
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "memo": tx.memo,
                    "timestamp": tx.timestamp,
                    "block_index": block.index,
                }));
                if txs.len() >= limit { break; }
            }
        }
        if txs.len() >= limit { break; }
    }

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": txs.len(),
        "transactions": txs,
    }))
}

// ── POST /api/v1/sdk/wallet/send ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletSendReq {
    pub to: String,
    pub amount: String,
    pub memo: Option<String>,
}

/// POST /api/v1/sdk/wallet/send – Coins senden (API-Key Auth, prüft Permission + Limit)
pub async fn handle_sdk_wallet_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WalletSendReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    // Session-Token aus Header für Wallet-Identifikation
    let session_token = match headers.get("X-SDK-Session").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => return (StatusCode::UNAUTHORIZED, err_json("X-SDK-Session Header fehlt")).into_response(),
    };

    let store = read_game_store(&state);
    let session = match store.validate_session(&session_token) {
        Some(s) => s.clone(),
        None => return (StatusCode::UNAUTHORIZED, err_json("Session ungültig oder abgelaufen")).into_response(),
    };

    if session.game_id != game_id {
        return (StatusCode::FORBIDDEN, err_json("Session gehört nicht zu diesem Spiel")).into_response();
    }

    // Game-Wallet finden
    let game_wallet_addr = derive_game_wallet(&session.wallet, &game_id);

    // Permission-Check
    {
        let store = read_game_store(&state);
        if let Err(e) = store.check_wallet_action(&game_wallet_addr, GamePermission::Basic) {
            return (StatusCode::FORBIDDEN, err_json(&e.to_string())).into_response();
        }
    }

    // Daily-Limit prüfen + registrieren
    {
        let limit_result = with_game_store_mut(&state, |store| {
            store.enforce_daily_limit(&game_wallet_addr, amount)
        });
        if let Err(e) = limit_result {
            return (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response();
        }
    }

    // TX erstellen (System-TX vom Game-Wallet)
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&game_wallet_addr);
    if balance < amount {
        return (StatusCode::BAD_REQUEST, err_json(&format!(
            "Nicht genug Guthaben: {} < {}", balance, amount
        ))).into_response();
    }

    let nonce = ledger.nonce(&game_wallet_addr);
    drop(ledger);

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: game_wallet_addr.clone(),
        to: req.to.clone(),
        amount,
        fee: Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: format!("sdk:{}:{}", game_id, session.wallet),
        memo: req.memo.unwrap_or_else(|| format!("SDK-Send: {}", game_id)),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Priority,
    };
    tx.tx_id = compute_tx_id(&tx);

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            with_game_store_mut(&state, |store| {
                store.audit(&game_id, &session.wallet, "sdk_send", serde_json::json!({
                    "to": req.to, "amount": amount.to_string(),
                }), true);
            });
            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "from": game_wallet_addr,
                "to": req.to,
                "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/withdraw ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct WithdrawReq {
    pub mnemonic: String,
    pub game_id: String,
    pub amount: String,
}

/// POST /api/v1/sdk/wallet/withdraw – Vom Game-Wallet ins Haupt-Wallet
pub async fn handle_sdk_wallet_withdraw(
    State(state): State<AppState>,
    Json(req): Json<WithdrawReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let store = read_game_store(&state);
    let game_wallet = match store.find_game_wallet(&wallet.address(), &req.game_id) {
        Some(gw) => gw.game_wallet.clone(),
        None => return (StatusCode::NOT_FOUND, err_json("Kein Game-Wallet gefunden")).into_response(),
    };

    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&game_wallet);
    if balance < amount {
        return (StatusCode::BAD_REQUEST, err_json(&format!(
            "Nicht genug: {} < {}", balance, amount
        ))).into_response();
    }

    let nonce = ledger.nonce(&game_wallet);
    drop(ledger);

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: game_wallet.clone(),
        to: wallet.address(),
        amount,
        fee: Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: format!("game-withdraw:{}", wallet.address()),
        memo: format!("Withdraw: {} → Main", req.game_id),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
    };
    tx.tx_id = compute_tx_id(&tx);

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "from": game_wallet,
                "to": wallet.address(),
                "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── GET /api/v1/sdk/wallet/nft-inventory ─────────────────────────────────────

/// GET /api/v1/sdk/wallet/nft-inventory?wallet=...&game_id=...
pub async fn handle_sdk_nft_inventory(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<WalletQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let items: Vec<_> = store.items_of(&q.wallet)
        .into_iter()
        .filter(|i| q.game_id.as_ref().map(|gid| i.game_id == *gid).unwrap_or(true))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": items.len(),
        "items": items,
    }))
}

// ── POST /api/v1/sdk/wallet/freeze ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct FreezeReq {
    pub mnemonic: String,
    pub game_id: String,
}

/// POST /api/v1/sdk/wallet/freeze – Nutzer friert Game-Wallet ein
pub async fn handle_sdk_wallet_freeze(
    State(state): State<AppState>,
    Json(req): Json<FreezeReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.freeze_wallet(&wallet.address(), &req.game_id)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "game_id": req.game_id, "status": "frozen" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/unfreeze ─────────────────────────────────────────

/// POST /api/v1/sdk/wallet/unfreeze – Nutzer gibt Game-Wallet frei
pub async fn handle_sdk_wallet_unfreeze(
    State(state): State<AppState>,
    Json(req): Json<FreezeReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.unfreeze_wallet(&wallet.address(), &req.game_id)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "game_id": req.game_id, "status": "active" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/set-limit ────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetLimitReq {
    pub mnemonic: String,
    pub game_id: String,
    pub daily_limit: String,
}

/// POST /api/v1/sdk/wallet/set-limit – Nutzer passt tägliches Limit an
pub async fn handle_sdk_wallet_set_limit(
    State(state): State<AppState>,
    Json(req): Json<SetLimitReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let limit: Decimal = match req.daily_limit.parse() {
        Ok(d) if d >= Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges Limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.set_daily_limit(&wallet.address(), &req.game_id, limit)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({
            "game_id": req.game_id,
            "daily_limit": limit.to_string(),
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §4 TX – Transaktionen
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/tx/buy-item ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BuyItemReq {
    pub mnemonic: String,
    pub listing_id: String,
}

/// POST /api/v1/sdk/tx/buy-item
pub async fn handle_sdk_buy_item(
    State(state): State<AppState>,
    Json(req): Json<BuyItemReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let buy_result = with_game_store_mut(&state, |store| {
        store.buy_item(&req.listing_id, &wallet.address())
    });

    let (fee, seller_amount, seller) = match buy_result {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    };

    let total = fee + seller_amount;
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.balance(&wallet.address()) < total {
            return (StatusCode::BAD_REQUEST, err_json("Nicht genug STONE")).into_response();
        }
    }

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer, seller.clone(), seller_amount, nonce,
        format!("Market-Buy: {}", req.listing_id),
        stone::token::FeeTier::Priority,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let fee_tx = if fee > Decimal::ZERO {
        wallet.sign_tx_with_tier(
            TxType::Transfer, MARKETPLACE_POOL.to_string(), fee, nonce + 1,
            format!("Market-Fee: {}", req.listing_id),
            stone::token::FeeTier::Priority,
        ).ok()
    } else {
        None
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    if let Err(e) = result {
        return (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response();
    }
    broadcast_tx(&state, tx.clone());

    if let Some(ftx) = fee_tx {
        let _ = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(ftx.clone(), Some(&ledger))
        };
        broadcast_tx(&state, ftx);
    }

    Json(serde_json::json!({
        "ok": true,
        "tx_id": tx.tx_id,
        "listing_id": req.listing_id,
        "price": total.to_string(),
        "fee": fee.to_string(),
        "seller": seller,
    })).into_response()
}

// ── POST /api/v1/sdk/tx/sell-item ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct SellItemReq {
    pub mnemonic: String,
    pub item_id: String,
    pub price: String,
    pub expires_hours: Option<i64>,
}

/// POST /api/v1/sdk/tx/sell-item
pub async fn handle_sdk_sell_item(
    State(state): State<AppState>,
    Json(req): Json<SellItemReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let price: Decimal = match req.price.parse() {
        Ok(p) if p > Decimal::ZERO => p,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Preis")).into_response(),
    };

    let expires_at = req.expires_hours.map(|h| chrono::Utc::now().timestamp() + h * 3600);

    let result = with_game_store_mut(&state, |store| {
        store.list_item(&wallet.address(), &req.item_id, price, expires_at)
    });

    match result {
        Ok(listing) => Json(serde_json::json!({ "ok": true, "listing": listing })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/tx/transfer ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GameTransferReq {
    pub mnemonic: String,
    pub to: String,
    pub amount: String,
    pub memo: Option<String>,
}

/// POST /api/v1/sdk/tx/transfer – Coins an anderen Spieler
pub async fn handle_sdk_transfer(
    State(state): State<AppState>,
    Json(req): Json<GameTransferReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let is_hex64 = req.to.len() == 64 && req.to.chars().all(|c| c.is_ascii_hexdigit());
    let is_game_wallet = req.to.starts_with("game:") && req.to.len() > 5;
    if req.to.is_empty() || (!is_hex64 && !is_game_wallet) {
        return (StatusCode::BAD_REQUEST, err_json("Ungültige Empfänger-Adresse")).into_response();
    }

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer, req.to.clone(), amount, nonce,
        req.memo.unwrap_or_default(),
        stone::token::FeeTier::Priority,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "from": wallet.address(),
                "to": req.to,
                "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── POST /api/v1/sdk/tx/batch ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BatchTxReq {
    pub mnemonic: String,
    pub transactions: Vec<BatchTxEntry>,
}

#[derive(Deserialize)]
pub struct BatchTxEntry {
    pub to: String,
    pub amount: String,
    pub memo: Option<String>,
}

/// POST /api/v1/sdk/tx/batch
pub async fn handle_sdk_batch_tx(
    State(state): State<AppState>,
    Json(req): Json<BatchTxReq>,
) -> impl IntoResponse {
    if req.transactions.is_empty() || req.transactions.len() > MAX_BATCH_SIZE {
        return (StatusCode::BAD_REQUEST, err_json(
            &format!("Batch-Größe muss 1-{MAX_BATCH_SIZE} sein")
        )).into_response();
    }

    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let mut base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let mut results = Vec::new();
    let mut success_count = 0u32;

    for entry in &req.transactions {
        let amount: Decimal = match entry.amount.parse() {
            Ok(a) if a > Decimal::ZERO => a,
            _ => {
                results.push(serde_json::json!({ "ok": false, "error": "Ungültiger Betrag", "to": entry.to }));
                continue;
            }
        };

        let tx = match wallet.sign_tx_with_tier(
            TxType::Transfer, entry.to.clone(), amount, base_nonce,
            entry.memo.clone().unwrap_or_default(),
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "error": e.to_string(), "to": entry.to }));
                continue;
            }
        };

        let add_result = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };

        match add_result {
            Ok(_) => {
                broadcast_tx(&state, tx.clone());
                results.push(serde_json::json!({
                    "ok": true, "tx_id": tx.tx_id, "to": entry.to, "amount": amount.to_string(),
                }));
                base_nonce += 1;
                success_count += 1;
            }
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "error": e.to_string(), "to": entry.to }));
            }
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "total": req.transactions.len(),
        "success": success_count,
        "results": results,
    })).into_response()
}

// ── GET /api/v1/sdk/tx/status/:tx_id ────────────────────────────────────────

/// GET /api/v1/sdk/tx/status/{tx_id}
pub async fn handle_sdk_tx_status(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    let pending = state.node.mempool.pending_txs();
    if let Some(tx) = pending.iter().find(|t| t.tx_id == tx_id) {
        return Json(serde_json::json!({
            "ok": true, "tx_id": tx_id, "status": "pending",
            "tx": { "from": tx.from, "to": tx.to, "amount": tx.amount.to_string(), "timestamp": tx.timestamp },
        }));
    }

    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    for block in chain.blocks.iter().rev() {
        if let Some(tx) = block.transactions.iter().find(|t| t.tx_id == tx_id) {
            return Json(serde_json::json!({
                "ok": true, "tx_id": tx_id, "status": "confirmed",
                "block_index": block.index, "block_hash": block.hash,
                "tx": { "from": tx.from, "to": tx.to, "amount": tx.amount.to_string(), "timestamp": tx.timestamp },
            }));
        }
    }

    Json(serde_json::json!({ "ok": false, "tx_id": tx_id, "status": "not_found" }))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §5 MARKETPLACE
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct ListingsQuery {
    pub category: Option<String>,
    pub game_id: Option<String>,
}

/// GET /api/v1/sdk/market/listings?category=weapon&game_id=...
pub async fn handle_sdk_market_listings(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ListingsQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let mut listings = store.active_listings(q.category.as_deref());
    if let Some(ref gid) = q.game_id {
        listings.retain(|l| l.item.game_id == *gid);
    }
    Json(serde_json::json!({ "ok": true, "count": listings.len(), "listings": listings }))
}

/// POST /api/v1/sdk/market/list (alias für sell-item)
pub async fn handle_sdk_market_list(
    state: State<AppState>,
    json: Json<SellItemReq>,
) -> impl IntoResponse {
    handle_sdk_sell_item(state, json).await
}

#[derive(Deserialize)]
pub struct DelistReq {
    pub mnemonic: String,
    pub listing_id: String,
}

/// POST /api/v1/sdk/market/delist
pub async fn handle_sdk_market_delist(
    State(state): State<AppState>,
    Json(req): Json<DelistReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.delist_item(&req.listing_id, &wallet.address())
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "listing_id": req.listing_id, "status": "cancelled" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct OfferReq {
    pub mnemonic: String,
    pub listing_id: String,
    pub amount: String,
}

/// POST /api/v1/sdk/market/offer
pub async fn handle_sdk_market_offer(
    State(state): State<AppState>,
    Json(req): Json<OfferReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.place_offer(&req.listing_id, &wallet.address(), amount)
    });

    match result {
        Ok(offer) => Json(serde_json::json!({ "ok": true, "offer": offer })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

/// GET /api/v1/sdk/market/history/{item_id}
pub async fn handle_sdk_market_history(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let history = store.price_history.get(&item_id).cloned().unwrap_or_default();
    Json(serde_json::json!({ "ok": true, "item_id": item_id, "count": history.len(), "history": history }))
}

/// GET /api/v1/sdk/market/floor/{category}
pub async fn handle_sdk_market_floor(
    State(state): State<AppState>,
    Path(category): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    match store.floor_price(&category) {
        Some((price, listing_id)) => Json(serde_json::json!({
            "ok": true, "category": category, "floor_price": price.to_string(), "listing_id": listing_id,
        })),
        None => Json(serde_json::json!({
            "ok": true, "category": category, "floor_price": null, "listing_id": null,
        })),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §6 GAME – Rewards, Burn, Leaderboard, Tournament
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct GameRewardReq {
    pub game_id: String,
    pub server_wallet_mnemonic: String,
    pub player_wallet: String,
    pub amount: String,
    pub reason: Option<String>,
}

/// POST /api/v1/sdk/game/reward – Belohnung ausschütten (Game-Server Auth)
pub async fn handle_sdk_game_reward(
    State(state): State<AppState>,
    Json(req): Json<GameRewardReq>,
) -> impl IntoResponse {
    let server_wallet = match Wallet::from_mnemonic(&req.server_wallet_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Server-Mnemonic: {e}"))).into_response(),
    };

    {
        let store = read_game_store(&state);
        if !store.is_game_server(&req.game_id, &server_wallet.address()) {
            return (StatusCode::FORBIDDEN, err_json("Nicht der registrierte Game-Server")).into_response();
        }
        if !store.game_has_permission(&req.game_id, GamePermission::Tournament) {
            return (StatusCode::FORBIDDEN, err_json("Spiel hat keine 'tournament' Berechtigung")).into_response();
        }
    }

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&server_wallet.address()) + state.node.mempool.sender_pending_count(&server_wallet.address())
    };

    let memo = req.reason.unwrap_or_else(|| format!("Game-Reward: {}", req.game_id));
    let tx = match server_wallet.sign_tx_with_tier(
        TxType::Transfer, req.player_wallet.clone(), amount, nonce, memo,
        stone::token::FeeTier::Standard,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            with_game_store_mut(&state, |store| {
                store.audit(&req.game_id, &req.player_wallet, "game_reward", serde_json::json!({
                    "amount": amount.to_string(),
                }), true);
            });
            Json(serde_json::json!({
                "ok": true, "tx_id": tx.tx_id, "player": req.player_wallet, "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct BurnItemReq {
    pub mnemonic: String,
    pub item_id: String,
}

/// POST /api/v1/sdk/game/burn – Item verbrennen
pub async fn handle_sdk_game_burn(
    State(state): State<AppState>,
    Json(req): Json<BurnItemReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.burn_item(&req.item_id, &wallet.address())
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "item_id": req.item_id, "status": "burned" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LeaderboardQuery {
    pub game_id: String,
    pub limit: Option<usize>,
}

/// GET /api/v1/sdk/game/leaderboard?game_id=...&limit=100
pub async fn handle_sdk_game_leaderboard(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<LeaderboardQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let board = store.leaderboard(&q.game_id, q.limit.unwrap_or(100).min(500));
    Json(serde_json::json!({ "ok": true, "game_id": q.game_id, "count": board.len(), "leaderboard": board }))
}

#[derive(Deserialize)]
pub struct TournamentPrizeReq {
    pub game_id: String,
    pub server_wallet_mnemonic: String,
    pub prizes: Vec<PrizeEntry>,
}

#[derive(Deserialize)]
pub struct PrizeEntry {
    pub wallet: String,
    pub amount: String,
    pub rank: u32,
}

/// POST /api/v1/sdk/game/tournament/prize – Turnierpreise
pub async fn handle_sdk_tournament_prize(
    State(state): State<AppState>,
    Json(req): Json<TournamentPrizeReq>,
) -> impl IntoResponse {
    let server_wallet = match Wallet::from_mnemonic(&req.server_wallet_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Server-Mnemonic: {e}"))).into_response(),
    };

    {
        let store = read_game_store(&state);
        if !store.is_game_server(&req.game_id, &server_wallet.address()) {
            return (StatusCode::FORBIDDEN, err_json("Nicht der registrierte Game-Server")).into_response();
        }
        if !store.game_has_permission(&req.game_id, GamePermission::Tournament) {
            return (StatusCode::FORBIDDEN, err_json("Keine 'tournament' Berechtigung")).into_response();
        }
    }

    if req.prizes.is_empty() || req.prizes.len() > 50 {
        return (StatusCode::BAD_REQUEST, err_json("1-50 Preise erlaubt")).into_response();
    }

    let mut base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&server_wallet.address()) + state.node.mempool.sender_pending_count(&server_wallet.address())
    };

    let mut results = Vec::new();
    for prize in &req.prizes {
        let amount: Decimal = match prize.amount.parse() {
            Ok(a) if a > Decimal::ZERO => a,
            _ => {
                results.push(serde_json::json!({ "ok": false, "wallet": prize.wallet, "error": "Ungültiger Betrag" }));
                continue;
            }
        };

        let tx = match server_wallet.sign_tx_with_tier(
            TxType::Transfer, prize.wallet.clone(), amount, base_nonce,
            format!("Tournament #{} Rank #{}", req.game_id, prize.rank),
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "wallet": prize.wallet, "error": e.to_string() }));
                continue;
            }
        };

        let add_result = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };

        match add_result {
            Ok(_) => {
                broadcast_tx(&state, tx.clone());
                results.push(serde_json::json!({
                    "ok": true, "tx_id": tx.tx_id, "wallet": prize.wallet,
                    "amount": amount.to_string(), "rank": prize.rank,
                }));
                base_nonce += 1;
            }
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "wallet": prize.wallet, "error": e.to_string() }));
            }
        }
    }

    Json(serde_json::json!({
        "ok": true, "game_id": req.game_id,
        "prizes_distributed": results.iter().filter(|r| r["ok"] == true).count(),
        "results": results,
    })).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §7 AUTH – Sessions & Permissions
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct LinkWalletReq {
    pub player_id: String,
    pub game_id: String,
    pub mnemonic: String,
}

/// POST /api/v1/sdk/auth/link-wallet
pub async fn handle_sdk_link_wallet(
    State(state): State<AppState>,
    Json(req): Json<LinkWalletReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let link = with_game_store_mut(&state, |store| {
        store.link_wallet(&req.player_id, &req.game_id, &wallet.address())
    });

    Json(serde_json::json!({ "ok": true, "link": link })).into_response()
}

#[derive(Deserialize)]
pub struct CreateSessionReq {
    pub mnemonic: String,
    pub game_id: String,
    pub permissions: Option<Vec<GamePermission>>,
}

/// POST /api/v1/sdk/auth/session – SDK-Session starten
pub async fn handle_sdk_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let permissions = req.permissions.unwrap_or_else(|| vec![GamePermission::Basic]);

    let session = with_game_store_mut(&state, |store| {
        store.create_session(&wallet.address(), &req.game_id, permissions)
    });

    Json(serde_json::json!({
        "ok": true,
        "session": {
            "token": session.token,
            "wallet": session.wallet,
            "game_id": session.game_id,
            "permissions": session.permissions,
            "expires_at": session.expires_at,
        },
    })).into_response()
}

#[derive(Deserialize)]
pub struct RevokeSessionReq {
    pub token: String,
}

/// POST /api/v1/sdk/auth/revoke
pub async fn handle_sdk_revoke(
    State(state): State<AppState>,
    Json(req): Json<RevokeSessionReq>,
) -> impl IntoResponse {
    let result = with_game_store_mut(&state, |store| store.revoke_session(&req.token));
    match result {
        Ok(_) => ok_json(serde_json::json!({ "status": "revoked" })).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, err_json(&e.to_string())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct PermissionsQuery {
    pub token: String,
}

/// GET /api/v1/sdk/auth/permissions?token=...
pub async fn handle_sdk_permissions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<PermissionsQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    match store.validate_session(&q.token) {
        Some(session) => Json(serde_json::json!({
            "ok": true,
            "wallet": session.wallet,
            "game_id": session.game_id,
            "permissions": session.permissions,
            "expires_at": session.expires_at,
        })),
        None => Json(serde_json::json!({ "ok": false, "error": "Session ungültig oder abgelaufen" })),
    }
}

// ── GET /api/v1/sdk/auth/audit-log ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub wallet: Option<String>,
    pub game_id: Option<String>,
    pub limit: Option<usize>,
}

/// GET /api/v1/sdk/auth/audit-log?wallet=...&game_id=...&limit=100
pub async fn handle_sdk_audit_log(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuditLogQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let limit = q.limit.unwrap_or(100).min(1000);

    let entries: Vec<&stone::token::game_economy::AuditLogEntry> = if let Some(ref wallet) = q.wallet {
        store.audit_log_for_player(wallet, limit)
    } else if let Some(ref gid) = q.game_id {
        store.audit_log_for_game(gid, limit)
    } else {
        store.audit_log.iter().rev().take(limit).collect()
    };

    Json(serde_json::json!({
        "ok": true,
        "count": entries.len(),
        "audit_log": entries,
    }))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §8 PLAYER DASHBOARD – Übersicht für den Nutzer
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct PlayerQuery {
    pub wallet: String,
}

/// GET /api/v1/sdk/player/wallets?wallet=... – Alle Game-Wallets des Nutzers
pub async fn handle_sdk_player_wallets(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<PlayerQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());

    let wallets: Vec<serde_json::Value> = store.wallets_of(&q.wallet)
        .iter()
        .map(|gw| {
            let game_name = store.get_game(&gw.game_id)
                .map(|g| g.name.as_str())
                .unwrap_or("Unbekannt");
            serde_json::json!({
                "game_id": gw.game_id,
                "game_name": game_name,
                "game_wallet": gw.game_wallet,
                "balance": ledger.balance(&gw.game_wallet).to_string(),
                "daily_limit": gw.daily_limit.to_string(),
                "spent_today": gw.spent_today.to_string(),
                "frozen": gw.frozen,
                "permissions": gw.allowed_permissions,
                "created_at": gw.created_at,
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "main_balance": ledger.balance(&q.wallet).to_string(),
        "game_wallets_count": wallets.len(),
        "game_wallets": wallets,
    }))
}

/// GET /api/v1/sdk/player/activity?wallet=...&limit=50 – Letzte Aktivitäten
pub async fn handle_sdk_player_activity(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<TxHistoryQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let limit = q.limit.unwrap_or(50).min(200);
    let audit = store.audit_log_for_player(&q.wallet, limit);

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": audit.len(),
        "activity": audit,
    }))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §9 DEVELOPER DASHBOARD – Übersicht für Spielentwickler
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/sdk/developer/dashboard – Dashboard für den Entwickler (X-SDK-Key nötig)
///
/// Gibt alle relevanten Infos zurück: Spiel-Details, Guthaben,
/// aktive Spieler-Wallets, Items, offene Listings, letzte Audit-Einträge.
pub async fn handle_sdk_developer_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let store = read_game_store(&state);

    let game = match store.registered_games.get(&game_id) {
        Some(g) => g.clone(),
        None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
    };

    // Entwickler-Wallet Balance
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let dev_balance = ledger.balance(&game.developer_wallet);

    // Treasury-Wallet (Einnahmen aus dem Shop)
    let treasury_addr = derive_game_wallet(&game.developer_wallet, &game_id);
    let treasury_balance = ledger.balance(&treasury_addr);
    drop(ledger);

    // Alle Spieler-Wallets dieses Spiels
    let player_wallets: Vec<serde_json::Value> = store.game_wallets.values()
        .filter(|gw| gw.game_id == game_id)
        .map(|gw| {
            let bal = state.node.token_ledger.read()
                .unwrap_or_else(|e| e.into_inner())
                .balance(&gw.game_wallet);
            serde_json::json!({
                "owner": gw.owner_wallet,
                "game_wallet": gw.game_wallet,
                "balance": bal.to_string(),
                "daily_limit": gw.daily_limit.to_string(),
                "frozen": gw.frozen,
            })
        })
        .collect();

    // Items dieses Spiels
    let items: Vec<serde_json::Value> = store.items.values()
        .filter(|i| i.game_id == game_id && !i.burned)
        .map(|i| serde_json::json!({
            "item_id": i.item_id,
            "name": i.name,
            "rarity": i.rarity.to_string(),
            "owner": i.owner,
            "category": i.category,
        }))
        .collect();

    // Aktive Listings
    let active_listings: Vec<serde_json::Value> = store.listings.values()
        .filter(|l| l.status == stone::token::game_economy::ListingStatus::Active)
        .filter_map(|l| {
            store.items.get(&l.item_id).filter(|i| i.game_id == game_id).map(|i| {
                serde_json::json!({
                    "listing_id": l.listing_id,
                    "item": i.name,
                    "price": l.price.to_string(),
                    "seller": l.seller,
                })
            })
        })
        .collect();

    // Shop-Items (Katalog)
    let shop_items: Vec<serde_json::Value> = store.shop_items.values()
        .filter(|si| si.game_id == game_id && si.active)
        .map(|si| serde_json::json!({
            "shop_item_id": si.shop_item_id,
            "name": si.name,
            "price": si.price.to_string(),
            "stock": si.stock,
            "sold": si.sold,
        }))
        .collect();

    // Letzte Audit-Einträge
    let audit = store.audit_log_for_game(&game_id, 20);

    Json(serde_json::json!({
        "ok": true,
        "game": {
            "game_id": game.game_id,
            "name": game.name,
            "description": game.description,
            "website": game.website,
            "status": game.status,
            "permissions": game.permissions,
            "created_at": game.created_at,
        },
        "developer_wallet": game.developer_wallet,
        "developer_balance": dev_balance.to_string(),
        "treasury_wallet": treasury_addr,
        "treasury_balance": treasury_balance.to_string(),
        "player_count": player_wallets.len(),
        "players": player_wallets,
        "items_count": items.len(),
        "items": items,
        "active_listings": active_listings,
        "shop_items": shop_items,
        "recent_audit": audit,
    })).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §10 IN-GAME SHOP – Memo-basierter Item-Kauf
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct ShopBuyReq {
    pub mnemonic: String,
    pub game_id: String,
    pub shop_item_id: String,
    pub quantity: Option<u64>,
}

/// POST /api/v1/sdk/shop/buy – Item aus dem Game-Shop kaufen.
///
/// Flow: Spieler sendet Stone an die Treasury-Wallet des Spiels.
/// Die TX enthält ein Memo mit `shop:{game_id}:{shop_item_id}:{qty}`.
/// Nach Mempool-Akzeptanz wird das Item sofort an den Spieler ausgeliefert.
pub async fn handle_sdk_shop_buy(
    State(state): State<AppState>,
    Json(req): Json<ShopBuyReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };
    let qty = req.quantity.unwrap_or(1).max(1).min(100);

    // Shop-Item prüfen
    let (price, item_name, treasury_addr) = {
        let store = read_game_store(&state);
        let shop_item = match store.shop_items.get(&req.shop_item_id) {
            Some(si) if si.game_id == req.game_id && si.active => si.clone(),
            Some(_) => return (StatusCode::BAD_REQUEST, err_json("Shop-Item nicht verfügbar")).into_response(),
            None => return (StatusCode::NOT_FOUND, err_json("Shop-Item nicht gefunden")).into_response(),
        };
        if let Some(stock) = shop_item.stock {
            if shop_item.sold >= stock {
                return (StatusCode::CONFLICT, err_json("Ausverkauft")).into_response();
            }
        }
        let game = match store.registered_games.get(&req.game_id) {
            Some(g) => g.clone(),
            None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
        };
        let treasury = derive_game_wallet(&game.developer_wallet, &req.game_id);
        (shop_item.price * Decimal::from(qty), shop_item.name.clone(), treasury)
    };

    // Balance prüfen
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.balance(&wallet.address()) < price {
            return (StatusCode::BAD_REQUEST, err_json(&format!(
                "Nicht genug STONE: benötigt {price}, verfügbar {}",
                ledger.balance(&wallet.address())
            ))).into_response();
        }
    }

    let memo = format!("shop:{}:{}:{}", req.game_id, req.shop_item_id, qty);

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer, treasury_addr.clone(), price, nonce,
        memo.clone(),
        stone::token::FeeTier::Priority,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());

            // Item an Spieler ausliefern + sold counter hochzählen
            let delivered_items = with_game_store_mut(&state, |store| {
                // Stock updaten
                if let Some(si) = store.shop_items.get_mut(&req.shop_item_id) {
                    si.sold += qty;
                }
                // NFT-Items minten und an Spieler geben
                let mut item_ids = Vec::new();
                for _ in 0..qty {
                    let item_id = format!("shop-{}-{}", req.shop_item_id, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let item = stone::token::game_economy::GameItem {
                        item_id: item_id.clone(),
                        name: item_name.clone(),
                        description: format!("Gekauft aus dem Shop von {}", req.game_id),
                        category: "shop".to_string(),
                        rarity: stone::token::game_economy::ItemRarity::Common,
                        owner: wallet.address(),
                        game_id: req.game_id.clone(),
                        creator: treasury_addr.clone(),
                        metadata: std::collections::HashMap::new(),
                        created_at: chrono::Utc::now().timestamp(),
                        transferable: true,
                        burned: false,
                    };
                    store.items.insert(item_id.clone(), item);
                    item_ids.push(item_id);
                }
                store.audit(&req.game_id, &wallet.address(), "shop_buy", serde_json::json!({
                    "shop_item_id": req.shop_item_id,
                    "quantity": qty,
                    "price": price.to_string(),
                    "items": item_ids,
                }), true);
                item_ids
            });

            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "shop_item_id": req.shop_item_id,
                "item_name": item_name,
                "quantity": qty,
                "price": price.to_string(),
                "treasury": treasury_addr,
                "memo": memo,
                "items_delivered": delivered_items,
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── Shop-Catalog Management (Developer-only) ────────────────────────────────

#[derive(Deserialize)]
pub struct ShopItemCreateReq {
    pub shop_item_id: String,
    pub name: String,
    pub description: Option<String>,
    pub price: String,
    pub stock: Option<u64>,
    pub category: Option<String>,
    pub rarity: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// POST /api/v1/sdk/shop/item – Neues Item im Shop anlegen (X-SDK-Key nötig)
pub async fn handle_sdk_shop_create_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ShopItemCreateReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let price: Decimal = match req.price.parse() {
        Ok(p) if p > Decimal::ZERO => p,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Preis")).into_response(),
    };

    if req.shop_item_id.len() < 2 || req.shop_item_id.len() > 64 {
        return (StatusCode::BAD_REQUEST, err_json("shop_item_id muss 2-64 Zeichen sein")).into_response();
    }

    let rarity = match req.rarity.as_deref() {
        Some("common") | None => stone::token::game_economy::ItemRarity::Common,
        Some("uncommon") => stone::token::game_economy::ItemRarity::Uncommon,
        Some("rare") => stone::token::game_economy::ItemRarity::Rare,
        Some("epic") => stone::token::game_economy::ItemRarity::Epic,
        Some("legendary") => stone::token::game_economy::ItemRarity::Legendary,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültige Rarität")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        if store.shop_items.contains_key(&req.shop_item_id) {
            return Err("Shop-Item existiert bereits".to_string());
        }
        let item = stone::token::game_economy::ShopItem {
            shop_item_id: req.shop_item_id.clone(),
            game_id: game_id.clone(),
            name: req.name.clone(),
            description: req.description.clone().unwrap_or_default(),
            price,
            stock: req.stock,
            sold: 0,
            category: req.category.clone().unwrap_or_else(|| "general".to_string()),
            rarity,
            metadata: req.metadata.clone().unwrap_or(serde_json::json!({})),
            active: true,
            created_at: chrono::Utc::now().timestamp(),
        };
        store.shop_items.insert(req.shop_item_id.clone(), item);
        store.audit(&game_id, "developer", "shop_create_item", serde_json::json!({
            "shop_item_id": req.shop_item_id,
            "name": req.name,
            "price": price.to_string(),
            "stock": req.stock,
        }), true);
        Ok(())
    });

    match result {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "shop_item_id": req.shop_item_id,
            "name": req.name,
            "price": price.to_string(),
            "stock": req.stock,
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e)).into_response(),
    }
}

/// GET /api/v1/sdk/shop/catalog?game_id=... – Shop-Katalog eines Spiels (öffentlich)
pub async fn handle_sdk_shop_catalog(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<GameIdQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let items: Vec<serde_json::Value> = store.shop_items.values()
        .filter(|si| si.game_id == q.game_id && si.active)
        .map(|si| {
            let remaining = si.stock.map(|s| s.saturating_sub(si.sold));
            serde_json::json!({
                "shop_item_id": si.shop_item_id,
                "name": si.name,
                "description": si.description,
                "price": si.price.to_string(),
                "category": si.category,
                "rarity": si.rarity.to_string(),
                "stock": si.stock,
                "remaining": remaining,
                "sold": si.sold,
                "metadata": si.metadata,
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "game_id": q.game_id,
        "count": items.len(),
        "items": items,
    }))
}

#[derive(Deserialize)]
pub struct GameIdQuery {
    pub game_id: String,
}
