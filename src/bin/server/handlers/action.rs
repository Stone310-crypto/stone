use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::token::{TokenTx, Wallet};

use super::game::{execute_market_buy_with_signed_txs, execute_market_buy_with_wallet};
use super::super::state::{AppState, CreateMobileAction, MobileActionStatus};

fn err_json(msg: &str) -> Json<serde_json::Value> {
    Json(json!({ "ok": false, "error": msg }))
}

fn ok_json(data: serde_json::Value) -> Json<serde_json::Value> {
    let mut obj = data;
    obj.as_object_mut()
        .map(|m| m.insert("ok".into(), serde_json::json!(true)));
    Json(obj)
}

#[derive(Deserialize)]
pub struct ActionCreateReq {
    #[serde(rename = "type")]
    pub action_type: String,
    pub wallet: Option<String>,
    pub buyer_wallet: Option<String>,
    pub listing_id: Option<String>,
    pub item_id: Option<String>,
    pub game_id: Option<String>,
    pub amount: Option<String>,
    pub memo: Option<String>,
    pub buyer_discord_id: Option<String>,
    pub item_name: Option<String>,
    pub ttl_seconds: Option<u64>,
}

pub async fn handle_action_create(
    State(state): State<AppState>,
    Json(req): Json<ActionCreateReq>,
) -> impl IntoResponse {
    let action_type = req.action_type.trim().to_string();
    if action_type != "market_buy" {
        return (StatusCode::BAD_REQUEST, err_json("Nur type=market_buy wird unterstützt")).into_response();
    }

    let wallet = req
        .wallet
        .or(req.buyer_wallet)
        .unwrap_or_default()
        .trim()
        .to_lowercase();

    if wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, err_json("wallet oder buyer_wallet ist erforderlich")).into_response();
    }

    let listing_id = req.listing_id.as_ref().map(|s| s.trim().to_string());
    if listing_id.as_deref().unwrap_or("").is_empty() {
        return (StatusCode::BAD_REQUEST, err_json("listing_id ist erforderlich für market_buy")).into_response();
    }

    let action = state.action_store.create(CreateMobileAction {
        action_type,
        wallet: wallet.clone(),
        listing_id,
        item_id: req.item_id,
        game_id: req.game_id,
        amount: req.amount,
        memo: req.memo,
        buyer_discord_id: req.buyer_discord_id,
        item_name: req.item_name,
        ttl_seconds: req.ttl_seconds.unwrap_or(300),
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let remaining = action.expires_at.saturating_sub(now);

    let open_url = std::env::var("STONE_ACTION_OPEN_URL_BASE")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .map(|base| format!("{base}/{}", action.id));

    ok_json(json!({
        "action_id": action.id,
        "status": "pending",
        "remaining_seconds": remaining,
        "action": action,
        "open_url": open_url,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ActionPendingQuery {
    pub wallet: String,
}

pub async fn handle_action_mobile_pending(
    State(state): State<AppState>,
    Query(q): Query<ActionPendingQuery>,
) -> impl IntoResponse {
    let wallet = q.wallet.trim().to_lowercase();
    if wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, err_json("wallet fehlt")).into_response();
    }

    let pending = state.action_store.pending_for_wallet(&wallet);
    ok_json(json!({
        "wallet": wallet,
        "count": pending.len(),
        "pending": pending,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ActionApproveReq {
    pub action_id: String,

    /// Signierte Payment-TX des Käufers (empfohlen)
    #[serde(default)]
    pub pay_tx: Option<TokenTx>,

    /// Optionale signierte Fee-TX an MARKETPLACE_POOL
    #[serde(default)]
    pub fee_tx: Option<TokenTx>,

    /// Legacy-Fallback (deprecated)
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,
}

pub async fn handle_action_mobile_approve(
    State(state): State<AppState>,
    Json(req): Json<ActionApproveReq>,
) -> impl IntoResponse {
    let action = match state.action_store.get(&req.action_id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, err_json("Action nicht gefunden")).into_response(),
    };

    if action.status != MobileActionStatus::Pending {
        return (StatusCode::CONFLICT, err_json("Action ist nicht mehr pending")).into_response();
    }

    let listing_id = match action.listing_id.as_deref() {
        Some(id) if !id.trim().is_empty() => id.trim(),
        _ => return (StatusCode::BAD_REQUEST, err_json("Action ohne listing_id")).into_response(),
    };

    let exec = if let Some(pay_tx) = req.pay_tx {
        if pay_tx.from.to_lowercase() != action.wallet.to_lowercase() {
            return (StatusCode::FORBIDDEN, err_json("pay_tx.from passt nicht zur Action-Wallet")).into_response();
        }

        match execute_market_buy_with_signed_txs(&state, listing_id, pay_tx, req.fee_tx) {
            Ok(r) => r,
            Err(msg) => return (StatusCode::BAD_REQUEST, err_json(&msg)).into_response(),
        }
    } else {
        let mnemonic = match req.mnemonic {
            Some(m) if !m.trim().is_empty() => m,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    err_json("Sende pay_tx (+ optional fee_tx) oder legacy mnemonic"),
                )
                    .into_response();
            }
        };

        if !req.allow_mnemonic_auth {
            return (
                StatusCode::BAD_REQUEST,
                err_json(
                    "Mnemonic-Approve ist deprecated. Bitte signierte TXs senden. Für Legacy-Tests: allow_mnemonic_auth=true.",
                ),
            )
                .into_response();
        }

        if !crate::server::auth_middleware::mnemonic_auth_enabled() {
            return (StatusCode::GONE, Json(
                crate::server::auth_middleware::mnemonic_killswitch_body("handle_action_mobile_approve")
            )).into_response();
        }

        let wallet = match Wallet::from_mnemonic(mnemonic.trim()) {
            Ok(w) => w,
            Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
        };

        if wallet.address().to_lowercase() != action.wallet.to_lowercase() {
            return (StatusCode::FORBIDDEN, err_json("Wallet passt nicht zur Action")).into_response();
        }

        match execute_market_buy_with_wallet(&state, &wallet, listing_id) {
            Ok(r) => r,
            Err(msg) => return (StatusCode::BAD_REQUEST, err_json(&msg)).into_response(),
        }
    };

    let approved = match state.action_store.approve(&req.action_id, exec.tx_id.clone()) {
        Some(a) => a,
        None => return (StatusCode::CONFLICT, err_json("Action konnte nicht abgeschlossen werden")).into_response(),
    };

    ok_json(json!({
        "status": "approved",
        "action": approved,
        "tx": {
            "tx_id": exec.tx_id,
            "listing_id": exec.listing_id,
            "price": exec.total.to_string(),
            "fee": exec.fee.to_string(),
            "seller": exec.seller,
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ActionRejectReq {
    pub action_id: String,

    /// Empfohlen: Public-Key der Wallet (Hex oder stone1...)
    #[serde(default)]
    pub player_pubkey: Option<String>,

    /// Empfohlen: Signatur über "stone:action:reject:{action_id}"
    #[serde(default)]
    pub signature: Option<String>,

    /// Legacy-Fallback (deprecated)
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,

    pub reason: Option<String>,
}

pub async fn handle_action_mobile_reject(
    State(state): State<AppState>,
    Json(req): Json<ActionRejectReq>,
) -> impl IntoResponse {
    let action = match state.action_store.get(&req.action_id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, err_json("Action nicht gefunden")).into_response(),
    };

    if action.status != MobileActionStatus::Pending {
        return (StatusCode::CONFLICT, err_json("Action ist nicht mehr pending")).into_response();
    }

    let requester_wallet = if let (Some(pk), Some(sig)) = (req.player_pubkey.as_deref(), req.signature.as_deref()) {
        let normalized = match stone::token::normalize_address(pk.trim()) {
            Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
            _ => return (StatusCode::BAD_REQUEST, err_json("player_pubkey ungültig")).into_response(),
        };
        let msg = format!("stone:action:reject:{}", req.action_id).into_bytes();
        if let Err(e) = stone::crypto::verify_message_signature(&normalized, &msg, sig.trim()) {
            return (StatusCode::UNAUTHORIZED, err_json(&format!("Signatur ungültig: {e}"))).into_response();
        }
        normalized
    } else {
        let mnemonic = match req.mnemonic {
            Some(m) if !m.trim().is_empty() => m,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    err_json("Sende player_pubkey+signature oder legacy mnemonic"),
                )
                    .into_response();
            }
        };

        if !req.allow_mnemonic_auth {
            return (
                StatusCode::BAD_REQUEST,
                err_json(
                    "Mnemonic-Reject ist deprecated. Bitte Signatur senden. Für Legacy-Tests: allow_mnemonic_auth=true.",
                ),
            )
                .into_response();
        }
        if !crate::server::auth_middleware::mnemonic_auth_enabled() {
            return (StatusCode::GONE, Json(
                crate::server::auth_middleware::mnemonic_killswitch_body("handle_action_mobile_reject")
            )).into_response();
        }

        let wallet = match Wallet::from_mnemonic(mnemonic.trim()) {
            Ok(w) => w,
            Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
        };
        wallet.address().to_lowercase()
    };

    if requester_wallet.to_lowercase() != action.wallet.to_lowercase() {
        return (StatusCode::FORBIDDEN, err_json("Wallet passt nicht zur Action")).into_response();
    }

    let rejected = match state.action_store.reject(&req.action_id, req.reason.clone()) {
        Some(a) => a,
        None => return (StatusCode::CONFLICT, err_json("Action konnte nicht abgelehnt werden")).into_response(),
    };

    ok_json(json!({
        "status": "rejected",
        "action": rejected,
    }))
    .into_response()
}
