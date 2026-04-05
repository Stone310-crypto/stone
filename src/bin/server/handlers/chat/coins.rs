//! Stonecoins im Chat senden & anfragen.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::token::{transaction::TxType, Wallet};

use crate::server::auth_middleware::require_user;
use crate::server::state::AppState;

use super::resolve_recipient;

#[derive(Deserialize)]
pub struct ChatSendCoinsRequest {
    /// Mnemonic (BIP39) des Senders
    #[serde(default)]
    pub mnemonic: String,
    /// Empfänger: Wallet-Adresse oder User-ID
    #[serde(default)]
    pub to: String,
    /// Betrag in STONE (z.B. "10.5")
    #[serde(default)]
    pub amount: String,
    /// Optionale Nachricht zum Transfer
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize)]
pub struct ChatRequestCoinsRequest {
    /// Mnemonic (BIP39) des Anfordernden
    #[serde(default)]
    pub mnemonic: String,
    /// Von wem angefordert: Wallet-Adresse oder User-ID
    #[serde(default)]
    pub from: String,
    /// Angeforderter Betrag in STONE
    #[serde(default)]
    pub amount: String,
    /// Optionale Nachricht zur Anforderung
    #[serde(default)]
    pub message: Option<String>,
}

/// POST /api/v1/chat/send-coins — Stonecoins im Chat senden
///
/// Kombiniert einen Token-Transfer mit einer Chat-Benachrichtigung.
pub async fn handle_chat_send_coins(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<ChatSendCoinsRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Sender-Wallet rekonstruieren
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": format!("Wallet-Fehler: {e}")})),
        ).into_response(),
    };

    if wallet.address() != user.wallet_address {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"ok": false, "error": "Wallet stimmt nicht mit dem User überein"})),
        ).into_response();
    }

    // Empfänger auflösen
    let to_wallet = match resolve_recipient(&req.to, &state) {
        Some(w) => w,
        None => return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Empfänger nicht gefunden"})),
        ).into_response(),
    };

    if to_wallet == wallet.address() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Du kannst dir nicht selbst Coins senden"})),
        ).into_response();
    }

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Ungültiger Betrag"})),
        ).into_response(),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Betrag muss positiv sein"})),
        ).into_response();
    }

    // Balance prüfen
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let balance = ledger.balance(&wallet.address());
        if balance < amount {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "ok": false,
                    "error": format!("Nicht genügend Guthaben. Balance: {} STONE, angefordert: {} STONE", balance, amount),
                    "balance": balance.to_string(),
                    "requested": amount.to_string(),
                })),
            ).into_response();
        }
    }

    // Nonce für Transfer-TX
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&wallet.address());
        base + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let msg_text = req.message.unwrap_or_default();

    // 1) Token-Transfer TX erstellen
    let transfer_memo = json!({
        "type": "chat_coin_transfer",
        "from_name": user.name,
        "message": msg_text,
    }).to_string();

    let transfer_tx = match wallet.sign_tx(
        TxType::Transfer,
        to_wallet.clone(),
        amount,
        rust_decimal::Decimal::ZERO,
        nonce,
        transfer_memo,
    ) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"ok": false, "error": format!("Transfer-TX fehlgeschlagen: {e}")})),
        ).into_response(),
    };

    // In Mempool
    let transfer_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(transfer_tx.clone(), Some(&ledger))
    };

    if let Err(e) = transfer_result {
        return (
            StatusCode::CONFLICT,
            axum::Json(json!({"ok": false, "error": format!("Transfer fehlgeschlagen: {e}")})),
        ).into_response();
    }

    // 2) Chat-Benachrichtigung als ChatMessage TX
    let chat_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&wallet.address());
        base + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let msg_id = uuid::Uuid::new_v4().to_string();
    let chat_memo = json!({
        "msg_id": msg_id,
        "encrypted": format!("💰 {} STONE gesendet{}", amount, if msg_text.is_empty() { String::new() } else { format!(" — {}", msg_text) }),
        "nonce": "",
        "from_user_id": user.id,
        "from_name": user.name,
        "msg_type": "coin_transfer",
        "amount": amount.to_string(),
        "transfer_tx_id": transfer_tx.tx_id,
    }).to_string();

    let chat_tx = match wallet.sign_tx(
        TxType::ChatMessage,
        to_wallet.clone(),
        rust_decimal::Decimal::ZERO,
        rust_decimal::Decimal::ZERO,
        chat_nonce,
        chat_memo,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[chat] Chat-Benachrichtigung fehlgeschlagen: {e}");
            return (
                StatusCode::ACCEPTED,
                axum::Json(json!({
                    "ok": true,
                    "transfer_tx_id": transfer_tx.tx_id,
                    "amount": amount.to_string(),
                    "to": to_wallet,
                    "warning": "Transfer erfolgreich, aber Chat-Benachrichtigung fehlgeschlagen",
                })),
            ).into_response();
        }
    };

    // Chat-TX in Mempool
    let _ = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(chat_tx.clone(), Some(&ledger))
    };

    // P2P broadcast (beide TXs)
    if let Some(ref net) = state.network {
        let net = net.clone();
        let tt = transfer_tx.clone();
        let ct = chat_tx.clone();
        tokio::spawn(async move {
            net.broadcast_tx(tt).await;
            net.broadcast_tx(ct).await;
        });
    }

    // Push-Benachrichtigung (Fire & Forget)
    {
        let push_store = state.push_tokens.lock().unwrap().clone();
        let fcm = state.fcm_client.clone();
        let sender_name = user.name.clone();
        let recipient = to_wallet.clone();
        let amt = amount.to_string();
        tokio::spawn(async move {
            let body = format!("{} hat dir {} STONE gesendet", sender_name, amt);
            let sent = fcm.notify_wallet_with_body(
                &push_store,
                &recipient,
                &stone::push::PushType::PaymentConfirmed,
                &body,
            ).await;
            if sent {
                println!("[push] 📬 Coin-Transfer-Push an {} gesendet", recipient);
            }
        });
    }

    (
        StatusCode::ACCEPTED,
        axum::Json(json!({
            "ok": true,
            "transfer_tx_id": transfer_tx.tx_id,
            "chat_tx_id": chat_tx.tx_id,
            "msg_id": msg_id,
            "from": wallet.address(),
            "to": to_wallet,
            "amount": amount.to_string(),
            "status": "pending",
            "message": format!("{} STONE an {} gesendet", amount, to_wallet),
        })),
    ).into_response()
}

/// POST /api/v1/chat/request-coins — Stonecoins im Chat anfordern
pub async fn handle_chat_request_coins(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<ChatRequestCoinsRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Wallet rekonstruieren
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": format!("Wallet-Fehler: {e}")})),
        ).into_response(),
    };

    if wallet.address() != user.wallet_address {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"ok": false, "error": "Wallet stimmt nicht mit dem User überein"})),
        ).into_response();
    }

    // Empfänger auflösen (von wem angefordert)
    let from_wallet = match resolve_recipient(&req.from, &state) {
        Some(w) => w,
        None => return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "User nicht gefunden"})),
        ).into_response(),
    };

    if from_wallet == wallet.address() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Du kannst nicht von dir selbst anfordern"})),
        ).into_response();
    }

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Ungültiger Betrag"})),
        ).into_response(),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Betrag muss positiv sein"})),
        ).into_response();
    }

    let msg_text = req.message.unwrap_or_default();

    // Chat-Nachricht als Coin-Request senden
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&wallet.address());
        base + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let msg_id = uuid::Uuid::new_v4().to_string();
    let memo = json!({
        "msg_id": msg_id,
        "encrypted": format!("🔔 {} STONE angefordert{}", amount, if msg_text.is_empty() { String::new() } else { format!(" — {}", msg_text) }),
        "nonce": "",
        "from_user_id": user.id,
        "from_name": user.name,
        "msg_type": "coin_request",
        "amount": amount.to_string(),
    }).to_string();

    let tx = match wallet.sign_tx(
        TxType::ChatMessage,
        from_wallet.clone(),
        rust_decimal::Decimal::ZERO,
        rust_decimal::Decimal::ZERO,
        nonce,
        memo,
    ) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"ok": false, "error": format!("TX-Erstellung fehlgeschlagen: {e}")})),
        ).into_response(),
    };

    // In Mempool
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    net.broadcast_tx(tx_clone).await;
                });
            }

            // Push-Benachrichtigung (Fire & Forget)
            {
                let push_store = state.push_tokens.lock().unwrap().clone();
                let fcm = state.fcm_client.clone();
                let sender_name = user.name.clone();
                let recipient = from_wallet.clone();
                let amt = amount.to_string();
                tokio::spawn(async move {
                    let body = format!("{} fordert {} STONE an", sender_name, amt);
                    let sent = fcm.notify_wallet_with_body(
                        &push_store,
                        &recipient,
                        &stone::push::PushType::PaymentRequest,
                        &body,
                    ).await;
                    if sent {
                        println!("[push] 📬 Coin-Request-Push an {} gesendet", recipient);
                    }
                });
            }

            (
                StatusCode::ACCEPTED,
                axum::Json(json!({
                    "ok": true,
                    "msg_id": msg_id,
                    "tx_id": tx.tx_id,
                    "from": wallet.address(),
                    "to": from_wallet,
                    "amount": amount.to_string(),
                    "status": "pending",
                    "msg_type": "coin_request",
                    "message": format!("{} STONE von {} angefordert", amount, from_wallet),
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            axum::Json(json!({"ok": false, "error": format!("Mempool-Fehler: {e}")})),
        ).into_response(),
    }
}
