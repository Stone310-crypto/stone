//! Global Chat handlers – verschlüsselte P2P-Nachrichten über die Blockchain.
//!
//! Jeder User kann jedem anderen User eine Nachricht senden (per User-ID oder
//! Wallet-Adresse). Die Nachrichten werden AES-256-GCM-verschlüsselt als
//! TxType::ChatMessage in die Chain geschrieben und beim Mining validiert.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::chat_policy::{ChatPolicyStore, MessageTtl, messenger_min_stake};
use stone::token::{transaction::TxType, Wallet};

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendChatRequest {
    /// Mnemonic (BIP39) des Senders – wird NICHT gespeichert
    pub mnemonic: String,
    /// Empfänger: Wallet-Adresse (64 Hex) oder User-ID (UUID)
    pub to: String,
    /// AES-256-GCM verschlüsselter Nachrichteninhalt (base64)
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    pub nonce: String,
    /// Nachrichten-TTL: "30" (30 Tage) oder "90" (90 Tage). Default: 30
    #[serde(default)]
    pub ttl: Option<String>,
}

#[derive(Deserialize)]
pub struct MessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/chat/send — Verschlüsselte Nachricht senden
///
/// Erstellt eine TxType::ChatMessage TX, signiert sie mit dem Sender-Wallet
/// und gibt sie in den Mempool. Die Nachricht wird beim Mining in die Chain
/// aufgenommen und damit validiert.
pub async fn handle_chat_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<SendChatRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Sender-Wallet aus Mnemonic rekonstruieren
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"ok": false, "error": format!("Wallet-Fehler: {e}")})),
            )
                .into_response()
        }
    };

    // Wallet muss zum User passen
    if wallet.address() != user.wallet_address {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"ok": false, "error": "Wallet stimmt nicht mit dem User überein"})),
        )
            .into_response();
    }

    // Empfänger-Wallet auflösen (User-ID → Wallet-Adresse)
    let to_wallet = resolve_recipient(&req.to, &state);
    let to_wallet = match to_wallet {
        Some(w) => w,
        None => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Empfänger nicht gefunden"})),
            )
                .into_response()
        }
    };

    if to_wallet == wallet.address() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Du kannst dir nicht selbst schreiben"})),
        )
            .into_response();
    }

    // ── Stake-Gate: Messenger erfordert Minimum-Stake ─────────────────────
    {
        let pool = state.node.staking_pool.read().unwrap();
        let staked = pool.stakers.get(&wallet.address())
            .map(|s| s.staked_amount)
            .unwrap_or(rust_decimal::Decimal::ZERO);
        if let Err(missing) = ChatPolicyStore::check_messenger_access(staked) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "ok": false,
                    "error": format!(
                        "Messenger erfordert mindestens {} STONE Stake. Du hast {} gestaked, es fehlen {} STONE.",
                        messenger_min_stake(), staked, missing
                    ),
                    "required_stake": messenger_min_stake().to_string(),
                    "current_stake": staked.to_string(),
                    "missing": missing.to_string(),
                })),
            )
                .into_response();
        }
    }

    // Prüfen: Empfänger muss ein registrierter Account sein
    {
        let ledger = state.node.token_ledger.read().unwrap();
        if !ledger.all_registered_accounts().contains_key(&to_wallet) {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Empfänger hat kein registriertes Konto"})),
            )
                .into_response();
        }
    }

    // TTL bestimmen
    let ttl = MessageTtl::from_str_or_default(
        req.ttl.as_deref().unwrap_or("30")
    );

    // Memo-JSON bauen (mit TTL)
    let msg_id = uuid::Uuid::new_v4().to_string();
    let memo = json!({
        "msg_id": msg_id,
        "encrypted": req.encrypted_content,
        "nonce": req.nonce,
        "from_user_id": user.id,
        "from_name": user.name,
        "ttl": ttl.to_string(),
    })
    .to_string();

    // Nonce für die TX
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap();
        ledger.nonce(&wallet.address())
    };

    // TX signieren (amount=0, fee=0 für Chat – ChatMessages sind gebührenfrei)
    let tx = match wallet.sign_tx(
        TxType::ChatMessage,
        to_wallet.clone(),
        rust_decimal::Decimal::ZERO,
        rust_decimal::Decimal::ZERO,
        nonce,
        memo,
    ) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"ok": false, "error": format!("TX-Signierung fehlgeschlagen: {e}")})),
            )
                .into_response()
        }
    };

    // In Mempool einfügen
    let result = {
        let ledger = state.node.token_ledger.read().unwrap();
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // P2P broadcast
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    net.broadcast_tx(tx_clone).await;
                });
            }
            (
                StatusCode::ACCEPTED,
                axum::Json(json!({
                    "ok": true,
                    "msg_id": msg_id,
                    "tx_id": tx.tx_id,
                    "from": tx.from,
                    "to": tx.to,
                    "status": "pending",
                    "ttl": ttl.to_string(),
                    "message": "Nachricht wird beim nächsten Mining-Block bestätigt",
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            axum::Json(json!({"ok": false, "error": format!("Mempool-Fehler: {e}")})),
        )
            .into_response(),
    }
}

/// GET /api/v1/chat/conversations — Alle Konversationen des Users
pub async fn handle_chat_conversations(
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
        )
            .into_response();
    }

    // Neue Blöcke indexieren
    index_new_blocks_if_needed(&state);

    let users_map = state.users.lock().unwrap().clone();
    let idx = state.chat_index.lock().unwrap();
    let convos = idx.conversations_for(&user.wallet_address, &users_map);

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "conversations": convos,
        })),
    )
        .into_response()
}

/// GET /api/v1/chat/messages/:peer_wallet — Nachrichten mit einem bestimmten Peer
pub async fn handle_chat_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(peer_wallet): Path<String>,
    Query(query): Query<MessagesQuery>,
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

    // Neue Blöcke indexieren
    index_new_blocks_if_needed(&state);

    let idx = state.chat_index.lock().unwrap();
    let messages = idx.messages_between(&user.wallet_address, &peer_wallet, query.limit, query.offset);

    // Diagnostic info
    let block_height = state.node.chain.lock().unwrap().blocks.len() as u64;
    let last_indexed = idx.last_indexed_block;
    let mempool_count = state.node.mempool.pending_count();
    let mining_active = state.node.metrics.mining_throttle_pct.load(std::sync::atomic::Ordering::Relaxed) > 0;

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "peer": peer_wallet,
            "messages": messages,
            "count": messages.len(),
            "limit": query.limit,
            "offset": query.offset,
            "_debug": {
                "block_height": block_height,
                "last_indexed_block": last_indexed,
                "mempool_count": mempool_count,
                "mining_active": mining_active,
            }
        })),
    )
        .into_response()
}

/// GET /api/v1/chat/resolve/:identifier — User-ID / Name → Wallet-Adresse auflösen
pub async fn handle_chat_resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
) -> impl IntoResponse {
    let _user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let users = state.users.lock().unwrap();

    // 1) Exakte User-ID
    if let Some(u) = users.iter().find(|u| u.id == identifier) {
        if !u.wallet_address.is_empty() {
            return (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "user_id": u.id,
                    "name": u.name,
                    "wallet": u.wallet_address,
                })),
            )
                .into_response();
        }
    }

    // 2) Wallet-Adresse direkt
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(u) = users.iter().find(|u| u.wallet_address == identifier) {
            return (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "user_id": u.id,
                    "name": u.name,
                    "wallet": u.wallet_address,
                })),
            )
                .into_response();
        }
        // Wallet ohne User – trotzdem gültig wenn im Ledger
        let ledger = state.node.token_ledger.read().unwrap();
        if ledger.all_registered_accounts().contains_key(&identifier) {
            return (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "user_id": "",
                    "name": "Unbekannt",
                    "wallet": identifier,
                })),
            )
                .into_response();
        }
    }

    // 3) Name-Suche (case-insensitive, substring)
    let lower = identifier.to_lowercase();
    let matches: Vec<_> = users
        .iter()
        .filter(|u| !u.wallet_address.is_empty() && u.name.to_lowercase().contains(&lower))
        .map(|u| {
            json!({
                "user_id": u.id,
                "name": u.name,
                "wallet": u.wallet_address,
            })
        })
        .collect();

    if matches.is_empty() {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Kein User gefunden"})),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            axum::Json(json!({
                "ok": true,
                "results": matches,
            })),
        )
            .into_response()
    }
}

/// GET /api/v1/chat/pending — Pending Chat-TXs im Mempool
pub async fn handle_chat_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let all_pending = state.node.mempool.pending_txs();
    let total_mempool = all_pending.len();
    let pending: Vec<_> = all_pending
        .into_iter()
        .filter(|tx| {
            tx.tx_type == TxType::ChatMessage
                && (tx.from == user.wallet_address || tx.to == user.wallet_address)
        })
        .map(|tx| {
            json!({
                "tx_id": tx.tx_id,
                "from": tx.from,
                "to": tx.to,
                "timestamp": tx.timestamp,
                "memo": tx.memo,
            })
        })
        .collect();

    let block_height = state.node.chain.lock().unwrap().blocks.len() as u64;

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "pending": pending,
            "count": pending.len(),
            "_debug": {
                "total_mempool": total_mempool,
                "block_height": block_height,
            }
        })),
    )
        .into_response()
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/// User-ID oder Wallet-Adresse zu Wallet auflösen
fn resolve_recipient(identifier: &str, state: &AppState) -> Option<String> {
    // Direkte Wallet-Adresse (64 Hex)
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(identifier.to_string());
    }

    let users = state.users.lock().unwrap();

    // User-ID (UUID)
    if let Some(u) = users.iter().find(|u| u.id == identifier) {
        if !u.wallet_address.is_empty() {
            return Some(u.wallet_address.clone());
        }
    }

    // Name (exakter Match, case-insensitive)
    let lower = identifier.to_lowercase();
    users
        .iter()
        .find(|u| u.name.to_lowercase() == lower && !u.wallet_address.is_empty())
        .map(|u| u.wallet_address.clone())
}

/// Neue Blöcke in den Chat-Index laden (inkrementell)
///
/// Erkennt auch Chain-Resets: wenn `last_indexed_block > chain_len`,
/// wird der Index komplett neu aufgebaut.
fn index_new_blocks_if_needed(state: &AppState) {
    let chain = state.node.chain.lock().unwrap();
    let mut idx = state.chat_index.lock().unwrap();

    let chain_len = chain.blocks.len() as u64;
    let last_idx = idx.last_indexed_block;

    // ── Chain-Reset erkennen ──────────────────────────────────────────────
    // Wenn der Index weiter ist als die aktuelle Chain, wurde die Chain neu
    // aufgebaut (z.B. nach Node-Reset). Index muss komplett neu gebaut werden.
    if last_idx > 0 && chain_len > 0 && last_idx >= chain_len {
        println!(
            "[chat-index] ⚠️ Chain-Reset erkannt! last_indexed_block={} aber chain hat nur {} Blöcke. Rebuild...",
            last_idx, chain_len
        );
        let all_blocks: Vec<_> = chain.blocks.iter().collect();
        *idx = stone::chat::ChatIndex::rebuild_from_chain(&all_blocks);
        let _ = stone::chat::save_chat_index(&idx);
        println!(
            "[chat-index] ✅ Rebuild fertig: {} Konversationen, last_indexed_block={}",
            idx.conversations.len(),
            idx.last_indexed_block,
        );
        return;
    }

    // ── Inkrementelles Indexieren ─────────────────────────────────────────
    // chain hat Blöcke [0..chain_len-1], last_indexed_block ist der letzte verarbeitete
    if chain_len > 0 && (chain_len - 1) > last_idx {
        let skip_count = (last_idx + 1) as usize;
        let new_blocks: Vec<_> = chain
            .blocks
            .iter()
            .skip(skip_count)
            .collect();

        if !new_blocks.is_empty() {
            println!(
                "[chat-index] 📋 {} neue Blöcke indexieren (Block #{} → #{})",
                new_blocks.len(),
                skip_count,
                chain_len - 1,
            );
            idx.index_new_blocks(&new_blocks);
            let _ = stone::chat::save_chat_index(&idx);
        }
    }

    // ── Self-Destruct GC: Abgelaufene Nachrichten-Content löschen ─────────
    {
        let mut policy = state.node.chat_policy.write().unwrap();
        let purged = stone::chat_policy::gc_expired_messages(&mut policy, &mut idx);
        if purged > 0 {
            let _ = stone::chat::save_chat_index(&idx);
            let _ = policy.persist();
        }
    }
}
