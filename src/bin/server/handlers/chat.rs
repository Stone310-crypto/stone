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
use stone::chat_policy::MessageTtl;
use stone::token::{transaction::TxType, Wallet};

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendChatRequest {
    /// Mnemonic (BIP39) des Senders – wird NICHT gespeichert
    #[serde(default)]
    pub mnemonic: String,
    /// Empfänger: Wallet-Adresse (64 Hex) oder User-ID (UUID)
    #[serde(default)]
    pub to: String,
    /// AES-256-GCM verschlüsselter Nachrichteninhalt (base64)
    #[serde(default)]
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    #[serde(default)]
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

    // Pflichtfelder prüfen
    if req.mnemonic.is_empty() || req.to.is_empty() || req.encrypted_content.is_empty() || req.nonce.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Fehlende Pflichtfelder (to, encrypted_content, nonce)"})),
        )
            .into_response();
    }

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

    // Prüfen: Empfänger muss ein registrierter Account sein
    // Primär: On-Chain Registry (account_names aus AccountRegister TXs)
    // Fallback: users.json (für Accounts die vor der Chain-Registrierung erstellt wurden)
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let on_chain = ledger.all_registered_accounts().contains_key(&to_wallet);
        if !on_chain {
            // Fallback: User in der lokalen User-Datenbank suchen
            let in_users = state.users.lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|u| u.wallet_address == to_wallet);
            if !in_users {
                return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({"ok": false, "error": "Empfänger hat kein registriertes Konto"})),
                )
                    .into_response();
            }
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

    // Nonce für die TX (Ledger-Nonce + pending TXs im Mempool vom selben Sender)
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&wallet.address());
        let pending = state.node.mempool.sender_pending_count(&wallet.address());
        base + pending
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
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
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

    let users_map = state.users.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
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

    let idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
    let messages = idx.messages_between(&user.wallet_address, &peer_wallet, query.limit, query.offset);

    // Diagnostic info
    let block_height = state.node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
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

/// Lokale Suche: state.users + on-chain account_names.
/// Gibt Vec<serde_json::Value> mit {user_id, name, wallet} zurück.
fn resolve_local(identifier: &str, state: &AppState) -> Vec<serde_json::Value> {
    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());

    // 1) Exakte User-ID
    if let Some(u) = users.iter().find(|u| u.id == identifier) {
        if !u.wallet_address.is_empty() {
            return vec![json!({
                "user_id": u.id,
                "name": u.name,
                "wallet": u.wallet_address,
            })];
        }
    }

    // 2) Wallet-Adresse direkt
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(u) = users.iter().find(|u| u.wallet_address == identifier) {
            return vec![json!({
                "user_id": u.id,
                "name": u.name,
                "wallet": u.wallet_address,
            })];
        }
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.all_registered_accounts().contains_key(identifier) {
            return vec![json!({
                "user_id": "",
                "name": "Unbekannt",
                "wallet": identifier,
            })];
        }
    }

    // 3) Name-Suche (case-insensitive, substring) — lokale Users
    let lower = identifier.to_lowercase();
    let mut matches: Vec<serde_json::Value> = users
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

    // 4) On-Chain Account-Registry (andere Nodes)
    {
        let known_wallets: std::collections::HashSet<String> = matches
            .iter()
            .filter_map(|m| m["wallet"].as_str().map(|s| s.to_string()))
            .collect();
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        for (wallet, name) in ledger.all_registered_accounts() {
            if known_wallets.contains(wallet) {
                continue;
            }
            if name.to_lowercase().contains(&lower) {
                let user_id = users.iter()
                    .find(|u| u.wallet_address == *wallet)
                    .map(|u| u.id.clone())
                    .unwrap_or_default();
                matches.push(json!({
                    "user_id": user_id,
                    "name": name,
                    "wallet": wallet,
                }));
            }
        }
    }

    matches
}

/// Peer-Nodes nach einem User fragen (parallel, Timeout 3s).
/// Nutzt den öffentlichen Sync-Port (4002) statt die Admin-API.
async fn resolve_from_peers(identifier: &str, state: &AppState) -> Vec<serde_json::Value> {
    let peers = state.node.get_peers();
    if peers.is_empty() {
        return vec![];
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut handles = Vec::new();
    for peer in &peers {
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        let url = format!(
            "{}/resolve/{}",
            sync_url,
            identifier
        );
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            match c.get(&url).send().await {
                Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
                _ => None,
            }
        }));
    }

    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut seen_wallets: std::collections::HashSet<String> = std::collections::HashSet::new();
    for h in handles {
        if let Ok(Some(body)) = h.await {
            if let Some(results) = body.get("results").and_then(|v| v.as_array()) {
                for r in results {
                    let w = r["wallet"].as_str().unwrap_or_default().to_string();
                    if !w.is_empty() && seen_wallets.insert(w) {
                        all.push(r.clone());
                    }
                }
            }
        }
    }
    all
}

/// GET /api/v1/chat/resolve/:identifier — User-ID / Name → Wallet-Adresse auflösen
///
/// Sucht erst lokal + on-chain, dann als Fallback auf allen Peer-Nodes.
pub async fn handle_chat_resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
) -> impl IntoResponse {
    let _user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let mut matches = resolve_local(&identifier, &state);

    // 5) Peer-Fallback: Wenn lokal nichts gefunden, Peer-Nodes fragen
    if matches.is_empty() {
        let peer_results = resolve_from_peers(&identifier, &state).await;
        // Deduplizieren gegen lokale Ergebnisse
        let known: std::collections::HashSet<String> = matches
            .iter()
            .filter_map(|m| m["wallet"].as_str().map(|s| s.to_string()))
            .collect();
        for r in peer_results {
            let w = r["wallet"].as_str().unwrap_or_default().to_string();
            if !w.is_empty() && !known.contains(&w) {
                matches.push(r);
            }
        }
    }

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

/// GET /api/v1/chat/resolve-public/:identifier — Öffentliche User-Suche (kein Auth)
///
/// Wird von Peer-Nodes aufgerufen um User cross-node aufzulösen.
/// Gibt nur lokale + on-chain Ergebnisse zurück (keine Peer-Weiterleitung,
/// um Endlos-Schleifen zu vermeiden).
pub async fn handle_chat_resolve_public(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
) -> impl IntoResponse {
    let matches = resolve_local(&identifier, &state);
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

    let block_height = state.node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;

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

    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());

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
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());

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
        let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
        let purged = stone::chat_policy::gc_expired_messages(&mut policy, &mut idx);
        if purged > 0 {
            let _ = stone::chat::save_chat_index(&idx);
            let _ = policy.persist();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Kontakte (Adding-Funktion)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct AddContactRequest {
    /// Wallet-Adresse oder User-ID oder Name des Kontakts
    pub identifier: String,
    /// Optionaler Spitzname
    #[serde(default)]
    pub nickname: Option<String>,
}

/// POST /api/v1/chat/contacts — Kontakt hinzufügen
pub async fn handle_add_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<AddContactRequest>,
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

    // Kontakt auflösen (Wallet, User-ID oder Name)
    let (contact_wallet, contact_user_id, contact_name) = {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        let identifier = req.identifier.trim();

        // 1) Direkte Wallet-Adresse (64 hex)
        if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
            let info = users.iter()
                .find(|u| u.wallet_address == identifier)
                .map(|u| (u.id.clone(), u.name.clone()));
            match info {
                Some((uid, name)) => (identifier.to_string(), uid, name),
                None => {
                    // Im Ledger nachschauen
                    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                    let name = ledger.account_name(identifier)
                        .unwrap_or("Unbekannt").to_string();
                    (identifier.to_string(), String::new(), name)
                }
            }
        }
        // 2) User-ID
        else if let Some(u) = users.iter().find(|u| u.id == identifier) {
            if u.wallet_address.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"ok": false, "error": "User hat kein Wallet"})),
                ).into_response();
            }
            (u.wallet_address.clone(), u.id.clone(), u.name.clone())
        }
        // 3) Name-Suche (exakt, case-insensitive)
        else {
            let lower = identifier.to_lowercase();
            let found = users.iter()
                .find(|u| !u.wallet_address.is_empty() && u.name.to_lowercase() == lower);
            match found {
                Some(u) => (u.wallet_address.clone(), u.id.clone(), u.name.clone()),
                None => {
                    // Fallback: On-Chain Ledger
                    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                    let chain_match = ledger.all_registered_accounts().iter()
                        .find(|(_, name)| name.to_lowercase() == lower)
                        .map(|(w, n)| (w.clone(), n.clone()));
                    match chain_match {
                        Some((wallet, name)) => (wallet, String::new(), name),
                        None => return (
                            StatusCode::NOT_FOUND,
                            axum::Json(json!({"ok": false, "error": "Kontakt nicht gefunden"})),
                        ).into_response(),
                    }
                }
            }
        }
    };

    if contact_wallet == user.wallet_address {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Du kannst dich nicht selbst hinzufügen"})),
        ).into_response();
    }

    let nickname = req.nickname.unwrap_or_else(|| contact_name.clone());

    let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    if contacts.add_contact(&user.wallet_address, &contact_wallet, &contact_user_id, &nickname) {
        stone::chat::save_contacts(&contacts);
        (
            StatusCode::CREATED,
            axum::Json(json!({
                "ok": true,
                "contact": {
                    "wallet": contact_wallet,
                    "user_id": contact_user_id,
                    "nickname": nickname,
                    "name": contact_name,
                },
                "message": format!("{} wurde zu deinen Kontakten hinzugefügt", contact_name),
            })),
        ).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            axum::Json(json!({"ok": false, "error": "Kontakt bereits vorhanden"})),
        ).into_response()
    }
}

/// GET /api/v1/chat/contacts — Kontaktliste abrufen
pub async fn handle_list_contacts(
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

    let contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    let my_contacts = contacts.get_contacts(&user.wallet_address);

    // Kontakte mit aktuellen User-Daten anreichern
    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let enriched: Vec<_> = my_contacts.iter().map(|c| {
        let current_name = users.iter()
            .find(|u| u.wallet_address == c.wallet)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| {
                // Fallback: Ledger
                let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                ledger.account_name(&c.wallet)
                    .unwrap_or("Unbekannt").to_string()
            });
        json!({
            "wallet": c.wallet,
            "user_id": c.user_id,
            "nickname": c.nickname,
            "name": current_name,
            "added_at": c.added_at,
            "is_contact": true,
        })
    }).collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "contacts": enriched,
            "count": enriched.len(),
        })),
    ).into_response()
}

/// DELETE /api/v1/chat/contacts/:wallet — Kontakt entfernen
pub async fn handle_remove_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(contact_wallet): Path<String>,
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

    let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
    if contacts.remove_contact(&user.wallet_address, &contact_wallet) {
        stone::chat::save_contacts(&contacts);
        (
            StatusCode::OK,
            axum::Json(json!({"ok": true, "message": "Kontakt entfernt"})),
        ).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Kontakt nicht gefunden"})),
        ).into_response()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Stonecoin im Chat senden & anfragen
// ═══════════════════════════════════════════════════════════════════════════════

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
/// Der Empfänger sieht im Chat eine Nachricht mit dem Transfer-Details.
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

    // Nonce für Transfer-TX (Ledger + pending TXs im Mempool)
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
        rust_decimal::Decimal::ZERO, // Fee
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

    // 2) Chat-Benachrichtigung als ChatMessage TX (Nonce inkl. pending TXs)
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
            // Transfer ist schon im Mempool, Chat-Nachricht ist nice-to-have
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
///
/// Sendet eine Chat-Nachricht mit einer Coin-Anforderung an einen anderen User.
/// Der Empfänger kann daraufhin über /api/v1/chat/send-coins die Coins senden.
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

    // Chat-Nachricht als Coin-Request senden (Nonce inkl. pending TXs)
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
