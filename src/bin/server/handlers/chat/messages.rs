//! Chat-Nachrichten: Senden, Konversationen, Nachrichten-Verlauf, Pending.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use stone::chat_policy::MessageTtl;
use stone::message_pool::PooledMessage;
use stone::token::{transaction::TxType, Wallet};

use crate::server::auth_middleware::require_user;
use crate::server::rate_limiter::{check_rate_limit, extract_client_ip};
use crate::server::state::AppState;

use super::{SendChatRequest, MessagesQuery, resolve_recipient, index_new_blocks_if_needed};

/// POST /api/v1/chat/send — Verschlüsselte Nachricht senden
pub async fn handle_chat_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<SendChatRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Rate Limiting: per User-Wallet
    let rl_key = if user.wallet_address.is_empty() {
        extract_client_ip(&headers)
    } else {
        user.wallet_address.clone()
    };
    if let Some(resp) = check_rate_limit(&state.rate_limits.chat_send, &rl_key, "Chat") {
        return resp;
    }

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
    if !to_wallet.starts_with("system:") {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let on_chain = ledger.all_registered_accounts().contains_key(&to_wallet);
        if !on_chain {
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

    // DSGVO: Nur content_hash landet on-chain, NICHT der verschluesselte Inhalt.
    let msg_id = uuid::Uuid::new_v4().to_string();
    let content_hash = stone::chat::compute_content_hash(&req.encrypted_content, &req.nonce);

    // ── System-Nachrichten: Off-chain only, kein TX nötig ──
    if to_wallet.starts_with("system:") {
        let now = chrono::Utc::now().timestamp();
        let entry = stone::chat::ChatEntry {
            msg_id: msg_id.clone(),
            from_wallet: wallet.address(),
            to_wallet: to_wallet.clone(),
            from_user_id: user.id.clone(),
            from_name: user.name.clone(),
            encrypted_content: req.encrypted_content.clone(),
            nonce: req.nonce.clone(),
            content_hash: content_hash.clone(),
            timestamp: now,
            block_index: 0,
            tx_id: String::new(),
        };
        let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
        idx.add_message(entry);
        stone::chat::save_chat_index(&idx);

        // Weiterleitung an Hub (damit Admin die Antwort sehen kann)
        let nomad_url = std::env::var("NOMAD_URL").unwrap_or_default();
        let node_secret = std::env::var("NODE_SECRET").unwrap_or_default();
        if !nomad_url.is_empty() && !node_secret.is_empty() {
            let body = json!({
                "from_user_id": user.id,
                "from_name": user.name,
                "from_wallet": wallet.address(),
                "message": req.encrypted_content,
                "timestamp": now,
            });
            tokio::spawn(async move {
                let _ = reqwest::Client::new()
                    .post(format!("{}/stone/testnet/support-reply", nomad_url))
                    .header("x-node-secret", node_secret)
                    .json(&body)
                    .send()
                    .await;
            });
        }

        return (
            StatusCode::OK,
            axum::Json(json!({
                "ok": true,
                "msg_id": msg_id,
                "status": "delivered",
                "system_message": true,
            })),
        ).into_response();
    }

    // ── Spam-Schutz / Message-Fee: derzeit DEAKTIVIERT ────────────────
    // Hintergrund: Es gab Inkonsistenzen zwischen UI-Balance und Ledger-Balance
    // (UI zeigt 0 obwohl 100 STONE vorhanden). Solange das nicht behoben ist
    // werden Nachrichten ohne Fee/Stake-Check zugestellt. Lite-PoW
    // (MESSAGE_POW_DIFFICULTY) bleibt als Basis-Spam-Schutz aktiv.
    //
    // Reaktivierung später: Balance prüfen + ledger.burn(addr, MESSAGE_FEE_STONE)
    // siehe Git-History dieser Datei für den ursprünglichen Code.

    // ── MessagePool: Nachricht bauen, signieren, in Pool einfügen ──────
    let now = chrono::Utc::now().timestamp();
    let from_wallet = wallet.address();

    // Deterministische msg_id berechnen
    let pool_msg_id = PooledMessage::compute_msg_id(
        &from_wallet,
        &to_wallet,
        &req.encrypted_content,
        &req.nonce,
        now,
    );

    // Ed25519-Signatur über SHA256(msg_id)
    let sig_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(pool_msg_id.as_bytes());
        hasher.finalize()
    };
    let signature = {
        use ed25519_dalek::Signer;
        wallet.signing_key().sign(&sig_hash)
    };

    // Lite-PoW lösen (Spam-Filter, ~2-5ms)
    let pow_nonce = stone::consensus::solve_message_pow(
        &pool_msg_id,
        stone::consensus::MESSAGE_POW_DIFFICULTY,
    );

    let pool_msg = PooledMessage {
        msg_id: pool_msg_id.clone(),
        sequence: 0, // wird vom Pool vergeben
        from_wallet: from_wallet.clone(),
        to_wallet: to_wallet.clone(),
        from_user_id: user.id.clone(),
        from_name: user.name.clone(),
        encrypted_content: req.encrypted_content.clone(),
        nonce: req.nonce.clone(),
        timestamp: now,
        signature: hex::encode(signature.to_bytes()),
        pow_nonce,
        status: stone::message_pool::MessageStatus::Pending,
    };

    // In MessagePool einfügen (Validierung + Sequenznummer)
    let seq = match state.node.message_pool.add_message(pool_msg.clone()) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({"ok": false, "error": format!("MessagePool: {e}")})),
            )
                .into_response()
        }
    };

    // Sofort im ChatIndex sichtbar (off-chain, block_index=0 = pending)
    {
        let entry = stone::chat::ChatEntry {
            msg_id: pool_msg_id.clone(),
            from_wallet: from_wallet.clone(),
            to_wallet: to_wallet.clone(),
            from_user_id: user.id.clone(),
            from_name: user.name.clone(),
            encrypted_content: req.encrypted_content.clone(),
            nonce: req.nonce.clone(),
            content_hash: content_hash.clone(),
            timestamp: now,
            block_index: 0,
            tx_id: String::new(),
        };
        let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
        idx.add_message(entry);
        stone::chat::save_chat_index(&idx);
    }

    // TTL im ChatPolicy-Store registrieren
    {
        let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
        policy.track_message(
            &pool_msg_id,
            "", // tx_id wird beim Batch-Confirm gesetzt
            &from_wallet,
            &to_wallet,
            ttl.clone(),
            now,
            0, // block_index wird beim Batch-Confirm aktualisiert
        );
    }

    // ── Zustellung an Empfänger (zweigleisig: P2P-Gossip + REST-Relay) ──
    // 1. P2P-Gossip: Sofortige libp2p Gossipsub-Zustellung (falls P2P aktiv)
    if let Some(ref net) = state.network {
        if let Ok(data) = serde_json::to_vec(&pool_msg) {
            let net = net.clone();
            tokio::spawn(async move {
                net.publish_gossip(stone::network::TOPIC_CHAT.as_str(), data).await;
            });
        }
    }

    // 2. REST-Relay: HTTP POST an alle bekannten Peers auf deren Sync-Port.
    //    Fallback wenn P2P-Gossip durch Firewalls/NAT blockiert wird.
    //    Der Empfänger speichert die Nachricht sofort in MessagePool + ChatIndex
    //    und das Dashboard sieht sie ohne auf einen Block warten zu müssen.
    {
        let msg_json = match serde_json::to_vec(&pool_msg) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        if !msg_json.is_empty() {
            let peers = state.node.get_peers();
            let msg_clone = pool_msg.clone();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                for peer in &peers {
                    if peer.status != stone::master::PeerStatus::Healthy {
                        continue;
                    }
                    let sync_url = crate::server::sync::to_sync_url(&peer.url);
                    let relay_url = format!("{sync_url}/message-relay");
                    match client
                        .post(&relay_url)
                        .json(&msg_clone)
                        .timeout(std::time::Duration::from_secs(3))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            println!(
                                "[chat] 📤 RELAY → {} – ok ({})",
                                &peer.url, resp.status(),
                            );
                        }
                        Ok(resp) => {
                            eprintln!(
                                "[chat] ⚠ RELAY → {} – HTTP {}",
                                &peer.url, resp.status(),
                            );
                        }
                        Err(e) => {
                            // Timeout/Netzwerk-Fehler → normal, nicht jeder Peer erreichbar
                            if !e.is_timeout() {
                                eprintln!("[chat] ⚠ RELAY → {} – {e}", &peer.url);
                            }
                        }
                    }
                }
            });
        }
    }

    // Push-Benachrichtigung an Empfänger senden (Fire & Forget)
    {
        let push_store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let fcm = state.fcm_client.clone();
        let sender_name = user.name.clone();
        let recipient = to_wallet.clone();
        tokio::spawn(async move {
            let body = format!("Nachricht von {}", sender_name);
            let sent = fcm.notify_wallet_with_body(
                &push_store,
                &recipient,
                &stone::push::PushType::NewMessage,
                &body,
            ).await;
            if sent {
                println!("[push] 📬 Chat-Push an {} gesendet", recipient);
            }
        });
    }

    (
        StatusCode::ACCEPTED,
        axum::Json(json!({
            "ok": true,
            "msg_id": pool_msg_id,
            "sequence": seq,
            "from": from_wallet,
            "to": to_wallet,
            "status": "pending",
            "ttl": ttl.to_string(),
            "message": "Nachricht sofort zugestellt, wird im nächsten Block per Merkle-Batch bestätigt",
        })),
    )
        .into_response()
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
    let mut convos = idx.conversations_for(&user.wallet_address, &users_map);
    let existing_peers: std::collections::HashSet<String> = convos.iter()
        .map(|c| c.peer_wallet.clone()).collect();
    drop(idx);

    // Keine Mempool-ChatTXs in die normale Konversationsansicht mischen:
    // Chat laeuft primar ueber MessagePool/ChatIndex (off-chain + Batch-Anchor).
    let _ = existing_peers;
    convos.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));

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
    let confirmed: Vec<stone::chat::ChatEntry> = idx.messages_between(&user.wallet_address, &peer_wallet, query.limit, query.offset)
        .into_iter().cloned().collect();
    let _confirmed_msg_ids: std::collections::HashSet<String> = confirmed.iter()
        .map(|m| m.msg_id.clone()).collect();
    drop(idx);

    let mut messages = confirmed;
    messages.sort_by_key(|m| m.timestamp);

    let block_height = state.node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
    let last_indexed = state.chat_index.lock().unwrap_or_else(|e| e.into_inner()).last_indexed_block;
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
