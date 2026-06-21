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

/// Pull pending messages from known peers.
/// Called on every chat request to ensure the local node has the latest messages.
async fn pull_messages_from_peers(state: &AppState) {
    let peers = state.node.get_peers();
    if peers.is_empty() {
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    for peer in &peers {
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        let url = format!("{sync_url}/message-pool");
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    if let Some(msgs) = body.get("messages") {
                        if let Ok(msgs) = serde_json::from_value::<Vec<PooledMessage>>(msgs.clone()) {
                            if msgs.is_empty() { continue; }
                            let mut added = 0usize;
                            let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
                            for msg in &msgs {
                                match state.node.message_pool.add_message(msg.clone()) {
                                    Ok(_) => {
                                        if idx.upsert_pool_message(msg) {
                                            added += 1;
                                        }
                                    }
                                    Err(e) => {
                                        // Duplikate sind ok
                                        if !format!("{e}").contains("Duplicate") {
                                            eprintln!("[chat-pull] ⚠️ add_message failed: {e}");
                                        }
                                    }
                                }
                            }
                            if added > 0 {
                                stone::chat::save_chat_index(&idx);
                                println!("[chat-pull] 📬 {added} new messages from {}", peer.url);
                            } else {
                                println!("[chat-pull] No new messages from {} ({} already known)", peer.url, msgs.len());
                            }
                            break; // got messages from one peer, stop
                        }
                    }
                }
            }
            Err(e) => {
                // Timeout is normal, don't log
                if !e.is_timeout() {
                    eprintln!("[chat-pull] Failed to reach {}: {e}", peer.url);
                }
            }
            _ => {}
        }
    }
}

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
        Ok(s) => {
            println!("[chat-send] ✅ msg_id={:20}… seq={} from={}…→{}…",
                &pool_msg_id[..20.min(pool_msg_id.len())], s,
                &from_wallet[..12], &to_wallet[..12]);
            s
        }
        Err(e) => {
            eprintln!("[chat-send] ❌ MessagePool-Fehler: {e}");
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({"ok": false, "error": format!("MessagePool: {e}")})),
            ).into_response()
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
        println!("[chat-send] 📝 ChatIndex: added pending message {}", &pool_msg_id[..16]);
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

    // 2. REST-Relay: HTTP POST an alle bekannten Peers
    {
        let msg_json = match serde_json::to_vec(&pool_msg) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        if !msg_json.is_empty() {
            let peers = state.node.get_peers();
            let msg_clone = pool_msg.clone();
            let self_url_hint = std::env::var("STONE_PUBLIC_URL").ok()
                .or_else(|| std::env::var("STONE_PUBLIC_IP").ok().map(|ip| format!("http://{ip}:3080")));
            println!("[chat-send] 🔗 Relay to {} peers", peers.len());
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                for peer in &peers {
                    if let Some(ref me) = self_url_hint {
                        if peer.url.contains(me) || me.contains(&peer.url) {
                            continue;
                        }
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
                            println!("[chat-relay] 📤→{} ok", &peer.url);
                        }
                        Ok(resp) => {
                            eprintln!("[chat-relay] ⚠️→{} HTTP {}", &peer.url, resp.status());
                        }
                        Err(e) => {
                            if !e.is_timeout() {
                                eprintln!("[chat-relay] ❌→{} {e}", &peer.url);
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
        let idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
        let users_map = state.users.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut convos: Vec<stone::chat::ConversationSummary> = Vec::new();
        for key in idx.conversations.keys() {
            let parts: Vec<&str> = key.splitn(2, ':').collect();
            if parts.len() == 2 {
                let p1 = parts[0]; let p2 = parts[1];
                let entries = &idx.conversations[key];
                let last = entries.last();
                convos.push(stone::chat::ConversationSummary {
                    peer_wallet: p2.to_string(),
                    peer_user_id: p1[..16.min(p1.len())].to_string(),
                    peer_name: format!("{}… ↔ {}…", &p1[..8], &p2[..8]),
                    last_message_preview: String::new(),
                    last_timestamp: last.map(|e| e.timestamp).unwrap_or(0),
                    last_msg_id: last.map(|e| e.msg_id.clone()).unwrap_or_default(),
                    last_from_wallet: last.map(|e| e.from_wallet.clone()).unwrap_or_default(),
                    unread_count: 0,
                    total_messages: entries.len() as u32,
                });
            }
        }
        convos.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));
        return (
            StatusCode::OK,
            axum::Json(json!({"ok": true, "conversations": convos, "_admin": true})),
        ).into_response();
    }

    // Pull messages from peers to stay synced
    pull_messages_from_peers(&state).await;

    // Index new blocks
    index_new_blocks_if_needed(&state);

    let users_map = state.users.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let wallet_short = &user.wallet_address[..16.min(user.wallet_address.len())];
    let pool_count = state.node.message_pool.pending_count();

    let idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
    println!(
        "[chat-conv] 👤 wallet={}… pool_pending={} chat_convs={}",
        wallet_short, pool_count, idx.conversations.len(),
    );

    let mut convos = idx.conversations_for(&user.wallet_address, &users_map);
    let all_conv_keys: Vec<String> = idx.conversations.keys().cloned().collect();
    drop(idx);

    if convos.is_empty() {
        println!(
            "[chat-conv] ⚠️ No conversations for wallet={}… — ChatIndex has {} total convs: {:?}",
            wallet_short, all_conv_keys.len(), all_conv_keys.iter().map(|k| &k[..40.min(k.len())]).collect::<Vec<_>>()
        );
    }

    // If no conversations from ChatIndex but pool has messages, show pool-only conversations
    if convos.is_empty() && pool_count > 0 {
        let pool_all = state.node.message_pool.messages_since(0);
        let mut seen_peers: std::collections::HashSet<String> = std::collections::HashSet::new();
        for pm in &pool_all {
            let peer = if pm.from_wallet == user.wallet_address {
                &pm.to_wallet
            } else if pm.to_wallet == user.wallet_address {
                &pm.from_wallet
            } else {
                continue;
            };
            if !seen_peers.insert(peer.clone()) {
                continue;
            }
            let peer_name = users_map.iter()
                .find(|u| u.wallet_address == *peer)
                .map(|u| u.name.clone())
                .unwrap_or_else(|| format!("{}…", &peer[..8]));
            convos.push(stone::chat::ConversationSummary {
                peer_wallet: peer.clone(),
                peer_user_id: String::new(),
                peer_name,
                last_message_preview: String::new(),
                last_timestamp: pm.timestamp,
                last_msg_id: pm.msg_id.clone(),
                last_from_wallet: pm.from_wallet.clone(),
                unread_count: 0,
                total_messages: 1,
            });
        }
        if !convos.is_empty() {
            println!("[chat-conv] 🔍 Added {} pool-only conversations", convos.len());
        }
    }

    convos.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));

    println!("[chat-conv] ✅ Returning {} conversations for {}", convos.len(), wallet_short);

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
        ).into_response();
    }

    // Pull messages from peers
    pull_messages_from_peers(&state).await;

    // Index new blocks
    index_new_blocks_if_needed(&state);

    // Get confirmed messages from ChatIndex
    let idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
    let confirmed: Vec<stone::chat::ChatEntry> = idx.messages_between(
        &user.wallet_address, &peer_wallet, query.limit, query.offset
    ).into_iter().cloned().collect();
    let confirmed_count = confirmed.len();
    drop(idx);

    // Get pending messages from pool
    let pool_msgs = state.node.message_pool.messages_for_conversation(
        &user.wallet_address, &peer_wallet
    );
    let pool_count = pool_msgs.len();

    let wallet_short = &user.wallet_address[..12.min(user.wallet_address.len())];
    let peer_short = &peer_wallet[..12.min(peer_wallet.len())];

    println!(
        "[chat-msg] 👤{}↔{} confirmed={} pool_pending={}",
        wallet_short, peer_short, confirmed_count, pool_count,
    );

    // Merge: confirmed + pool (deduplicated)
    let mut messages = confirmed;
    for pm in &pool_msgs {
        if !messages.iter().any(|m| m.msg_id == pm.msg_id) {
            messages.push(stone::chat::ChatEntry {
                msg_id: pm.msg_id.clone(),
                from_wallet: pm.from_wallet.clone(),
                to_wallet: pm.to_wallet.clone(),
                from_user_id: pm.from_user_id.clone(),
                from_name: pm.from_name.clone(),
                encrypted_content: pm.encrypted_content.clone(),
                nonce: pm.nonce.clone(),
                content_hash: String::new(),
                timestamp: pm.timestamp,
                block_index: 0,
                tx_id: String::new(),
            });
        }
    }
    messages.sort_by_key(|m| m.timestamp);

    let pool_added = messages.len() - confirmed_count;
    println!(
        "[chat-msg] ✅ Returning {} msgs ({} confirmed + {} pool) for {}↔{}",
        messages.len(), confirmed_count, pool_added, wallet_short, peer_short,
    );

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "peer": peer_wallet,
            "messages": messages,
            "count": messages.len(),
            "limit": query.limit,
            "offset": query.offset,
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