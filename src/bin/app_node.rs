//! stone-app-node — Lightweight embedded node for the macOS Tauri desktop app.
//!
//! Differences from stone-master:
//!   • No snapshot sync on first start
//!   • No OTA-updater, no rollback check
//!   • No sync router (one port only)
//!   • No bridge monitor
//!   • No setup wizard / config file
//!   • No stage-4 recovery
//!   • All config via env vars:
//!       STONE_PORT            HTTP port          (default 3080)
//!       STONE_DATA_DIR        data directory     (default ./stone_data)
//!       STONE_API_KEY         cluster key
//!       STONE_BOOTSTRAP_NODES comma-separated peer URLs
//!       MINING_THROTTLE_PCT   CPU throttle 1-100 (default 25)
//!       STONE_P2P_DISABLED    set to "1" to disable libp2p

#[path = "server/mod.rs"]
mod server;

use std::{
    net::SocketAddr,
    sync::Arc,
};

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole},
    master::MasterNodeState,
    network::{start_network, NetworkHandle},
    storage::ChunkStore,
};

use server::{
    router::build_router,
    rate_limiter::RateLimits,
    state::{
        load_api_key, load_admin_key, load_peers_from_disk, load_trust_from_disk,
        AppState, HEARTBEAT_INTERVAL,
    },
    sync::{bootstrap_announce, pull_from_peer, spawn_auto_sync_task, spawn_peer_health_task},
};

use stone::network::NetworkEvent;

#[tokio::main]
async fn main() {
    // ── .env laden ────────────────────────────────────────────────────────
    match dotenvy::from_filename(".env") {
        Ok(path) => println!("[app-node] .env geladen: {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {}
        Err(e) => eprintln!("[app-node] .env Warnung: {e}"),
    }

    // ── Data-Dir anlegen ─────────────────────────────────────────────────
    let ddir = data_dir();
    if let Err(e) = std::fs::create_dir_all(&ddir) {
        eprintln!("[app-node] Warnung: Data-Dir konnte nicht erstellt werden: {e}");
    }

    // ── ChunkStore (ignoriert Fehler – app-node braucht keinen Storage) ──
    if let Err(e) = ChunkStore::new() {
        eprintln!("[app-node] ChunkStore-Warnung: {e}");
    }

    // ── API/Admin-Key ─────────────────────────────────────────────────────
    let api_key = Arc::new(load_api_key());
    let admin_key = Arc::new(load_admin_key(&api_key));

    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "stone-app-node".into())
        });

    println!("[app-node] Node-ID: {node_id}");
    println!("[app-node] Data-Dir: {ddir}");

    // ── Mining-Throttle aus Env ──────────────────────────────────────────
    if let Ok(pct) = std::env::var("MINING_THROTTLE_PCT") {
        if let Ok(v) = pct.trim().parse::<u64>() {
            println!("[app-node] Mining-Throttle: {v}%");
        }
    }

    // ── MasterNodeState (Blockchain + Token-Ledger) ──────────────────────
    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);

    // ── Users laden ──────────────────────────────────────────────────────
    let users = load_users();

    // ── Gespeicherte Peers laden ─────────────────────────────────────────
    let mut saved_peers = load_peers_from_disk();
    // Trust-Registry laden (kein Fehler wenn Datei fehlt)
    load_trust_from_disk(&node);
    if !saved_peers.is_empty() {
        println!("[app-node] {} Peer(s) aus Datei geladen", saved_peers.len());
        node.replace_peers(saved_peers.clone());
    }

    // ── Bootstrap-Nodes aus Env laden ───────────────────────────────────
    {
        let mut bootstrap: Vec<String> = Vec::new();
        if let Ok(env_val) = std::env::var("STONE_BOOTSTRAP_NODES") {
            for url in env_val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                bootstrap.push(url);
            }
        }
        // Fallback: hardcoded testnet seed
        if bootstrap.is_empty() {
            bootstrap.push("http://212.227.54.241:3080".to_string());
        }
        let existing = node.get_peers();
        for url in bootstrap {
            if !existing.iter().any(|p| p.url == url) {
                node.upsert_peer(stone::master::PeerInfo::new(&url));
            }
        }
    }

    // ── Heartbeat, Auto-Sync, Block-Timer ────────────────────────────────
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    let pop_mining_shared = stone::pop_mining::PopMiningState::new();
    MasterNodeState::start_block_timer(node.clone(), pop_mining_shared.clone());

    bootstrap_announce(&node).await;
    spawn_peer_health_task(node.clone());

    // ── Mempool GC ───────────────────────────────────────────────────────
    {
        let node_evict = node.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut gc: u64 = 0;
            loop {
                interval.tick().await;
                node_evict.mempool.evict_expired();
                gc += 1;
                if gc % 5 == 0 {
                    node_evict.mempool.gc_known_ids();
                }
            }
        });
    }

    // ── Chat-Index aufbauen ──────────────────────────────────────────────
    let chat_index_arc: Arc<std::sync::Mutex<stone::chat::ChatIndex>> = {
        let mut idx = stone::chat::load_chat_index();
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let chain_len = chain.blocks.len() as u64;
        let last_chain_block_idx = chain.blocks.last().map(|b| b.index).unwrap_or(0);
        if idx.last_indexed_block > 0 && chain_len > 0
            && idx.last_indexed_block > last_chain_block_idx
        {
            let all_blocks: Vec<_> = chain.blocks.iter().collect();
            idx = stone::chat::ChatIndex::rebuild_from_chain(&all_blocks, Some(&node.message_pool));
            let _ = stone::chat::save_chat_index(&idx);
        } else if chain_len > 0 && last_chain_block_idx > idx.last_indexed_block {
            let new_blocks: Vec<_> = chain.blocks.iter()
                .filter(|b| b.index > idx.last_indexed_block)
                .collect();
            idx.index_new_blocks(&new_blocks, Some(&node.message_pool));
            let _ = stone::chat::save_chat_index(&idx);
        }
        Arc::new(std::sync::Mutex::new(idx))
    };

    // ── Chat-Policy GC ───────────────────────────────────────────────────
    {
        let mut policy = node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
        let mut idx = chat_index_arc.lock().unwrap_or_else(|e| e.into_inner());
        let purged = stone::chat_policy::gc_expired_messages(&mut policy, &mut idx);
        if purged > 0 {
            stone::chat::save_chat_index(&idx);
            let _ = policy.persist();
        }
    }

    // ── P2P-Netzwerk (optional) ───────────────────────────────────────────
    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            println!("[app-node] P2P deaktiviert (STONE_P2P_DISABLED=1)");
            None
        } else {
            match start_network(None).await {
                Ok(handle) => {
                    println!("[app-node] P2P gestartet – PeerId: {}", handle.local_peer_id);
                    {
                        let count = node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                        handle.set_chain_count(count).await;
                    }
                    handle.set_chain_ref(node.chain.clone()).await;

                    // P2P Event-Loop ──────────────────────────────────────
                    {
                        let mut event_rx = handle.subscribe();
                        let node_bg = node.clone();
                        let handle_bg = handle.clone();
                        let api_key_bg = api_key.clone();
                        let chat_idx_bg = chat_index_arc.clone();

                        tokio::spawn(async move {
                            while let Ok(event) = event_rx.recv().await {
                                match event {
                                    // ── Neuer Block per Gossip ─────────────────
                                    NetworkEvent::BlockReceived { block, from_peer } => {
                                        let idx = block.index;
                                        let chain_result: Result<u64, String> = {
                                            let mut chain = node_bg.chain.lock().unwrap_or_else(|e| e.into_inner());

                                            // Discover validators from received blocks
                                            if !block.validator_pub_key.is_empty() {
                                                let mut vs = node_bg.validator_set.write().unwrap_or_else(|e| e.into_inner());
                                                if !vs.validators.iter().any(|v| v.public_key_hex == block.validator_pub_key) {
                                                    let info = stone::consensus::ValidatorInfo::new(
                                                        &block.signer, &block.validator_pub_key,
                                                    );
                                                    vs.add(info);
                                                    drop(vs);
                                                }
                                            }

                                            let block_txs: Vec<_> = block.transactions.clone();
                                            let chat_batches: Vec<_> = block.chat_batches.clone();

                                            // Determine PoA: accept with None (bypass PoA for embedded nodes)
                                            match chain.accept_peer_block((*block).clone(), Some(true), None) {
                                                Ok(_) => {
                                                    // TXs im Ledger verarbeiten
                                                    if !block_txs.is_empty() {
                                                        let mut ledger = node_bg.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                                        ledger.replay_mode = true;
                                                        let _receipts = ledger.apply_block_txs(&block_txs, idx);
                                                        ledger.replay_mode = false;
                                                        if let Err(e) = ledger.persist() {
                                                            eprintln!("[p2p] Token-Ledger persistieren fehlgeschlagen nach Block #{}: {}", idx, e);
                                                        }
                                                    }
                                                    stone::master::MasterNodeState::process_htlc_txs(&node_bg, &block_txs, idx);
                                                    for batch in &chat_batches {
                                                        if !batch.messages.is_empty() {
                                                            node_bg.message_pool.store_batch_record(
                                                                &batch.merkle_root, &batch.messages, idx,
                                                            );
                                                        }
                                                    }
                                                    {
                                                        let mut chat_idx = chat_idx_bg.lock().unwrap_or_else(|e| e.into_inner());
                                                        chat_idx.index_new_blocks(&[&block], Some(&node_bg.message_pool));
                                                        stone::chat::save_chat_index(&chat_idx);
                                                    }
                                                    if let Ok(mut t) = node_bg.block_timer.lock() {
                                                        t.reset();
                                                    }
                                                    Ok(chain.blocks.len() as u64)
                                                }
                                                Err(e) => Err(e),
                                            }
                                        };
                                        match chain_result {
                                            Ok(count) => {
                                                handle_bg.set_chain_count(count).await;
                                            }
                                            Err(ref e) if e.starts_with("Stale:") || e.contains("Duplikat") => {}
                                            Err(ref e) if e.starts_with("Gap:") || e.contains("previous_hash") => {
                                                eprintln!("[p2p] Block #{idx} Gap — erwarte Nachfolge-Blöcke");
                                                // Don't trigger HTTP resync — wait for the missing blocks
                                                // to arrive via P2P. The auto-sync task will handle gaps
                                                // every 30s.
                                            }
                                            Err(e) => {
                                                eprintln!("[p2p] Block #{idx} abgelehnt: {e}");
                                            }
                                        }
                                    }

                                    // ── TX per Gossip ───────────────────────────
                                    NetworkEvent::TxReceived { tx, .. } => {
                                        let ledger = node_bg.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                                        let _ = node_bg.mempool.add_tx(*tx, Some(&ledger));
                                    }

                                    // ── Chat per Gossip ─────────────────────────
                                    NetworkEvent::ChatMessageReceived { message, from_peer } => {
                                        let msg_clone = message.clone();
                                        if node_bg.message_pool.add_message(message).is_ok() {
                                            let mut idx = chat_idx_bg.lock().unwrap_or_else(|e| e.into_inner());
                                            if idx.upsert_pool_message(&msg_clone) {
                                                stone::chat::save_chat_index(&idx);
                                            }
                                            node_bg.events.publish(stone::master::NodeEvent::ChatMessageReceived {
                                                msg_id: msg_clone.msg_id.clone(),
                                                from_wallet: msg_clone.from_wallet.clone(),
                                                to_wallet: msg_clone.to_wallet.clone(),
                                                from_name: msg_clone.from_name.clone(),
                                                timestamp: msg_clone.timestamp,
                                                channel_type: "direct".to_string(),
                                                group_id: String::new(),
                                            });
                                            println!("[p2p] 💬 Chat von {}", &from_peer[..12.min(from_peer.len())]);
                                        }
                                    }

                                    // ── Chat Content Sync ───────────────────────
                                    NetworkEvent::ChatContentReceived { content, .. } => {
                                        let mut idx = chat_idx_bg.lock().unwrap_or_else(|e| e.into_inner());
                                        let key = stone::chat::ChatIndex::conv_key(&content.from_wallet, &content.to_wallet);
                                        let updated = if let Some(entries) = idx.conversations.get_mut(&key) {
                                            if let Some(entry) = entries.iter_mut().find(|e| e.msg_id == content.msg_id) {
                                                if entry.encrypted_content.is_empty() && !content.encrypted_content.is_empty() {
                                                    entry.encrypted_content = content.encrypted_content.clone();
                                                    entry.nonce = content.nonce.clone();
                                                    true
                                                } else { false }
                                            } else {
                                                entries.push(stone::chat::ChatEntry {
                                                    msg_id: content.msg_id.clone(),
                                                    from_wallet: content.from_wallet.clone(),
                                                    to_wallet: content.to_wallet.clone(),
                                                    from_user_id: String::new(),
                                                    from_name: String::new(),
                                                    encrypted_content: content.encrypted_content.clone(),
                                                    nonce: content.nonce.clone(),
                                                    content_hash: content.content_hash.clone(),
                                                    timestamp: chrono::Utc::now().timestamp(),
                                                    block_index: 0,
                                                    tx_id: String::new(),
                                                });
                                                true
                                            }
                                        } else {
                                            idx.conversations.insert(key, vec![stone::chat::ChatEntry {
                                                msg_id: content.msg_id.clone(),
                                                from_wallet: content.from_wallet.clone(),
                                                to_wallet: content.to_wallet.clone(),
                                                from_user_id: String::new(),
                                                from_name: String::new(),
                                                encrypted_content: content.encrypted_content.clone(),
                                                nonce: content.nonce.clone(),
                                                content_hash: content.content_hash.clone(),
                                                timestamp: chrono::Utc::now().timestamp(),
                                                block_index: 0,
                                                tx_id: String::new(),
                                            }]);
                                            true
                                        };
                                        if updated {
                                            stone::chat::save_chat_index(&idx);
                                        }
                                    }

                                    // ── Peer-Discovery ──────────────────────────
                                    NetworkEvent::PeerIdentified { peer_id, addresses, .. } => {
                                        let http_port = std::env::var("STONE_PORT")
                                            .ok()
                                            .and_then(|v| v.parse::<u16>().ok())
                                            .unwrap_or(3080);
                                        for addr in &addresses {
                                            let parts: Vec<&str> = addr.split('/').collect();
                                            for (i, part) in parts.iter().enumerate() {
                                                if *part == "ip4" {
                                                    if let Some(ip) = parts.get(i + 1) {
                                                        if *ip != "127.0.0.1" && *ip != "0.0.0.0"
                                                            && !ip.starts_with("172.")
                                                            && !ip.starts_with("10.")
                                                            && !ip.starts_with("192.168.")
                                                        {
                                                            let url = format!("http://{}:{}", ip, http_port);
                                                            let mut peer_info = stone::master::PeerInfo::new(&url);
                                                            peer_info.name = Some(peer_id[..12.min(peer_id.len())].to_string());
                                                            node_bg.upsert_peer(peer_info);
                                                            if let Ok(json) = serde_json::to_string_pretty(&node_bg.get_peers()) {
                                                                let _ = std::fs::write(
                                                                    format!("{}/peers.json", stone::blockchain::data_dir()),
                                                                    json,
                                                                );
                                                            }
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    NetworkEvent::PeerConnected { peer_id, .. } => {
                                        println!("[app-node] 🔗 Peer: {}", &peer_id[..12.min(peer_id.len())]);
                                    }

                                    NetworkEvent::PeerDisconnected { peer_id } => {
                                        eprintln!("[app-node] ⚡ Peer getrennt: {}", &peer_id[..12.min(peer_id.len())]);
                                    }

                                    // Unbehandelte Events stillschweigend ignorieren
                                    _ => {}
                                }
                            }
                        });
                    }

                    Some(handle)
                }
                Err(e) => {
                    eprintln!("[app-node] P2P-Fehler: {e} – fahre ohne P2P fort");
                    None
                }
            }
        };

    // ── Sync-Infrastruktur: peers aus bootstrap holen ────────────────────
    {
        // Erst nach P2P-Start: HTTP-Peer-Liste mit Peers abgleichen
        let peers = node.get_peers();
        if let Some(first) = peers.first() {
            let n = node.clone();
            let k = api_key.clone();
            let url = first.url.clone();
            tokio::spawn(async move {
                // Kurz warten, damit P2P-Handshake abgeschlossen ist
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                pull_from_peer(&n, &url, &k).await;
            });
        }
    }

    // ── System-Ressourcen-Cache ──────────────────────────────────────────
    {
        let node_res = node.clone();
        node_res.update_resource_cache();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let n = node_res.clone();
                tokio::task::spawn_blocking(move || n.update_resource_cache()).await.ok();
            }
        });
    }

    // ── AppState zusammenbauen ────────────────────────────────────────────
    let rate_limits = Arc::new(RateLimits::new());
    let updater = Arc::new(std::sync::RwLock::new({
        let mut um = stone::updater::UpdateManager::new(&ddir);
        um.load_persisted_update();
        um
    }));

    let state = AppState {
        node: node.clone(),
        users,
        api_key: api_key.clone(),
        admin_key,
        network: network_handle,
        rate_limits,
        updater,
        orgs: Arc::new(std::sync::Mutex::new(stone::organization::load_orgs())),
        chat_index: chat_index_arc,
        contacts: Arc::new(std::sync::Mutex::new(stone::chat::load_contacts())),
        contact_requests: Arc::new(std::sync::Mutex::new(stone::chat::load_contact_requests())),
        challenge_store: stone::auth::ChallengeStore::new(),
        qr_login_store: stone::auth::QrLoginStore::new(),
        miner_status_store: server::state::MinerStatusStore::new(),
        chat_groups: Arc::new(std::sync::Mutex::new(stone::chat::load_chat_groups())),
        announcements: Arc::new(std::sync::Mutex::new(stone::chat::load_announcements())),
        call_signals: Arc::new(stone::chat::CallSignalStore::default()),
        audio_rooms: server::handlers::audio_relay::new_audio_rooms(),
        push_tokens: Arc::new(std::sync::Mutex::new(stone::push::load_push_tokens())),
        fcm_client: Arc::new(stone::push::FcmClient::new()),
        action_store: server::state::ActionStore::new(),
        play_drops: server::state::PlayDropTracker::new(server::state::PlayDropConfig::from_env()),
        watchdog: stone::watchdog::WatchdogState::new(),
        pop_mining: pop_mining_shared,
    };

    // ── Router + HTTP-Server ──────────────────────────────────────────────
    let router = build_router(state);

    let mainnet = stone::network::is_mainnet();
    let default_port: u16 = if mainnet { 3180 } else { 3080 };
    let port: u16 = std::env::var("STONE_HTTP_PORT")
        .or_else(|_| std::env::var("STONE_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_port);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("[app-node] ❌ Port {port} bereits belegt! Beende alten Prozess oder setze STONE_PORT.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[app-node] ❌ Bind-Fehler: {e}");
            std::process::exit(1);
        }
    };

    let net_label = if mainnet { "MAINNET" } else { "TESTNET" };
    println!("[app-node] ═══════════════════════════════════════");
    println!("[app-node] 🌐 Netzwerk: {net_label}");
    println!("[app-node] HTTP auf 0.0.0.0:{port}");
    println!("[app-node] stone-app-node läuft ✅");
    println!("[app-node] ═══════════════════════════════════════");

    axum::serve(listener, router).await.expect("[app-node] HTTP-Server Fehler");
}
