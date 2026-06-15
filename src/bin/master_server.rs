//! Stone Master Node – entry point
//!
//! Stellt eine vollständige REST + WebSocket API für die externe Web-UI bereit.
//! Kein lokales GUI – alle Steuerung erfolgt über die vom Benutzer entwickelte Webseite.
//!
//! API-Übersicht:
//!   GET    /api/v1/status                    – Node- & Chain-Status
//!   GET    /api/v1/health                    – Einfacher Healthcheck (kein Auth)
//!   GET    /api/v1/metrics                   – Master-Node-Metriken
//!   GET    /api/v1/blocks                    – Alle Blöcke (paginiert)
//!   GET    /api/v1/blocks/:index             – Block nach Index
//!   GET    /api/v1/documents                 – Alle aktiven Dokumente (admin)
//!   GET    /api/v1/documents/user/:user_id   – Dokumente eines Nutzers
//!   GET    /api/v1/documents/:doc_id         – Dokument per ID
//!   GET    /api/v1/documents/:doc_id/history – Versionshistorie
//!   GET    /api/v1/documents/:doc_id/data    – Roh-Bytes (Chunk-Rekonstruktion)
//!   POST   /api/v1/documents                       – Dokument hochladen (Multipart)
//!   POST   /api/v1/documents/:doc_id/transfer       – Eigentum übertragen
//!   DELETE /api/v1/documents/:doc_id               – Soft-Delete
//!   GET    /api/v1/peers                     – Peer-Liste
//!   POST   /api/v1/peers                     – Peer hinzufügen
//!   DELETE /api/v1/peers/:idx                – Peer entfernen
//!   POST   /api/v1/sync                      – Manuelle Synchronisation
//!   POST   /api/v1/auth/signup               – Neuen Nutzer anlegen (pusht an Peers)
//!   POST   /api/v1/auth/login                – Phrase-Login
//!   POST   /api/v1/admin/sync-users          – Nutzer-Liste von Peer empfangen & mergen
//!   GET    /api/v1/chain/verify              – Chain-Integrität prüfen
//!   GET    /ws                               – WebSocket Event-Stream

#[path = "server/mod.rs"]
mod server;

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
};

use chrono::Timelike;

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole},
    master::MasterNodeState,
    network::{start_network, NetworkHandle},
    storage::ChunkStore,
};

use server::{
    router::build_router,
    sync_router::build_sync_router,
    rate_limiter::RateLimits,
    state::{load_api_key, load_admin_key, load_peers_from_disk, load_trust_from_disk, save_peers, AppState, HEARTBEAT_INTERVAL},
    sync::{bootstrap_announce, fetch_missing_chunks, pull_from_peer, spawn_auto_sync_task, spawn_peer_health_task},
};

static STAGE4_RECOVERY_RUNNING: AtomicBool = AtomicBool::new(false);

async fn maybe_run_stage4_snapshot_recovery(
    node: &Arc<MasterNodeState>,
    reason: &str,
) {
    let auto_enabled = std::env::var("STONE_SYNC_AUTO_SNAPSHOT_RECOVERY")
        .map(|v| v == "1")
        .unwrap_or(false);

    if !auto_enabled {
        eprintln!(
            "[snapshot] ⚠ WS-C Stage4 erkannt, Auto-Recovery aus (STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=1 zum Aktivieren): {reason}"
        );
        return;
    }

    if STAGE4_RECOVERY_RUNNING
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        eprintln!("[snapshot] ℹ Stage4-Recovery läuft bereits");
        return;
    }

    let (chain_height, local_genesis) = {
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let h = chain.blocks.len() as u64;
        let g = chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default();
        (h, g)
    };

    eprintln!(
        "[snapshot] 🚨 Starte WS-C Stage4 Auto-Recovery (height={}, reason={})",
        chain_height,
        reason,
    );

    match stone::snapshot::verified_download_snapshot(&local_genesis, chain_height).await {
        Ok(meta) => {
            eprintln!(
                "[snapshot] ✅ WS-C Stage4 Recovery erfolgreich: Block #{}, {:.1} MB",
                meta.block_height,
                meta.archive_size as f64 / 1_048_576.0,
            );
            eprintln!("[snapshot] 🔄 Beende Prozess für sauberen Neustart...");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[snapshot] ❌ WS-C Stage4 Recovery fehlgeschlagen: {e}");
            STAGE4_RECOVERY_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[tokio::main]
async fn main() {
    // ── .env laden (nur aus CWD, nicht aus Parent-Verzeichnissen) ─────────────
    match dotenvy::from_filename(".env") {
        Ok(path) => println!("[master] .env geladen: {}", path.display()),
        Err(dotenvy::Error::Io(_)) => { /* .env nicht gefunden – kein Fehler */ }
        Err(e) => eprintln!("[master] .env Warnung: {e}"),
    }

    std::fs::create_dir_all(data_dir()).expect("DATA_DIR anlegen");

    // Post-Update Rollback prüfen
    if stone::updater::check_post_update_rollback(&data_dir()) {
        eprintln!("[master] ⚠ Rollback durchgeführt – Neustart mit altem Binary...");
        let exe = std::env::current_exe().expect("current_exe");
        let args: Vec<String> = std::env::args().collect();
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(&exe).args(&args[1..]).exec();
        }
        std::process::exit(1);
    }

    ChunkStore::new().expect("ChunkStore anlegen");

    let api_key = Arc::new(load_api_key());
    let admin_key = Arc::new(load_admin_key(&api_key));
    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "stone-master".into())
        });

    println!("[master] Node-ID: {node_id}");
    println!(
        "[master] API-Key geladen: {}...",
        &api_key[..8.min(api_key.len())]
    );

    // ── Snapshot-Bootstrap: Prüfen ob wir eine frische Node sind ──────────
    {
        let (chain_height, local_genesis) = {
            let tmp_chain = stone::blockchain::StoneChain::load_or_create(&api_key);
            let h = tmp_chain.blocks.len() as u64;
            let g = tmp_chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default();
            (h, g)
        };
        if chain_height <= 1 {
            eprintln!("[snapshot] 🔍 Frische Node – starte verifizierten Snapshot-Sync...");
            match stone::snapshot::verified_download_snapshot(
                &local_genesis, chain_height,
            ).await {
                Ok(meta) => {
                    eprintln!(
                        "[snapshot] ✅ Verifizierter Snapshot geladen: Block #{}, {:.1} MB, state_root: {}",
                        meta.block_height,
                        meta.archive_size as f64 / 1_048_576.0,
                        &meta.state_root[..16.min(meta.state_root.len())],
                    );
                }
                Err(e) => {
                    eprintln!("[snapshot] ℹ️  Snapshot-Sync nicht möglich: {e}");
                    eprintln!("[snapshot] Normaler Block-Sync wird verwendet");
                }
            }
        }
    }

    // Master Node State initialisieren
    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);
    let updater = Arc::new(std::sync::RwLock::new({
        let mut um = stone::updater::UpdateManager::new(&stone::blockchain::data_dir());
        um.load_persisted_update();
        um
    }));

    // Gespeicherte Peers laden
    let mut saved_peers = load_peers_from_disk();
    if !saved_peers.is_empty() {
        let default_http = if stone::network::is_mainnet() { 3180 } else { 3080 };
        for p in &mut saved_peers {
            if let Some((scheme, rest)) = p.url.split_once("://") {
                let host_port = rest.split('/').next().unwrap_or(rest);
                let host = host_port.split(':').next().unwrap_or(host_port).trim();
                let port = host_port
                    .split(':')
                    .nth(1)
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(0);
                if !host.is_empty() && port == 8080 {
                    p.url = format!("{}://{}:{}", scheme, host, default_http);
                }
            }
            if let Some(pid) = &p.peer_id {
                if pid.parse::<libp2p::PeerId>().is_err() {
                    p.peer_id = None;
                }
            }
        }
        save_peers(&saved_peers);
    }
    if !saved_peers.is_empty() {
        println!("[master] {} Peer(s) aus Datei geladen", saved_peers.len());
        node.replace_peers(saved_peers);
    }

    // ── Bootstrap-Nodes laden ─────────────────────────────────────────────────
    // Quellen (in Priorität):
    //   1) STONE_BOOTSTRAP_NODES env (komma-separiert: "http://1.2.3.4:3080,http://5.6.7.8:3080")
    //   2) node_config.json → "bootstrap_nodes": ["http://..."]
    // Bootstrap-Nodes werden als Peers hinzugefügt (falls nicht schon vorhanden)
    {
        let mut bootstrap: Vec<String> = Vec::new();

        let self_url = {
            if let Ok(url) = std::env::var("STONE_PUBLIC_URL") {
                let trimmed = url.trim().to_string();
                if !trimmed.is_empty() {
                    Some(trimmed)
                } else {
                    None
                }
            } else if let Ok(ip) = std::env::var("STONE_PUBLIC_IP") {
                let ip = ip.trim().to_string();
                if ip.is_empty() {
                    None
                } else {
                    let default_http = if stone::network::is_mainnet() { 3180 } else { 3080 };
                    let configured_port = std::env::var("STONE_HTTP_PORT")
                        .or_else(|_| std::env::var("STONE_PORT"))
                        .ok()
                        .and_then(|v| v.parse::<u16>().ok())
                        .unwrap_or(default_http);
                    let port = if configured_port == 8080 { default_http } else { configured_port }
                        .to_string();
                    Some(format!("http://{}:{}", ip, port))
                }
            } else {
                None
            }
        };

        let same_host = |a: &str, b: &str| {
            let host = |url: &str| {
                let without_scheme = url.split("://").nth(1).unwrap_or(url);
                let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
                host_port.split(':').next().unwrap_or(host_port).trim().to_ascii_lowercase()
            };
            let ha = host(a);
            let hb = host(b);
            !ha.is_empty() && ha == hb
        };

        let normalize_bootstrap_url = |raw: &str| {
            let base = raw.trim().trim_end_matches('/');
            let default_http = if stone::network::is_mainnet() { 3180 } else { 3080 };
            let Some((scheme, rest)) = base.split_once("://") else {
                return base.to_string();
            };
            let host_port = rest.split('/').next().unwrap_or(rest);
            let host = host_port.split(':').next().unwrap_or(host_port).trim();
            let port = host_port
                .split(':')
                .nth(1)
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(default_http);
            let normalized_port = if port == 8080 { default_http } else { port };
            if host.is_empty() {
                base.to_string()
            } else {
                format!("{}://{}:{}", scheme, host, normalized_port)
            }
        };

        // Aus Env
        if let Ok(env_val) = std::env::var("STONE_BOOTSTRAP_NODES") {
            for url in env_val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                bootstrap.push(normalize_bootstrap_url(&url));
            }
        }

        // Aus node_config.json
        if bootstrap.is_empty() {
            let config_path = format!("{}/../../node_config.json", stone::blockchain::data_dir());
            let config_path2 = "node_config.json".to_string();
            for path in &[&config_path, &config_path2] {
                if let Ok(data) = std::fs::read_to_string(path) {
                    if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&data) {
                        if let Some(nodes) = cfg.get("bootstrap_nodes").and_then(|v| v.as_array()) {
                            for n in nodes {
                                if let Some(url) = n.as_str() {
                                    bootstrap.push(normalize_bootstrap_url(url));
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }

        // Fallback: zentrale Default-Bootstrap-URLs aus der Netzwerk-Schicht
        if bootstrap.is_empty() {
            bootstrap = stone::network::default_bootstrap_http_urls()
                .into_iter()
                .map(|u| normalize_bootstrap_url(&u))
                .collect();
        }

        if let Some(ref me) = self_url {
            bootstrap.retain(|url| !same_host(url, me));
        }

        if !bootstrap.is_empty() {
            let existing_urls: std::collections::HashSet<String> = node
                .get_peers()
                .iter()
                .map(|p| p.url.clone())
                .collect();

            let mut added = 0;
            for url in &bootstrap {
                if !existing_urls.contains(url)
                    && !existing_urls.iter().any(|u| same_host(u, url))
                {
                    let peer = stone::master::PeerInfo::new(url);
                    node.upsert_peer(peer);
                    added += 1;
                }
            }
            println!(
                "[master] 🌍 Bootstrap-Nodes: {} konfiguriert, {} neu hinzugefügt",
                bootstrap.len(),
                added
            );
        }
    }

    // Trust-Registry laden
    load_trust_from_disk(&node);
    {
        let summary = node.trust_summary();
        println!(
            "[master] Trust-Registry geladen: {} aktiv, {} pending, {} widerrufen",
            summary.active, summary.pending, summary.revoked
        );
    }

    let users = load_users();

    // On-Chain Account-Registry: Merge Chain-registrierte Accounts mit lokalen Users
    {
        let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.registered_account_count() > 0 {
            let mut local = users.lock().unwrap_or_else(|e| e.into_inner());
            let merged = stone::auth::rebuild_users_from_ledger(&ledger, &local);
            let chain_count = ledger.registered_account_count();
            *local = merged;
            stone::auth::save_users(&local);
            println!("[master] 📋 Users aus Chain-Registry geladen: {} Chain + {} lokal = {} gesamt",
                chain_count, local.len() - chain_count, local.len());
        }
    }

    // Hintergrund-Tasks starten
    // master_server ist ein reiner Full-Node (Sync, API, Validierung, Storage).
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    // Auto-Block-Timer: produziert nach auto_timeout_secs einen Block, wenn
    // kein CPU-Miner und kein aktiver Minecraft-PoP-Server verbunden ist.
    let pop_mining_shared = stone::pop_mining::PopMiningState::new();
    MasterNodeState::start_block_timer(node.clone(), pop_mining_shared.clone());

    // Peer-Discovery: Bei Bootstrap-Nodes registrieren & Health-Check starten
    bootstrap_announce(&node).await;
    spawn_peer_health_task(node.clone());

    // Mempool-Eviction: abgelaufene TXs und known_ids periodisch bereinigen
    {
        let node_evict = node.clone();
        tokio::spawn(async move {
            let mut evict_interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut gc_counter: u64 = 0;
            loop {
                evict_interval.tick().await;
                node_evict.mempool.evict_expired();
                gc_counter += 1;
                // known_ids GC alle 5 Minuten
                if gc_counter % 5 == 0 {
                    node_evict.mempool.gc_known_ids();
                }
            }
        });
    }

    // Game-Economy Dormancy-Tick (Active → Dormant → Abandoned).
    {
        let ne = node.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(3600));
            let mut ticks: u64 = 0;
            loop {
                iv.tick().await;
                let now = chrono::Utc::now().timestamp();
                {
                    let mut store = ne.game_economy.write().unwrap_or_else(|e| e.into_inner());
                    store.tick_dormancy(now);
                }
                ticks += 1;
                if ticks % 24 == 0 {
                    let store = ne.game_economy.read().unwrap_or_else(|e| e.into_inner()).clone();
                    if let Err(e) = store.persist() {
                        eprintln!("[game_economy] persist nach dormancy-tick fehlgeschlagen: {e}");
                    }
                }
            }
        });
    }

    // ChatIndex vorab erstellen, damit der P2P-Event-Loop ihn nutzen kann
    let chat_index_arc: Arc<std::sync::Mutex<stone::chat::ChatIndex>> = {
        let mut idx = stone::chat::load_chat_index();
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let chain_len = chain.blocks.len() as u64;
        let last_chain_block_idx = chain.blocks.last().map(|b| b.index).unwrap_or(0);
        if idx.last_indexed_block > 0 && chain_len > 0 && idx.last_indexed_block > last_chain_block_idx {
            println!("[chat-index] ⚠️ Chain-Reset erkannt beim Start! last_indexed_block={} aber letzter Block ist #{}. Rebuild...", idx.last_indexed_block, last_chain_block_idx);
            let old_content: std::collections::HashMap<String, (String, String)> = idx.conversations.values()
                .flat_map(|entries| entries.iter())
                .filter(|e| !e.encrypted_content.is_empty())
                .map(|e| (e.msg_id.clone(), (e.encrypted_content.clone(), e.nonce.clone())))
                .collect();
            let all_blocks: Vec<_> = chain.blocks.iter().collect();
            idx = stone::chat::ChatIndex::rebuild_from_chain(&all_blocks, Some(&node.message_pool));
            if !old_content.is_empty() {
                for entries in idx.conversations.values_mut() {
                    for entry in entries.iter_mut() {
                        if entry.encrypted_content.is_empty() {
                            if let Some((enc, nc)) = old_content.get(&entry.msg_id) {
                                entry.encrypted_content = enc.clone();
                                entry.nonce = nc.clone();
                            }
                        }
                    }
                }
            }
            let _ = stone::chat::save_chat_index(&idx);
            println!("[chat-index] ✅ Rebuild fertig: {} Konversationen, last_indexed_block={}", idx.conversations.len(), idx.last_indexed_block);
        } else if chain_len > 0 && last_chain_block_idx > idx.last_indexed_block {
            let new_blocks: Vec<_> = chain.blocks.iter()
                .filter(|b| b.index > idx.last_indexed_block)
                .collect();
            idx.index_new_blocks(&new_blocks, Some(&node.message_pool));
            let _ = stone::chat::save_chat_index(&idx);
        }
        Arc::new(std::sync::Mutex::new(idx))
    };

    // GC: Abgelaufene Nachrichten beim Start bereinigen
    {
        let mut policy = node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
        let mut idx = chat_index_arc.lock().unwrap_or_else(|e| e.into_inner());
        let purged = stone::chat_policy::gc_expired_messages(&mut policy, &mut idx);
        if purged > 0 {
            stone::chat::save_chat_index(&idx);
            let _ = policy.persist();
            println!("[startup] 🗑️ {} abgelaufene Nachrichten beim Start bereinigt", purged);
        }
    }

    // P2P-Netzwerk starten (optional – deaktivieren via STONE_P2P_DISABLED=1)
    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            println!("[master] P2P-Netzwerk deaktiviert (STONE_P2P_DISABLED=1)");
            None
        } else {
            match start_network(None).await {
                Ok(handle) => {
                    println!(
                        "[master] P2P-Netzwerk gestartet – PeerId: {}",
                        handle.local_peer_id
                    );

                    {
                        let count = node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                        handle.set_chain_count(count).await;
                    }
                    // Chain-Referenz setzen damit P2P-Peers Blöcke direkt serviert bekommen
                    handle.set_chain_ref(node.chain.clone()).await;

                    // Eigenen Stake-Level für Relay-Priorität setzen
                    {
                        let wallet = node.validator_set.read().unwrap_or_else(|e| e.into_inner())
                            .get(&node.node_id).map(|v| v.public_key_hex.clone())
                            .unwrap_or_default();
                        let level = {
                            let pool = node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
                            pool.stake_level(&wallet).min_stake() as u64
                        };
                        handle.set_stake_level(level).await;
                    }

                    // Periodisch Stake-Level aktualisieren (alle 5 Min)
                    {
                        let node_sl = node.clone();
                        let handle_sl = handle.clone();
                        tokio::spawn(async move {
                            let mut sl_interval = tokio::time::interval(std::time::Duration::from_secs(300));
                            loop {
                                sl_interval.tick().await;
                                let wallet = node_sl.validator_set.read().unwrap_or_else(|e| e.into_inner())
                                    .get(&node_sl.node_id).map(|v| v.public_key_hex.clone())
                                    .unwrap_or_default();
                                let level = {
                                    let pool = node_sl.staking_pool.read().unwrap_or_else(|e| e.into_inner());
                                    pool.stake_level(&wallet).min_stake() as u64
                                };
                                handle_sl.set_stake_level(level).await;
                            }
                        });
                    }

                    {
                        use stone::network::NetworkEvent;
                        let mut event_rx = handle.subscribe();
                        let node_bg = node.clone();
                        let handle_bg = handle.clone();
                        let api_key_bg = api_key.clone();
                        let chat_idx_bg = chat_index_arc.clone();
                        let updater_bg = updater.clone();
                        tokio::spawn(async move {
                            loop {
                                let event = match event_rx.recv().await {
                                    Ok(ev) => ev,
                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                        eprintln!("[p2p] ⚠ Event-Empfänger lag {n} Events hinterher – setze fort");
                                        continue;
                                    }
                                    Err(_) => break, // Sender dropped
                                };
                                match event {
                                NetworkEvent::BlockReceived { block, from_peer } => {
                                    let peer_urls: Vec<String> = {
                                        node_bg
                                            .get_peers()
                                            .into_iter()
                                            .filter(|p| p.is_healthy())
                                            .map(|p| p.url.clone())
                                            .collect()
                                    };
                                    for url in &peer_urls {
                                        fetch_missing_chunks(&block, url, &api_key_bg).await;
                                    }

                                    let poa_ok = {
                                        // Während Initial-Sync: PoA-Prüfung überspringen.
                                        // Die synced Blöcke wurden vom Netzwerk bereits akzeptiert.
                                        let syncing = !node_bg.metrics.initial_sync_done.load(
                                            std::sync::atomic::Ordering::Relaxed
                                        );
                                        if syncing {
                                            None // PoA bei Sync überspringen
                                        } else {
                                            let vs = node_bg.validator_set.read().unwrap_or_else(|e| e.into_inner());
                                            if vs.validators.is_empty() {
                                                // SECURITY: Nach initial_sync ist ein leeres ValidatorSet
                                                // nicht mehr erlaubt – kein PoA-Bypass.
                                                Some(false)
                                            } else {
                                                let (prev_hash, last_block_ts) = {
                                                    let chain = node_bg.chain.lock().unwrap_or_else(|e| e.into_inner());
                                                    let ph = chain.blocks.last().map(|b| b.hash.clone()).unwrap_or_else(|| "genesis".into());
                                                    let ts = chain.blocks.last().map(|b| b.timestamp);
                                                    (ph, ts)
                                                };
                                                let sync_done = node_bg.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed);
                                                let (sel_stakes, sel_jailed, sel_wallets) = node_bg.build_selection_context();
                                                let result = vs.verify_block_with_context(
                                                    &block.hash,
                                                    &block.signer,
                                                    &block.validator_signature,
                                                    &prev_hash,
                                                    block.index,
                                                    block.pow_nonce,
                                                    &sel_jailed,
                                                    &sel_stakes,
                                                    &sel_wallets,
                                                    last_block_ts,
                                                    sync_done,
                                                    &block.pow_hash,
                                                    block.pow_difficulty,
                                                    &block.validator_pub_key,
                                                    block.effective_difficulty,
                                                );
                                                Some(result.is_acceptable())
                                            }
                                        }
                                    };

                                    let block_for_chat = block.clone();

                                    // Block-Akzeptanz in eigenem Scope (Lock vor await droppen)
                                    enum BlockResult {
                                        Accepted(u64),
                                        Stale,
                                        NeedsResync { idx: u64, from: String, err: String },
                                        AlreadyKnown,
                                        Fork,
                                        Rejected,
                                    }

                                    let result = {
                                        let mut chain = node_bg.chain.lock().unwrap_or_else(|e| e.into_inner());
                                        let already_known =
                                            chain.blocks.iter().any(|b| b.hash == block.hash);
                                        if already_known {
                                            BlockResult::AlreadyKnown
                                        } else {
                                            let idx = block.index;
                                            let block_txs = block.transactions.clone();
                                            let chat_batches = block.chat_batches.clone();

                                            // Equivocation-Check vor Block-Akzeptanz
                                            {
                                                let mut tracker = node_bg.equivocation_tracker.lock().unwrap_or_else(|e| e.into_inner());
                                                if let Some(evidence) = tracker.check_and_record(
                                                    block.index,
                                                    &block.validator_pub_key,
                                                    &block.hash,
                                                ) {
                                                    eprintln!(
                                                        "[p2p] ⚠️  EQUIVOCATION: Validator {} hat Block #{} doppelt signiert! \
                                                         hash_a={}… hash_b={}…",
                                                        &evidence.validator_pub_key[..16.min(evidence.validator_pub_key.len())],
                                                        evidence.block_index,
                                                        &evidence.hash_a[..12.min(evidence.hash_a.len())],
                                                        &evidence.hash_b[..12.min(evidence.hash_b.len())],
                                                    );
                                                    // Auto-Slashing: Double-Sign → Stake-Penalty + Jail
                                                    MasterNodeState::slash_equivocation(&node_bg, &evidence);
                                                }
                                            }

                                            match chain.accept_peer_block(
                                                *block,
                                                poa_ok,
                                                Some(&*node_bg.checkpoint_store.read().unwrap_or_else(|e| e.into_inner())),
                                            ) {
                                                Ok(_) => {
                                                    // Orphan-TX-Recovery
                                                    let orphaned = std::mem::take(&mut chain.orphaned_blocks);
                                                    if !orphaned.is_empty() {
                                                        node_bg.mempool.requeue_orphaned_txs(&orphaned);
                                                        // Ledger nach Single-Block-Reorg neu aufbauen (BUG-11 Fix)
                                                        let rebuilt = stone::token::TokenLedger::rebuild_from_chain(&chain.blocks);
                                                        let mut ledger = node_bg.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                                        *ledger = rebuilt;
                                                        eprintln!(
                                                            "[sync] Token-Ledger nach Single-Block-Reorg neu aufgebaut: {} Accounts, Supply: {}",
                                                            ledger.account_count(),
                                                            ledger.total_supply()
                                                        );
                                                    } else if !block_txs.is_empty() {
                                                        let receipts;
                                                        {
                                                            let mut ledger = node_bg.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                                            // Block ist bereits in Chain aufgenommen → replay_mode
                                                            // (Nonce/Balance-Checks überspringen, Block ist finalisiert)
                                                            ledger.replay_mode = true;
                                                            receipts = ledger.apply_block_txs(&block_txs, idx);
                                                            ledger.replay_mode = false;
                                                            ledger.set_last_synced_block(idx);
                                                        }
                                                        // ── Persist außerhalb des Write-Locks ──
                                                        if !receipts.is_empty() {
                                                            if let Err(e) = node_bg.token_ledger.read().unwrap_or_else(|e| e.into_inner()).persist() {
                                                                eprintln!("[token] Ledger-Persist nach Peer-Block #{idx}: {e}");
                                                            }
                                                        }
                                                        for tx in &block_txs {
                                                            node_bg.mempool.mark_known(&tx.tx_id);
                                                            node_bg.mempool.remove_tx(&tx.tx_id);
                                                        }
                                                    }
                                                    // HTLC-TXs verarbeiten (Master-Server P2P-Pfad)
                                                    stone::master::MasterNodeState::process_htlc_txs(&node_bg, &block_txs, idx);
                                                    // Chat-Batch-Records speichern (für Chat-Index)
                                                    for batch in &chat_batches {
                                                        if !batch.messages.is_empty() {
                                                            node_bg.message_pool.store_batch_record(
                                                                &batch.merkle_root, &batch.messages, idx,
                                                            );
                                                        }
                                                    }
                                                    {
                                                        let mut chat_idx = chat_idx_bg.lock().unwrap_or_else(|e| e.into_inner());
                                                        chat_idx.index_new_blocks(&[&block_for_chat], Some(&node_bg.message_pool));
                                                        stone::chat::save_chat_index(&chat_idx);
                                                    }
                                                    BlockResult::Accepted(chain.blocks.len() as u64)
                                                }
                                                Err(ref e) if e.starts_with("Stale:") => BlockResult::Stale,
                                                Err(ref e)
                                                    if e.starts_with("Gap:")
                                                        || e.contains("previous_hash") =>
                                                {
                                                    let err = e.clone();
                                                    BlockResult::NeedsResync { idx, from: from_peer.clone(), err }
                                                }
                                                Err(ref e) if e.contains("Fork") || e.contains("fork")
                                                    || e.contains("nicht schwerer") || e.contains("Tiebreak")
                                                    || e.contains("Reorg abgelehnt") || e.contains("Timestamp") =>
                                                {
                                                    eprintln!("[p2p] Block #{idx} Fork/Reorg: {e}");
                                                    BlockResult::Fork
                                                }
                                                Err(ref e) if e.contains("PoA") || e.contains("Argon2")
                                                    || e.contains("Storage-Proof") || e.contains("difficulty")
                                                    || e.contains("Difficulty") || e.contains("Signer")
                                                    || e.contains("Signatur") =>
                                                {
                                                    eprintln!("[p2p] Block #{idx} validation mismatch (no penalty): {e}");
                                                    BlockResult::Fork
                                                }
                                                Err(e) => {
                                                    eprintln!("[p2p] Block #{idx} abgelehnt: {e}");
                                                    BlockResult::Rejected
                                                }
                                            }
                                        }
                                    }; // chain-Lock ist hier gedroppt

                                    match result {
                                        BlockResult::Accepted(count) => {
                                            handle_bg.set_chain_count(count).await;
                                            // Logging bei erstem Peer-Block, aber
                                            // initial_sync_done NICHT setzen – das macht
                                            // erst der 60-Sekunden-Timeout im Mining-Loop,
                                            // damit die PoA-Bypass-Phase den kompletten
                                            // initialen Sync abdeckt.

                                            // BlockTimer zurücksetzen (auch für Gossip-Blöcke),
                                            // sonst erzeugen alle Master nach 120s parallel Auto-Blöcke.
                                            if let Ok(mut t) = node_bg.block_timer.lock() {
                                                t.reset();
                                            }
                                        }
                                        BlockResult::NeedsResync { idx, from, err } => {
                                            eprintln!(
                                                "[p2p] Block #{idx} von {from}: {err} → starte HTTP-Resync"
                                            );
                                            // PeerId → HTTP-URL auflösen
                                            let http_port = std::env::var("STONE_PORT")
                                                .ok()
                                                .and_then(|v| v.parse::<u16>().ok())
                                                .unwrap_or(3080);
                                            // Eigene öffentliche IP ermitteln, um Resync-an-sich-selbst zu vermeiden
                                            let own_public_ip = std::env::var("STONE_PUBLIC_IP").unwrap_or_default();
                                            let mut resolved_url: Option<String> = None;

                                            let net_peers = handle_bg.get_peers().await;
                                            if let Some(np) = net_peers.iter().find(|p| p.peer_id == from) {
                                                for addr in &np.addresses {
                                                    let parts: Vec<&str> = addr.split('/').collect();
                                                    for (i, part) in parts.iter().enumerate() {
                                                        if *part == "ip4" {
                                                            if let Some(ip) = parts.get(i + 1) {
                                                                // Localhost, Unspecified, Docker-Bridge
                                                                // und private Netzwerke überspringen
                                                                if *ip == "127.0.0.1"
                                                                    || *ip == "0.0.0.0"
                                                                    || ip.starts_with("172.")
                                                                    || ip.starts_with("10.")
                                                                    || ip.starts_with("192.168.")
                                                                    || ip.starts_with("169.254.")
                                                                {
                                                                    continue;
                                                                }
                                                                // Eigene öffentliche IP nicht als Peer-URL verwenden
                                                                if !own_public_ip.is_empty() && *ip == own_public_ip.as_str() {
                                                                    eprintln!("[sync] ⚠ Überspringe eigene IP {ip} bei Peer-URL-Auflösung");
                                                                    continue;
                                                                }
                                                                resolved_url = Some(format!("http://{}:{}", ip, http_port));
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    if resolved_url.is_some() { break; }
                                                }
                                                // Fallback: Wenn kein öffentliches IP gefunden,
                                                // nimm das erste nicht-localhost IP (z.B. Tailscale 100.x / privates Netz)
                                                if resolved_url.is_none() {
                                                    for addr in &np.addresses {
                                                        let parts: Vec<&str> = addr.split('/').collect();
                                                        for (i, part) in parts.iter().enumerate() {
                                                            if *part == "ip4" {
                                                                if let Some(ip) = parts.get(i + 1) {
                                                                    if *ip != "127.0.0.1"
                                                                        && *ip != "0.0.0.0"
                                                                        && !ip.starts_with("172.")
                                                                    {
                                                                        // Auch hier eigene IP ausschließen
                                                                        if !own_public_ip.is_empty() && *ip == own_public_ip.as_str() {
                                                                            continue;
                                                                        }
                                                                        resolved_url = Some(format!("http://{}:{}", ip, http_port));
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if resolved_url.is_some() { break; }
                                                    }
                                                }
                                            }

                                            if let Some(url) = resolved_url {
                                                eprintln!("[sync] Resync via {url} (Peer {from})");
                                                let node_r = node_bg.clone();
                                                let key_r = api_key_bg.clone();
                                                tokio::spawn(async move {
                                                    pull_from_peer(&node_r, &url, &key_r).await;
                                                });
                                            } else {
                                                eprintln!("[sync] ⚠ Keine URL für Peer {from} – versuche alle bekannten Peers");
                                                let node_r = node_bg.clone();
                                                let key_r = api_key_bg.clone();
                                                tokio::spawn(async move {
                                                    let peers = node_r.get_peers();
                                                    for p in peers.iter().filter(|p| p.is_healthy()) {
                                                        pull_from_peer(&node_r, &p.url, &key_r).await;
                                                    }
                                                });
                                            }
                                        }
                                        BlockResult::Rejected => {
                                            // Peer hat ungültigen Block geliefert → Penalty
                                            handle_bg.report_penalty(&from_peer, 5, "rejected block").await;
                                        }
                                        _ => {} // Stale, AlreadyKnown, Fork
                                    }
                                }

                                // ── Token-TX per Gossipsub empfangen → in Mempool ──
                                NetworkEvent::TxReceived { tx, from_peer } => {
                                    // WICHTIG: P2P-Gossip-TXs NICHT als "local" markieren!
                                    // add_tx(tx, None) verhindert dass has_local_txs() true wird,
                                    // sonst triggern ALLE Nodes gleichzeitig den Auto-Block-Timer
                                    // und produzieren parallele Blöcke derselben TX → Fork.
                                    // Nur HTTP-TXs (add_tx(tx, Some(&ledger))) sind lokal.
                                    match node_bg.mempool.add_tx(*tx, None) {
                                        Ok(()) => {
                                            println!(
                                                "[p2p] 💸 TX von {from_peer} in Mempool aufgenommen (size={})",
                                                node_bg.mempool.pending_count()
                                            );
                                        }
                                        Err(e) => {
                                            let msg = format!("{e}");
                                            if !msg.contains("Duplikat") {
                                                eprintln!("[p2p] TX von {from_peer} abgelehnt: {e}");
                                            }
                                        }
                                    }
                                }

                                // ── Shard-Events ──────────────────────────────
                                NetworkEvent::ShardReceived { chunk_hash, shard_index, data, from_peer } => {
                                    // Shard wurde bereits in der P2P-Schicht gespeichert → nur Registry aktualisieren
                                    println!("[shard] ✅ Shard empfangen: {}[{}] ({} bytes) von {}", &chunk_hash[..8.min(chunk_hash.len())], shard_index, data.len(), &from_peer[..8.min(from_peer.len())]);
                                    let local_pid = handle_bg.local_peer_id.to_string();
                                    node_bg.shard_registry.add_holder(&chunk_hash, shard_index, &local_pid);
                                    node_bg.shard_registry.add_holder(&chunk_hash, shard_index, &from_peer);
                                    node_bg.shard_registry.persist();
                                }
                                NetworkEvent::ShardStored { chunk_hash, shard_index, peer_id, success, .. } => {
                                    if success {
                                        println!("[shard] ✅ Shard bestätigt: {}[{}] auf {}", &chunk_hash[..8.min(chunk_hash.len())], shard_index, &peer_id[..8.min(peer_id.len())]);
                                        node_bg.shard_registry.add_holder(&chunk_hash, shard_index, &peer_id);
                                        node_bg.shard_registry.persist();
                                    }
                                }
                                NetworkEvent::ShardRequestFailed { chunk_hash, shard_index, peer_id, error } => {
                                    eprintln!("[shard] ❌ Transfer fehlgeschlagen: {}[{}] → {}: {error}", &chunk_hash[..8.min(chunk_hash.len())], shard_index, &peer_id[..8.min(peer_id.len())]);
                                }

                                // ── Peer-Discovery → HTTP-Peer auto-registrieren ──
                                NetworkEvent::PeerIdentified { peer_id, addresses, .. } => {
                                    let http_port = std::env::var("STONE_PORT")
                                        .ok()
                                        .and_then(|v| v.parse::<u16>().ok())
                                        .unwrap_or(3080);
                                    let mut ip: Option<String> = None;
                                    for addr in &addresses {
                                        let parts: Vec<&str> = addr.split('/').collect();
                                        for (i, part) in parts.iter().enumerate() {
                                            if *part == "ip4" {
                                                if let Some(found_ip) = parts.get(i + 1) {
                                                    if *found_ip != "127.0.0.1" && *found_ip != "0.0.0.0" {
                                                        ip = Some(found_ip.to_string());
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if ip.is_some() { break; }
                                    }
                                    if let Some(ip) = ip {
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
                                    }
                                }

                                // ── Update-Events ──────────────────────────────────
                                NetworkEvent::UpdateManifestReceived { manifest_json, from_peer } => {
                                    match serde_json::from_slice::<stone::updater::UpdateManifest>(&manifest_json) {
                                        Ok(manifest) => {
                                            let mut um = updater_bg.write().unwrap_or_else(|e| e.into_inner());
                                            match um.receive_manifest(manifest.clone()) {
                                                Ok(true) => {
                                                    println!(
                                                        "[updater] 🆕 Update v{} von Peer {} empfangen",
                                                        manifest.version,
                                                        &from_peer[..12.min(from_peer.len())]
                                                    );
                                                    if um.config.auto_download {
                                                        let peer_urls: Vec<String> = node_bg.get_peers()
                                                            .iter()
                                                            .map(|p| p.url.clone())
                                                            .collect();
                                                        let missing = um.missing_chunks();
                                                        drop(um);

                                                        if !missing.is_empty() {
                                                            let updater_clone = updater_bg.clone();
                                                            tokio::spawn(async move {
                                                                let client = reqwest::Client::builder()
                                                                    .danger_accept_invalid_certs(true)
                                                                    .timeout(std::time::Duration::from_secs(30))
                                                                    .build()
                                                                    .unwrap();
                                                                for idx in missing {
                                                                    for url in &peer_urls {
                                                                        let chunk_url = format!(
                                                                            "{}/api/v1/updates/chunk/{}",
                                                                            url.trim_end_matches('/'), idx
                                                                        );
                                                                        if let Ok(resp) = client.get(&chunk_url).send().await {
                                                                            if resp.status().is_success() {
                                                                                if let Ok(data) = resp.bytes().await {
                                                                                    let mut um = updater_clone.write().unwrap_or_else(|e| e.into_inner());
                                                                                    if um.store_chunk(idx, data.to_vec()).is_ok() {
                                                                                        println!("[updater] ✓ Chunk {idx} heruntergeladen");
                                                                                        break;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                let mut um = updater_clone.write().unwrap_or_else(|e| e.into_inner());
                                                                if um.missing_chunks().is_empty() {
                                                                    if let Err(e) = um.verify_and_prepare() {
                                                                        eprintln!("[updater] Verifizierung: {e}");
                                                                    }
                                                                }
                                                            });
                                                        }
                                                    }
                                                }
                                                Ok(false) => {}
                                                Err(e) => eprintln!("[updater] Manifest abgelehnt: {e}"),
                                            }
                                        }
                                        Err(e) => eprintln!("[updater] Manifest-Parse: {e}"),
                                    }
                                }

                                // ── Neuer Peer → Shard-Rebalancing ──────────
                                NetworkEvent::PeerConnected { peer_id, .. } => {
                                    println!("[master] 🔗 Peer verbunden: {}", &peer_id[..12.min(peer_id.len())]);
                                    let node_rb = node_bg.clone();
                                    let handle_rb = handle_bg.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        let local_peer_id = handle_rb.local_peer_id.clone();
                                        let shard_store = match stone::shard::ShardStore::new() {
                                            Ok(s) => s,
                                            Err(e) => {
                                                eprintln!("[rebalance] ShardStore-Fehler: {e}");
                                                return;
                                            }
                                        };
                                        let (migrated, failed) = stone::storage::rebalance_shards(
                                            &shard_store,
                                            &node_rb.shard_registry,
                                            &handle_rb,
                                            &local_peer_id,
                                        ).await;
                                        if migrated > 0 || failed > 0 {
                                            println!("[master] 📦 Rebalancing: {} migriert, {} fehlgeschlagen",
                                                migrated, failed);
                                        }
                                    });
                                }

                                // ── Peer getrennt → Registry bereinigen + Repair ──
                                NetworkEvent::PeerDisconnected { peer_id } => {
                                    eprintln!("[master] ⚡ Peer getrennt: {}", &peer_id[..12.min(peer_id.len())]);
                                    // Holder aus Shard-Registry entfernen
                                    node_bg.shard_registry.remove_holder(&peer_id);
                                    node_bg.shard_registry.persist();

                                    // Verzögerten Repair-Check starten:
                                    // Nach 30 Sek prüfen ob degradierte Chunks repariert werden müssen
                                    let node_repair = node_bg.clone();
                                    let handle_repair = handle_bg.clone();
                                    tokio::spawn(async move {
                                        // Warten, damit kurze Reconnects keinen unnötigen Repair triggern
                                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                                        // Prüfen ob der Peer inzwischen wieder da ist
                                        let still_gone = !handle_repair.connected_peers().await
                                            .iter().any(|p| p.peer_id == peer_id);
                                        if !still_gone {
                                            println!("[repair] Peer {} ist wieder da – kein Repair nötig",
                                                &peer_id[..12.min(peer_id.len())]);
                                            return;
                                        }

                                        // Degradierte Chunks finden und Shards an verbleibende Peers re-verteilen
                                        let local_peer_id = handle_repair.local_peer_id.clone();
                                        let shard_store = match stone::shard::ShardStore::new() {
                                            Ok(s) => s,
                                            Err(e) => {
                                                eprintln!("[repair] ShardStore: {e}");
                                                return;
                                            }
                                        };
                                        let (migrated, failed) = stone::storage::rebalance_shards(
                                            &shard_store,
                                            &node_repair.shard_registry,
                                            &handle_repair,
                                            &local_peer_id,
                                        ).await;
                                        if migrated > 0 || failed > 0 {
                                            println!("[repair] 🔧 Repair nach Peer-Verlust: {} migriert, {} fehlgeschlagen",
                                                migrated, failed);
                                        }
                                    });
                                }

                                // ── Chat per Gossip empfangen ──────────
                                NetworkEvent::ChatMessageReceived { message, from_peer } => {
                                    let msg_clone = message.clone();
                                    match node_bg.message_pool.add_message(message) {
                                        Ok(seq) => {
                                            println!(
                                                "[p2p] 💬 Chat von {} (seq: {})",
                                                &from_peer[..12.min(from_peer.len())], seq,
                                            );
                                            // Sofort in ChatIndex aufnehmen, damit der Empfänger
                                            // die Nachricht via /api/v1/chat/messages/:peer sieht.
                                            {
                                                let mut idx = chat_idx_bg.lock().unwrap_or_else(|e| e.into_inner());
                                                if idx.upsert_pool_message(&msg_clone) {
                                                    stone::chat::save_chat_index(&idx);
                                                }
                                            }
                                            // WebSocket-Push an verbundene Clients
                                            node_bg.events.publish(stone::master::NodeEvent::ChatMessageReceived {
                                                msg_id: msg_clone.msg_id.clone(),
                                                from_wallet: msg_clone.from_wallet.clone(),
                                                to_wallet: msg_clone.to_wallet.clone(),
                                                from_name: msg_clone.from_name.clone(),
                                                timestamp: msg_clone.timestamp,
                                                channel_type: "direct".to_string(),
                                                group_id: String::new(),
                                            });
                                        }
                                        Err(_) => {}
                                    }
                                }

                                // ── Chat Content Sync (DSGVO off-chain) ───────────
                                NetworkEvent::ChatContentReceived { content, from_peer } => {
                                    let chat_index = chat_idx_bg.clone();
                                    let mut idx = chat_index.lock().unwrap_or_else(|e| e.into_inner());
                                    let key = stone::chat::ChatIndex::conv_key(&content.from_wallet, &content.to_wallet);
                                    let updated = if let Some(entries) = idx.conversations.get_mut(&key) {
                                        if let Some(entry) = entries.iter_mut().find(|e| e.msg_id == content.msg_id) {
                                            if entry.encrypted_content.is_empty() && !content.encrypted_content.is_empty() {
                                                entry.encrypted_content = content.encrypted_content.clone();
                                                entry.nonce = content.nonce.clone();
                                                true
                                            } else { false }
                                        } else {
                                            // Noch kein Eintrag — Content für spätere Zuordnung vorhalten
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
                                        // Neue Konversation — Entry anlegen
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
                                        println!(
                                            "[p2p] 📝 Chat-Content sync: msg_id={}… von {}",
                                            &content.msg_id[..8.min(content.msg_id.len())],
                                            &from_peer[..12.min(from_peer.len())],
                                        );
                                    }
                                }

                                // ── Range-Sync Batch (Fork-Reorg) ─────────────────
                                NetworkEvent::RangeSyncReceived { blocks, from_peer } => {
                                    let mut sorted = blocks;
                                    sorted.sort_by_key(|b| b.index);

                                    let reorg_result: Option<(u64, u64)> = {
                                        let mut chain = node_bg.chain.lock().unwrap_or_else(|e| e.into_inner());
                                        let local_len = chain.blocks.len();

                                        // Fork-Punkt finden
                                        let mut fork_at = 0usize;
                                        let first_received_idx = sorted.first().map(|b| b.index as usize).unwrap_or(0);
                                        let mut fork_before_range = false;
                                        for block in &sorted {
                                            let idx = block.index as usize;
                                            if idx < local_len {
                                                if chain.blocks[idx].hash == block.hash {
                                                    fork_at = idx + 1;
                                                } else {
                                                    if idx == first_received_idx {
                                                        // Fork liegt VOR dem Beginn des empfangenen Bereichs
                                                        fork_before_range = true;
                                                    }
                                                    break;
                                                }
                                            } else {
                                                fork_at = local_len;
                                                break;
                                            }
                                        }

                                        // Wenn der Fork vor dem empfangenen Bereich liegt,
                                        // müssen wir den überlappenden Teil als Fork-Punkt nehmen.
                                        // Wir vertrauen der längeren Peer-Chain und machen einen Deep-Reorg.
                                        if fork_before_range && first_received_idx > 0 {
                                            println!(
                                                "[sync] ⚠️  Fork vor Range-Beginn (Block #{}) – Deep-Reorg ab Block #{}",
                                                first_received_idx, first_received_idx
                                            );
                                            fork_at = first_received_idx;
                                        }

                                        let peer_new: Vec<_> = sorted.into_iter()
                                            .filter(|b| b.index as usize >= fork_at)
                                            .collect();
                                        let our_after_fork = local_len.saturating_sub(fork_at);

                                        if peer_new.len() > our_after_fork {
                                            // Reorg-Schutz: finalisierter Checkpoint darf nicht verletzt werden.
                                            {
                                                let cps = node_bg.checkpoint_store.read().unwrap_or_else(|e| e.into_inner());
                                                if let Err(e) = cps.check_reorg_allowed(fork_at as u64) {
                                                    eprintln!("[sync] ❌ Range-Sync abgelehnt: {e}");
                                                    continue;
                                                }
                                            }
                                            println!(
                                                "[sync] 🔄 Range-Sync von {}: fork_at={fork_at}, lokal={local_len}, {} neue Blöcke",
                                                &from_peer[..12.min(from_peer.len())], peer_new.len()
                                            );
                                            let orphaned = chain.truncate_to(fork_at as u64);
                                            if !orphaned.is_empty() {
                                                node_bg.mempool.requeue_orphaned_txs(&orphaned);
                                            }

                                            // Ledger komplett aus der getrunkten Chain neu aufbauen,
                                            // damit Balancen/Nonces konsistent sind (BUG-11 Fix)
                                            {
                                                let rebuilt = stone::token::TokenLedger::rebuild_from_chain(&chain.blocks);
                                                let mut ledger = node_bg.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                                *ledger = rebuilt;
                                                eprintln!(
                                                    "[sync] Token-Ledger nach Reorg neu aufgebaut: {} Accounts, Supply: {}",
                                                    ledger.account_count(),
                                                    ledger.total_supply()
                                                );
                                            }

                                            let mut applied = 0u64;
                                            for block in peer_new {
                                                let idx = block.index;
                                                let txs = block.transactions.clone();
                                                let chat_batches = block.chat_batches.clone();

                                                // Equivocation-Check
                                                {
                                                    let mut tracker = node_bg.equivocation_tracker.lock().unwrap_or_else(|e| e.into_inner());
                                                    let _ = tracker.check_and_record(
                                                        block.index,
                                                        &block.validator_pub_key,
                                                        &block.hash,
                                                    );
                                                }

                                                match chain.accept_peer_block(
                                                    block,
                                                    None,
                                                    Some(&*node_bg.checkpoint_store.read().unwrap_or_else(|e| e.into_inner())),
                                                ) {
                                                    Ok(_) => {
                                                        applied += 1;
                                                        if !txs.is_empty() {
                                                            let mut ledger = node_bg.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                                            ledger.replay_mode = true;
                                                            let _receipts = ledger.apply_block_txs(&txs, idx);
                                                            ledger.replay_mode = false;
                                                            if let Err(e) = ledger.persist() {
                                                                eprintln!("[token] Ledger-Persist nach Range-Sync Block #{idx}: {e}");
                                                            }
                                                            ledger.set_last_synced_block(idx);
                                                            for tx in &txs {
                                                                node_bg.mempool.mark_known(&tx.tx_id);
                                                                node_bg.mempool.remove_tx(&tx.tx_id);
                                                            }
                                                        }
                                                        // HTLC-TXs verarbeiten (Master-Server Range-Sync)
                                                        stone::master::MasterNodeState::process_htlc_txs(&node_bg, &txs, idx);
                                                        // Chat-Batch-Records speichern
                                                        for batch in &chat_batches {
                                                            if !batch.messages.is_empty() {
                                                                node_bg.message_pool.store_batch_record(
                                                                    &batch.merkle_root, &batch.messages, idx,
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("[sync] ✗ Range-Sync Block #{idx} fehlgeschlagen: {e}");
                                                        break;
                                                    }
                                                }
                                            }
                                            Some((chain.blocks.len() as u64, applied))
                                        } else {
                                            None
                                        }
                                    }; // chain-Lock hier gedroppt

                                    if let Some((new_count, applied)) = reorg_result {
                                        handle_bg.set_chain_count(new_count).await;
                                        println!("[sync] ✓ Range-Sync: {applied} Blöcke applied, Chain-Höhe={new_count}");
                                        // Auch Range-Sync resettet den BlockTimer
                                        if let Ok(mut t) = node_bg.block_timer.lock() {
                                            t.reset();
                                        }
                                    }
                                }

                                // ── Miner Connect/Heartbeat über Gossipsub ─────
                                NetworkEvent::MinerGossipReceived { kind, payload, from_peer } => {
                                    let now = chrono::Utc::now().timestamp();
                                    match kind.as_str() {
                                        "connect" => {
                                            if let Ok(msg) = serde_json::from_slice::<stone::master::MinerConnectMsg>(&payload) {
                                                if stone::master::miner_registry::validate_connect(&msg, now).is_ok() {
                                                    let mut reg = node_bg.miner_registry.write().unwrap_or_else(|e| e.into_inner());
                                                    reg.register_miner(
                                                        msg.wallet.clone(),
                                                        msg.pubkey.clone(),
                                                        msg.signature.clone(),
                                                        msg.timestamp,
                                                    );
                                                } else {
                                                    // Fake Connect vom Peer → Penalty
                                                    handle_bg.report_penalty(&from_peer, 2, "invalid miner-connect").await;
                                                }
                                            }
                                        }
                                        "heartbeat" => {
                                            if let Ok(msg) = serde_json::from_slice::<stone::master::MinerHeartbeat>(&payload) {
                                                let template = {
                                                    let tmpl = node_bg.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
                                                    tmpl.as_ref().map(|(t, _)| t.clone())
                                                };
                                                let partial_delta = node_bg.auto_mining_config.heartbeat_partial_delta;
                                                if let Some(template) = template {
                                                    match stone::master::miner_registry::validate_heartbeat_with_template(
                                                        &msg, now, &template, partial_delta,
                                                    ) {
                                                        Ok(()) => {
                                                            let eff = if template.effective_difficulty > 0 {
                                                                template.effective_difficulty
                                                            } else {
                                                                template.difficulty
                                                            };
                                                            let mut reg = node_bg.miner_registry.write().unwrap_or_else(|e| e.into_inner());
                                                            // Miner ggf. implizit registrieren (Gossip kann vor Connect ankommen)
                                                            if reg.get(&msg.wallet).is_none() {
                                                                reg.register_miner(
                                                                    msg.wallet.clone(),
                                                                    msg.pubkey.clone(),
                                                                    msg.signature.clone(),
                                                                    msg.timestamp,
                                                                );
                                                            }
                                                            let _ = reg.record_heartbeat(
                                                                &msg.wallet,
                                                                &msg.template_id,
                                                                msg.nonce,
                                                                msg.timestamp,
                                                                eff as u64,
                                                            );
                                                        }
                                                        Err(_) => {
                                                            handle_bg.report_penalty(&from_peer, 2, "invalid miner-heartbeat").await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                NetworkEvent::Error { message } => {
                                    if message.contains("WS-C Stage4")
                                        || message.contains("Snapshot-Eskalation")
                                    {
                                        maybe_run_stage4_snapshot_recovery(&node_bg, &message).await;
                                    } else {
                                        eprintln!("[p2p] Fehler: {message}");
                                    }
                                }

                                _ => {} // Listening etc.
                                }
                            }
                        });
                    }

                    Some(handle)
                }
                Err(e) => {
                    eprintln!("[master] P2P-Netzwerk konnte nicht gestartet werden: {e}");
                    None
                }
            }
        };

    let rate_limits = Arc::new(RateLimits::new());

    // Rate-Limiter Cleanup-Task (alle 5 Minuten)
    {
        let rl = rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                rl.cleanup_all();
            }
        });
    }

    // ── Periodischer Shard-Health-Check (alle 5 Minuten) ─────────────────────
    // Prüft ob Shards degradiert/kritisch sind und repariert automatisch
    // durch Re-Verteilung an verfügbare Peers.
    if let Some(ref network) = network_handle {
        let node_health = node.clone();
        let handle_health = network.clone();
        tokio::spawn(async move {
            // Erst 2 Minuten nach Start warten (P2P muss sich stabilisieren)
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut health_interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                health_interval.tick().await;

                let connected = handle_health.connected_peers().await;
                if connected.is_empty() {
                    continue; // Keine Peers → nichts zu tun
                }

                // Alle Chunks in der Registry durchgehen
                let chunks = node_health.shard_registry.all_chunks();
                let ec_k = stone::shard::DEFAULT_EC_K;
                let mut healthy = 0u64;
                let mut degraded = 0u64;
                let mut critical = 0u64;

                for chunk_hash in &chunks {
                    let (status, _count) = node_health.shard_registry.chunk_health(chunk_hash, ec_k);
                    match status {
                        "healthy" => healthy += 1,
                        "degraded" => degraded += 1,
                        "critical" => critical += 1,
                        _ => {}
                    }
                }

                if degraded > 0 || critical > 0 {
                    eprintln!(
                        "[health] ⚠ Shard-Status: {} healthy, {} degraded, {} critical – starte Repair",
                        healthy, degraded, critical
                    );

                    let local_peer_id = handle_health.local_peer_id.clone();
                    let shard_store = match stone::shard::ShardStore::new() {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[health] ShardStore: {e}");
                            continue;
                        }
                    };
                    let (migrated, failed) = stone::storage::rebalance_shards(
                        &shard_store,
                        &node_health.shard_registry,
                        &handle_health,
                        &local_peer_id,
                    ).await;
                    if migrated > 0 || failed > 0 {
                        println!(
                            "[health] 🔧 Auto-Repair: {} migriert, {} fehlgeschlagen",
                            migrated, failed
                        );
                    }
                } else if !chunks.is_empty() {
                    println!("[health] ✅ Alle {} Chunks healthy", healthy);
                }
            }
        });
    }

    let state = AppState {
        node: node.clone(),
        users,
        api_key: api_key.clone(),
        admin_key,
        network: network_handle,
        rate_limits,
        updater: updater.clone(),
        orgs: Arc::new(std::sync::Mutex::new(stone::organization::load_orgs())),
        chat_index: chat_index_arc.clone(),
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

    let router = build_router(state.clone());

    // ── Bridge Payment Monitor ──────────────────────────────────────────
    server::bridge_monitor::start_bridge_monitor(state.clone());

    // Post-Update Erfolg bestätigen (nach 120s gesundem Betrieb)
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        stone::updater::confirm_update_success(&stone::blockchain::data_dir());
    });

    // ── Auto-Update Scheduler ───────────────────────────────────────────
    // Prüft jede Minute ob ein Update bereit ist und ob die konfigurierte
    // Stunde erreicht ist → automatische Installation + Neustart.
    {
        let sched_updater = updater.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut last_install_date = String::new();
            loop {
                interval.tick().await;
                let (should_install, version) = {
                    let um = sched_updater.read().unwrap_or_else(|e| e.into_inner());
                    let hour = match um.config.auto_update_hour {
                        Some(h) => h,
                        None => continue,
                    };
                    let now = chrono::Local::now();
                    let today = now.format("%Y-%m-%d").to_string();
                    if today == last_install_date {
                        continue;
                    }
                    let current_hour = now.hour() as u8;
                    let is_ready = matches!(um.state, stone::updater::UpdateState::Ready);
                    let version = um.manifest.as_ref().map(|m| m.version.clone()).unwrap_or_default();
                    (current_hour == hour && is_ready, version)
                };
                if should_install {
                    println!("[updater] ⏰ Geplantes Auto-Update: v{version} wird installiert...");
                    let now = chrono::Local::now();
                    last_install_date = now.format("%Y-%m-%d").to_string();
                    let install_result = {
                        let mut um = sched_updater.write().unwrap_or_else(|e| e.into_inner());
                        um.install()
                    };
                    match install_result {
                        Ok(_path) => {
                            println!("[updater] ✅ Auto-Update installiert → Neustart in 5 Sekunden");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            #[cfg(unix)]
                            {
                                use std::os::unix::process::CommandExt;
                                let exe = std::env::current_exe().unwrap();
                                let args: Vec<String> = std::env::args().collect();
                                let mut cmd = std::process::Command::new(&exe);
                                cmd.args(&args[1..]);
                                let err = cmd.exec();
                                eprintln!("[updater] exec fehlgeschlagen: {err}");
                                std::process::exit(1);
                            }
                            #[cfg(not(unix))]
                            {
                                std::process::exit(0);
                            }
                        }
                        Err(e) => {
                            eprintln!("[updater] ❌ Auto-Update fehlgeschlagen: {e}");
                        }
                    }
                }
            }
        });
    }

    // Audio-Room GC: Idle-Rooms alle 60s aufräumen (Rooms ohne Aktivität > 5 Min)
    {
        let audio_rooms = state.audio_rooms.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                server::handlers::audio_relay::gc_idle_rooms(&audio_rooms);
            }
        });
    }

    // ── Hintergrund-Task: System-Ressourcen-Cache ────────────────────────
    {
        let node_res = node.clone();
        node_res.update_resource_cache();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let n = node_res.clone();
                tokio::task::spawn_blocking(move || n.update_resource_cache()).await.ok();
            }
        });
    }

    // ── Netzwerk-abhängige Default-Ports ─────────────────────────────────────
    // Mainnet: HTTP 3180, Sync 5002 | Testnet: HTTP 3080, Sync 4002
    let mainnet = stone::network::is_mainnet();
    let default_http = if mainnet { 3180 } else { 3080 };
    let default_sync = if mainnet { 5002 } else { 4002 };

    let preferred_port: u16 = std::env::var("STONE_HTTP_PORT")
        .or_else(|_| std::env::var("STONE_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_http);

    // ── Public Sync Port (kein Auth, für Node-zu-Node Kommunikation) ─────
    let sync_port: u16 = std::env::var("STONE_SYNC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_sync);

    let sync_router = build_sync_router(state);
    let sync_listener = bind_with_fallback(sync_port).await;
    println!("[master] 🌐 Sync-Port auf 0.0.0.0:{sync_port} (öffentlich, kein Auth)");
    tokio::spawn(async move {
        axum::serve(sync_listener, sync_router)
            .await
            .expect("Sync-Server Fehler");
    });

    let listener = bind_with_fallback(preferred_port).await;
    let bound_port = listener.local_addr().unwrap().port();
    let net_label = if mainnet { "MAINNET" } else { "TESTNET" };
    println!("[master] ═══════════════════════════════════════");
    println!("[master] 🌐 Netzwerk: {net_label}");
    println!("[master] HTTP auf 0.0.0.0:{bound_port} (Admin-API)");
    println!("[master] Stone Master Node läuft auf http://0.0.0.0:{bound_port}");
    println!("[master] Web-UI kann sich via ws://0.0.0.0:{bound_port}/ws verbinden");
    println!("[master] ═══════════════════════════════════════");
    axum::serve(listener, router).await.expect("HTTP-Server Fehler");
}

/// Bindet an `preferred_port`. Bei Port-Konflikt: harter Fehler statt zufälligem Port.
async fn bind_with_fallback(preferred_port: u16) -> tokio::net::TcpListener {
    let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
    match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("[master] ❌ Port {preferred_port} ist bereits belegt!");
            eprintln!("[master] Lösungen:");
            eprintln!("[master]   1) Alte Prozesse beenden:  pkill -f stone-master");
            eprintln!(
                "[master]   2) Anderen Port nutzen:    STONE_PORT={} in .env",
                preferred_port + 1
            );
            eprintln!("[master]   3) Belegenden Prozess prüfen: lsof -i :{preferred_port}");
            std::process::exit(1);
        }
        Err(e) => panic!("TCP-Bind fehlgeschlagen: {e}"),
    }
}
