//! stone-setup — Unified Node Binary (Setup-Wizard + Full Node + Dashboard)
//!
//! Startet einen Axum-Webserver:
//! - Vor dem Setup: 4-Step-Wizard (Passwort → Node → Storage → Peers)
//! - Nach dem Setup: Full-Node mit P2P, Blockchain, Token-Economy + Dashboard-UI
//!
//! Alle Routes der master_server.rs API werden als Fallback bereitgestellt,
//! sodass Flask/forge-nomad auf dem gleichen Port arbeiten kann.

#[path = "server/mod.rs"]
mod server;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
    sync::Arc,
    time::Instant,
};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono::Timelike;
use tokio::sync::RwLock;
use tower::ServiceExt;

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole},
    consensus::{
        ARGON2_POW_ACTIVATION_BLOCK, TARGET_BLOCK_TIME_SECS,
        get_current_pow_difficulty, MIN_POW_DIFFICULTY, MAX_POW_DIFFICULTY,
    },
    master::{MasterNodeState, HALVING_INTERVAL, MINING_INTERVAL_SECS},
    network::{start_network, NetworkEvent, NetworkHandle, StorageAnnouncement, TOPIC_STORAGE},
    shard::ShardStore,
    storage::ChunkStore,
    token::genesis::SupplyInfo,
};

use server::{
    rate_limiter::RateLimits,
    router::build_router,
    sync_router::build_sync_router,
    state::{
        load_api_key, load_admin_key, load_peers_from_disk, load_trust_from_disk,
        AppState as NodeAppState, HEARTBEAT_INTERVAL,
    },
    sync::{bootstrap_announce, fetch_missing_chunks, pull_from_peer, spawn_auto_sync_task, spawn_peer_health_task},
};

const CONFIG_FILE: &str = "node_config.json";

// ─── Config ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeConfig {
    setup_complete: bool,
    password_hash: String,
    node_name: String,
    wallet_address: String,
    mnemonic_once: String,
    seed_peers: Vec<String>,
    http_port: u16,
    p2p_port: u16,
    data_dir: String,
    api_key: String,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    storage_offered_gb: u64,
    #[serde(default)]
    reward_per_day: f64,
    #[serde(default)]
    public_ip: String,
    #[serde(default)]
    wallet_balance: f64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            setup_complete: false,
            password_hash: String::new(),
            node_name: String::new(),
            wallet_address: String::new(),
            mnemonic_once: String::new(),
            seed_peers: Vec::new(),
            http_port: 8080,
            p2p_port: 4001,
            data_dir: "./stone_data".into(),
            api_key: String::new(),
            created_at: String::new(),
            storage_offered_gb: 0,
            reward_per_day: 0.0,
            public_ip: String::new(),
            wallet_balance: 0.0,
        }
    }
}

impl NodeConfig {
    fn load() -> Self {
        if Path::new(CONFIG_FILE).exists() {
            let data = std::fs::read_to_string(CONFIG_FILE).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(CONFIG_FILE, json)?;
        Ok(())
    }
}

/// Tiered reward calculation
fn calc_reward_per_day(gb: u64) -> f64 {
    if gb == 0 { return 0.0; }
    let mut reward = 0.0;
    let tiers: [(u64, u64, f64); 4] = [
        (1,    10,   0.5),
        (11,   100,  1.0),
        (101,  1000, 2.0),
        (1001, u64::MAX, 3.0),
    ];
    let mut remaining = gb;
    for (lo, hi, rate) in &tiers {
        if remaining == 0 { break; }
        let tier_size = hi.saturating_sub(lo - 1);
        let in_tier = remaining.min(tier_size);
        reward += in_tier as f64 * rate;
        remaining -= in_tier;
    }
    reward
}

// ─── Unified App State ─────────────────────────────────────────────────────

#[derive(Clone)]
struct SetupState {
    config: Arc<RwLock<NodeConfig>>,
    start_time: Instant,
    session_token: Arc<RwLock<Option<String>>>,
    /// Full-Node-State (Some = Node läuft)
    node_state: Arc<RwLock<Option<NodeAppState>>>,
    /// P2P-Handle (Some = P2P verbunden)
    network: Arc<RwLock<Option<NetworkHandle>>>,
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    print_banner();

    // .env laden (nur aus CWD, nicht aus Parent-Verzeichnissen)
    match dotenvy::from_filename(".env") {
        Ok(path) => println!("[setup] .env geladen: {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {}
        Err(e) => eprintln!("[setup] .env Warnung: {e}"),
    }

    let mut config = NodeConfig::load();

    // Öffentliche IP ermitteln
    if config.public_ip.is_empty() {
        if let Some(ip) = fetch_public_ip().await {
            config.public_ip = ip;
            let _ = config.save();
        }
    }

    let state = SetupState {
        config: Arc::new(RwLock::new(config.clone())),
        start_time: Instant::now(),
        session_token: Arc::new(RwLock::new(None)),
        node_state: Arc::new(RwLock::new(None)),
        network: Arc::new(RwLock::new(None)),
    };

    // Wenn Setup schon abgeschlossen → Full-Node sofort starten
    if config.setup_complete {
        println!("[setup] Setup bereits abgeschlossen → starte Full-Node...");
        let s = state.clone();
        tokio::spawn(async move {
            start_full_node(s).await;
        });
    }

    let app = Router::new()
        .route("/", get(page_index))
        .route("/api/status", get(api_status))
        .route("/api/setup/password", post(api_set_password))
        .route("/api/setup/node", post(api_set_node))
        .route("/api/setup/peers", post(api_set_peers))
        .route("/api/setup/finish", post(api_finish_setup))
        .route("/api/login", post(api_login))
        .route("/api/dashboard", get(api_dashboard))
        .route("/api/settings", get(api_get_settings))
        .route("/api/settings", post(api_save_settings))
        .route("/api/send", post(api_send))
        // OTA Update Dashboard-Endpoints
        .route("/api/updates", get(api_update_status))
        .route("/api/updates/download", post(api_update_download))
        .route("/api/updates/install", post(api_update_install))
        .route("/api/updates/config", post(api_update_config))
        // Shard Repair
        .route("/api/shards/repair", post(api_shard_repair))
        // Network Storage
        .route("/api/network/storage", get(api_network_storage))
        .fallback(forward_to_node_api)
        .with_state(state.clone());

    // Port: STONE_PORT aus .env (default 8080)
    let port: u16 = std::env::var("STONE_HTTP_PORT")
        .or_else(|_| std::env::var("STONE_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(config.http_port);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".into());

    println!();
    println!("  ┌─────────────────────────────────────────────────────┐");
    println!("  │                                                     │");
    println!("  │  🌐 Node-UI:   http://{}:{:<5} │", pad_right(&local_ip, 16), port);
    println!("  │                                                     │");
    println!("  │  📡 Lokal:     http://localhost:{:<18}│", port);
    println!("  │                                                     │");
    println!("  └─────────────────────────────────────────────────────┘");
    println!();
    if config.setup_complete {
        println!("  ✅ Node läuft! Dashboard öffnen im Browser.");
    } else {
        println!("  Öffne die URL im Browser um den Node einzurichten.");
    }
    println!("  Ctrl+C zum Beenden.");
    println!();

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("[setup] ❌ Port {port} belegt: {e}");
        eprintln!("[setup] Tipp: pkill -f stone-setup && pkill -f stone-master");
        std::process::exit(1);
    });
    axum::serve(listener, app).await.unwrap();
}

// ─── Start Full Node ────────────────────────────────────────────────────────

async fn start_full_node(state: SetupState) {
    println!("[node] Full-Node wird gestartet...");

    std::fs::create_dir_all(data_dir()).ok();

    // Post-Update Rollback prüfen (bei Crash-Loop → altes Binary wiederherstellen)
    if stone::updater::check_post_update_rollback(&data_dir()) {
        eprintln!("[node] ⚠ Rollback durchgeführt – Neustart mit altem Binary...");
        let exe = std::env::current_exe().expect("current_exe");
        let args: Vec<String> = std::env::args().collect();
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(&exe).args(&args[1..]).exec();
        }
        std::process::exit(1);
    }

    if let Err(e) = ChunkStore::new() {
        eprintln!("[node] ChunkStore-Fehler: {e}");
    }

    let api_key = Arc::new(load_api_key());
    let admin_key = Arc::new(load_admin_key(&api_key));
    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| {
            let cfg = state.config.try_read();
            match cfg {
                Ok(c) if !c.node_name.is_empty() => c.node_name.clone(),
                _ => hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "stone-node".into()),
            }
        });

    println!("[node] Node-ID: {node_id}");

    // ── Snapshot-Bootstrap: Prüfen ob wir eine frische Node sind ──────────
    // Wenn die lokale Chain sehr kurz ist (nur Genesis), versuchen wir einen
    // verifizierten Snapshot von den Bootstrap-Nodes herunterzuladen.
    // Ablauf: Alle Bootstrap-Nodes nach state_root fragen → Konsens prüfen →
    // Snapshot downloaden → lokalen state_root nach Restore verifizieren.
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

    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);

    // Peers laden
    let saved_peers = load_peers_from_disk();
    if !saved_peers.is_empty() {
        println!("[node] {} Peer(s) geladen", saved_peers.len());
        node.replace_peers(saved_peers);
    }

    // Trust laden
    load_trust_from_disk(&node);

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
            println!("[node] 📋 Users aus Chain-Registry: {} Chain + {} gesamt",
                chain_count, local.len());
        }
    }

    // Hintergrund-Tasks
    // HINWEIS: Mining wurde entfernt — nur stone-miner erzeugt neue Blöcke.
    // setup ist ein reiner Full-Node (Sync, API, Validierung, Storage).
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    // Peer-Discovery: Bei Bootstrap-Nodes registrieren & Health-Check starten
    bootstrap_announce(&node).await;
    spawn_peer_health_task(node.clone());

    // Mempool-Eviction
    {
        let node_evict = node.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut gc = 0u64;
            loop {
                interval.tick().await;
                node_evict.mempool.evict_expired();
                gc += 1;
                if gc % 5 == 0 { node_evict.mempool.gc_known_ids(); }
            }
        });
    }

    // OTA Update Manager
    let updater = Arc::new(std::sync::RwLock::new({
        let mut um = stone::updater::UpdateManager::new(&data_dir());
        um.load_persisted_update();
        um
    }));

    // Post-Update Erfolg bestätigen (nach 120s gesundem Betrieb → Rollback-Marker löschen)
    {
        let dd = data_dir();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            stone::updater::confirm_update_success(&dd);
        });
    }

    // ChatIndex vorab erstellen, damit der P2P-Event-Loop ihn nutzen kann
    let chat_index_arc: Arc<std::sync::Mutex<stone::chat::ChatIndex>> = {
        let mut idx = stone::chat::load_chat_index();
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let chain_len = chain.blocks.len() as u64;
        let last_chain_block_idx = chain.blocks.last().map(|b| b.index).unwrap_or(0);
        println!("[chat-index] 🔍 Startup: chain_len={}, last_block_idx={}, last_indexed_block={}", chain_len, last_chain_block_idx, idx.last_indexed_block);
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
            println!("[chat-index] 📋 Inkrementell: {} neue Blöcke", new_blocks.len());
            idx.index_new_blocks(&new_blocks, Some(&node.message_pool));
            let _ = stone::chat::save_chat_index(&idx);
            println!("[chat-index] ✅ Index aktualisiert: {} Konversationen, last_indexed_block={}", idx.conversations.len(), idx.last_indexed_block);
        } else {
            println!("[chat-index] ℹ️ Kein Update nötig (last_block_idx={}, last_indexed={})", last_chain_block_idx, idx.last_indexed_block);
        }
        Arc::new(std::sync::Mutex::new(idx))
    };

    // P2P starten
    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            println!("[node] P2P deaktiviert");
            None
        } else {
            // Result sofort auspacken damit Box<dyn Error> nicht über .await lebt
            let maybe_handle = match start_network(None).await {
                Ok(h) => Some(h),
                Err(e) => {
                    eprintln!("[node] P2P-Fehler: {e}");
                    None
                }
            };
            if let Some(handle) = maybe_handle {
                println!("[node] ✅ P2P gestartet – PeerId: {}", handle.local_peer_id);
                let count = node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                handle.set_chain_count(count).await;
                // Chain-Referenz setzen damit P2P-Peers Blöcke direkt serviert bekommen
                handle.set_chain_ref(node.chain.clone()).await;
                // Event-Handler
                {
                    let mut event_rx = handle.subscribe();
                    let node_bg = node.clone();
                    let handle_bg = handle.clone();
                    let api_key_bg = api_key.clone();
                    let updater_bg = updater.clone();
                    let chat_idx_bg = chat_index_arc.clone();
                    let pending_sync = std::sync::Mutex::new(Vec::<stone::blockchain::Block>::new());
                    tokio::spawn(async move {
                        loop {
                            match event_rx.recv().await {
                                Ok(event) => {
                                    handle_p2p_event(event, &node_bg, &handle_bg, &api_key_bg, Some(&updater_bg), &chat_idx_bg, &pending_sync).await;
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    eprintln!("[p2p] ⚠ {n} Events übersprungen (Lagged)");
                                    continue;
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                // Network-Handle speichern
                *state.network.write().await = Some(handle.clone());

                // ── Mining → Gossip Bridge: geminete Blöcke broadcasten ──
                {
                    let (broadcast_tx, mut broadcast_rx) =
                        tokio::sync::mpsc::unbounded_channel::<stone::blockchain::Block>();
                    *node.block_broadcast_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(broadcast_tx);
                    let net_bc = handle.clone();
                    tokio::spawn(async move {
                        while let Some(block) = broadcast_rx.recv().await {
                            net_bc.broadcast_block(block).await;
                        }
                    });
                }

                Some(handle)
            } else {
                None
            }
        };

    // ── Periodischer Shard-Health-Scan ──────────────────────────────────────
    // Alle 5 Minuten: ListShards bei verbundenen Peers abfragen → Registry aktualisieren
    if let Some(ref net_handle) = network_handle {
        let scan_node = node.clone();
        let scan_net = net_handle.clone();
        tokio::spawn(async move {
            // Erster Scan nach 30s, dann alle 5 Minuten
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                // Alle EC-Chunks aus der Chain sammeln
                let chunk_hashes: Vec<(String, u8)> = {
                    let chain = scan_node.chain.lock().unwrap_or_else(|e| e.into_inner());
                    let mut hashes = Vec::new();
                    for block in &chain.blocks {
                        for doc in &block.documents {
                            for chunk in &doc.chunks {
                                if chunk.ec_k > 0 && !chunk.shards.is_empty() {
                                    hashes.push((chunk.hash.clone(), chunk.ec_k));
                                }
                            }
                        }
                    }
                    hashes
                };
                if chunk_hashes.is_empty() { continue; }

                let peers = scan_net.connected_peers().await;
                if peers.is_empty() { continue; }

                let mut updated = 0usize;
                for (chunk_hash, _ec_k) in &chunk_hashes {
                    for peer in &peers {
                        if let Ok(pid) = peer.peer_id.parse::<libp2p::PeerId>() {
                            let indices = scan_net.list_peer_shards(pid, chunk_hash.clone()).await;
                            if !indices.is_empty() {
                                for idx in &indices {
                                    scan_node.shard_registry.add_holder(chunk_hash, *idx, &peer.peer_id);
                                }
                                updated += indices.len();
                            }
                        }
                    }
                }
                if updated > 0 {
                    scan_node.shard_registry.persist();
                    println!("[shard-scan] ✅ Registry aktualisiert: {updated} Shard-Einträge von {} Peers für {} Chunks", peers.len(), chunk_hashes.len());
                }

                // ── Auto-Repair nach Scan ─────────────────────────────────────
                // Prüfe ob degradierte/kritische Chunks repariert werden können
                let result = repair_degraded_shards(&scan_node, &scan_net).await;
                if result.repaired > 0 || result.failed > 0 {
                    println!(
                        "[shard-repair] 🔧 Auto-Repair: {} angefordert, {} fehlgeschlagen",
                        result.repaired, result.failed
                    );
                }
            }
        });
    }

    // ── Periodischer Storage-Broadcast ──────────────────────────────────────
    // Alle 60 Sekunden: eigenen Speicher-Status per Gossipsub broadcasten
    if let Some(ref net_handle) = network_handle {
        let storage_net = net_handle.clone();
        let storage_state = state.clone();
        tokio::spawn(async move {
            // Erster Broadcast nach 10s, dann alle 60 Sekunden
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let cfg = storage_state.config.read().await;
                let offered_gb = cfg.storage_offered_gb;
                let data_path = cfg.data_dir.clone();
                let node_name = cfg.node_name.clone();
                drop(cfg);

                let used = dir_size(std::path::Path::new(&data_path));
                let total_bytes = offered_gb * 1024 * 1024 * 1024;
                let free = total_bytes.saturating_sub(used);

                let announcement = StorageAnnouncement {
                    peer_id: storage_net.local_peer_id.clone(),
                    offered_gb,
                    used_bytes: used,
                    free_bytes: free,
                    timestamp: chrono::Utc::now().timestamp(),
                    node_name,
                };

                if let Ok(json) = serde_json::to_vec(&announcement) {
                    storage_net.publish_gossip(TOPIC_STORAGE, json).await;
                }
            }
        });
    }

    // ── Auto-Update Scheduler ───────────────────────────────────────────────
    // Prüft jede Minute ob ein Update bereit ist und ob die konfigurierte
    // Stunde erreicht ist → automatische Installation + Neustart
    {
        let sched_updater = updater.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut last_install_date = String::new(); // Verhindert doppelte Installation am selben Tag
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
                        continue; // Schon heute installiert/versucht
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

    let rate_limits = Arc::new(RateLimits::new());
    {
        let rl = rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop { interval.tick().await; rl.cleanup_all(); }
        });
    }

    let node_app_state = NodeAppState {
        node: node.clone(),
        users,
        api_key,
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
    };

    *state.node_state.write().await = Some(node_app_state.clone());

    // Audio-Room GC: Idle-Rooms alle 60s aufräumen (Rooms ohne Aktivität > 5 Min)
    {
        let audio_rooms = node_app_state.audio_rooms.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                server::handlers::audio_relay::gc_idle_rooms(&audio_rooms);
            }
        });
    }

    // ── Bridge Payment Monitor ──────────────────────────────────────────
    server::bridge_monitor::start_bridge_monitor(node_app_state.clone());

    // ── Hintergrund-Task: System-Ressourcen-Cache aktualisieren ─────────
    // RAM, CPU, Disk werden alle 10s gecacht statt bei jedem /network-Request
    // berechnet (~100-200ms gespart pro Request).
    {
        let node_res = node.clone();
        // Initiale Berechnung sofort ausführen
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

    // ── Public API Port (nur /api/v1/* — kein Dashboard) ────────────────
    // Für externen Zugriff via Cloudflare Tunnel (chain.unrooted.dev).
    // Dashboard bleibt nur auf dem Haupt-Port (8080) erreichbar.
    {
        let api_port: u16 = std::env::var("STONE_API_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3080);

        let api_router = build_router(node_app_state.clone());

        match tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], api_port))).await {
            Ok(api_listener) => {
                println!("[node] 🌐 Public API auf 0.0.0.0:{api_port} (nur /api/v1/*, kein Dashboard)");
                tokio::spawn(async move {
                    axum::serve(api_listener, api_router)
                        .await
                        .expect("API-Server Fehler");
                });
            }
            Err(e) => {
                eprintln!("[node] ⚠ API-Port {api_port} konnte nicht gebunden werden: {e}");
            }
        }
    }

    // ── Hintergrund-Task: Chat-Index nach Sync aktualisieren ────────────
    {
        let chat_idx = node_app_state.chat_index.clone();
        let chain_ref = node.chain.clone();
        let node_bg = node.clone();
        tokio::spawn(async move {
            // Warten bis die Chain synchronisiert ist
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let chain = chain_ref.lock().unwrap_or_else(|e| e.into_inner());
            let mut idx = chat_idx.lock().unwrap_or_else(|e| e.into_inner());
            let chain_len = chain.blocks.len() as u64;
            if chain_len <= 1 { return; }
            if idx.last_indexed_block > 0 && idx.last_indexed_block >= chain_len {
                println!("[chat-index] ⚠️ Post-Sync Chain-Reset erkannt! Rebuild...");
                let all_blocks: Vec<_> = chain.blocks.iter().collect();
                *idx = stone::chat::ChatIndex::rebuild_from_chain(&all_blocks, Some(&node_bg.message_pool));
                let _ = stone::chat::save_chat_index(&idx);
                println!("[chat-index] ✅ Rebuild: {} Konversationen, last_indexed_block={}", idx.conversations.len(), idx.last_indexed_block);
            } else if (chain_len - 1) > idx.last_indexed_block {
                let skip = (idx.last_indexed_block + 1) as usize;
                let new_blocks: Vec<_> = chain.blocks.iter().skip(skip).collect();
                println!("[chat-index] 📋 Post-Sync: {} Blöcke indexieren", new_blocks.len());
                idx.index_new_blocks(&new_blocks, Some(&node_bg.message_pool));
                let _ = stone::chat::save_chat_index(&idx);
                println!("[chat-index] ✅ Index: {} Konversationen, last_indexed_block={}", idx.conversations.len(), idx.last_indexed_block);
            }
        });
    }

    // ── Public Sync Port starten (kein Auth, Node-zu-Node) ──────────────
    let sync_port: u16 = std::env::var("STONE_SYNC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4002);
    let sync_router = build_sync_router(node_app_state);
    match tokio::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], sync_port))).await {
        Ok(sync_listener) => {
            println!("[node] 🌐 Sync-Port auf 0.0.0.0:{sync_port} (öffentlich, kein Auth)");
            tokio::spawn(async move {
                axum::serve(sync_listener, sync_router)
                    .await
                    .expect("Sync-Server Fehler");
            });
        }
        Err(e) => {
            eprintln!("[node] ⚠ Sync-Port {sync_port} konnte nicht gebunden werden: {e}");
        }
    }

    println!("[node] ✅ Full-Node aktiv — API via Fallback-Handler erreichbar");
}

// ─── P2P Event Handler ──────────────────────────────────────────────────────

async fn handle_p2p_event(
    event: NetworkEvent,
    node: &Arc<MasterNodeState>,
    handle: &NetworkHandle,
    api_key: &Arc<String>,
    updater: Option<&Arc<std::sync::RwLock<stone::updater::UpdateManager>>>,
    chat_index_rc: &Arc<std::sync::Mutex<stone::chat::ChatIndex>>,
    pending_sync_blocks: &std::sync::Mutex<Vec<stone::blockchain::Block>>,
) {
    match event {
        NetworkEvent::BlockReceived { block, from_peer } => {
            let peer_urls: Vec<String> = node.get_peers()
                .into_iter()
                .filter(|p| p.is_healthy())
                .map(|p| p.url.clone())
                .collect();
            for url in &peer_urls {
                fetch_missing_chunks(&block, url, api_key).await;
            }

            let poa_ok = {
                // Während Initial-Sync: PoA-Prüfung überspringen.
                // Die synced Blöcke wurden vom Netzwerk bereits akzeptiert.
                let syncing = !node.metrics.initial_sync_done.load(
                    std::sync::atomic::Ordering::Relaxed
                );
                if syncing {
                    None // PoA bei Sync überspringen
                } else {
                    let vs = node.validator_set.read().unwrap_or_else(|e| e.into_inner());
                    // Kein sinnvolles PoA möglich wenn ValidatorSet leer ist
                    // oder nur den eigenen Validator enthält
                    if vs.validators.is_empty() || vs.active_count() <= 1 { None }
                    else {
                        let (prev_hash, last_block_ts) = {
                            let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                            let ph = chain.blocks.last().map(|b| b.hash.clone()).unwrap_or_else(|| "genesis".into());
                            let ts = chain.blocks.last().map(|b| b.timestamp);
                            (ph, ts)
                        };
                        let sync_done = node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed);
                        let (sel_stakes, sel_jailed, sel_wallets) = node.build_selection_context();
                        Some(vs.verify_block_with_context(
                            &block.hash, &block.signer, &block.validator_signature,
                            &prev_hash, block.index, block.pow_nonce,
                            &sel_jailed, &sel_stakes, &sel_wallets,
                            last_block_ts, sync_done,
                            &block.pow_hash, block.pow_difficulty, &block.validator_pub_key,
                            block.effective_difficulty,
                        ).is_acceptable())
                    }
                }
            };

            // Block-Akzeptanz in einem eigenen Scope, damit der Lock vor dem await dropped wird
            enum BlockResult {
                Accepted(u64),
                Stale,
                NeedsResync { idx: u64, from: String, err: String },
                Rejected,
                AlreadyKnown,
                Fork,
            }

            let result = {
                let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                let already = chain.blocks.iter().any(|b| b.hash == block.hash);
                if already {
                    BlockResult::AlreadyKnown
                } else {
                    let idx = block.index;
                    let txs = block.transactions.clone();
                    let chat_batches = block.chat_batches.clone();
                    let block_signer = block.signer.clone();
                    let block_validator_pk = block.validator_pub_key.clone();

                    // Equivocation-Check vor Block-Akzeptanz
                    {
                        let mut tracker = node.equivocation_tracker.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(evidence) = tracker.check_and_record(
                            block.index,
                            &block.validator_pub_key,
                            &block.hash,
                        ) {
                            eprintln!(
                                "[p2p] ⚠️  EQUIVOCATION: Validator {} hat Block #{} doppelt signiert!",
                                &evidence.validator_pub_key[..16.min(evidence.validator_pub_key.len())],
                                evidence.block_index,
                            );
                            MasterNodeState::slash_equivocation(node, &evidence);
                        }
                    }

                    match chain.accept_peer_block(*block, poa_ok) {
                        Ok(_) => {
                            // Orphan-TX-Recovery
                            let orphaned = std::mem::take(&mut chain.orphaned_blocks);
                            if !orphaned.is_empty() {
                                node.mempool.requeue_orphaned_txs(&orphaned);
                                // Ledger nach Single-Block-Reorg neu aufbauen (BUG-11 Fix)
                                let rebuilt = stone::token::TokenLedger::rebuild_from_chain(&chain.blocks);
                                let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                *ledger = rebuilt;
                                eprintln!(
                                    "[sync] Token-Ledger nach Single-Block-Reorg neu aufgebaut: {} Accounts, Supply: {}",
                                    ledger.account_count(),
                                    ledger.total_supply()
                                );
                                // StakingPool nach Reorg auch neu aufbauen
                                let rebuilt_pool = stone::token::StakingPool::rebuild_from_chain(&chain.blocks);
                                *node.staking_pool.write().unwrap_or_else(|e| e.into_inner()) = rebuilt_pool;
                            } else if !txs.is_empty() {
                                let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                // Peer-Blöcke wurden bereits vom Netzwerk validiert →
                                // replay_mode aktivieren um Nonce-Checks zu überspringen
                                // (bei Initial-Sync hat der Ledger noch nicht alle Nonces)
                                ledger.replay_mode = true;
                                let _receipts = ledger.apply_block_txs(&txs, idx);
                                ledger.replay_mode = false;
                                let _ = ledger.persist();
                                for tx in &txs {
                                    node.mempool.mark_known(&tx.tx_id);
                                    node.mempool.remove_tx(&tx.tx_id);
                                }
                            }
                            // Staking-TXs im StakingPool verarbeiten (P2P-Pfad)
                            node.apply_staking_from_txs(&txs);
                            // HTLC-Contracts verarbeiten (P2P-Pfad)
                            MasterNodeState::process_htlc_txs(&node, &txs, idx);
                            // Chat-Batch-Records speichern (für Chat-Index)
                            for batch in &chat_batches {
                                if !batch.messages.is_empty() {
                                    node.message_pool.store_batch_record(
                                        &batch.merkle_root, &batch.messages, idx,
                                    );
                                }
                            }
                            // Validator Auto-Discovery: Nur für LIVE Blöcke
                            // (nicht während Initial-Sync, dort kommen historische
                            // Blöcke die tote Nodes registrieren würden)
                            let sync_done = node.metrics.initial_sync_done.load(
                                std::sync::atomic::Ordering::Relaxed
                            );
                            if sync_done
                                && !block_signer.is_empty()
                                && !block_validator_pk.is_empty()
                                && block_signer != node.node_id
                            {
                                let mut vs = node.validator_set.write().unwrap_or_else(|e| e.into_inner());
                                if vs.get(&block_signer).is_none() {
                                    // Auto-Discovery: als pending registrieren (active=false)
                                    let info = stone::consensus::ValidatorInfo::new_pending(
                                        block_signer.clone(),
                                        block_validator_pk.clone(),
                                    );
                                    vs.add(info);
                                    println!(
                                        "[consensus] 🔗 Validator '{}' auto-discovered (pending) via Block #{} (Wallet: {}…)",
                                        &block_signer, idx,
                                        &block_validator_pk[..16.min(block_validator_pk.len())]
                                    );
                                }
                            }
                            BlockResult::Accepted(chain.blocks.len() as u64)
                        }
                        Err(ref e) if e.starts_with("Stale:") => BlockResult::Stale,
                        Err(ref e) if e.starts_with("Gap:") || e.contains("previous_hash") => {
                            let err = e.clone();
                            BlockResult::NeedsResync { idx, from: from_peer.clone(), err }
                        }
                        Err(ref e) if e.contains("Fork") || e.contains("fork")
                            || e.contains("nicht schwerer") || e.contains("Tiebreak")
                            || e.contains("Reorg abgelehnt") || e.contains("Timestamp") => {
                            eprintln!("[p2p] Block #{idx} Fork/Reorg: {e}");
                            BlockResult::Fork
                        }
                        Err(ref e) if e.contains("PoA") || e.contains("Argon2")
                            || e.contains("Storage-Proof") || e.contains("difficulty")
                            || e.contains("Difficulty") || e.contains("Signer")
                            || e.contains("Signatur") => {
                            eprintln!("[p2p] Block #{idx} validation mismatch (no penalty): {e}");
                            BlockResult::Fork
                        }
                        Err(e) => { eprintln!("[p2p] Block #{idx} abgelehnt: {e}"); BlockResult::Rejected }
                    }
                }
            }; // chain-Lock ist hier gedroppt

            match result {
                BlockResult::Accepted(count) => {
                    handle.set_chain_count(count).await;
                }
                BlockResult::NeedsResync { idx, from, err } => {
                    eprintln!("[p2p] Block #{idx}: {err} → Resync");
                    if let Some(url) = resolve_peer_url(&from, handle, node).await {
                        eprintln!("[sync] Resync via {url} (Peer {from})");
                        let n = node.clone();
                        let k = api_key.clone();
                        tokio::spawn(async move { pull_from_peer(&n, &url, &k).await; });
                    } else {
                        eprintln!("[sync] ⚠ Keine URL für Peer {from} – versuche alle bekannten Peers");
                        let n = node.clone();
                        let k = api_key.clone();
                        tokio::spawn(async move {
                            let peers = n.get_peers();
                            for p in peers.iter().filter(|p| p.is_healthy()) {
                                pull_from_peer(&n, &p.url, &k).await;
                            }
                        });
                    }
                }
                BlockResult::Rejected => {
                    handle.report_penalty(&from_peer, 5, "rejected block").await;
                }
                _ => {} // Stale, AlreadyKnown, Fork
            }
        }

        // ── Range-Sync Batch (Fork-Reorg) ─────────────────────────────────
        NetworkEvent::RangeSyncReceived { blocks, from_peer: _from_peer } => {
            // Blöcke in den Puffer aufnehmen, sortieren, Duplikate entfernen
            {
                let batch_min = blocks.iter().map(|b| b.index).min().unwrap_or(0);
                let batch_max = blocks.iter().map(|b| b.index).max().unwrap_or(0);
                let batch_len = blocks.len();
                let mut buf = pending_sync_blocks.lock().unwrap_or_else(|e| e.into_inner());
                buf.extend(blocks);
                buf.sort_by_key(|b| b.index);
                buf.dedup_by_key(|b| b.index);
                eprintln!(
                    "[sync] 📦 Batch: {batch_len} Blöcke [{batch_min}..{batch_max}], Puffer jetzt: {} (first={})",
                    buf.len(),
                    buf.first().map(|b| b.index).unwrap_or(0)
                );
            }

            // Chain-Lock in eigenem Scope → wird vor .await gedroppt
            let reorg_result: Option<(u64, u64)> = {
                let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                let chain_tip = chain.blocks.len() as u64;

                // Lückenlose Blöcke ab Chain-Tip aus dem Puffer entnehmen
                let mut buf = pending_sync_blocks.lock().unwrap_or_else(|e| e.into_inner());
                buf.retain(|b| b.index >= chain_tip);

                let mut contiguous = Vec::new();
                let mut expected = chain_tip;
                let mut take_indices = Vec::new();
                for (i, block) in buf.iter().enumerate() {
                    if block.index == expected {
                        contiguous.push(block.clone());
                        take_indices.push(i);
                        expected += 1;
                    } else if block.index > expected {
                        break;
                    }
                }
                for &i in take_indices.iter().rev() {
                    buf.remove(i);
                }
                let buf_remaining = buf.len();
                drop(buf);

                if contiguous.is_empty() {
                    eprintln!(
                        "[sync] ⏳ Puffer: {buf_remaining} Blöcke wartend, chain_tip={chain_tip}, nächster im Puffer={}",
                        pending_sync_blocks.lock().unwrap_or_else(|e| e.into_inner()).first().map(|b| b.index).unwrap_or(0)
                    );
                    None
                } else {
                    println!(
                        "[sync] 📥 Append: {} Blöcke ab #{chain_tip} (Puffer: {buf_remaining} verbleibend)",
                        contiguous.len()
                    );

                    let mut applied = 0u64;
                    for block in contiguous {
                        let idx = block.index;
                        let txs = block.transactions.clone();
                        let chat_batches = block.chat_batches.clone();
                        let _block_signer = block.signer.clone();
                        let _block_validator_pk = block.validator_pub_key.clone();

                        // Equivocation-Check
                        {
                            let mut tracker = node.equivocation_tracker.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = tracker.check_and_record(
                                block.index,
                                &block.validator_pub_key,
                                &block.hash,
                            );
                        }

                        // Ed25519-Signatur prüfen (auch ohne PoA-Rotation)
                        if block.index > 0
                            && (!block.validator_pub_key.is_empty() || !block.validator_signature.is_empty())
                        {
                            if !stone::consensus::verify_block_signature_standalone(
                                &block.hash,
                                &block.validator_pub_key,
                                &block.validator_signature,
                            ) {
                                eprintln!(
                                    "[sync] ⚠ Block #{} hat ungültige Validator-Signatur – übersprungen",
                                    block.index
                                );
                                continue;
                            }
                        }

                        match chain.accept_peer_block(block, None) {
                            Ok(_) => {
                                applied += 1;
                                if !txs.is_empty() {
                                    let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                                    ledger.replay_mode = true;
                                    let _receipts = ledger.apply_block_txs(&txs, idx);
                                    ledger.replay_mode = false;
                                    let _ = ledger.persist();
                                    for tx in &txs {
                                        node.mempool.mark_known(&tx.tx_id);
                                        node.mempool.remove_tx(&tx.tx_id);
                                    }
                                }
                                // Staking-TXs im StakingPool verarbeiten (RangeSync-Pfad)
                                node.apply_staking_from_txs(&txs);
                                // HTLC-Contracts verarbeiten (RangeSync-Pfad)
                                MasterNodeState::process_htlc_txs(&node, &txs, idx);
                                // Chat-Batch-Records speichern
                                for batch in &chat_batches {
                                    if !batch.messages.is_empty() {
                                        node.message_pool.store_batch_record(
                                            &batch.merkle_root, &batch.messages, idx,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("[sync] ✗ Reorg Block #{idx} fehlgeschlagen: {e}");
                                break;
                            }
                        }
                    }
                    Some((chain.blocks.len() as u64, applied))
                }
            }; // chain-Lock hier gedroppt

            if let Some((new_count, applied)) = reorg_result {
                handle.set_chain_count(new_count).await;
                println!("[sync] ✓ Sync abgeschlossen: {applied} Blöcke applied, Chain-Höhe={new_count}");
            }
        }

        NetworkEvent::TxReceived { tx, from_peer } => {
            let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            match node.mempool.add_tx(*tx, Some(&ledger)) {
                Ok(()) => println!("[p2p] 💸 TX von {from_peer} (mempool={})", node.mempool.pending_count()),
                Err(e) => { if !format!("{e}").contains("Duplikat") { eprintln!("[p2p] TX abgelehnt: {e}"); } }
            }
        }

        // ── Shard-Events ──────────────────────────────────────────────────────
        NetworkEvent::ShardReceived { chunk_hash, shard_index, data, from_peer } => {
            // Shard wurde bereits in der P2P-Schicht gespeichert → nur Registry aktualisieren
            println!(
                "[shard] ✅ Shard empfangen: {}[{}] ({} bytes) von {}",
                &chunk_hash[..8.min(chunk_hash.len())], shard_index, data.len(),
                &from_peer[..8.min(from_peer.len())]
            );
            let local_pid = handle.local_peer_id.to_string();
            node.shard_registry.add_holder(&chunk_hash, shard_index, &local_pid);
            node.shard_registry.add_holder(&chunk_hash, shard_index, &from_peer);
            node.shard_registry.persist();
        }

        NetworkEvent::ShardStored { chunk_hash, shard_index, peer_id, success, error } => {
            // Bestätigung: ein Peer hat unseren Shard erfolgreich gespeichert
            if success {
                println!(
                    "[shard] ✅ Shard bestätigt: {}[{}] auf Peer {}",
                    &chunk_hash[..8.min(chunk_hash.len())], shard_index,
                    &peer_id[..8.min(peer_id.len())]
                );
                node.shard_registry.add_holder(&chunk_hash, shard_index, &peer_id);
                node.shard_registry.persist();
            } else {
                eprintln!(
                    "[shard] ⚠ Shard abgelehnt: {}[{}] auf Peer {} — {}",
                    &chunk_hash[..8.min(chunk_hash.len())], shard_index,
                    &peer_id[..8.min(peer_id.len())],
                    error.as_deref().unwrap_or("unbekannter Fehler")
                );
            }
        }

        NetworkEvent::ShardRequestFailed { chunk_hash, shard_index, peer_id, error } => {
            eprintln!(
                "[shard] ❌ Shard-Transfer fehlgeschlagen: {}[{}] → Peer {} — {error}",
                &chunk_hash[..8.min(chunk_hash.len())], shard_index,
                &peer_id[..8.min(peer_id.len())]
            );
        }

        // ── Update-Events ─────────────────────────────────────────────────────
        NetworkEvent::UpdateManifestReceived { manifest_json, from_peer } => {
            if let Some(updater_ref) = updater {
                match serde_json::from_slice::<stone::updater::UpdateManifest>(&manifest_json) {
                    Ok(manifest) => {
                        let mut um = updater_ref.write().unwrap_or_else(|e| e.into_inner());
                        match um.receive_manifest(manifest.clone()) {
                            Ok(true) => {
                                println!(
                                    "[updater] 🆕 Update v{} von Peer {} empfangen",
                                    manifest.version,
                                    &from_peer[..12.min(from_peer.len())]
                                );
                                // Auto-Download starten
                                if um.config.auto_download {
                                    let peer_urls: Vec<String> = node.get_peers()
                                        .iter()
                                        .map(|p| p.url.clone())
                                        .collect();
                                    let missing = um.missing_chunks();
                                    drop(um); // Lock freigeben

                                    if !missing.is_empty() {
                                        let updater_clone = updater_ref.clone();
                                        let _node_clone = node.clone();
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
                                            // Verifizieren
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
                            Ok(false) => {} // Bereits bekannt oder nicht neuer
                            Err(e) => eprintln!("[updater] Manifest abgelehnt: {e}"),
                        }
                    }
                    Err(e) => {
                        eprintln!("[updater] Manifest-Deserialisierung: {e}");
                    }
                }
            }
        }

        // ── Peer-Discovery → HTTP-Peer auto-registrieren ─────────────────
        NetworkEvent::PeerIdentified { peer_id, addresses, .. } => {
            let http_port = std::env::var("STONE_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(8080);

            // IP aus Multiaddrs extrahieren (erstes nicht-loopback /ip4/ Segment)
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
                node.upsert_peer(peer_info);
                // peers.json aktualisieren
                let peers = node.get_peers();
                if let Ok(json) = serde_json::to_string_pretty(&peers) {
                    let _ = std::fs::write(
                        format!("{}/peers.json", stone::blockchain::data_dir()),
                        json,
                    );
                }
            }
        }

        // ── Storage-Announcement (nur Logging, Tracking passiert in SwarmTask) ──
        NetworkEvent::StorageAnnouncementReceived { announcement, from_peer } => {
            println!(
                "[storage] 💾 {} bietet {} GB an ({} belegt)",
                &from_peer[..12.min(from_peer.len())],
                announcement.offered_gb,
                human_bytes(announcement.used_bytes)
            );
        }

        // ── Neuer Peer verbunden → Shard-Rebalancing ─────────────────────
        NetworkEvent::PeerConnected { peer_id, .. } => {
            println!("[node] 🔗 Peer verbunden: {}", &peer_id[..12.min(peer_id.len())]);

            // Rebalancing nach kurzer Wartezeit starten (damit Peer-Liste stabil ist)
            let node_rb = node.clone();
            let handle_rb = handle.clone();
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
                    println!("[node] 📦 Rebalancing abgeschlossen: {} migriert, {} fehlgeschlagen",
                        migrated, failed);
                }
            });
        }

        // ── Chat-Pool-Nachricht von Peer empfangen → in lokalen Pool ──────
        NetworkEvent::ChatMessageReceived { message, from_peer } => {
            match node.message_pool.add_message(message) {
                Ok(seq) => println!(
                    "[p2p] 💬 Chat-Nachricht von {} (seq: {}, pool={})",
                    &from_peer[..12.min(from_peer.len())], seq,
                    node.message_pool.pending_count(),
                ),
                Err(e) => {
                    if !format!("{e}").contains("bereits bekannt") {
                        eprintln!("[p2p] Chat-Nachricht abgelehnt: {e}");
                    }
                }
            }
        }

        // ── Chat Content Sync (DSGVO off-chain) ──────────────────────────
        NetworkEvent::ChatContentReceived { content, from_peer: _ } => {
            let mut idx = chat_index_rc.lock().unwrap_or_else(|e| e.into_inner());
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
                        from_user_id: String::new(), from_name: String::new(),
                        encrypted_content: content.encrypted_content.clone(),
                        nonce: content.nonce.clone(),
                        content_hash: content.content_hash.clone(),
                        timestamp: chrono::Utc::now().timestamp(), block_index: 0, tx_id: String::new(),
                    });
                    true
                }
            } else {
                idx.conversations.insert(key, vec![stone::chat::ChatEntry {
                    msg_id: content.msg_id.clone(),
                    from_wallet: content.from_wallet.clone(), to_wallet: content.to_wallet.clone(),
                    from_user_id: String::new(), from_name: String::new(),
                    encrypted_content: content.encrypted_content.clone(),
                    nonce: content.nonce.clone(), content_hash: content.content_hash.clone(),
                    timestamp: chrono::Utc::now().timestamp(), block_index: 0, tx_id: String::new(),
                }]);
                true
            };
            if updated {
                stone::chat::save_chat_index(&idx);
                println!("[p2p] 📝 Chat-Content sync: msg_id={}…", &content.msg_id[..8.min(content.msg_id.len())]);
            }
        }

        _ => {} // PeerDisconnected, Listening etc.
    }
}

// ─── Shard-Repair ───────────────────────────────────────────────────────────

/// Ergebnis einer Shard-Repair-Operation
#[derive(Serialize, Clone)]
struct ShardRepairResult {
    repaired: u64,
    failed: u64,
    skipped: u64,
    details: Vec<String>,
}

/// Repariert degradierte/kritische Shards indem fehlende Shards von Peers geholt werden.
///
/// Ablauf für jeden EC-Chunk:
/// 1. Prüfe lokal vorhandene Shard-Indices
/// 2. Ermittle fehlende Indices (sollten n = k+m sein, fehlen = n - lokal)
/// 3. Suche in der ShardHolderRegistry nach Peers die den fehlenden Shard haben
/// 4. Fordere den Shard per `request_shard` an → wird asynchron via Event empfangen
async fn repair_degraded_shards(
    node: &Arc<MasterNodeState>,
    net: &NetworkHandle,
) -> ShardRepairResult {
    let shard_store = match ShardStore::new() {
        Ok(s) => s,
        Err(e) => {
            return ShardRepairResult {
                repaired: 0, failed: 0, skipped: 0,
                details: vec![format!("ShardStore-Fehler: {e}")],
            };
        }
    };

    // Alle EC-Chunks aus der Blockchain sammeln
    let ec_chunks: Vec<(String, u8, u8)> = {
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut chunks = Vec::new();
        for block in &chain.blocks {
            for doc in &block.documents {
                for chunk in &doc.chunks {
                    if chunk.ec_k > 0 && !chunk.shards.is_empty() {
                        chunks.push((chunk.hash.clone(), chunk.ec_k, chunk.ec_m));
                    }
                }
            }
        }
        chunks
    };

    if ec_chunks.is_empty() {
        return ShardRepairResult {
            repaired: 0, failed: 0, skipped: 0,
            details: vec!["Keine EC-Chunks in der Blockchain".into()],
        };
    }

    let connected_peers = net.connected_peers().await;
    if connected_peers.is_empty() {
        return ShardRepairResult {
            repaired: 0, failed: 0, skipped: 0,
            details: vec!["Keine verbundenen Peers für Repair".into()],
        };
    }

    let local_peer_id = net.local_peer_id.clone();
    let mut repaired = 0u64;
    let mut failed = 0u64;
    let mut skipped = 0u64;
    let mut details = Vec::new();

    for (chunk_hash, ec_k, ec_m) in &ec_chunks {
        let n = (*ec_k as usize) + (*ec_m as usize);
        let local_indices = shard_store.local_shard_indices(chunk_hash);

        // Welche Indices fehlen lokal?
        let missing: Vec<u8> = (0..n as u8)
            .filter(|i| !local_indices.contains(i))
            .collect();

        if missing.is_empty() {
            skipped += 1;
            continue; // Alle Shards lokal vorhanden
        }

        // Nur reparieren wenn wir degradiert oder kritisch sind
        let available_count = node.shard_registry.available_shards_for_chunk(chunk_hash);
        if available_count >= n {
            skipped += 1;
            continue; // Gesund, genug Shards im Netzwerk
        }

        for shard_idx in &missing {
            // Suche einen Peer der diesen Shard hat
            let holders = node.shard_registry.holders_for(chunk_hash, *shard_idx);
            let remote_holder = holders.iter().find(|h| **h != local_peer_id);

            if let Some(holder_id) = remote_holder {
                if let Ok(peer_id) = holder_id.parse::<libp2p::PeerId>() {
                    // Prüfe ob der Peer verbunden ist
                    let is_connected = connected_peers.iter().any(|p| p.peer_id == *holder_id);
                    if is_connected {
                        println!(
                            "[repair] 🔧 Requesting {}[{}] from {}",
                            &chunk_hash[..8.min(chunk_hash.len())], shard_idx,
                            &holder_id[..12.min(holder_id.len())]
                        );
                        net.request_shard(peer_id, chunk_hash.clone(), *shard_idx).await;
                        repaired += 1;
                        details.push(format!(
                            "{}[{}] → angefordert von {}",
                            &chunk_hash[..8.min(chunk_hash.len())], shard_idx,
                            &holder_id[..12.min(holder_id.len())]
                        ));
                    } else {
                        failed += 1;
                        details.push(format!(
                            "{}[{}] → Holder {} nicht verbunden",
                            &chunk_hash[..8.min(chunk_hash.len())], shard_idx,
                            &holder_id[..12.min(holder_id.len())]
                        ));
                    }
                } else {
                    failed += 1;
                }
            } else {
                // Kein bekannter Holder → bei verbundenen Peers nachfragen
                let mut found = false;
                for peer in &connected_peers {
                    if let Ok(pid) = peer.peer_id.parse::<libp2p::PeerId>() {
                        let peer_shards = net.list_peer_shards(pid.clone(), chunk_hash.clone()).await;
                        if peer_shards.contains(shard_idx) {
                            println!(
                                "[repair] 🔧 Found {}[{}] at {} (discovery)",
                                &chunk_hash[..8.min(chunk_hash.len())], shard_idx,
                                &peer.peer_id[..12.min(peer.peer_id.len())]
                            );
                            net.request_shard(pid, chunk_hash.clone(), *shard_idx).await;
                            // Registry aktualisieren
                            node.shard_registry.add_holder(chunk_hash, *shard_idx, &peer.peer_id);
                            repaired += 1;
                            found = true;
                            details.push(format!(
                                "{}[{}] → angefordert von {} (discovery)",
                                &chunk_hash[..8.min(chunk_hash.len())], shard_idx,
                                &peer.peer_id[..12.min(peer.peer_id.len())]
                            ));
                            break;
                        }
                    }
                }
                if !found {
                    failed += 1;
                    details.push(format!(
                        "{}[{}] → kein Holder gefunden",
                        &chunk_hash[..8.min(chunk_hash.len())], shard_idx
                    ));
                }
            }
        }
    }

    if repaired > 0 {
        node.shard_registry.persist();
    }

    println!(
        "[repair] ✅ Shard-Repair abgeschlossen: {} angefordert, {} fehlgeschlagen, {} übersprungen",
        repaired, failed, skipped
    );

    ShardRepairResult { repaired, failed, skipped, details }
}

/// Löst eine libp2p PeerId in eine HTTP-URL auf.
/// 1. Versucht, die IP aus den bekannten Peer-Adressen (NetworkHandle) zu extrahieren
/// 2. Fällt zurück auf die registrierten Peers (MasterNodeState) falls dort die PeerId in der URL steht
/// 3. Nutzt STONE_PORT / 8080 als HTTP-Port
async fn resolve_peer_url(
    peer_id_str: &str,
    handle: &NetworkHandle,
    node: &Arc<MasterNodeState>,
) -> Option<String> {
    let http_port = std::env::var("STONE_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8080);

    // 1) Netzwerk-Peer-Liste: IP aus Multiaddr extrahieren
    let peers = handle.get_peers().await;
    if let Some(np) = peers.iter().find(|p| p.peer_id == peer_id_str) {
        for addr in &np.addresses {
            // Multiaddr-Format: /ip4/<IP>/tcp/<PORT>/p2p/<PeerId>
            let parts: Vec<&str> = addr.split('/').collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "ip4" {
                    if let Some(ip) = parts.get(i + 1) {
                        // Loopback überspringen
                        if *ip != "127.0.0.1" && *ip != "0.0.0.0" {
                            return Some(format!("http://{}:{}", ip, http_port));
                        }
                    }
                }
            }
        }
    }

    // 2) Fallback: registrierte Peers durchsuchen
    let registered = node.get_peers();
    for p in &registered {
        if p.url.contains(peer_id_str) || p.url.contains(&peer_id_str[..12.min(peer_id_str.len())]) {
            return Some(p.url.clone());
        }
    }

    None
}

// ─── API: Update-Status (Dashboard) ─────────────────────────────────────────

#[derive(Serialize)]
struct UpdateStatusResponse {
    current_version: String,
    update_available: bool,
    update_version: Option<String>,
    update_changelog: Option<String>,
    update_size: Option<u64>,
    update_published_at: Option<String>,
    download_state: String,
    download_percent: u8,
    chunks_total: usize,
    chunks_downloaded: usize,
    can_install: bool,
    auto_download: bool,
    auto_install: bool,
    auto_update_hour: Option<u8>,
    trusted_keys_count: usize,
}

async fn api_update_status(State(state): State<SetupState>) -> Json<UpdateStatusResponse> {
    let ns = state.node_state.read().await;
    if let Some(ref ns) = *ns {
        let um = ns.updater.read().unwrap_or_else(|e| e.into_inner());
        let progress = um.progress();
        let manifest = progress.manifest.as_ref();
        let is_available = manifest.is_some();
        let can_install = matches!(um.state, stone::updater::UpdateState::Ready);

        Json(UpdateStatusResponse {
            current_version: stone::updater::CURRENT_VERSION.to_string(),
            update_available: is_available,
            update_version: manifest.map(|m| m.version.clone()),
            update_changelog: manifest.map(|m| {
                if m.changelog.is_empty() { None } else { Some(m.changelog.clone()) }
            }).flatten(),
            update_size: manifest.map(|m| m.binary_size),
            update_published_at: manifest.map(|m| m.published_at.to_rfc3339()),
            download_state: format!("{:?}", um.state),
            download_percent: progress.percent,
            chunks_total: progress.chunks_total,
            chunks_downloaded: progress.chunks_downloaded,
            can_install,
            auto_download: um.config.auto_download,
            auto_install: um.config.auto_install,
            auto_update_hour: um.config.auto_update_hour,
            trusted_keys_count: um.config.trusted_keys.len(),
        })
    } else {
        Json(UpdateStatusResponse {
            current_version: stone::updater::CURRENT_VERSION.to_string(),
            update_available: false,
            update_version: None,
            update_changelog: None,
            update_size: None,
            update_published_at: None,
            download_state: "NodeOffline".to_string(),
            download_percent: 0,
            chunks_total: 0,
            chunks_downloaded: 0,
            can_install: false,
            auto_download: true,
            auto_install: false,
            auto_update_hour: None,
            trusted_keys_count: 0,
        })
    }
}

// ─── API: Update herunterladen ──────────────────────────────────────────────

async fn api_update_download(State(state): State<SetupState>) -> (StatusCode, Json<serde_json::Value>) {
    let ns = state.node_state.read().await;
    match ns.as_ref() {
        Some(ns) => {
            let (missing, manifest_version) = {
                let um = ns.updater.read().unwrap_or_else(|e| e.into_inner());
                let missing = um.missing_chunks();
                let version = um.manifest.as_ref().map(|m| m.version.clone());
                (missing, version)
            };

            let version = match manifest_version {
                Some(v) => v,
                None => return (StatusCode::CONFLICT, Json(serde_json::json!({
                    "ok": false, "error": "Kein Update-Manifest vorhanden"
                }))),
            };

            if missing.is_empty() {
                // Alle Chunks vorhanden → verifizieren
                let mut um = ns.updater.write().unwrap_or_else(|e| e.into_inner());
                if !matches!(um.state, stone::updater::UpdateState::Ready) {
                    if let Err(e) = um.verify_and_prepare() {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                            "ok": false, "error": format!("Verifizierung fehlgeschlagen: {e}")
                        })));
                    }
                }
                return (StatusCode::OK, Json(serde_json::json!({
                    "ok": true, "status": "complete", "message": "Alle Chunks vorhanden"
                })));
            }

            let chunk_count = missing.len();
            let peer_urls: Vec<String> = ns.node.get_peers()
                .iter()
                .filter(|p| p.is_healthy())
                .map(|p| p.url.clone())
                .collect();

            // Download im Hintergrund
            let updater_clone = ns.updater.clone();
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
                // Verifizieren wenn komplett
                let mut um = updater_clone.write().unwrap_or_else(|e| e.into_inner());
                if um.missing_chunks().is_empty() {
                    println!("[updater] ✓ Alle Chunks heruntergeladen – verifiziere...");
                    if let Err(e) = um.verify_and_prepare() {
                        eprintln!("[updater] Verifizierung: {e}");
                    }
                }
            });

            (StatusCode::ACCEPTED, Json(serde_json::json!({
                "ok": true, "status": "downloading",
                "version": version,
                "missing_chunks": chunk_count
            })))
        }
        None => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "ok": false, "error": "Node noch nicht gestartet"
        }))),
    }
}

// ─── API: Update installieren ───────────────────────────────────────────────

async fn api_update_install(State(state): State<SetupState>) -> (StatusCode, Json<serde_json::Value>) {
    let ns = state.node_state.read().await;
    match ns.as_ref() {
        Some(ns) => {
            // Erst verifizieren
            {
                let mut um = ns.updater.write().unwrap_or_else(|e| e.into_inner());
                if um.manifest.is_none() {
                    return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                        "ok": false, "error": "Kein Update verfügbar"
                    })));
                }
                if let Err(e) = um.verify_and_prepare() {
                    // Wenn schon Ready, ist das OK
                    if !matches!(um.state, stone::updater::UpdateState::Ready) {
                        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                            "ok": false, "error": format!("Verifizierung fehlgeschlagen: {e}")
                        })));
                    }
                }
            }
            // Installieren
            {
                let mut um = ns.updater.write().unwrap_or_else(|e| e.into_inner());
                // Version vor install() holen, weil install() manifest auf None setzt
                let version = um.manifest.as_ref()
                    .map(|m| m.version.clone())
                    .unwrap_or_else(|| "?".into());
                match um.install() {
                    Ok(_path) => {
                        // Neustart nach 2 Sekunden
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            println!("[updater] 🔄 Neustart nach Update...");
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
                        });
                        (StatusCode::OK, Json(serde_json::json!({
                            "ok": true,
                            "message": format!("Update v{version} installiert! Node startet in 2 Sekunden neu...")
                        })))
                    }
                    Err(e) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                            "ok": false, "error": format!("Installation fehlgeschlagen: {e}")
                        })))
                    }
                }
            }
        }
        None => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "ok": false, "error": "Node noch nicht gestartet"
            })))
        }
    }
}

// ─── API: Update-Config ändern ──────────────────────────────────────────────

#[derive(Deserialize)]
struct UpdateConfigReq {
    #[serde(default)]
    auto_download: Option<bool>,
    #[serde(default)]
    auto_install: Option<bool>,
    #[serde(default)]
    auto_update_hour: Option<Option<u8>>,  // Some(Some(3)) = 03:00, Some(None) = deaktiviert
}

async fn api_update_config(
    State(state): State<SetupState>,
    Json(body): Json<UpdateConfigReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ns = state.node_state.read().await;
    match ns.as_ref() {
        Some(ns) => {
            let mut um = ns.updater.write().unwrap_or_else(|e| e.into_inner());
            if let Some(ad) = body.auto_download {
                um.config.auto_download = ad;
            }
            if let Some(ai) = body.auto_install {
                um.config.auto_install = ai;
            }
            if let Some(hour) = body.auto_update_hour {
                um.config.auto_update_hour = hour.filter(|&h| h < 24);
            }
            let _ = um.save_config();
            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "auto_download": um.config.auto_download,
                "auto_install": um.config.auto_install,
                "auto_update_hour": um.config.auto_update_hour
            })))
        }
        None => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "ok": false, "error": "Node noch nicht gestartet"
            })))
        }
    }
}

// ─── API: Shard Repair ──────────────────────────────────────────────────────

async fn api_shard_repair(State(state): State<SetupState>) -> (StatusCode, Json<serde_json::Value>) {
    let ns = state.node_state.read().await;
    let net = state.network.read().await;
    match (ns.as_ref(), net.as_ref()) {
        (Some(ns), Some(net)) => {
            let result = repair_degraded_shards(&ns.node, net).await;
            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "repaired": result.repaired,
                "failed": result.failed,
                "skipped": result.skipped,
                "details": result.details,
            })))
        }
        _ => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "ok": false,
                "error": "Node oder P2P nicht gestartet"
            })))
        }
    }
}

// ─── API: Network Storage ───────────────────────────────────────────────────

#[derive(Serialize)]
struct NetworkStorageResponse {
    ok: bool,
    /// Eigener angebotener Speicher in GB
    local_offered_gb: u64,
    /// Eigener belegter Speicher in Bytes
    local_used_bytes: u64,
    /// Netzwerk-Gesamt angebotener Speicher in GB (inkl. lokal)
    total_offered_gb: u64,
    /// Netzwerk-Gesamt belegter Speicher in Bytes (inkl. lokal)
    total_used_bytes: u64,
    /// Netzwerk-Gesamt freier Speicher in Bytes
    total_free_bytes: u64,
    /// Anzahl Nodes die Speicher melden
    reporting_nodes: usize,
    /// Details pro Node
    nodes: Vec<StorageAnnouncement>,
}

async fn api_network_storage(State(state): State<SetupState>) -> Json<NetworkStorageResponse> {
    let cfg = state.config.read().await;
    let local_offered_gb = cfg.storage_offered_gb;
    let local_used = dir_size(std::path::Path::new(&cfg.data_dir));
    let local_total_bytes = local_offered_gb * 1024 * 1024 * 1024;
    let local_free = local_total_bytes.saturating_sub(local_used);
    drop(cfg);

    let net = state.network.read().await;
    let mut nodes: Vec<StorageAnnouncement> = Vec::new();
    let mut total_offered_gb = local_offered_gb;
    let mut total_used_bytes = local_used;
    let mut total_free_bytes = local_free;

    if let Some(ref handle) = *net {
        if let Some(status) = handle.get_status().await {
            for ann in &status.peer_storage {
                // Eigenen Eintrag überspringen (kommt von uns selbst)
                if ann.peer_id == handle.local_peer_id {
                    continue;
                }
                total_offered_gb += ann.offered_gb;
                total_used_bytes += ann.used_bytes;
                total_free_bytes += ann.free_bytes;
                nodes.push(ann.clone());
            }
        }
    }

    // Eigenen Node auch in die Liste aufnehmen
    let local_peer_id = net.as_ref().map(|h| h.local_peer_id.clone()).unwrap_or_default();
    let node_name = state.config.read().await.node_name.clone();
    nodes.insert(0, StorageAnnouncement {
        peer_id: local_peer_id,
        offered_gb: local_offered_gb,
        used_bytes: local_used,
        free_bytes: local_free,
        timestamp: chrono::Utc::now().timestamp(),
        node_name,
    });

    Json(NetworkStorageResponse {
        ok: true,
        local_offered_gb,
        local_used_bytes: local_used,
        total_offered_gb,
        total_used_bytes,
        total_free_bytes,
        reporting_nodes: nodes.len(),
        nodes,
    })
}

// ─── Fallback: /api/* und /ws an Node-Router weiterleiten ───────────────────

async fn forward_to_node_api(
    State(state): State<SetupState>,
    mut req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();

    // /api/* und /ws weiterleiten
    if !path.starts_with("/api/") && path != "/ws" {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    // Compat: /api/xxx → /api/v1/xxx rewrite (Flask/iOS nutzen alte Pfade)
    if path.starts_with("/api/") && !path.starts_with("/api/v1/") {
        let new_path = format!("/api/v1/{}", &path[5..]);
        let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        if let Ok(new_uri) = format!("{new_path}{query}").parse() {
            *req.uri_mut() = new_uri;
        }
    }

    let ns = state.node_state.read().await;
    match ns.as_ref() {
        Some(node_state) => {
            let router = build_router(node_state.clone());
            match router.oneshot(req).await {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("[forward] Router-Fehler: {e}");
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response()
                }
            }
        }
        None => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "error": "Node wird gestartet...",
                "node_running": false
            }))).into_response()
        }
    }
}

// ─── Page ───────────────────────────────────────────────────────────────────

async fn page_index() -> impl IntoResponse {
    Html(include_str!("setup_ui.html"))
}

// ─── API: Status ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    setup_complete: bool,
    has_password: bool,
    has_node_name: bool,
    has_wallet: bool,
    has_peers: bool,
    node_name: String,
}

async fn api_status(State(state): State<SetupState>) -> Json<StatusResponse> {
    let cfg = state.config.read().await;
    Json(StatusResponse {
        setup_complete: cfg.setup_complete,
        has_password: !cfg.password_hash.is_empty(),
        has_node_name: !cfg.node_name.is_empty(),
        has_wallet: !cfg.wallet_address.is_empty(),
        has_peers: !cfg.seed_peers.is_empty(),
        node_name: cfg.node_name.clone(),
    })
}

// ─── API: Set Password ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SetPasswordReq { password: String }

#[derive(Serialize)]
struct ApiResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

async fn api_set_password(
    State(state): State<SetupState>,
    Json(body): Json<SetPasswordReq>,
) -> (StatusCode, Json<ApiResult>) {
    let pw = &body.password;
    if pw.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(ApiResult {
            ok: false, error: Some("Passwort muss mindestens 8 Zeichen lang sein".into()), token: None,
        }));
    }
    let has_upper = pw.chars().any(|c| c.is_uppercase());
    let has_lower = pw.chars().any(|c| c.is_lowercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_special = pw.chars().any(|c| !c.is_alphanumeric());
    if !has_upper || !has_lower || !has_digit || !has_special {
        return (StatusCode::BAD_REQUEST, Json(ApiResult {
            ok: false, error: Some("Passwort braucht Groß-/Kleinbuchstaben, Zahl und Sonderzeichen".into()), token: None,
        }));
    }
    let hash = double_sha256(pw);
    let token = generate_token();
    let mut cfg = state.config.write().await;
    cfg.password_hash = hash;
    let _ = cfg.save();
    *state.session_token.write().await = Some(token.clone());
    (StatusCode::OK, Json(ApiResult { ok: true, error: None, token: Some(token) }))
}

// ─── API: Set Node ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SetNodeReq { node_name: String }

#[derive(Serialize)]
struct SetNodeResp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    wallet_address: String,
    mnemonic: String,
}

async fn api_set_node(
    State(state): State<SetupState>,
    Json(body): Json<SetNodeReq>,
) -> (StatusCode, Json<SetNodeResp>) {
    let name = body.node_name.trim().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SetNodeResp {
            ok: false, error: Some("Node-Name darf nicht leer sein".into()),
            wallet_address: String::new(), mnemonic: String::new(),
        }));
    }
    let (mnemonic, wallet_address) = generate_wallet_12();
    let api_key = format!("sk_{}", generate_hex(32));
    let mut cfg = state.config.write().await;
    cfg.node_name = name;
    cfg.wallet_address = wallet_address.clone();
    cfg.mnemonic_once = mnemonic.clone();
    cfg.api_key = api_key;
    cfg.created_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = cfg.save();
    (StatusCode::OK, Json(SetNodeResp { ok: true, error: None, wallet_address, mnemonic }))
}

// ─── API: Set Peers ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SetPeersReq { seed_peers: Vec<String> }

async fn api_set_peers(
    State(state): State<SetupState>,
    Json(body): Json<SetPeersReq>,
) -> Json<ApiResult> {
    let peers: Vec<String> = body.seed_peers.iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    let mut cfg = state.config.write().await;
    cfg.seed_peers = peers;
    let _ = cfg.save();
    Json(ApiResult { ok: true, error: None, token: None })
}

// ─── API: Finish Setup ──────────────────────────────────────────────────────

async fn api_finish_setup(State(state): State<SetupState>) -> Json<ApiResult> {
    {
        let mut cfg = state.config.write().await;
        if cfg.password_hash.is_empty() || cfg.node_name.is_empty() || cfg.wallet_address.is_empty() {
            return Json(ApiResult { ok: false, error: Some("Setup nicht vollständig".into()), token: None });
        }
        cfg.setup_complete = true;
        cfg.mnemonic_once.clear();
        if cfg.storage_offered_gb == 0 {
            cfg.storage_offered_gb = 50;
        }
        let _ = write_env_file(&cfg);
        let _ = cfg.save();
    }

    // Full-Node im Hintergrund starten
    let s = state.clone();
    tokio::spawn(async move {
        start_full_node(s).await;
    });

    Json(ApiResult { ok: true, error: None, token: None })
}

// ─── API: Login ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginReq { password: String }

async fn api_login(
    State(state): State<SetupState>,
    Json(body): Json<LoginReq>,
) -> (StatusCode, Json<ApiResult>) {
    let cfg = state.config.read().await;
    let hash = double_sha256(&body.password);
    if hash != cfg.password_hash {
        return (StatusCode::UNAUTHORIZED, Json(ApiResult {
            ok: false, error: Some("Falsches Passwort".into()), token: None,
        }));
    }
    let token = generate_token();
    *state.session_token.write().await = Some(token.clone());
    (StatusCode::OK, Json(ApiResult { ok: true, error: None, token: Some(token) }))
}

// ─── API: Dashboard (mit echten Node-Daten) ─────────────────────────────────

#[derive(Serialize)]
struct DashboardData {
    ok: bool,
    node_name: String,
    wallet_address: String,
    wallet_balance: f64,
    uptime_secs: u64,
    peers_connected: usize,
    seed_peers: Vec<String>,
    http_port: u16,
    p2p_port: u16,
    public_ip: String,
    node_running: bool,
    block_count: u64,
    p2p_peer_id: String,
    mempool_size: usize,
    // Mining & Blockchain
    mining: MiningInfo,
    // Token Economy
    token_economy: TokenEconomyInfo,
    // Shard-Health
    shard_health: ShardHealthInfo,
    // Netzwerk-Metriken
    network_metrics: Option<NetworkMetricsData>,
    // Connected Peers
    connected_peers: Vec<PeerEntry>,
}

#[derive(Serialize)]
struct MiningInfo {
    pow_type: String,
    difficulty: u32,
    min_difficulty: u32,
    max_difficulty: u32,
    current_reward: f64,
    halving_epoch: u64,
    next_halving_block: u64,
    blocks_until_halving: u64,
    target_block_time: u64,
    avg_block_time: f64,
    mining_interval: u64,
}

#[derive(Serialize)]
struct TokenEconomyInfo {
    total_supply: f64,
    max_supply: f64,
    circulating: f64,
    burned: f64,
    fees_burned: f64,
    accounts: usize,
    total_staked: f64,
    staker_count: usize,
    estimated_apy: f64,
    reward_pool_balance: f64,
    // Staking-Details
    fee_pool_balance: f64,
    node_operator_pool_balance: f64,
    your_stake: f64,
    your_pending_rewards: f64,
    your_stake_level: String,
    your_total_rewards: f64,
    validator_eligible_count: usize,
    guardian_eligible_count: usize,
    node_operator_fee_multiplier: f64,
    total_delegated: f64,
    epoch: u64,
    epoch_length: u64,
}

#[derive(Serialize)]
struct PeerEntry {
    url: String,
    name: String,
    healthy: bool,
    block_height: u64,
}

#[derive(Serialize)]
struct NetworkMetricsData {
    bytes_in: u64,
    bytes_out: u64,
    messages_in: u64,
    messages_out: u64,
    blocks_received: u64,
    blocks_sent: u64,
    txs_received: u64,
    txs_sent: u64,
    shard_bytes_in: u64,
    shard_bytes_out: u64,
    uptime_secs: u64,
    avg_bytes_in_per_sec: f64,
    avg_bytes_out_per_sec: f64,
    connected_peers: usize,
    gossipsub_mesh_size: usize,
    total_known_peers: usize,
}


#[derive(Serialize)]
struct ShardHealthInfo {
    status: String,           // "healthy" | "degraded" | "critical" | "no_ec_data" | "offline"
    local_shards: u64,
    local_bytes: u64,
    local_chunks: u64,
    ec_documents: u64,
    ec_chunks: u64,
    total_shards_blockchain: u64,
    healthy_chunks: u64,
    degraded_chunks: u64,
    critical_chunks: u64,
    documents: Vec<ShardDocInfo>,
}

#[derive(Serialize)]
struct ShardDocInfo {
    doc_id: String,
    title: String,
    chunks: usize,
    ec_k: u8,
    ec_m: u8,
    status: String,
    healthy: u64,
    degraded: u64,
    critical: u64,
    size: u64,
}


async fn api_dashboard(State(state): State<SetupState>) -> Json<DashboardData> {
    let cfg = state.config.read().await;
    let uptime = state.start_time.elapsed().as_secs();

    // Echte Node-Daten auslesen
    let ns = state.node_state.read().await;
    // Effektive Wallet: STONE_NODE_WALLET env → effective_reward_wallet → Setup-Wallet
    let effective_wallet = if let Some(ref ns) = *ns {
        std::env::var("STONE_NODE_WALLET").ok()
            .filter(|w| !w.is_empty())
            .unwrap_or_else(|| ns.node.effective_reward_wallet())
    } else {
        cfg.wallet_address.clone()
    };
    let (node_running, block_count, peers_connected, p2p_peer_id, mempool_size, real_balance) =
        if let Some(ref ns) = *ns {
            let bc = ns.node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
            let pc = ns.node.get_peers().into_iter().filter(|p| p.is_healthy()).count();
            let pid = ns.network.as_ref().map(|h| h.local_peer_id.to_string()).unwrap_or_default();
            let ms = ns.node.mempool.pending_count();
            let bal = {
                let ledger = ns.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                if !effective_wallet.is_empty() {
                    let d = ledger.balance(&effective_wallet);
                    d.to_string().parse::<f64>().unwrap_or(0.0)
                } else { 0.0 }
            };
            (true, bc, pc, pid, ms, bal)
        } else {
            (false, 0, 0, String::new(), 0, cfg.wallet_balance)
        };

    // ── Mining-Info ─────────────────────────────────────────────────────
    let mining = if let Some(ref ns) = *ns {
        let chain = ns.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let bc = chain.blocks.len() as u64;
        let difficulty = get_current_pow_difficulty(&chain.blocks, bc);
        let pow_type = if bc >= ARGON2_POW_ACTIVATION_BLOCK { "Argon2id" } else { "SHA256 Lite" };
        let halving_epoch = bc / HALVING_INTERVAL;
        let next_halving_block = (halving_epoch + 1) * HALVING_INTERVAL;
        let blocks_until_halving = next_halving_block.saturating_sub(bc);

        // Current reward
        let reward_pool = {
            let ledger = ns.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            ledger.balance("pool:mining_rewards")
        };
        let current_reward = MasterNodeState::calculate_block_reward(bc, reward_pool);

        // Avg block time (last 20 blocks)
        let avg_block_time = if chain.blocks.len() >= 2 {
            let window = chain.blocks.len().min(20);
            let recent = &chain.blocks[chain.blocks.len() - window..];
            if recent.len() >= 2 {
                let time_span = (recent.last().unwrap().timestamp - recent.first().unwrap().timestamp).max(1);
                time_span as f64 / (recent.len() - 1) as f64
            } else { 0.0 }
        } else { 0.0 };

        MiningInfo {
            pow_type: pow_type.to_string(),
            difficulty,
            min_difficulty: MIN_POW_DIFFICULTY,
            max_difficulty: MAX_POW_DIFFICULTY,
            current_reward: current_reward.to_string().parse().unwrap_or(0.0),
            halving_epoch,
            next_halving_block,
            blocks_until_halving,
            target_block_time: TARGET_BLOCK_TIME_SECS,
            avg_block_time,
            mining_interval: MINING_INTERVAL_SECS,
        }
    } else {
        MiningInfo {
            pow_type: "offline".to_string(),
            difficulty: 0, min_difficulty: MIN_POW_DIFFICULTY, max_difficulty: MAX_POW_DIFFICULTY,
            current_reward: 0.0, halving_epoch: 0, next_halving_block: HALVING_INTERVAL,
            blocks_until_halving: HALVING_INTERVAL, target_block_time: TARGET_BLOCK_TIME_SECS,
            avg_block_time: 0.0, mining_interval: MINING_INTERVAL_SECS,
        }
    };

    // ── Token Economy ───────────────────────────────────────────────────
    let token_economy = if let Some(ref ns) = *ns {
        let ledger = ns.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let supply = SupplyInfo::from_ledger(&ledger);
        let reward_pool = ledger.balance("pool:mining_rewards");
        let fee_pool = ledger.balance(stone::token::reputation::STAKER_FEE_POOL);
        let node_op_pool = ledger.balance(stone::token::reputation::NODE_OPERATOR_POOL);
        let staking = ns.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
        let pool_info = staking.pool_info(reward_pool);
        let wallet = effective_wallet.clone();
        let (your_stake, your_pending, your_total, your_level) = if !wallet.is_empty() {
            if let Some(info) = staking.staker_info(&wallet) {
                (
                    info.staked_amount.to_string().parse().unwrap_or(0.0),
                    info.pending_rewards.to_string().parse().unwrap_or(0.0),
                    info.total_rewards.to_string().parse().unwrap_or(0.0),
                    info.stake_level.to_string(),
                )
            } else {
                (0.0, 0.0, 0.0, "observer".to_string())
            }
        } else {
            (0.0, 0.0, 0.0, "observer".to_string())
        };
        TokenEconomyInfo {
            total_supply: supply.total_supply.to_string().parse().unwrap_or(0.0),
            max_supply: supply.max_supply.to_string().parse().unwrap_or(0.0),
            circulating: supply.circulating.to_string().parse().unwrap_or(0.0),
            burned: supply.burned.to_string().parse().unwrap_or(0.0),
            fees_burned: supply.fees_burned.to_string().parse().unwrap_or(0.0),
            accounts: supply.accounts,
            total_staked: pool_info.total_staked.to_string().parse().unwrap_or(0.0),
            staker_count: pool_info.staker_count,
            estimated_apy: pool_info.estimated_apy.to_string().parse().unwrap_or(0.0),
            reward_pool_balance: pool_info.reward_pool_balance.to_string().parse().unwrap_or(0.0),
            fee_pool_balance: fee_pool.to_string().parse().unwrap_or(0.0),
            node_operator_pool_balance: node_op_pool.to_string().parse().unwrap_or(0.0),
            your_stake,
            your_pending_rewards: your_pending,
            your_stake_level: your_level,
            your_total_rewards: your_total,
            validator_eligible_count: pool_info.validator_eligible_count,
            guardian_eligible_count: pool_info.guardian_eligible_count,
            node_operator_fee_multiplier: stone::token::staking::NODE_OPERATOR_FEE_MULTIPLIER.parse().unwrap_or(1.5),
            total_delegated: staking.total_delegated.to_string().parse().unwrap_or(0.0),
            epoch: staking.current_epoch,
            epoch_length: stone::token::staking::EPOCH_LENGTH,
        }
    } else {
        TokenEconomyInfo {
            total_supply: 0.0, max_supply: 55_000_000.0, circulating: 0.0, burned: 0.0,
            fees_burned: 0.0, accounts: 0, total_staked: 0.0, staker_count: 0,
            estimated_apy: 0.0, reward_pool_balance: 0.0,
            fee_pool_balance: 0.0, node_operator_pool_balance: 0.0,
            your_stake: 0.0, your_pending_rewards: 0.0,
            your_stake_level: "observer".to_string(), your_total_rewards: 0.0,
            validator_eligible_count: 0, guardian_eligible_count: 0,
            node_operator_fee_multiplier: 1.5, total_delegated: 0.0,
            epoch: 0, epoch_length: 720,
        }
    };

    // ── Connected Peers ─────────────────────────────────────────────────
    let connected_peers = if let Some(ref ns) = *ns {
        ns.node.get_peers().iter().map(|p| PeerEntry {
            url: p.url.clone(),
            name: p.name.clone().unwrap_or_default(),
            healthy: p.is_healthy(),
            block_height: p.block_height,
        }).collect()
    } else {
        vec![]
    };

    // ── Shard-Health berechnen (Registry-basiert) ─────────────────────
    let shard_health = if let Some(ref ns) = *ns {
        // Lokale ShardStore-Statistik
        let (local_shards, local_bytes, local_chunks) = match ShardStore::new() {
            Ok(store) => {
                let s = store.stats();
                (s.total_shards, s.total_bytes, s.chunks_with_shards)
            }
            Err(_) => (0, 0, 0),
        };

        let registry = &ns.node.shard_registry;

        // Blockchain EC-Daten analysieren, Registry für Verfügbarkeit nutzen
        let chain = ns.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut ec_documents = 0u64;
        let mut ec_chunks = 0u64;
        let mut total_shards_blockchain = 0u64;
        let mut healthy_chunks = 0u64;
        let mut degraded_chunks = 0u64;
        let mut critical_chunks = 0u64;
        let mut doc_details: Vec<ShardDocInfo> = Vec::new();

        for block in &chain.blocks {
            for doc in &block.documents {
                let ec_ch: Vec<_> = doc.chunks.iter().filter(|c| !c.shards.is_empty()).collect();
                if ec_ch.is_empty() { continue; }
                ec_documents += 1;

                let mut doc_healthy = 0u64;
                let mut doc_degraded = 0u64;
                let mut doc_critical = 0u64;

                for chunk in &ec_ch {
                    ec_chunks += 1;
                    total_shards_blockchain += chunk.shards.len() as u64;
                    let k = chunk.ec_k as u64;

                    // Registry: wie viele Shards haben bekannte Holder?
                    let available = registry.available_shards_for_chunk(&chunk.hash) as u64;

                    if available > k {
                        healthy_chunks += 1;
                        doc_healthy += 1;
                    } else if available >= k {
                        degraded_chunks += 1;
                        doc_degraded += 1;
                    } else {
                        critical_chunks += 1;
                        doc_critical += 1;
                    }
                }

                let doc_status = if doc_critical > 0 { "critical" }
                    else if doc_degraded > 0 { "degraded" }
                    else { "healthy" };

                doc_details.push(ShardDocInfo {
                    doc_id: doc.doc_id.clone(),
                    title: doc.title.clone(),
                    chunks: ec_ch.len(),
                    ec_k: ec_ch.first().map(|c| c.ec_k).unwrap_or(0),
                    ec_m: ec_ch.first().map(|c| c.ec_m).unwrap_or(0),
                    status: doc_status.to_string(),
                    healthy: doc_healthy,
                    degraded: doc_degraded,
                    critical: doc_critical,
                    size: doc.chunks.iter().map(|c| c.size).sum::<u64>(),
                });
            }
        }

        let overall = if critical_chunks > 0 { "critical" }
            else if degraded_chunks > 0 { "degraded" }
            else if ec_chunks > 0 { "healthy" }
            else { "no_ec_data" };

        ShardHealthInfo {
            status: overall.to_string(),
            local_shards, local_bytes, local_chunks,
            ec_documents, ec_chunks, total_shards_blockchain,
            healthy_chunks, degraded_chunks, critical_chunks,
            documents: doc_details,
        }
    } else {
        ShardHealthInfo {
            status: "offline".to_string(),
            local_shards: 0, local_bytes: 0, local_chunks: 0,
            ec_documents: 0, ec_chunks: 0, total_shards_blockchain: 0,
            healthy_chunks: 0, degraded_chunks: 0, critical_chunks: 0,
            documents: vec![],
        }
    };

    // ── Netzwerk-Metriken ──────────────────────────────────────────────
    let network_metrics = {
        let net = state.network.read().await;
        if let Some(ref handle) = *net {
            if let Some(status) = handle.get_status().await {
                let m = &status.metrics;
                Some(NetworkMetricsData {
                    bytes_in: m.bytes_in,
                    bytes_out: m.bytes_out,
                    messages_in: m.messages_in,
                    messages_out: m.messages_out,
                    blocks_received: m.blocks_received,
                    blocks_sent: m.blocks_sent,
                    txs_received: m.txs_received,
                    txs_sent: m.txs_sent,
                    shard_bytes_in: m.shard_bytes_in,
                    shard_bytes_out: m.shard_bytes_out,
                    uptime_secs: m.uptime_secs,
                    avg_bytes_in_per_sec: m.avg_bytes_in_per_sec,
                    avg_bytes_out_per_sec: m.avg_bytes_out_per_sec,
                    connected_peers: status.connected_peers,
                    gossipsub_mesh_size: status.gossipsub_mesh_size,
                    total_known_peers: status.total_known_peers,
                })
            } else { None }
        } else { None }
    };

    Json(DashboardData {
        ok: true,
        node_name: cfg.node_name.clone(),
        wallet_address: effective_wallet.clone(),
        wallet_balance: real_balance,
        uptime_secs: uptime,
        peers_connected,
        seed_peers: cfg.seed_peers.clone(),
        http_port: cfg.http_port,
        p2p_port: cfg.p2p_port,
        public_ip: cfg.public_ip.clone(),
        node_running,
        block_count,
        p2p_peer_id,
        mempool_size,
        mining,
        token_economy,
        shard_health,
        network_metrics,
        connected_peers,
    })
}

// ─── API: Settings ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SettingsData {
    ok: bool,
    node_name: String,
    wallet_address: String,
    storage_offered_gb: u64,
    reward_per_day: f64,
    seed_peers: Vec<String>,
    http_port: u16,
    p2p_port: u16,
    data_dir: String,
    public_ip: String,
}

async fn api_get_settings(State(state): State<SetupState>) -> Json<SettingsData> {
    let cfg = state.config.read().await;
    Json(SettingsData {
        ok: true,
        node_name: cfg.node_name.clone(),
        wallet_address: cfg.wallet_address.clone(),
        storage_offered_gb: cfg.storage_offered_gb,
        reward_per_day: cfg.reward_per_day,
        seed_peers: cfg.seed_peers.clone(),
        http_port: cfg.http_port,
        p2p_port: cfg.p2p_port,
        data_dir: cfg.data_dir.clone(),
        public_ip: cfg.public_ip.clone(),
    })
}

#[derive(Deserialize)]
struct SaveSettingsReq {
    #[serde(default)] node_name: Option<String>,
    #[serde(default)] storage_offered_gb: Option<u64>,
    #[serde(default)] seed_peers: Option<Vec<String>>,
    #[serde(default)] http_port: Option<u16>,
    #[serde(default)] p2p_port: Option<u16>,
    #[serde(default)] data_dir: Option<String>,
}

async fn api_save_settings(
    State(state): State<SetupState>,
    Json(body): Json<SaveSettingsReq>,
) -> Json<ApiResult> {
    let mut cfg = state.config.write().await;
    if let Some(n) = body.node_name { if !n.trim().is_empty() { cfg.node_name = n.trim().to_string(); } }
    if let Some(gb) = body.storage_offered_gb { cfg.storage_offered_gb = gb; cfg.reward_per_day = calc_reward_per_day(gb); }
    if let Some(peers) = body.seed_peers { cfg.seed_peers = peers.into_iter().filter(|p| !p.trim().is_empty()).collect(); }
    if let Some(p) = body.http_port { cfg.http_port = p; }
    if let Some(p) = body.p2p_port { cfg.p2p_port = p; }
    if let Some(d) = body.data_dir { if !d.trim().is_empty() { cfg.data_dir = d; } }
    let _ = write_env_file(&cfg);
    let _ = cfg.save();
    Json(ApiResult { ok: true, error: None, token: None })
}

// ─── API: Send STONE ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SendReq { to: String, amount: f64 }

#[derive(Serialize)]
struct SendResp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
}

async fn api_send(
    State(state): State<SetupState>,
    Json(body): Json<SendReq>,
) -> (StatusCode, Json<SendResp>) {
    let to = body.to.trim().to_string();
    if to.is_empty() || to.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(SendResp {
            ok: false, error: Some("Ungültige Empfänger-Adresse (64 hex Zeichen)".into()), tx_hash: None,
        }));
    }
    if body.amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(SendResp {
            ok: false, error: Some("Betrag muss > 0 sein".into()), tx_hash: None,
        }));
    }

    // Balance aus Node-Ledger prüfen (falls Node läuft)
    let ns = state.node_state.read().await;
    let real_balance = if let Some(ref ns) = *ns {
        let cfg = state.config.read().await;
        let addr = cfg.wallet_address.clone();
        drop(cfg);
        if !addr.is_empty() {
            let ledger = ns.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            let d = ledger.balance(&addr);
            d.to_string().parse::<f64>().unwrap_or(0.0)
        } else { 0.0 }
    } else { -1.0 }; // -1 = Node nicht gestartet
    drop(ns);

    let cfg = state.config.read().await;
    let check_bal = if real_balance >= 0.0 { real_balance } else { cfg.wallet_balance };
    if body.amount > check_bal {
        return (StatusCode::BAD_REQUEST, Json(SendResp {
            ok: false, error: Some(format!("Nicht genug Guthaben ({:.4} STONE)", cfg.wallet_balance)), tx_hash: None,
        }));
    }
    drop(cfg);
    let tx_hash = generate_hex(32);
    let mut cfg = state.config.write().await;
    cfg.wallet_balance -= body.amount;
    let _ = cfg.save();
    (StatusCode::OK, Json(SendResp { ok: true, error: None, tx_hash: Some(tx_hash) }))
}

// ─── Wallet-Generierung ────────────────────────────────────────────────────

fn generate_wallet_12() -> (String, String) {
    use bip39::Mnemonic;
    use ed25519_dalek::SigningKey;
    let mnemonic = Mnemonic::generate(12).expect("Mnemonic generation failed");
    let phrase = mnemonic.to_string();
    let entropy = mnemonic.to_entropy();
    let key_bytes: [u8; 32] = Sha256::digest(&entropy).into();
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let public_key = signing_key.verifying_key();
    let wallet_address = hex::encode(public_key.to_bytes());
    // Display-Adresse loggen für den Nutzer
    eprintln!("Wallet generiert: {}", stone::token::display_address(&wallet_address));
    (phrase, wallet_address)
}

// ─── .env Schreiben ─────────────────────────────────────────────────────────

fn write_env_file(cfg: &NodeConfig) -> anyhow::Result<()> {
    let seed_str = cfg.seed_peers.join(",");
    let seed_line = if seed_str.is_empty() {
        "# STONE_SEED_NODES=".to_string()
    } else {
        format!("STONE_SEED_NODES={}", seed_str)
    };
    let content = format!(
"# Stone Node — generiert von stone-setup
# Erstellt: {}
# Node: {}

STONE_DATA_DIR={}
STONE_PORT={}
STONE_NODE_NAME={}
STONE_NODE_ID={}
STONE_CLUSTER_API_KEY={}
STONE_API_KEY={}
STONE_P2P_LISTEN=/ip4/0.0.0.0/tcp/{}
STONE_P2P_PORT={}
{}
STONE_NODE_WALLET={}
STONE_STORAGE_GB={}
STONE_PUBLIC_IP={}
",
        cfg.created_at, cfg.node_name,
        cfg.data_dir, cfg.http_port,
        cfg.node_name, cfg.node_name,
        cfg.api_key, cfg.api_key,
        cfg.p2p_port, cfg.p2p_port,
        seed_line, cfg.wallet_address,
        cfg.storage_offered_gb, cfg.public_ip,
    );
    std::fs::write(".env", content)?;
    Ok(())
}

// ─── Public IP ──────────────────────────────────────────────────────────────

async fn fetch_public_ip() -> Option<String> {
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];
    for url in &services {
        if let Ok(resp) = reqwest::get(*url).await {
            if let Ok(ip) = resp.text().await {
                let ip = ip.trim().to_string();
                if !ip.is_empty() && ip.len() < 50 { return Some(ip); }
            }
        }
    }
    None
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn double_sha256(input: &str) -> String {
    let first = Sha256::digest(input.as_bytes());
    let second = Sha256::digest(&first);
    hex::encode(second)
}

fn generate_token() -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen()).collect();
    hex::encode(bytes)
}

fn generate_hex(n: usize) -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..n).map(|_| rand::thread_rng().gen()).collect();
    hex::encode(bytes)
}

fn get_local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width { s.to_string() }
    else { format!("{}{}", s, " ".repeat(width - s.len())) }
}

fn dir_size(path: &Path) -> u64 {
    if !path.exists() { return 0; }
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(m) = entry.metadata() {
                if m.is_file() { total += m.len(); }
                else if m.is_dir() { total += dir_size(&entry.path()); }
            }
        }
    }
    total
}

fn human_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB { format!("{:.2} GB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.2} MB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.2} KB", bytes as f64 / KB as f64) }
    else { format!("{} B", bytes) }
}

fn print_banner() {
    eprintln!("\x1b[36;1m");
    eprintln!(r"  ███████╗████████╗ ██████╗ ███╗   ██╗███████╗");
    eprintln!(r"  ██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝");
    eprintln!(r"  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗  ");
    eprintln!(r"  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝  ");
    eprintln!(r"  ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗");
    eprintln!(r"  ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝");
    eprintln!("\x1b[0m");
    eprintln!("  \x1b[1mStone Node — Unified Binary (Setup + Full Node)\x1b[0m");
    eprintln!("  \x1b[2m──────────────────────────────────────────────────\x1b[0m");
}
