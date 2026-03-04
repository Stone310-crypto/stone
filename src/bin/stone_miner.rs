//! stone-miner — Standalone Mining Client mit Web-Dashboard
//!
//! Eigenständiges Mining-Programm für die StoneChain.
//! Verbindet sich zum Netzwerk, mined Blöcke und zeigt ein Web-Dashboard.
//!
//! Features:
//! - **Web UI**: Dashboard unter http://localhost:<port>/ui
//! - **Proof-of-Storage**: Periodische Storage-Audits, Challenge/Reward-System
//! - **Payout-Wallet**: Coins werden 1× täglich überwiesen
//! - **System-Monitoring**: CPU, RAM, Disk live im Dashboard
//! - **Voller Node**: P2P, Block-Sync, Konsensus im Hintergrund
//!
//! Usage:
//!   stone-miner                       # Start mit Web-Dashboard
//!   stone-miner --wallet <ADRESSE>    # Wallet direkt angeben
//!   stone-miner --headless            # Ohne Dashboard (Log-Modus)
//!   stone-miner --port 3030           # Dashboard-Port ändern (Default: 8080)

#[path = "server/mod.rs"]
mod server;

use std::{
    io::IsTerminal,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::{Local, Utc, Timelike};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole, StoneChain},
    consensus::{load_or_create_validator_key, local_validator_pubkey_hex, sign_block},
    master_node::{
        MasterNodeState, PeerInfo, HALVING_INTERVAL, INITIAL_BLOCK_REWARD,
        MINING_INTERVAL_SECS,
    },
    network::{start_network, NetworkEvent, NetworkHandle},
    storage::ChunkStore,
    storage_proof,
    token::transaction::{create_signed_tx, TxType},
};

use server::{
    rate_limiter::RateLimits,
    router::build_router,
    state::{
        load_api_key, load_admin_key, load_peers_from_disk, load_trust_from_disk,
        AppState as NodeAppState, HEARTBEAT_INTERVAL,
    },
    sync::{fetch_missing_chunks, pull_from_peer, spawn_auto_sync_task},
};

// ─── Embedded Dashboard HTML ─────────────────────────────────────────────────

const DASHBOARD_HTML: &str = include_str!("miner_dashboard.html");

// ─── Miner-Konfiguration ────────────────────────────────────────────────────

const MINER_CONFIG_FILE: &str = "miner_config.json";

/// Interval in Sekunden für Storage-Audits (Proof-of-Spacetime)
const STORAGE_AUDIT_INTERVAL_SECS: u64 = 300; // alle 5 Minuten

/// Anzahl Chunks die pro Audit geprüft werden
const AUDIT_CHUNKS_PER_ROUND: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinerConfig {
    /// Wallet-Adresse an die Rewards täglich ausgezahlt werden
    payout_wallet: String,
    /// Stunde (0-23) zu der die tägliche Auszahlung stattfindet
    #[serde(default = "default_payout_hour")]
    payout_hour: u8,
    /// Node-Name
    #[serde(default = "default_node_name")]
    node_name: String,
    /// Seed-Peers (HTTP-URLs)
    #[serde(default)]
    seed_peers: Vec<String>,
    /// HTTP-Port für Node-API
    #[serde(default = "default_http_port")]
    http_port: u16,
    /// Port für das Miner-Dashboard (Web UI)
    #[serde(default = "default_dashboard_port")]
    dashboard_port: u16,
    /// Letzte Auszahlung (ISO-8601)
    #[serde(default)]
    last_payout: String,
    /// Gesamte bisherige Auszahlungen
    #[serde(default)]
    total_paid_out: String,
    /// Wallet wurde konfiguriert (Setup abgeschlossen)
    #[serde(default)]
    configured: bool,
}

fn default_payout_hour() -> u8 { 14 }
fn default_node_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "stone-miner".into())
}
fn default_http_port() -> u16 { 8080 }
fn default_dashboard_port() -> u16 { 4005 }

impl MinerConfig {
    fn config_path() -> String {
        format!("{}/{MINER_CONFIG_FILE}", data_dir())
    }

    fn load() -> Option<Self> {
        let data = std::fs::read_to_string(Self::config_path()).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(&self) {
        std::fs::create_dir_all(data_dir()).ok();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            if let Err(e) = std::fs::write(Self::config_path(), json) {
                eprintln!("[miner] Config konnte nicht gespeichert werden: {e}");
            }
        }
    }
}

// ─── Storage Mining Metrics ──────────────────────────────────────────────────

/// Tracks Proof-of-Storage auditing: challenges, successes, failures.
#[derive(Debug, Clone, Serialize, Default)]
struct StorageMetrics {
    chunks_stored: usize,
    storage_used_bytes: u64,
    challenges_total: u64,
    challenges_passed: u64,
    challenges_failed: u64,
    health_pct: f64,
    last_audit: String,
    last_audit_human: String,
    // Chain-driven challenge stats
    chain_challenges_received: u64,
    chain_challenges_responded: u64,
    chain_challenges_missed: u64,
    chain_rewards_earned: String,
    pending_challenges: usize,
}

// ─── System Metrics ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
struct SystemMetrics {
    cpu_usage_pct: f32,
    memory_used_mb: u64,
    memory_total_mb: u64,
    disk_used_mb: u64,
    disk_total_mb: u64,
    stone_data_size_bytes: u64,
}

// ─── Shared Miner State (für Web UI Zugriff) ────────────────────────────────

#[derive(Clone)]
struct MinerWebState {
    node: Arc<MasterNodeState>,
    config: Arc<std::sync::RwLock<MinerConfig>>,
    logs: Arc<std::sync::RwLock<Vec<String>>>,
    validator_wallet: String,
    started_at: Instant,
    storage_metrics: Arc<std::sync::RwLock<StorageMetrics>>,
    system_metrics: Arc<std::sync::RwLock<SystemMetrics>>,
    network_active: bool,
}

impl MinerWebState {
    fn add_log(&self, msg: String) {
        let ts = Local::now().format("%H:%M:%S");
        let mut logs = self.logs.write().unwrap();
        logs.push(format!("[{ts}] {msg}"));
        if logs.len() > 300 {
            let excess = logs.len() - 300;
            logs.drain(0..excess);
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    fn uptime_str(&self) -> String {
        let secs = self.uptime_secs();
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        if h > 0 { format!("{h}h {m:02}m") } else { format!("{m}m {s:02}s") }
    }

    fn block_height(&self) -> u64 {
        self.node.chain.lock().unwrap().blocks.len() as u64
    }

    fn blocks_mined(&self) -> u64 {
        self.node.metrics.blocks_mined.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn total_rewards(&self) -> Decimal {
        let milli = self.node.metrics.total_rewards_milli.load(std::sync::atomic::Ordering::Relaxed);
        Decimal::new(milli as i64, 3)
    }

    fn mining_balance(&self) -> Decimal {
        self.node.token_ledger.read().unwrap().balance(&self.validator_wallet)
    }

    fn payout_balance(&self) -> Decimal {
        let config = self.config.read().unwrap();
        self.node.token_ledger.read().unwrap().balance(&config.payout_wallet)
    }

    fn current_reward(&self) -> Decimal {
        let pool = self.node.token_ledger.read().unwrap().balance("pool:storage_rewards");
        MasterNodeState::calculate_block_reward(self.block_height(), pool)
    }

    fn blocks_until_halving(&self) -> u64 {
        HALVING_INTERVAL - (self.block_height() % HALVING_INTERVAL)
    }

    fn throttle(&self) -> u64 {
        self.node.metrics.mining_throttle_pct.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn is_mining(&self) -> bool {
        self.throttle() > 0
            && self.node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn next_payout_str(&self) -> String {
        let hour = self.config.read().unwrap().payout_hour;
        let now = Local::now();
        let today = now.date_naive().and_hms_opt(hour as u32, 0, 0).unwrap();
        let next = if now.naive_local() > today {
            today + chrono::Duration::days(1)
        } else {
            today
        };
        next.format("%d.%m.%Y %H:%M").to_string()
    }
}

// ─── Web UI Handlers ─────────────────────────────────────────────────────────

/// GET /ui — Serves the dashboard HTML
async fn handle_dashboard() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
}

/// GET /api/miner/stats — All miner stats as JSON
async fn handle_miner_stats(State(state): State<MinerWebState>) -> impl IntoResponse {
    let config = state.config.read().unwrap().clone();
    let storage = state.storage_metrics.read().unwrap().clone();
    let system = state.system_metrics.read().unwrap().clone();
    let logs = state.logs.read().unwrap().clone();
    let (peers_healthy, peers_total) = {
        let peers = state.node.get_peers();
        let h = peers.iter().filter(|p| p.is_healthy()).count();
        (h, peers.len())
    };
    let chain_valid = {
        let chain = state.node.chain.lock().unwrap();
        // Lightweight check: just verify last block links correctly (not entire chain)
        if chain.blocks.len() <= 1 {
            true
        } else {
            let last = &chain.blocks[chain.blocks.len() - 1];
            let prev = &chain.blocks[chain.blocks.len() - 2];
            last.previous_hash == prev.hash
        }
    };

    Json(serde_json::json!({
        "configured": config.configured,
        "mining": {
            "active": state.is_mining(),
            "block_height": state.block_height(),
            "blocks_mined": state.blocks_mined(),
            "total_rewards": state.total_rewards().to_string(),
            "current_reward": state.current_reward().to_string(),
            "blocks_until_halving": state.blocks_until_halving(),
            "throttle_pct": state.throttle(),
            "mining_interval_secs": MINING_INTERVAL_SECS,
        },
        "storage": storage,
        "wallet": {
            "mining_address": state.validator_wallet,
            "payout_address": config.payout_wallet,
            "mining_balance": state.mining_balance().to_string(),
            "payout_balance": state.payout_balance().to_string(),
            "total_paid_out": config.total_paid_out,
            "next_payout": state.next_payout_str(),
        },
        "network": {
            "peers_healthy": peers_healthy,
            "peers_total": peers_total,
            "p2p_active": state.network_active,
            "chain_valid": chain_valid,
        },
        "system": system,
        "info": {
            "version": env!("CARGO_PKG_VERSION"),
            "node_name": config.node_name,
            "uptime_secs": state.uptime_secs(),
            "uptime_human": state.uptime_str(),
        },
        "logs": logs,
    }))
}

/// POST /api/miner/mining/toggle — Toggle mining on/off
async fn handle_toggle_mining(State(state): State<MinerWebState>) -> impl IntoResponse {
    let current = state.throttle();
    if current > 0 {
        state.node.metrics.mining_throttle_pct.store(0, std::sync::atomic::Ordering::Relaxed);
        state.add_log("Mining PAUSIERT".into());
        Json(serde_json::json!({"mining": false, "message": "Mining pausiert"}))
    } else {
        state.node.metrics.mining_throttle_pct.store(100, std::sync::atomic::Ordering::Relaxed);
        state.add_log("Mining GESTARTET".into());
        Json(serde_json::json!({"mining": true, "message": "Mining gestartet"}))
    }
}

/// POST /api/miner/mining/throttle?value=<0-100>
#[derive(Deserialize)]
struct ThrottleQuery { value: u64 }

async fn handle_set_throttle(
    State(state): State<MinerWebState>,
    Query(q): Query<ThrottleQuery>,
) -> impl IntoResponse {
    let val = q.value.min(100);
    state.node.metrics.mining_throttle_pct.store(val, std::sync::atomic::Ordering::Relaxed);
    state.add_log(format!("Throttle: {val}%"));
    Json(serde_json::json!({"throttle_pct": val}))
}

/// POST /api/miner/payout — Force payout
async fn handle_force_payout(State(state): State<MinerWebState>) -> impl IntoResponse {
    let mut config = state.config.write().unwrap().clone();
    let msg = force_payout(&state.node, &mut config, &state.validator_wallet);
    *state.config.write().unwrap() = config;
    state.add_log(msg.clone());
    Json(serde_json::json!({"message": msg}))
}

/// GET /api/miner/logs — Recent logs as JSON
async fn handle_miner_logs(State(state): State<MinerWebState>) -> impl IntoResponse {
    let logs = state.logs.read().unwrap().clone();
    Json(logs)
}

/// POST /api/miner/config — Save wallet configuration from Setup UI
#[derive(Deserialize)]
struct ConfigPayload {
    payout_wallet: Option<String>,
    payout_hour: Option<u8>,
    node_name: Option<String>,
}

async fn handle_save_config(
    State(state): State<MinerWebState>,
    Json(payload): Json<ConfigPayload>,
) -> impl IntoResponse {
    let mut config = state.config.write().unwrap();

    if let Some(wallet) = payload.payout_wallet {
        let wallet = wallet.trim().to_string();
        if wallet.is_empty() {
            // Keep mining wallet as payout
            config.payout_wallet = state.validator_wallet.clone();
        } else {
            config.payout_wallet = wallet;
        }
    }
    if let Some(hour) = payload.payout_hour {
        config.payout_hour = hour.min(23);
    }
    if let Some(name) = payload.node_name {
        let name = name.trim().to_string();
        if !name.is_empty() {
            config.node_name = name;
        }
    }
    config.configured = true;
    config.save();

    state.add_log("✅ Konfiguration gespeichert".into());

    Json(serde_json::json!({
        "ok": true,
        "message": "Konfiguration gespeichert",
        "payout_wallet": config.payout_wallet,
    }))
}

// ─── Tägliche Auszahlung ────────────────────────────────────────────────────

fn try_daily_payout(
    node: &Arc<MasterNodeState>,
    config: &mut MinerConfig,
    validator_wallet: &str,
) -> Option<String> {
    let now = Local::now();

    // Schon heute ausgezahlt?
    if !config.last_payout.is_empty() {
        if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&config.last_payout) {
            if last.with_timezone(&Local).date_naive() == now.date_naive() {
                return None;
            }
        }
    }

    // Richtige Stunde?
    if now.hour() as u8 != config.payout_hour { return None; }
    if validator_wallet == config.payout_wallet { return None; }

    let balance = node.token_ledger.read().unwrap().balance(validator_wallet);
    if balance <= Decimal::ZERO {
        return Some("Kein Guthaben zum Auszahlen".into());
    }

    let signing_key = load_or_create_validator_key();
    let nonce = node.token_ledger.read().unwrap().nonce(validator_wallet);
    let fee = Decimal::new(1, 4);
    let payout_amount = balance - fee;
    if payout_amount <= Decimal::ZERO {
        return Some("Balance zu gering für Auszahlung".into());
    }

    match create_signed_tx(
        &signing_key, TxType::Transfer,
        validator_wallet.to_string(), config.payout_wallet.clone(),
        payout_amount, fee, nonce,
        format!("Daily Miner Payout {}", now.format("%Y-%m-%d")),
    ) {
        Ok(tx) => {
            let ledger = node.token_ledger.read().unwrap();
            match node.mempool.add_tx(tx, Some(&ledger)) {
                Ok(()) => {
                    config.last_payout = Utc::now().to_rfc3339();
                    let prev: Decimal = config.total_paid_out.parse().unwrap_or(Decimal::ZERO);
                    config.total_paid_out = (prev + payout_amount).to_string();
                    config.save();
                    Some(format!("💸 Payout: {} STONE → {}…", payout_amount,
                        &config.payout_wallet[..16.min(config.payout_wallet.len())]))
                }
                Err(e) => Some(format!("Payout TX fehlgeschlagen: {e}")),
            }
        }
        Err(e) => Some(format!("Payout TX-Erstellung fehlgeschlagen: {e}")),
    }
}

fn force_payout(
    node: &Arc<MasterNodeState>,
    config: &mut MinerConfig,
    validator_wallet: &str,
) -> String {
    if validator_wallet == config.payout_wallet {
        return "Mining-Wallet = Payout-Wallet → kein Transfer nötig".into();
    }

    let balance = node.token_ledger.read().unwrap().balance(validator_wallet);
    if balance <= Decimal::ZERO {
        return "Kein Guthaben zum Auszahlen".into();
    }

    let signing_key = load_or_create_validator_key();
    let nonce = node.token_ledger.read().unwrap().nonce(validator_wallet);
    let fee = Decimal::new(1, 4);
    let payout_amount = balance - fee;
    if payout_amount <= Decimal::ZERO {
        return "Balance zu gering für Auszahlung".into();
    }

    match create_signed_tx(
        &signing_key, TxType::Transfer,
        validator_wallet.to_string(), config.payout_wallet.clone(),
        payout_amount, fee, nonce,
        format!("Manual Miner Payout {}", Local::now().format("%Y-%m-%d %H:%M")),
    ) {
        Ok(tx) => {
            let ledger = node.token_ledger.read().unwrap();
            match node.mempool.add_tx(tx, Some(&ledger)) {
                Ok(()) => {
                    config.last_payout = Utc::now().to_rfc3339();
                    let prev: Decimal = config.total_paid_out.parse().unwrap_or(Decimal::ZERO);
                    config.total_paid_out = (prev + payout_amount).to_string();
                    config.save();
                    format!("💸 {payout_amount} STONE → Payout-Wallet gesendet")
                }
                Err(e) => format!("TX abgelehnt: {e}"),
            }
        }
        Err(e) => format!("TX-Erstellung fehlgeschlagen: {e}"),
    }
}

// ─── P2P Event Handler ──────────────────────────────────────────────────────

async fn handle_p2p_event(
    event: NetworkEvent,
    node: &Arc<MasterNodeState>,
    handle: &NetworkHandle,
    api_key: &Arc<String>,
) {
    match event {
        NetworkEvent::BlockReceived { block, from_peer: _ } => {
            let peer_urls: Vec<String> = node.get_peers()
                .into_iter()
                .filter(|p| p.is_healthy())
                .map(|p| p.url.clone())
                .collect();
            for url in &peer_urls {
                fetch_missing_chunks(&block, url, api_key).await;
            }

            let poa_ok = {
                let syncing = !node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed);
                if syncing { None }
                else {
                    let vs = node.validator_set.read().unwrap();
                    if vs.validators.is_empty() { None }
                    else {
                        let prev_hash = {
                            let chain = node.chain.lock().unwrap();
                            chain.blocks.last().map(|b| b.hash.clone()).unwrap_or("genesis".into())
                        };
                        Some(vs.verify_block_with_selection(
                            &block.hash, &block.signer, &block.validator_signature,
                            &prev_hash, block.index,
                        ).is_acceptable())
                    }
                }
            };

            enum BlockResult { Accepted(u64), NeedsResync, Other }

            let result = {
                let mut chain = node.chain.lock().unwrap();
                if chain.blocks.iter().any(|b| b.hash == block.hash) {
                    BlockResult::Other
                } else {
                    let txs = block.transactions.clone();
                    let idx = block.index;
                    match chain.accept_peer_block(*block, poa_ok) {
                        Ok(_) => {
                            if !txs.is_empty() {
                                let mut ledger = node.token_ledger.write().unwrap();
                                let _ = ledger.apply_block_txs(&txs, idx);
                                let _ = ledger.persist();
                                for tx in &txs {
                                    node.mempool.mark_known(&tx.tx_id);
                                    node.mempool.remove_tx(&tx.tx_id);
                                }
                            }
                            BlockResult::Accepted(chain.blocks.len() as u64)
                        }
                        Err(ref e) if e.starts_with("Gap:") || e.contains("previous_hash") => {
                            BlockResult::NeedsResync
                        }
                        _ => BlockResult::Other,
                    }
                }
            };

            match result {
                BlockResult::Accepted(count) => { handle.set_chain_count(count).await; }
                BlockResult::NeedsResync => {
                    let n = node.clone();
                    let k = api_key.clone();
                    tokio::spawn(async move {
                        for p in n.get_peers().iter().filter(|p| p.is_healthy()) {
                            pull_from_peer(&n, &p.url, &k).await;
                        }
                    });
                }
                _ => {}
            }
        }

        NetworkEvent::TxReceived { tx, .. } => {
            let ledger = node.token_ledger.read().unwrap();
            let _ = node.mempool.add_tx(*tx, Some(&ledger));
        }

        NetworkEvent::PeerIdentified { peer_id, addresses, .. } => {
            let http_port = std::env::var("STONE_PORT")
                .ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(8080);
            let mut ip: Option<String> = None;
            for addr in &addresses {
                let parts: Vec<&str> = addr.split('/').collect();
                for (i, part) in parts.iter().enumerate() {
                    if *part == "ip4" {
                        if let Some(found) = parts.get(i + 1) {
                            if *found != "127.0.0.1" && *found != "0.0.0.0" {
                                ip = Some(found.to_string());
                                break;
                            }
                        }
                    }
                }
                if ip.is_some() { break; }
            }
            if let Some(ip) = ip {
                let url = format!("http://{}:{}", ip, http_port);
                let mut peer_info = PeerInfo::new(&url);
                peer_info.name = Some(peer_id[..12.min(peer_id.len())].to_string());
                node.upsert_peer(peer_info);
                if let Ok(json) = serde_json::to_string_pretty(&node.get_peers()) {
                    let _ = std::fs::write(format!("{}/peers.json", data_dir()), json);
                }
            }
        }

        NetworkEvent::PeerConnected { peer_id, .. } => {
            eprintln!("[p2p] Peer verbunden: {}", &peer_id[..12.min(peer_id.len())]);
        }
        _ => {}
    }
}

// ─── Storage Challenge Worker (Proof-of-Spacetime) ──────────────────────────

/// Background task: periodically audits locally stored chunks.
///
/// This is the "Proof-of-Spacetime" mechanism:
/// - Every STORAGE_AUDIT_INTERVAL_SECS, pick random chunks
/// - Read them from disk, verify their hash matches
/// - Track success/failure as challenges_passed/challenges_failed
/// - A high success rate means healthy storage → better mining rewards
fn spawn_storage_audit_worker(
    node: Arc<MasterNodeState>,
    storage_metrics: Arc<std::sync::RwLock<StorageMetrics>>,
    log_tx: std::sync::mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        // Initial delay
        tokio::time::sleep(Duration::from_secs(10)).await;

        let mut interval = tokio::time::interval(Duration::from_secs(STORAGE_AUDIT_INTERVAL_SECS));
        loop {
            interval.tick().await;

            // Collect info about stored chunks
            let store = match ChunkStore::new() {
                Ok(s) => s,
                Err(_) => continue,
            };

            let all_chunks = store.list_chunks();
            let total_size = store.total_size_bytes();
            let chunk_count = all_chunks.len();

            // Pick random chunks for audit
            let audit_count = AUDIT_CHUNKS_PER_ROUND.min(chunk_count);
            let mut passed = 0u64;
            let mut failed = 0u64;

            if audit_count > 0 {
                use sha2::{Digest, Sha256};

                // Use current timestamp as seed for "random" selection
                let seed = Utc::now().timestamp_millis() as u64;
                for i in 0..audit_count {
                    let idx = ((seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64))
                        % chunk_count as u64) as usize;
                    let chunk_hash = &all_chunks[idx];

                    // Read chunk and verify hash
                    match store.read_chunk(chunk_hash) {
                        Ok(data) => {
                            let computed = format!("{:x}", Sha256::digest(&data));
                            if computed == *chunk_hash {
                                passed += 1;
                            } else {
                                failed += 1;
                                let _ = log_tx.send(format!(
                                    "🚨 Storage-Audit: Chunk {}… KORRUPT! Hash mismatch",
                                    &chunk_hash[..12]
                                ));
                            }
                        }
                        Err(_) => {
                            failed += 1;
                            let _ = log_tx.send(format!(
                                "⚠ Storage-Audit: Chunk {}… nicht lesbar",
                                &chunk_hash[..12]
                            ));
                        }
                    }
                }
            }

            // Also incorporate block storage proofs from chain
            let _block_proof_stats = {
                let chain = node.chain.lock().unwrap();
                let recent_blocks: Vec<_> = chain.blocks.iter().rev().take(100).collect();
                let mut bp_total = 0u64;
                let mut bp_proven = 0u64;
                for block in &recent_blocks {
                    bp_total += block.storage_proof.proofs.len() as u64;
                    bp_proven += block.storage_proof.proofs.len() as u64; // all committed proofs are valid
                }
                (bp_total, bp_proven)
            };

            // Update metrics
            {
                let mut m = storage_metrics.write().unwrap();
                m.chunks_stored = chunk_count;
                m.storage_used_bytes = total_size;
                m.challenges_total += passed + failed;
                m.challenges_passed += passed;
                m.challenges_failed += failed;

                let total = m.challenges_total;
                m.health_pct = if total > 0 {
                    (m.challenges_passed as f64 / total as f64) * 100.0
                } else {
                    100.0
                };

                let now = Utc::now();
                m.last_audit = now.to_rfc3339();
                m.last_audit_human = now.with_timezone(&Local).format("%H:%M:%S").to_string();
            }

            if audit_count > 0 {
                let _ = log_tx.send(format!(
                    "💾 Storage-Audit: {passed}/{audit_count} Chunks OK, {} gespeichert ({:.1} MB)",
                    chunk_count,
                    total_size as f64 / 1_048_576.0
                ));
            }
        }
    });
}

// ─── Chain Challenge Response Worker ────────────────────────────────────────

/// Background task: watches for NetworkChallenges targeting our wallet
/// and automatically responds with proofs.
///
/// This is the core of the chain-driven Proof-of-Storage system:
/// - Scans new blocks for challenges where target_wallet == our wallet
/// - Reads the challenged chunk, computes the proof
/// - Submits the ChallengeResponse to the node's pending_challenge_responses
fn spawn_challenge_response_worker(
    node: Arc<MasterNodeState>,
    validator_wallet: String,
    storage_metrics: Arc<std::sync::RwLock<StorageMetrics>>,
    log_tx: std::sync::mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        // Initial delay
        tokio::time::sleep(Duration::from_secs(15)).await;

        let signing_key = load_or_create_validator_key();
        let mut last_checked_block: u64 = 0;
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            let chain = node.chain.lock().unwrap();
            let current_height = chain.blocks.len() as u64;

            if current_height <= last_checked_block {
                continue;
            }

            // Scan new blocks for challenges targeting us
            let start = last_checked_block.max(1) as usize;
            let end = chain.blocks.len();

            let mut our_challenges: Vec<stone::storage_proof::NetworkChallenge> = Vec::new();

            for block in &chain.blocks[start..end] {
                for challenge in &block.storage_challenges {
                    if challenge.target_wallet == validator_wallet {
                        // Check deadline hasn't passed
                        if challenge.deadline_block >= current_height {
                            our_challenges.push(challenge.clone());
                        }
                    }
                }
            }

            last_checked_block = current_height;

            if our_challenges.is_empty() {
                continue;
            }

            drop(chain); // Release lock before disk I/O

            let _ = log_tx.send(format!(
                "📋 {} Chain-Challenges an uns gerichtet! Beantworte...",
                our_challenges.len()
            ));

            // Open chunk store once
            let store = match ChunkStore::new() {
                Ok(s) => s,
                Err(e) => {
                    let _ = log_tx.send(format!("❌ ChunkStore-Fehler: {e}"));
                    continue;
                }
            };

            let mut responded = 0u64;
            let mut failed = 0u64;

            for challenge in &our_challenges {
                match stone::storage_proof::create_challenge_response(
                    challenge,
                    &store,
                    &validator_wallet,
                    &signing_key,
                    current_height,
                ) {
                    Some(response) => {
                        // Submit to node's pending responses
                        node.pending_challenge_responses.lock().unwrap().push(response);
                        responded += 1;
                        let _ = log_tx.send(format!(
                            "✅ Challenge {}… beantwortet (Chunk {}… Offset {})",
                            &challenge.challenge_id[..8.min(challenge.challenge_id.len())],
                            &challenge.chunk_hash[..8.min(challenge.chunk_hash.len())],
                            challenge.offset
                        ));
                    }
                    None => {
                        failed += 1;
                        let _ = log_tx.send(format!(
                            "⚠ Challenge {}… NICHT beantwortbar (Chunk {}… nicht lokal)",
                            &challenge.challenge_id[..8.min(challenge.challenge_id.len())],
                            &challenge.chunk_hash[..8.min(challenge.chunk_hash.len())],
                        ));
                    }
                }
            }

            // Update metrics
            {
                let mut m = storage_metrics.write().unwrap();
                m.chain_challenges_received += our_challenges.len() as u64;
                m.chain_challenges_responded += responded;
                m.chain_challenges_missed += failed;
                // Approximate rewards (CHALLENGE_REWARD per successful response)
                let reward_per: rust_decimal::Decimal = stone::storage_proof::CHALLENGE_REWARD.parse().unwrap_or_default();
                let prev: rust_decimal::Decimal = m.chain_rewards_earned.parse().unwrap_or_default();
                m.chain_rewards_earned = (prev + reward_per * rust_decimal::Decimal::from(responded)).to_string();
            }

            if responded > 0 || failed > 0 {
                let _ = log_tx.send(format!(
                    "💾 Chain-Challenges: {responded} beantwortet, {failed} verpasst"
                ));
            }
        }
    });
}

// ─── System Metrics Worker ──────────────────────────────────────────────────

fn spawn_system_metrics_worker(
    system_metrics: Arc<std::sync::RwLock<SystemMetrics>>,
) {
    tokio::spawn(async move {
        let mut sys = System::new();
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            // CPU
            sys.refresh_cpu_usage();
            tokio::time::sleep(Duration::from_millis(200)).await;
            sys.refresh_cpu_usage();
            let cpu = sys.global_cpu_usage();

            // Memory
            sys.refresh_memory();
            let mem_used = sys.used_memory() / 1_048_576;
            let mem_total = sys.total_memory() / 1_048_576;

            // Disk
            let disks = Disks::new_with_refreshed_list();
            let (disk_used, disk_total) = disks.list().iter()
                .find(|d| {
                    let mp = d.mount_point().to_string_lossy();
                    mp == "/" || mp == "C:\\"
                })
                .map(|d| {
                    let total = d.total_space() / 1_048_576;
                    let avail = d.available_space() / 1_048_576;
                    (total - avail, total)
                })
                .unwrap_or((0, 0));

            // stone_data directory size
            let data_size = dir_size_bytes(&data_dir());

            let mut m = system_metrics.write().unwrap();
            m.cpu_usage_pct = cpu;
            m.memory_used_mb = mem_used;
            m.memory_total_mb = mem_total;
            m.disk_used_mb = disk_used;
            m.disk_total_mb = disk_total;
            m.stone_data_size_bytes = data_size;
        }
    });
}

/// Recursively calculate directory size.
fn dir_size_bytes(path: &str) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_file() {
                total += meta.len();
            } else if meta.is_dir() {
                total += dir_size_bytes(&entry.path().to_string_lossy());
            }
        }
    }
    total
}

// ─── Log Watcher ────────────────────────────────────────────────────────────

fn spawn_log_watcher(
    node: Arc<MasterNodeState>,
    log_tx: std::sync::mpsc::Sender<String>,
) {
    let mut events = node.events.subscribe();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let msg = match &event {
                        stone::master_node::NodeEvent::BlockAdded { index, hash, .. } => {
                            Some(format!("✅ Block #{index} committed ({}…)", &hash[..8.min(hash.len())]))
                        }
                        stone::master_node::NodeEvent::TokenTransfer { tx_type, amount, from, to, block_index, .. } => {
                            if tx_type == "reward" {
                                Some(format!("⛏ Reward: {amount} STONE → {}… (Block #{block_index})", &to[..8.min(to.len())]))
                            } else if tx_type == "transfer" {
                                Some(format!("💸 Transfer: {amount} STONE {}… → {}…", &from[..8.min(from.len())], &to[..8.min(to.len())]))
                            } else { None }
                        }
                        stone::master_node::NodeEvent::SyncCompleted { peer_url, blocks_added } => {
                            Some(format!("🔄 Sync: {blocks_added} Blöcke von {peer_url}"))
                        }
                        stone::master_node::NodeEvent::PeerStatusChanged { url, status } => {
                            Some(format!("🔗 Peer {url}: {status:?}"))
                        }
                        _ => None,
                    };
                    if let Some(msg) = msg { let _ = log_tx.send(msg); }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let _ = log_tx.send(format!("⚠ {n} Events übersprungen"));
                }
                Err(_) => break,
            }
        }
    });
}

// ─── Hauptprogramm ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // ── Argumente parsen ────────────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let mut wallet_arg: Option<String> = None;
    let mut headless = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" | "-w" => {
                if i + 1 < args.len() {
                    wallet_arg = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Fehler: --wallet benötigt eine Adresse");
                    std::process::exit(1);
                }
            }
            "--headless" => { headless = true; i += 1; }
            "--help" | "-h" => {
                println!("stone-miner — StoneChain Standalone Miner mit Web-Dashboard");
                println!();
                println!("Usage:");
                println!("  stone-miner                        Start mit Web-Dashboard");
                println!("  stone-miner --wallet <ADRESSE>     Wallet direkt angeben");
                println!("  stone-miner --headless             Ohne Dashboard (Log-Modus)");
                println!();
                println!("Optionen:");
                println!("  -w, --wallet <ADDR>  Payout-Wallet-Adresse (64 Hex-Zeichen)");
                println!("      --headless       Log-Modus ohne Web-Dashboard");
                println!("  -h, --help           Diese Hilfe anzeigen");
                println!();
                println!("Dashboard: http://localhost:<port>/ui (Default: 8080)");
                std::process::exit(0);
            }
            _ => { i += 1; }
        }
    }

    // Auto-detect headless
    if !headless && !std::io::stdout().is_terminal() {
        headless = true;
    }

    // ── Konfiguration laden oder erstellen ──────────────────────────────
    std::fs::create_dir_all(data_dir()).ok();
    let mut config = MinerConfig::load().unwrap_or_else(|| {
        let seed_peers = load_peers_from_disk()
            .into_iter()
            .map(|p| p.url)
            .collect::<Vec<_>>();
        MinerConfig {
            payout_wallet: String::new(),
            payout_hour: default_payout_hour(),
            node_name: default_node_name(),
            seed_peers,
            http_port: default_http_port(),
            dashboard_port: default_dashboard_port(),
            last_payout: String::new(),
            total_paid_out: "0".into(),
            configured: false,
        }
    });

    // Wallet aus Argument oder Prompt
    if let Some(w) = wallet_arg {
        config.payout_wallet = w;
        config.configured = true;
    }

    if config.payout_wallet.is_empty() && !config.configured {
        // Wallet nicht konfiguriert → Setup über Web UI
        // Mining-Wallet trotzdem erstellen (für's Signieren)
        let signing_key = load_or_create_validator_key();
        let vw = local_validator_pubkey_hex(&signing_key);
        config.payout_wallet = vw.clone(); // Temporär: Rewards auf Mining-Wallet

        print_banner();
        println!();
        println!("  ⚠  Keine Payout-Wallet konfiguriert!");
        println!("  → Konfiguriere deine Wallet im Web-Dashboard:");
        println!("  → \x1b[36;1mhttp://localhost:{}/ui\x1b[0m", config.dashboard_port);
        println!();

        config.save();
    } else if !config.configured {
        // Wallet per CLI gesetzt, aber Setup war noch nicht abgeschlossen
        config.configured = true;
        config.save();
    } else {
        config.save();
    }

    // ── Node starten ────────────────────────────────────────────────────
    if let Err(e) = ChunkStore::new() {
        eprintln!("[miner] ChunkStore-Fehler: {e}");
    }

    let api_key = Arc::new(load_api_key());
    let admin_key = Arc::new(load_admin_key(&api_key));

    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| config.node_name.clone());

    let signing_key = load_or_create_validator_key();
    let validator_wallet = local_validator_pubkey_hex(&signing_key);

    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);

    // Peers laden
    let saved_peers = load_peers_from_disk();
    if !saved_peers.is_empty() {
        node.replace_peers(saved_peers);
    }
    for peer_url in &config.seed_peers {
        node.upsert_peer(PeerInfo::new(peer_url));
    }
    load_trust_from_disk(&node);

    let users = load_users();
    {
        let ledger = node.token_ledger.read().unwrap();
        if ledger.registered_account_count() > 0 {
            let mut local = users.lock().unwrap();
            let merged = stone::auth::rebuild_users_from_ledger(&ledger, &local);
            *local = merged;
            stone::auth::save_users(&local);
        }
    }

    // Hintergrund-Tasks
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    MasterNodeState::start_mining_loop(node.clone());
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    // Mempool-Eviction
    {
        let ne = node.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            let mut gc = 0u64;
            loop {
                iv.tick().await;
                ne.mempool.evict_expired();
                gc += 1;
                if gc % 5 == 0 { ne.mempool.gc_known_ids(); }
            }
        });
    }

    // P2P starten
    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            None
        } else {
            match start_network(None).await {
                Ok(handle) => {
                    let count = node.chain.lock().unwrap().blocks.len() as u64;
                    handle.set_chain_count(count).await;
                    handle.set_chain_ref(node.chain.clone()).await;
                    {
                        let mut event_rx = handle.subscribe();
                        let node_bg = node.clone();
                        let handle_bg = handle.clone();
                        let api_key_bg = api_key.clone();
                        tokio::spawn(async move {
                            while let Ok(event) = event_rx.recv().await {
                                handle_p2p_event(event, &node_bg, &handle_bg, &api_key_bg).await;
                            }
                        });
                    }
                    Some(handle)
                }
                Err(e) => { eprintln!("[miner] P2P-Fehler: {e}"); None }
            }
        };

    // ── Shared Miner State ──────────────────────────────────────────────
    let storage_metrics = Arc::new(std::sync::RwLock::new(StorageMetrics::default()));
    let system_metrics = Arc::new(std::sync::RwLock::new(SystemMetrics::default()));
    let logs = Arc::new(std::sync::RwLock::new(Vec::<String>::new()));

    let miner_state = MinerWebState {
        node: node.clone(),
        config: Arc::new(std::sync::RwLock::new(config.clone())),
        logs: logs.clone(),
        validator_wallet: validator_wallet.clone(),
        started_at: Instant::now(),
        storage_metrics: storage_metrics.clone(),
        system_metrics: system_metrics.clone(),
        network_active: network_handle.is_some(),
    };

    // ── Log-Channel ─────────────────────────────────────────────────────
    let (log_tx, log_rx) = std::sync::mpsc::channel::<String>();
    spawn_log_watcher(node.clone(), log_tx.clone());

    // ── Storage Audit Worker (Proof-of-Spacetime) ───────────────────────
    spawn_storage_audit_worker(node.clone(), storage_metrics.clone(), log_tx.clone());

    // ── Chain Challenge Response Worker ──────────────────────────────────
    spawn_challenge_response_worker(
        node.clone(),
        validator_wallet.clone(),
        storage_metrics.clone(),
        log_tx.clone(),
    );

    // ── System Metrics Worker ───────────────────────────────────────────
    spawn_system_metrics_worker(system_metrics.clone());

    // ── Log receiver → shared logs ──────────────────────────────────────
    {
        let miner_state_log = miner_state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                while let Ok(msg) = log_rx.try_recv() {
                    miner_state_log.add_log(msg);
                }
            }
        });
    }

    // ── HTTP-API + Dashboard ────────────────────────────────────────────
    let node_app_state = NodeAppState {
        node: node.clone(),
        users,
        api_key: api_key.clone(),
        admin_key,
        network: network_handle.clone(),
        rate_limits: Arc::new(RateLimits::new()),
        updater: Arc::new(std::sync::RwLock::new({
            let mut um = stone::updater::UpdateManager::new(&data_dir());
            um.load_persisted_update();
            um
        })),
        orgs: Arc::new(std::sync::Mutex::new(stone::organization::load_orgs())),
        chat_index: {
            let mut idx = stone::chat::load_chat_index();
            let chain = node.chain.lock().unwrap();
            if chain.blocks.len() as u64 > idx.last_indexed_block {
                let new_blocks: Vec<_> = chain.blocks.iter()
                    .skip(idx.last_indexed_block as usize)
                    .collect();
                idx.index_new_blocks(&new_blocks);
                let _ = stone::chat::save_chat_index(&idx);
            }
            Arc::new(std::sync::Mutex::new(idx))
        },
    };

    // Main node API
    let main_router = build_router(node_app_state);

    // Miner Dashboard routes (separate port)
    let miner_router = Router::new()
        .route("/ui", get(handle_dashboard))
        .route("/", get(handle_dashboard))
        .route("/api/miner/stats", get(handle_miner_stats))
        .route("/api/miner/mining/toggle", post(handle_toggle_mining))
        .route("/api/miner/mining/throttle", post(handle_set_throttle))
        .route("/api/miner/payout", post(handle_force_payout))
        .route("/api/miner/logs", get(handle_miner_logs))
        .route("/api/miner/config", post(handle_save_config))
        .with_state(miner_state.clone());

    // Main node API (no miner UI routes)
    let node_router = main_router;

    let http_port = std::env::var("STONE_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(config.http_port);

    let dashboard_port = std::env::var("STONE_DASHBOARD_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(config.dashboard_port);

    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
    let dashboard_addr = std::net::SocketAddr::from(([0, 0, 0, 0], dashboard_port));

    // Start Node-API HTTP server (port 8080)
    let node_listener = tokio::net::TcpListener::bind(http_addr).await?;

    // Start Dashboard HTTP server (port 4005)
    let dashboard_listener = tokio::net::TcpListener::bind(dashboard_addr).await?;

    miner_state.add_log(format!("Node: {node_id}"));
    miner_state.add_log(format!("Mining Wallet: {}...", &validator_wallet[..16.min(validator_wallet.len())]));
    miner_state.add_log(format!("Payout Wallet: {}...", &config.payout_wallet[..16.min(config.payout_wallet.len())]));
    miner_state.add_log(format!("Node-API auf Port {http_port}"));
    miner_state.add_log(format!("Dashboard auf Port {dashboard_port}"));
    if network_handle.is_some() {
        miner_state.add_log("P2P-Netzwerk aktiv".into());
    }

    println!();
    println!("  Stone Miner v{} gestartet", env!("CARGO_PKG_VERSION"));
    println!("  -------------------------------------");
    println!("  Node:     {node_id}");
    println!("  Wallet:   {}...", &validator_wallet[..16.min(validator_wallet.len())]);
    println!("  Payout:   {}...", &config.payout_wallet[..16.min(config.payout_wallet.len())]);
    if !headless {
        println!();
        println!("  \x1b[36;1mDashboard: http://localhost:{dashboard_port}/ui\x1b[0m");
        println!("  \x1b[2mNode-API:  http://localhost:{http_port}\x1b[0m");
    }
    println!("  -------------------------------------");
    println!();

    if headless {
        // === HEADLESS MODUS ===
        println!("[miner] Headless-Modus (kein Dashboard)");
        println!("[miner] Node-API auf Port {http_port}, Dashboard auf Port {dashboard_port}");

        // Node-API im Hintergrund
        tokio::spawn(async move {
            axum::serve(node_listener, node_router).await.unwrap();
        });

        // Dashboard trotzdem starten (kann headless trotzdem erreicht werden)
        tokio::spawn(async move {
            axum::serve(dashboard_listener, miner_router).await.unwrap();
        });

        let mut last_payout_check = Instant::now();
        let mut last_stats = Instant::now();
        let mut cfg = config.clone();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Stats alle 30 Sekunden
            if last_stats.elapsed() >= Duration::from_secs(30) {
                last_stats = Instant::now();
                let height = node.chain.lock().unwrap().blocks.len() as u64;
                let mined = node.metrics.blocks_mined.load(std::sync::atomic::Ordering::Relaxed);
                let balance = node.token_ledger.read().unwrap().balance(&validator_wallet);
                let (h, t) = {
                    let peers = node.get_peers();
                    (peers.iter().filter(|p| p.is_healthy()).count(), peers.len())
                };
                let sm = storage_metrics.read().unwrap();
                println!(
                    "[miner] Height: {} | Mined: {} | Balance: {} STONE | Peers: {}/{} | Chunks: {} ({:.1} MB)",
                    height, mined, balance, h, t, sm.chunks_stored, sm.storage_used_bytes as f64 / 1_048_576.0
                );
            }

            // Taegliche Auszahlung
            if last_payout_check.elapsed() >= Duration::from_secs(60) {
                last_payout_check = Instant::now();
                if let Some(msg) = try_daily_payout(&node, &mut cfg, &validator_wallet) {
                    println!("[miner] {msg}");
                }
            }
        }
    } else {
        // === DASHBOARD MODUS ===
        // Payout-Check im Hintergrund
        let payout_node = node.clone();
        let payout_config = miner_state.config.clone();
        let payout_wallet = validator_wallet.clone();
        let payout_state = miner_state.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                iv.tick().await;
                let mut cfg = payout_config.write().unwrap().clone();
                if let Some(msg) = try_daily_payout(&payout_node, &mut cfg, &payout_wallet) {
                    payout_state.add_log(msg);
                    *payout_config.write().unwrap() = cfg;
                }
            }
        });

        println!("[miner] Dashboard bereit unter http://localhost:{dashboard_port}/ui");
        println!("[miner] Node-API unter http://localhost:{http_port}");

        // Node-API im Hintergrund
        tokio::spawn(async move {
            axum::serve(node_listener, node_router).await.unwrap();
        });

        // Dashboard-Server (blockiert)
        axum::serve(dashboard_listener, miner_router).await?;
    }

    Ok(())
}

// ─── Hilfsfunktionen ────────────────────────────────────────────────────────

fn print_banner() {
    eprintln!("\x1b[36;1m");
    eprintln!(r"  ███████╗████████╗ ██████╗ ███╗   ██╗███████╗");
    eprintln!(r"  ██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝");
    eprintln!(r"  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗  ");
    eprintln!(r"  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝  ");
    eprintln!(r"  ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗");
    eprintln!(r"  ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝");
    eprintln!("\x1b[0m");
    eprintln!("  \x1b[1mStone Miner — Standalone Mining Client\x1b[0m");
    eprintln!("  \x1b[2m──────────────────────────────────────────────────\x1b[0m");
}
