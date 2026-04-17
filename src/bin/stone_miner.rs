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
//!   stone-miner --port 3030           # Dashboard-Port ändern (Default: 8081)

#[allow(dead_code)]
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
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{Local, Utc, Timelike};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole},
    consensus::{load_or_create_validator_key, local_validator_pubkey_hex},
    master::{
        MasterNodeState, PeerInfo, HALVING_INTERVAL,
        MINING_INTERVAL_SECS,
    },
    network::{start_network, NetworkEvent, NetworkHandle},
    shard::ShardStore,
    storage::ChunkStore,
    token::genesis::NetworkMode,
    token::transaction::{create_signed_tx, TxType},
};

use server::{
    rate_limiter::RateLimits,
    router::build_router,
    state::{
        load_api_key, load_admin_key, load_peers_from_disk, load_trust_from_disk,
        AppState as NodeAppState, HEARTBEAT_INTERVAL,
    },
    sync::{bootstrap_announce, fetch_missing_chunks, pull_from_peer, spawn_auto_sync_task, spawn_peer_health_task},
};

// ─── Embedded Dashboard HTML ─────────────────────────────────────────────────

const DASHBOARD_HTML: &str = include_str!("miner_dashboard.html");

// ─── Miner-Konfiguration ────────────────────────────────────────────────────

const MINER_CONFIG_FILE: &str = "miner_config.json";

/// Interval in Sekunden für Storage-Audits (Proof-of-Spacetime)
const STORAGE_AUDIT_INTERVAL_SECS: u64 = 300; // alle 5 Minuten

/// Anzahl Chunks die pro Audit geprüft werden
const AUDIT_CHUNKS_PER_ROUND: usize = 10;

/// Interval in Sekunden für automatische Shard-Reparatur
const SHARD_REPAIR_INTERVAL_SECS: u64 = 600; // alle 10 Minuten

/// Maximale Anzahl Shards die pro Reparatur-Runde repariert werden
const REPAIR_SHARDS_PER_ROUND: usize = 20;

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
fn default_http_port() -> u16 {
    if NetworkMode::from_env().is_testnet() { 8081 } else { 8082 }
}
fn default_dashboard_port() -> u16 {
    if NetworkMode::from_env().is_testnet() { 6969 } else { 6970 }
}
fn default_p2p_port() -> u16 {
    if NetworkMode::from_env().is_testnet() { 4002 } else { 5002 }
}

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
    // Shard-Repair stats
    repairs_completed: u64,
    repairs_failed: u64,
    repairs_skipped: u64,
    repair_rewards_earned: String,
    last_repair: String,
    last_repair_human: String,
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

// ─── PoW Mining Metrics ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
struct PowMetrics {
    /// Aktiv am Mining?
    solving: bool,
    /// Aktuelle Hashrate (Hashes/Sekunde)
    hashrate: f64,
    /// Aktueller Nonce-Fortschritt
    current_nonce: u64,
    /// Aktuelle Difficulty
    current_difficulty: u32,
    /// Block-Index des aktuellen Templates
    current_block_index: u64,
    /// Template-ID
    current_template_id: String,
    /// Gelöste Blöcke insgesamt (lokal gezählt)
    blocks_solved: u64,
    /// Letzter gelöster Block
    last_solved_block: u64,
    /// Zeit seit letztem gelösten Block (Sekunden)
    last_solve_elapsed_secs: f64,
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
    pow_metrics: Arc<std::sync::RwLock<PowMetrics>>,
    network_active: bool,
}

impl MinerWebState {
    fn add_log(&self, msg: String) {
        let ts = Local::now().format("%H:%M:%S");
        let mut logs = self.logs.write().unwrap_or_else(|e| e.into_inner());
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
        self.node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64
    }

    fn blocks_mined(&self) -> u64 {
        self.node.metrics.blocks_mined.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn total_rewards(&self) -> Decimal {
        let milli = self.node.metrics.total_rewards_milli.load(std::sync::atomic::Ordering::Relaxed);
        Decimal::new(milli as i64, 3)
    }

    fn mining_balance(&self) -> Decimal {
        self.node.token_ledger.read().unwrap_or_else(|e| e.into_inner()).balance(&self.validator_wallet)
    }

    fn payout_balance(&self) -> Decimal {
        let config = self.config.read().unwrap_or_else(|e| e.into_inner());
        self.node.token_ledger.read().unwrap_or_else(|e| e.into_inner()).balance(&config.payout_wallet)
    }

    fn current_reward(&self) -> Decimal {
        let pool = self.node.token_ledger.read().unwrap_or_else(|e| e.into_inner()).balance("pool:mining_rewards");
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
        let hour = self.config.read().unwrap_or_else(|e| e.into_inner()).payout_hour;
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
    let config = state.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let storage = state.storage_metrics.read().unwrap_or_else(|e| e.into_inner()).clone();
    let system = state.system_metrics.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pow = state.pow_metrics.read().unwrap_or_else(|e| e.into_inner()).clone();
    let logs = state.logs.read().unwrap_or_else(|e| e.into_inner()).clone();
    let (peers_healthy, peers_total) = {
        let peers = state.node.get_peers();
        let h = peers.iter().filter(|p| p.is_healthy()).count();
        (h, peers.len())
    };
    let chain_valid = {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
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
            "initial_sync_done": state.node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed),
            "syncing_from_height": state.node.metrics.syncing_from_height.load(std::sync::atomic::Ordering::Relaxed),
            "syncing_to_height": state.node.metrics.syncing_to_height.load(std::sync::atomic::Ordering::Relaxed),
        },
        "system": system,
        "pow": pow,
        "info": {
            "version": env!("CARGO_PKG_VERSION"),
            "node_name": config.node_name,
            "network": NetworkMode::from_env().to_string(),
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
    let mut config = state.config.write().unwrap_or_else(|e| e.into_inner()).clone();
    let msg = force_payout(&state.node, &mut config, &state.validator_wallet);
    *state.config.write().unwrap_or_else(|e| e.into_inner()) = config;
    state.add_log(msg.clone());
    Json(serde_json::json!({"message": msg}))
}

/// GET /api/miner/logs — Recent logs as JSON
async fn handle_miner_logs(State(state): State<MinerWebState>) -> impl IntoResponse {
    let logs = state.logs.read().unwrap_or_else(|e| e.into_inner()).clone();
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
    let mut config = state.config.write().unwrap_or_else(|e| e.into_inner());

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

    // Balance und Nonce atomar lesen (inkl. Pending-TXs im Mempool)
    let (balance, nonce) = {
        let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base_nonce = ledger.nonce(validator_wallet);
        let pending = node.mempool.sender_pending_count(validator_wallet);
        (ledger.balance(validator_wallet), base_nonce + pending)
    };
    if balance <= Decimal::ZERO {
        return Some("Kein Guthaben zum Auszahlen".into());
    }

    let signing_key = load_or_create_validator_key();
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
        stone::token::FeeTier::Standard,
    ) {
        Ok(tx) => {
            let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
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

    // Balance und Nonce atomar lesen (inkl. Pending-TXs im Mempool)
    let (balance, nonce) = {
        let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base_nonce = ledger.nonce(validator_wallet);
        let pending = node.mempool.sender_pending_count(validator_wallet);
        (ledger.balance(validator_wallet), base_nonce + pending)
    };
    if balance <= Decimal::ZERO {
        return "Kein Guthaben zum Auszahlen".into();
    }

    let signing_key = load_or_create_validator_key();
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
        stone::token::FeeTier::Standard,
    ) {
        Ok(tx) => {
            let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
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
            let block_for_chunks = block.clone();
            let api_key_bg = api_key.clone();
            tokio::spawn(async move {
                for url in peer_urls {
                    fetch_missing_chunks(&block_for_chunks, &url, &api_key_bg).await;
                }
            });

            let poa_ok = {
                let syncing = !node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed);
                if syncing { None }
                else {
                    let vs = node.validator_set.read().unwrap_or_else(|e| e.into_inner());
                    if vs.validators.is_empty() || vs.active_count() <= 1 { None }
                    else {
                        let (prev_hash, last_block_ts) = {
                            let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                            let ph = chain.blocks.last().map(|b| b.hash.clone()).unwrap_or("genesis".into());
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

            enum BlockResult { Accepted(u64), NeedsResync, Rejected, AlreadyKnown, Stale, Fork }

            let result = {
                let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                if chain.blocks.iter().any(|b| b.hash == block.hash) {
                    BlockResult::AlreadyKnown
                } else {
                    let txs = block.transactions.clone();
                    let chat_batches = block.chat_batches.clone();
                    let idx = block.index;
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
                                "[p2p] ⚠️  EQUIVOCATION: Validator {} hat Block #{} doppelt signiert! \
                                 hash_a={}… hash_b={}…",
                                &evidence.validator_pub_key[..16.min(evidence.validator_pub_key.len())],
                                evidence.block_index,
                                &evidence.hash_a[..12.min(evidence.hash_a.len())],
                                &evidence.hash_b[..12.min(evidence.hash_b.len())],
                            );
                            MasterNodeState::slash_equivocation(node, &evidence);
                        }
                    }

                    match chain.accept_peer_block(*block, poa_ok) {
                        Ok(_) => {
                            // Orphan-TX-Recovery: User-TXs aus verwaisten Blöcken zurück in Mempool
                            let orphaned = std::mem::take(&mut chain.orphaned_blocks);
                            if !orphaned.is_empty() {
                                node.mempool.requeue_orphaned_txs(&orphaned);
                                // Ledger nach Single-Block-Reorg neu aufbauen (BUG-11 Fix)
                                // accept_peer_block hat truncate_to intern gerufen,
                                // danach den neuen Block angefügt → Ledger muss konsistent sein
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
                                let receipts = ledger.apply_block_txs(&txs, idx);
                                ledger.replay_mode = false;
                                let _ = ledger.persist();
                                for tx in &txs {
                                    node.mempool.mark_known(&tx.tx_id);
                                    node.mempool.remove_tx(&tx.tx_id);
                                }
                                // Staking-TXs im StakingPool verarbeiten (P2P-Pfad)
                                node.apply_staking_from_txs(&txs, &receipts);
                            }
                            // HTLC-TXs verarbeiten (P2P-Pfad)
                            MasterNodeState::process_htlc_txs(&node, &txs, idx);
                            // Chat-Batch-Records speichern (für Chat-Index)
                            for batch in &chat_batches {
                                if !batch.messages.is_empty() {
                                    node.message_pool.store_batch_record(
                                        &batch.merkle_root, &batch.messages, idx,
                                    );
                                }
                            }
                            // Validator Auto-Discovery: Nur nach Initial-Sync
                            // SECURITY: Nur Signer mit ausreichend Stake werden aufgenommen
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
                                    // Stake-Check: Signer muss mindestens VALIDATOR_MIN_STAKE haben
                                    let has_stake = {
                                        let pool = node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
                                        let min_stake: rust_decimal::Decimal = stone::token::staking::VALIDATOR_MIN_STAKE.parse().unwrap();
                                        pool.stakers.values().any(|entry| entry.staked_amount >= min_stake)
                                            || pool.total_staked >= min_stake
                                    };
                                    if has_stake {
                                        let info = stone::consensus::ValidatorInfo::new_pending(
                                            block_signer.clone(),
                                            block_validator_pk.clone(),
                                        );
                                        vs.add(info);
                                        println!(
                                            "[consensus] 🔗 Validator '{}' auto-discovered (pending) via Block #{}",
                                            &block_signer, idx,
                                        );
                                    } else {
                                        eprintln!(
                                            "[consensus] ⚠ Validator '{}' auto-discovery abgelehnt – kein ausreichender Stake im Pool",
                                            &block_signer,
                                        );
                                    }
                                }
                            }
                            BlockResult::Accepted(chain.blocks.len() as u64)
                        }
                        Err(ref e) if e.starts_with("Stale:") => BlockResult::Stale,
                        Err(ref e) if e.starts_with("Gap:") || e.contains("previous_hash") => {
                            BlockResult::NeedsResync
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
                        Err(e) => {
                            eprintln!("[p2p] Block #{idx} abgelehnt: {e}");
                            BlockResult::Rejected
                        }
                    }
                }
            };

            match result {
                BlockResult::Accepted(count) => { handle.set_chain_count(count).await; }
                BlockResult::NeedsResync => {
                    let n = node.clone();
                    let k = api_key.clone();
                    tokio::spawn(async move {
                        // Peer mit der längsten Chain zuerst, parallel (max 3) —
                        // kein sequenzielles Warten auf jeden Peer (Issue #6)
                        let mut sync_peers: Vec<_> = n.get_peers()
                            .into_iter()
                            .filter(|p| p.is_healthy())
                            .collect();
                        sync_peers.sort_by(|a, b| b.block_height.cmp(&a.block_height));
                        let urls: Vec<String> = sync_peers.into_iter()
                            .take(3)
                            .map(|p| p.url)
                            .collect();
                        let handles: Vec<_> = urls.into_iter().map(|url| {
                            let nn = n.clone();
                            let kk = k.clone();
                            tokio::spawn(async move {
                                pull_from_peer(&nn, &url, &kk).await;
                            })
                        }).collect();
                        for h in handles { let _ = h.await; }
                    });
                }
                BlockResult::Rejected => {
                    handle.report_penalty(&from_peer, 5, "rejected block").await;
                }
                _ => {} // AlreadyKnown, Stale, Fork — kein Penalty
            }
        }

        // ── Range-Sync Batch (Fork-Reorg) ─────────────────────────────────
        NetworkEvent::RangeSyncReceived { blocks, from_peer: _from_peer } => {
            // Blöcke in den Puffer aufnehmen, sortieren, Duplikate entfernen
            {
                let mut buf = pending_sync_blocks.lock().unwrap_or_else(|e| e.into_inner());
                buf.extend(blocks);
                buf.sort_by_key(|b| b.index);
                buf.dedup_by_key(|b| b.index);
            }

            let reorg_result: Option<(u64, u64)> = {
                let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                let chain_tip = chain.blocks.len() as u64;

                // Lückenlose Blöcke ab Chain-Tip aus dem Puffer entnehmen
                let mut buf = pending_sync_blocks.lock().unwrap_or_else(|e| e.into_inner());
                // Alte Blöcke (< chain_tip) entfernen
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
                // Entnommene Blöcke aus dem Puffer entfernen (rückwärts)
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
                            // SECURITY: Prüfe ob der Signer im ValidatorSet bekannt ist
                            let vs = node.validator_set.read().unwrap_or_else(|e| e.into_inner());
                            let is_known_validator = vs.validators.iter().any(|v| {
                                v.public_key_hex == block.validator_pub_key
                            });
                            drop(vs);
                            if !is_known_validator {
                                eprintln!(
                                    "[sync] ⚠ Block #{} Signer PubKey {}… nicht im ValidatorSet – übersprungen",
                                    block.index,
                                    &block.validator_pub_key[..16.min(block.validator_pub_key.len())],
                                );
                                continue;
                            }
                        }

                        // SECURITY: Timestamp-Validierung (wie im Gossip-Handler)
                        if block.index > 0 {
                            let now = chrono::Utc::now().timestamp();
                            if block.timestamp > now + 5 * 60 {
                                eprintln!(
                                    "[sync] ⚠ Block #{} liegt {}s in der Zukunft – übersprungen",
                                    block.index, block.timestamp - now,
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
                                    let receipts = ledger.apply_block_txs(&txs, idx);
                                    ledger.replay_mode = false;
                                    let _ = ledger.persist();
                                    for tx in &txs {
                                        node.mempool.mark_known(&tx.tx_id);
                                        node.mempool.remove_tx(&tx.tx_id);
                                    }
                                    // Staking-TXs im StakingPool verarbeiten (RangeSync-Pfad)
                                    node.apply_staking_from_txs(&txs, &receipts);
                                }
                                // HTLC-TXs verarbeiten (RangeSync-Pfad)
                                MasterNodeState::process_htlc_txs(&node, &txs, idx);
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
            let tx_id_short = tx.tx_id[..12.min(tx.tx_id.len())].to_string();
            let peer_short = from_peer[..8.min(from_peer.len())].to_string();
            let tx_type = format!("{:?}", tx.tx_type);
            // Kein Ledger-Check bei Gossip-TXs: Nonces können out-of-order
            // ankommen. Echte Validierung passiert in filter_valid_txs() beim
            // Block-Build. Signatur wurde bereits in handle_gossip_tx() geprüft.
            match node.mempool.add_tx(*tx, None) {
                Ok(()) => {
                    println!("[p2p] 💸 TX {} von Peer {} aufgenommen ({})",
                        tx_id_short, peer_short, tx_type);
                }
                Err(e) => {
                    println!("[p2p] ⚠️  TX {} von Peer {} abgelehnt: {}",
                        tx_id_short, peer_short, e);
                }
            }
        }

        NetworkEvent::PeerIdentified { peer_id, addresses, .. } => {
            // IPv4 bevorzugen, IPv6 als Fallback (beide aber akzeptieren)
            let mut ipv4: Option<String> = None;
            let mut ipv6: Option<String> = None;

            for addr in &addresses {
                let parts: Vec<&str> = addr.split('/').collect();
                for (i, part) in parts.iter().enumerate() {
                    if *part == "ip4" {
                        if let Some(found) = parts.get(i + 1) {
                            if *found != "127.0.0.1" && *found != "0.0.0.0" && ipv4.is_none() {
                                ipv4 = Some(found.to_string());
                            }
                        }
                    } else if *part == "ip6" {
                        if let Some(found) = parts.get(i + 1) {
                            // Loopback und link-local überspringen
                            if *found != "::1" && !found.starts_with("fe80") && ipv6.is_none() {
                                ipv6 = Some(format!("[{}]", found));
                            }
                        }
                    }
                }
            }

            let ip_str = ipv4.or(ipv6);

            if let Some(ref ip) = ip_str {
                // Bekannte Peer-URLs nach IP prüfen (Deduplizierung über alle Ports/Peer-IDs)
                let known_peers = node.get_peers();
                let ip_already_known = known_peers.iter().any(|p| {
                    // URL enthält die IP (bei IPv6 geklammert)
                    p.url.contains(ip.trim_start_matches('[').trim_end_matches(']'))
                });

                if !ip_already_known {
                    // Kandidaten-Ports in Prioritätsreihenfolge
                    let candidate_ports = [8081u16, 3080, 3030];
                    for port in candidate_ports {
                        let url = format!("http://{}:{}", ip, port);
                        if !known_peers.iter().any(|p| p.url.trim_end_matches('/') == url.trim_end_matches('/')) {
                            let mut peer_info = PeerInfo::new(&url);
                            peer_info.name = Some(peer_id[..12.min(peer_id.len())].to_string());
                            node.upsert_peer(peer_info);
                            eprintln!("[p2p] 🔍 Neuer Peer entdeckt: {} ({})", &peer_id[..12.min(peer_id.len())], url);
                            break;
                        }
                    }
                }
            }
        }

        NetworkEvent::PeerConnected { peer_id, addr: _ } => {
            let local_height = node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
            // Handshake: eigene Version + Chain-Höhe via Gossip ankündigen
            let handshake = serde_json::json!({
                "type": "handshake",
                "version": env!("CARGO_PKG_VERSION"),
                "chain_height": local_height,
                "node_id": &node.node_id,
            });
            if let Ok(data) = serde_json::to_vec(&handshake) {
                handle.publish_gossip("chain-info", data).await;
            }
            eprintln!(
                "[p2p] 🤝 Peer verbunden: {} (handshake gesendet, lokal: #{})",
                &peer_id[..12.min(peer_id.len())], local_height
            );
        }

        NetworkEvent::ChatMessageReceived { message, from_peer } => {
            match node.message_pool.add_message(message) {
                Ok(seq) => eprintln!(
                    "[p2p] 💬 Chat von {} (seq: {})",
                    &from_peer[..12.min(from_peer.len())], seq,
                ),
                Err(_) => {}
            }
        }
        NetworkEvent::PeerDisconnected { peer_id, .. } => {
            let pid_short = &peer_id[..12.min(peer_id.len())];
            // Nur den getrennten Peer als Unreachable markieren – NICHT alle Peers löschen.
            let peers = node.get_peers();
            for peer in &peers {
                if peer.name.as_deref() == Some(pid_short) {
                    node.mark_peer_unhealthy_by_url(&peer.url);
                    eprintln!("[p2p] 🔌 Peer getrennt: {} ({})", pid_short, peer.url);
                }
            }
            if peers.iter().all(|p| p.name.as_deref() != Some(pid_short)) {
                eprintln!("[p2p] 🔌 Peer getrennt: {} (kein HTTP-Peer bekannt)", pid_short);
            }
        },
        NetworkEvent::ChatContentReceived { content, from_peer } => {
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
                println!(
                    "[p2p] 📝 Chat-Content sync: msg_id={}… von {}",
                    &content.msg_id[..8.min(content.msg_id.len())],
                    &from_peer[..12.min(from_peer.len())],
                );
            }
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
                let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
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
                let mut m = storage_metrics.write().unwrap_or_else(|e| e.into_inner());
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

            let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
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
                        node.pending_challenge_responses.lock().unwrap_or_else(|e| e.into_inner()).push(response);
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
                let mut m = storage_metrics.write().unwrap_or_else(|e| e.into_inner());
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

// ─── Shard Repair Worker ────────────────────────────────────────────────────

/// Background task: scans for degraded/critical shards and repairs them by
/// fetching missing shards from peers. Successful repairs earn REPAIR_REWARD.
fn spawn_shard_repair_worker(
    node: Arc<MasterNodeState>,
    net: NetworkHandle,
    validator_wallet: String,
    storage_metrics: Arc<std::sync::RwLock<StorageMetrics>>,
    log_tx: std::sync::mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        // Initial delay — wait for sync and network
        tokio::time::sleep(Duration::from_secs(30)).await;

        let mut interval = tokio::time::interval(Duration::from_secs(SHARD_REPAIR_INTERVAL_SECS));
        loop {
            interval.tick().await;

            // Check we have connected peers
            let connected_peers = net.connected_peers().await;
            if connected_peers.is_empty() {
                continue;
            }

            let shard_store = match ShardStore::new() {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Collect EC chunks from chain
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
                continue;
            }

            let local_peer_id = net.local_peer_id.clone();
            let mut repaired = 0u64;
            let mut failed = 0u64;
            let mut skipped = 0u64;
            let mut total_shards = 0usize;

            for (chunk_hash, ec_k, ec_m) in &ec_chunks {
                if total_shards >= REPAIR_SHARDS_PER_ROUND {
                    break;
                }

                let n = (*ec_k as usize) + (*ec_m as usize);
                let local_indices = shard_store.local_shard_indices(chunk_hash);

                // Which indices are missing locally?
                let missing: Vec<u8> = (0..n as u8)
                    .filter(|i| !local_indices.contains(i))
                    .collect();

                if missing.is_empty() {
                    skipped += 1;
                    continue;
                }

                // Only repair if degraded or critical
                let available_count = node.shard_registry.available_shards_for_chunk(chunk_hash);
                if available_count >= n {
                    skipped += 1;
                    continue;
                }

                for shard_idx in &missing {
                    if total_shards >= REPAIR_SHARDS_PER_ROUND {
                        break;
                    }

                    // Find a peer that holds this shard
                    let holders = node.shard_registry.holders_for(chunk_hash, *shard_idx);
                    let remote_holder = holders.iter().find(|h| **h != local_peer_id);

                    let requested = if let Some(holder_id) = remote_holder {
                        if let Ok(peer_id) = holder_id.parse::<libp2p::PeerId>() {
                            let is_connected = connected_peers.iter().any(|p| p.peer_id == *holder_id);
                            if is_connected {
                                net.request_shard(peer_id, chunk_hash.clone(), *shard_idx).await;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        // No known holder — try discovery from connected peers
                        let mut found = false;
                        for peer in &connected_peers {
                            if let Ok(pid) = peer.peer_id.parse::<libp2p::PeerId>() {
                                let peer_shards = net.list_peer_shards(pid.clone(), chunk_hash.clone()).await;
                                if peer_shards.contains(shard_idx) {
                                    net.request_shard(pid, chunk_hash.clone(), *shard_idx).await;
                                    node.shard_registry.add_holder(chunk_hash, *shard_idx, &peer.peer_id);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        found
                    };

                    if requested {
                        repaired += 1;
                        total_shards += 1;

                        // Submit repair reward for inclusion in next block
                        use sha2::{Digest, Sha256};
                        let repair_id = format!("{:x}", Sha256::digest(
                            format!("{}{}{}{}",
                                validator_wallet, chunk_hash, shard_idx,
                                Utc::now().timestamp()
                            ).as_bytes()
                        ));
                        node.pending_repair_rewards.lock().unwrap_or_else(|e| e.into_inner()).push(
                            stone::storage_proof::RepairReward {
                                repair_id,
                                repairer_wallet: validator_wallet.clone(),
                                chunk_hash: chunk_hash.clone(),
                                shard_index: *shard_idx,
                                timestamp: Utc::now().timestamp(),
                            }
                        );

                        let _ = log_tx.send(format!(
                            "🔧 Shard {}…[{}] repariert (angefordert)",
                            &chunk_hash[..8.min(chunk_hash.len())], shard_idx
                        ));
                    } else {
                        failed += 1;
                    }
                }
            }

            // Update metrics
            {
                let mut m = storage_metrics.write().unwrap_or_else(|e| e.into_inner());
                m.repairs_completed += repaired;
                m.repairs_failed += failed;
                m.repairs_skipped += skipped;

                let reward_per: rust_decimal::Decimal = stone::storage_proof::REPAIR_REWARD.parse().unwrap_or_default();
                let prev: rust_decimal::Decimal = m.repair_rewards_earned.parse().unwrap_or_default();
                m.repair_rewards_earned = (prev + reward_per * rust_decimal::Decimal::from(repaired)).to_string();

                let now = Utc::now();
                m.last_repair = now.to_rfc3339();
                m.last_repair_human = now.with_timezone(&Local).format("%H:%M:%S").to_string();
            }

            if repaired > 0 || failed > 0 {
                let _ = log_tx.send(format!(
                    "🔧 Shard-Repair: {} repariert, {} fehlgeschlagen, {} übersprungen",
                    repaired, failed, skipped
                ));
            }
        }
    });
}

// ─── PoW Solver Worker (Argon2id Mining) ────────────────────────────────────

/// Background task: continuously solves Argon2id PoW puzzles using templates
/// from the local node.
///
/// Workflow:
/// 1. Warte auf Initial-Sync
/// 2. Hole aktuelles Mining-Template vom lokalen Node
/// 3. Iteriere Nonces, berechne Argon2id-Hash
/// 4. Bei Treffer: submit_mining_solution() → Block committed + broadcastet
/// 5. Wiederhole mit neuem Template
///
/// Multi-Thread: Spawnt N Worker-Threads (= CPU-Kerne), jeder sucht
/// eigene Nonce-Range. Erster Fund stoppt alle via AtomicBool.
fn spawn_pow_solver(
    node: Arc<MasterNodeState>,
    pow_metrics: Arc<std::sync::RwLock<PowMetrics>>,
    log_tx: std::sync::mpsc::Sender<String>,
) {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let num_threads: usize = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Coordinator-Thread: verwaltet Templates und startet Worker-Runden
    std::thread::Builder::new()
        .name("pow-coordinator".into())
        .spawn(move || {
            // Warte auf Initial-Sync (blockierend)
            loop {
                if node.metrics.initial_sync_done.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_secs(2));
            }

            let _ = log_tx.send(format!(
                "⛏️  PoW-Solver gestartet (Argon2id, 64 MiB, {num_threads} Threads)"
            ));

            loop {
                // Throttle-Check: Mining pausiert?
                let throttle = node.metrics.mining_throttle_pct.load(Ordering::Relaxed);
                if throttle == 0 {
                    {
                        let mut m = pow_metrics.write().unwrap_or_else(|e| e.into_inner());
                        m.solving = false;
                        m.hashrate = 0.0;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }

                // Template holen (oder erstellen)
                let template = {
                    let tmpl = node.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
                    if let Some((t, _)) = tmpl.as_ref() {
                        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                        let current_height = chain.blocks.len() as u64;
                        if t.block_index == current_height {
                            Some(t.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                let template = match template {
                    Some(t) => t,
                    None => {
                        match node.prepare_block_template() {
                            Ok(t) => t,
                            Err(e) => {
                                if !e.contains("Kein Reward") {
                                    let _ = log_tx.send(format!("⚠ Template-Fehler: {e}"));
                                }
                                std::thread::sleep(Duration::from_secs(5));
                                continue;
                            }
                        }
                    }
                };

                // Mining-Parameter
                let difficulty = template.difficulty;
                let eff_difficulty = if template.effective_difficulty > 0 {
                    template.effective_difficulty
                } else {
                    difficulty
                };
                let block_index = template.block_index;
                let template_id = template.template_id.clone();

                {
                    let mut m = pow_metrics.write().unwrap_or_else(|e| e.into_inner());
                    m.solving = true;
                    m.current_difficulty = eff_difficulty;
                    m.current_block_index = block_index;
                    m.current_template_id = template_id.clone();
                    m.current_nonce = 0;
                }

                let stake_info = if eff_difficulty < difficulty {
                    format!(", stake-bonus={}bits", difficulty - eff_difficulty)
                } else {
                    String::new()
                };
                let _ = log_tx.send(format!(
                    "⛏️  Mining Block #{block_index} (d={eff_difficulty}/{difficulty}{stake_info}, {num_threads} threads, template={})…",
                    &template_id[..8.min(template_id.len())],
                ));

                // ── Multi-Thread Nonce-Suche ────────────────────────────
                let found = Arc::new(AtomicBool::new(false));
                let total_hashes = Arc::new(AtomicU64::new(0));
                let start = Instant::now();

                // Channel für Ergebnis: (nonce, pow_hash)
                let (result_tx, result_rx) = std::sync::mpsc::channel::<(u64, String)>();

                // Aktive Worker-Threads bestimmen (Throttle < 100 → weniger Threads)
                let active_threads = if throttle < 100 {
                    ((num_threads as u64 * throttle) / 100).max(1) as usize
                } else {
                    num_threads
                };

                let mut worker_handles = Vec::with_capacity(active_threads);

                for thread_id in 0..active_threads {
                    let found_c = found.clone();
                    let total_hashes_c = total_hashes.clone();
                    let result_tx_c = result_tx.clone();
                    let prev_hash = template.previous_hash.clone();
                    let validator_pub = template.validator_pubkey.clone();
                    let tmpl_id = template_id.clone();
                    let node_c = node.clone();

                    let handle = std::thread::Builder::new()
                        .name(format!("pow-worker-{thread_id}"))
                        .spawn(move || {
                            // Jeder Thread startet bei eigenem Offset, stride = active_threads
                            let mut nonce = thread_id as u64;
                            let stride = active_threads as u64;

                            loop {
                                if found_c.load(Ordering::Relaxed) {
                                    break;
                                }

                                let hash_bytes = stone::consensus::compute_argon2_pow_hash(
                                    &prev_hash,
                                    block_index,
                                    &validator_pub,
                                    nonce,
                                );

                                total_hashes_c.fetch_add(1, Ordering::Relaxed);

                                if stone::consensus::leading_zero_bits(&hash_bytes) >= eff_difficulty {
                                    found_c.store(true, Ordering::Relaxed);
                                    let _ = result_tx_c.send((nonce, hex::encode(&hash_bytes)));
                                    break;
                                }

                                nonce += stride;

                                // Alle 5 Hashes pro Thread: Staleness-Check
                                if (nonce / stride) % 5 == 0 {
                                    let stale = {
                                        let tmpl = node_c.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
                                        match tmpl.as_ref() {
                                            Some((t, _)) => t.template_id != tmpl_id,
                                            None => true,
                                        }
                                    };
                                    if stale {
                                        found_c.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                    // Throttle-Stop Check
                                    let thr = node_c.metrics.mining_throttle_pct.load(Ordering::Relaxed);
                                    if thr == 0 {
                                        found_c.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        })
                        .expect("pow worker thread");

                    worker_handles.push(handle);
                }
                // Drop the coordinator's copy so channel closes when all workers done
                drop(result_tx);

                // Metrics-Update in Hintergrund während Workers laufen
                let pow_metrics_c = pow_metrics.clone();
                let total_hashes_c = total_hashes.clone();
                let found_c = found.clone();
                let log_tx_c = log_tx.clone();
                let metrics_handle = std::thread::Builder::new()
                    .name("pow-metrics".into())
                    .spawn(move || {
                        loop {
                            std::thread::sleep(Duration::from_secs(5));
                            if found_c.load(Ordering::Relaxed) {
                                break;
                            }
                            let hashes = total_hashes_c.load(Ordering::Relaxed);
                            let elapsed = start.elapsed();
                            let hashrate = hashes as f64 / elapsed.as_secs_f64().max(0.001);
                            {
                                let mut m = pow_metrics_c.write().unwrap_or_else(|e| e.into_inner());
                                m.current_nonce = hashes;
                                m.hashrate = hashrate;
                            }
                            let _ = log_tx_c.send(format!(
                                "⛏️  Mining… {} Hashes in {:.1}s ({:.1} H/s, d={eff_difficulty}/{difficulty}, {active_threads}T)",
                                hashes, elapsed.as_secs_f64(), hashrate,
                            ));
                        }
                    })
                    .ok();

                // Auf Ergebnis warten
                let solution = result_rx.recv().ok();

                // Alle Workers joinen
                for h in worker_handles {
                    let _ = h.join();
                }
                if let Some(mh) = metrics_handle {
                    let _ = mh.join();
                }

                let hashes_total = total_hashes.load(Ordering::Relaxed);
                let elapsed = start.elapsed();

                if let Some((nonce, pow_hash)) = solution {
                    let hashrate = hashes_total as f64 / elapsed.as_secs_f64().max(0.001);

                    let _ = log_tx.send(format!(
                        "✅ Block #{block_index} gelöst! nonce={nonce}, d={eff_difficulty}/{difficulty}, {:.1}s ({:.1} H/s, {active_threads}T)",
                        elapsed.as_secs_f64(), hashrate,
                    ));

                    let submission = stone::master::MiningSubmission {
                        template_id: template_id.clone(),
                        nonce,
                        pow_hash,
                    };

                    match node.submit_mining_solution(&submission) {
                        Ok(block) => {
                            MasterNodeState::run_post_block_hooks(&node, &block);

                            {
                                let tx = node.block_broadcast_tx.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(ref sender) = *tx {
                                    let _ = sender.send(block.clone());
                                }
                            }

                            {
                                let mut m = pow_metrics.write().unwrap_or_else(|e| e.into_inner());
                                m.blocks_solved += 1;
                                m.last_solved_block = block.index;
                                m.last_solve_elapsed_secs = elapsed.as_secs_f64();
                                m.hashrate = hashrate;
                            }

                            let _ = log_tx.send(format!(
                                "📦 Block #{} committed + broadcastet ({} TXs)",
                                block.index, block.transactions.len(),
                            ));
                        }
                        Err(e) => {
                            let _ = log_tx.send(format!("⚠ Submit fehlgeschlagen: {e}"));
                        }
                    }
                } else {
                    // Kein Ergebnis → Template stale oder Mining gestoppt
                    {
                        let mut m = pow_metrics.write().unwrap_or_else(|e| e.into_inner());
                        m.solving = false;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .expect("PoW coordinator thread");
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

            let mut m = system_metrics.write().unwrap_or_else(|e| e.into_inner());
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
                        stone::master::NodeEvent::BlockAdded { index, hash, .. } => {
                            Some(format!("✅ Block #{index} committed ({}…)", &hash[..8.min(hash.len())]))
                        }
                        stone::master::NodeEvent::TokenTransfer { tx_type, amount, from, to, block_index, .. } => {
                            if tx_type == "reward" {
                                Some(format!("⛏ Reward: {amount} STONE → {}… (Block #{block_index})", &to[..8.min(to.len())]))
                            } else if tx_type == "transfer" {
                                Some(format!("💸 Transfer: {amount} STONE {}… → {}…", &from[..8.min(from.len())], &to[..8.min(to.len())]))
                            } else { None }
                        }
                        stone::master::NodeEvent::SyncCompleted { peer_url, blocks_added } => {
                            Some(format!("🔄 Sync: {blocks_added} Blöcke von {peer_url}"))
                        }
                        stone::master::NodeEvent::PeerStatusChanged { url, status } => {
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

// ─── Mempool Sync (Pending TXs von Peers holen) ────────────────────────────

/// Alle 15 Sekunden: Pending TXs von bekannten Peers + Seed-Peers abrufen
/// und in den lokalen Mempool aufnehmen. So werden TXs die auf entfernten
/// Nodes eingereicht wurden zuverlässig zum Miner synchronisiert.
fn spawn_mempool_sync(
    node: Arc<MasterNodeState>,
    seed_peers: Vec<String>,
    _api_key: Arc<String>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;

            // Nur syncen wenn Initial-Sync fertig
            if !node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed) {
                continue;
            }

            // Peer-URLs sammeln (gesunde Peers + Seed-Peers)
            let mut urls: Vec<String> = node.get_peers()
                .into_iter()
                .filter(|p| p.is_healthy())
                .map(|p| p.url.clone())
                .collect();
            for sp in &seed_peers {
                let normalized = sp.trim_end_matches('/').to_string();
                if !urls.iter().any(|u| u.trim_end_matches('/') == normalized) {
                    urls.push(normalized);
                }
            }

            // Private/Docker-IPs filtern (nicht erreichbar vom Miner)
            urls.retain(|url| {
                let is_private = url.contains("://10.")
                    || url.contains("://172.16.") || url.contains("://172.17.")
                    || url.contains("://172.18.") || url.contains("://172.19.")
                    || url.contains("://172.2") || url.contains("://172.3")
                    || url.contains("://192.168.")
                    || url.contains("://100.") // Tailscale
                    || url.contains("://127.");
                !is_private
            });

            if urls.is_empty() {
                continue;
            }

            let mut total_added = 0usize;
            let mut total_received = 0usize;
            let mut total_known = 0usize;

            for url in &urls {
                let endpoint = format!("{}/api/v1/mempool/sync", url.trim_end_matches('/'));
                match client.get(&endpoint).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<Vec<stone::token::TokenTx>>().await {
                            Ok(mut txs) => {
                                // Nach Nonce sortieren damit TXs vom selben Sender
                                // in der richtigen Reihenfolge aufgenommen werden
                                txs.sort_by_key(|tx| (tx.from.clone(), tx.nonce));
                                let count = txs.len();
                                total_received += count;
                                let mut added = 0usize;
                                let mut rejected = 0usize;
                                for tx in txs {
                                    if tx.tx_type == stone::token::TxType::Reward
                                        || tx.tx_type == stone::token::TxType::Mint
                                    {
                                        continue;
                                    }
                                    if node.mempool.is_known(&tx.tx_id) {
                                        total_known += 1;
                                        continue;
                                    }
                                    // None = keine Nonce/Balance-Prüfung beim Sync.
                                    // Nodes können unterschiedliche Ledger-Stände haben.
                                    // Echte Validierung erfolgt beim Block-Bau via filter_valid_txs().
                                    match node.mempool.add_tx(tx, None) {
                                        Ok(_) => added += 1,
                                        Err(e) => {
                                            rejected += 1;
                                            println!("[mempool-sync] ⚠️  TX abgelehnt von {}: {}", url, e);
                                        }
                                    }
                                }
                                if added > 0 {
                                    total_added += added;
                                    println!(
                                        "[mempool-sync] ✅ {} TXs von {} aufgenommen ({} empfangen, {} abgelehnt)",
                                        added, url, count, rejected,
                                    );
                                }
                            }
                            Err(e) => {
                                println!("[mempool-sync] ⚠️  JSON-Parse-Fehler von {}: {}", url, e);
                            }
                        }
                    }
                    Ok(resp) => {
                        println!("[mempool-sync] ⚠️  {} antwortete mit Status {}", url, resp.status());
                    }
                    Err(e) => {
                        println!("[mempool-sync] ⚠️  {} nicht erreichbar: {}", url, e);
                    }
                }
            }

            if total_added > 0 || total_received > 0 {
                println!(
                    "[mempool-sync] 🔄 {} Peers, {} empfangen, {} neu, {} bekannt, Mempool: {}",
                    urls.len(), total_received, total_added, total_known, node.mempool.pending_count(),
                );
            }
        }
    });
}

// ─── Status Relay Push ──────────────────────────────────────────────────────

/// Pusht alle 10 Sekunden den Miner-Status (signiert) an die Seed-Peers
fn spawn_status_relay_push(
    node: Arc<MasterNodeState>,
    pow_metrics: Arc<std::sync::RwLock<PowMetrics>>,
    validator_wallet: String,
    seed_peers: Vec<String>,
    miner_state: MinerWebState,
) {
    use ed25519_dalek::Signer;
    use sha2::{Sha256, Digest};
    use stone::consensus::load_or_create_validator_key;

    tokio::spawn(async move {
        let signing_key = load_or_create_validator_key();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;

            // Metriken sammeln
            let pm = pow_metrics.read().unwrap_or_else(|e| e.into_inner()).clone();
            let block_height = miner_state.block_height();
            let blocks_mined = miner_state.blocks_mined();
            let total_rewards = miner_state.total_rewards().to_string();
            let throttle = miner_state.throttle();
            let active = miner_state.is_mining();
            let uptime = miner_state.uptime_secs();
            let peers_connected = {
                let peers = node.get_peers();
                peers.iter().filter(|p| p.is_healthy()).count() as u64
            };
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Signatur erstellen
            let sig_data = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                validator_wallet, timestamp, pm.hashrate as u64,
                block_height, blocks_mined, pm.current_difficulty, active
            );
            let hash = Sha256::digest(sig_data.as_bytes());
            let signature = signing_key.sign(&hash);

            let report = serde_json::json!({
                "wallet": validator_wallet,
                "timestamp": timestamp,
                "hashrate": pm.hashrate,
                "block_height": block_height,
                "blocks_mined": blocks_mined,
                "difficulty": pm.current_difficulty,
                "active": active,
                "throttle_pct": throttle,
                "total_rewards": total_rewards,
                "peers_connected": peers_connected,
                "uptime_secs": uptime,
                "version": env!("CARGO_PKG_VERSION"),
                "node_name": node.node_id.chars().take(12).collect::<String>(),
                "signature": hex::encode(signature.to_bytes()),
            });

            // An alle Seed-Peers senden
            for peer in &seed_peers {
                let url = format!("{}/api/v1/mining/report", peer.trim_end_matches('/'));
                let _ = client.post(&url).json(&report).send().await;
            }
        }
    });
}

// ─── Hauptprogramm ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::from_filename(".env").ok();

    // UPnP-Panic abfangen (libp2p-upnp 0.3 Bug: panicked wenn Sender dropped wird)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.to_string();
        if msg.contains("sender shouldn't have been dropped") || msg.contains("upnp") {
            eprintln!("[p2p] ⚠ UPnP-Hintergrund-Task beendet (harmlos)");
            return;
        }
        default_hook(info);
    }));

    // ── Argumente parsen ────────────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let mut wallet_arg: Option<String> = None;
    let mut headless = false;
    let mut port_arg: Option<u16> = None;
    let mut p2p_port_arg: Option<u16> = None;
    let mut network_arg: Option<String> = None;
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
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port_arg = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    eprintln!("Fehler: --port benötigt eine Portnummer");
                    std::process::exit(1);
                }
            }
            "--p2p-port" => {
                if i + 1 < args.len() {
                    p2p_port_arg = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    eprintln!("Fehler: --p2p-port benötigt eine Portnummer");
                    std::process::exit(1);
                }
            }
            "--network" | "-n" => {
                if i + 1 < args.len() {
                    network_arg = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Fehler: --network benötigt 'testnet' oder 'mainnet'");
                    std::process::exit(1);
                }
            }
            "--testnet" => { network_arg = Some("testnet".into()); i += 1; }
            "--mainnet" => { network_arg = Some("mainnet".into()); i += 1; }
            "--headless" => { headless = true; i += 1; }
            "--help" | "-h" => {
                println!("stone-miner — StoneChain Standalone Miner mit Web-Dashboard");
                println!();
                println!("Usage:");
                println!("  stone-miner                        Start im Testnet (Default)");
                println!("  stone-miner --mainnet              Start im Mainnet");
                println!("  stone-miner --testnet              Start im Testnet (explizit)");
                println!("  stone-miner --wallet <ADRESSE>     Wallet direkt angeben");
                println!("  stone-miner --headless             Ohne Dashboard (Log-Modus)");
                println!();
                println!("Netzwerk:");
                println!("  -n, --network <NET>    'testnet' oder 'mainnet' (Default: testnet)");
                println!("      --testnet          Kurzform für --network testnet");
                println!("      --mainnet          Kurzform für --network mainnet");
                println!();
                println!("Ports (Defaults: Testnet / Mainnet):");
                println!("  -p, --port <PORT>      Node-API-Port (8081 / 8082)");
                println!("      --p2p-port <PORT>  P2P-Port (4002 / 5002)");
                println!("      Dashboard-Port wird per STONE_DASHBOARD_PORT gesetzt (6969 / 6970)");
                println!();
                println!("Weitere Optionen:");
                println!("  -w, --wallet <ADDR>    Payout-Wallet-Adresse (64 Hex-Zeichen)");
                println!("      --headless         Log-Modus ohne Web-Dashboard");
                println!("  -h, --help             Diese Hilfe anzeigen");
                println!();
                println!("Umgebungsvariablen:");
                println!("  STONE_NETWORK=testnet|mainnet    Netzwerk (überschrieben durch --network)");
                println!("  STONE_MINER_PORT=8081            Node-API-Port");
                println!("  STONE_DASHBOARD_PORT=6969        Dashboard-Port");
                println!("  STONE_MINER_P2P_PORT=4002        P2P-Port");
                std::process::exit(0);
            }
            _ => { i += 1; }
        }
    }

    // CLI --network/--testnet/--mainnet überschreibt STONE_NETWORK env var
    if let Some(net) = network_arg {
        std::env::set_var("STONE_NETWORK", &net);
    }

    // Auto-detect headless
    if !headless && !std::io::stdout().is_terminal() {
        headless = true;
    }

    // ── Konfiguration laden oder erstellen ──────────────────────────────
    std::fs::create_dir_all(data_dir()).ok();

    // Post-Update Rollback prüfen
    if stone::updater::check_post_update_rollback(&data_dir()) {
        eprintln!("[miner] ⚠ Rollback durchgeführt – Neustart mit altem Binary...");
        let exe = std::env::current_exe().expect("current_exe");
        let args_exec: Vec<String> = std::env::args().collect();
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(&exe).args(&args_exec[1..]).exec();
        }
        std::process::exit(1);
    }

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
        let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.registered_account_count() > 0 {
            let mut local = users.lock().unwrap_or_else(|e| e.into_inner());
            let merged = stone::auth::rebuild_users_from_ledger(&ledger, &local);
            *local = merged;
            stone::auth::save_users(&local);
        }
    }

    // Hintergrund-Tasks
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    MasterNodeState::start_mining_loop(node.clone());
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    // Peer-Discovery: Bei Bootstrap-Nodes registrieren & Health-Check starten
    bootstrap_announce(&node).await;
    spawn_peer_health_task(node.clone());

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

    // P2P starten – Miner verwendet eigene Ports pro Netzwerk
    // (Testnet: 4002, Mainnet: 5002), damit kein Konflikt mit stone-setup.
    let miner_p2p_port = p2p_port_arg
        .or_else(|| std::env::var("STONE_MINER_P2P_PORT").ok()?.parse().ok())
        .unwrap_or_else(default_p2p_port);

    // ChatIndex vorab erstellen, damit der P2P-Event-Loop ihn nutzen kann
    let chat_index_arc: Arc<std::sync::Mutex<stone::chat::ChatIndex>> = {
        let mut idx = stone::chat::load_chat_index();
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let chain_len = chain.blocks.len() as u64;
        let last_chain_block_idx = chain.blocks.last().map(|b| b.index).unwrap_or(0);
        if idx.last_indexed_block > 0 && chain_len > 0 && idx.last_indexed_block > last_chain_block_idx {
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
        } else if chain_len > 0 && last_chain_block_idx > idx.last_indexed_block {
            let new_blocks: Vec<_> = chain.blocks.iter()
                .filter(|b| b.index > idx.last_indexed_block)
                .collect();
            idx.index_new_blocks(&new_blocks, Some(&node.message_pool));
            let _ = stone::chat::save_chat_index(&idx);
        }
        Arc::new(std::sync::Mutex::new(idx))
    };

    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            None
        } else {
            // Custom P2P-Config: eigener Port, damit kein Konflikt mit stone-setup
            let mut p2p_config = stone::network::P2pConfig::load_or_default();
            p2p_config.merge_env();
            // Miner-spezifischen Port setzen (überschreibt STONE_P2P_PORT aus .env)
            p2p_config.listen_addr = format!("/ip4/0.0.0.0/tcp/{miner_p2p_port}");
            match start_network(Some(p2p_config)).await {
                Ok(handle) => {
                    let count = node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                    handle.set_chain_count(count).await;
                    handle.set_chain_ref(node.chain.clone()).await;
                    {
                        let mut event_rx = handle.subscribe();
                        let node_bg = node.clone();
                        let handle_bg = handle.clone();
                        let api_key_bg = api_key.clone();
                        let chat_idx_bg = chat_index_arc.clone();
                        let pending_sync = std::sync::Mutex::new(Vec::<stone::blockchain::Block>::new());
                        tokio::spawn(async move {
                            loop {
                                match event_rx.recv().await {
                                    Ok(event) => {
                                        handle_p2p_event(event, &node_bg, &handle_bg, &api_key_bg, &chat_idx_bg, &pending_sync).await;
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
                }
                Err(e) => { eprintln!("[miner] P2P-Fehler: {e}"); None }
            }
        };

    // ── Shared Miner State ──────────────────────────────────────────────
    let storage_metrics = Arc::new(std::sync::RwLock::new(StorageMetrics::default()));
    let system_metrics = Arc::new(std::sync::RwLock::new(SystemMetrics::default()));
    let pow_metrics = Arc::new(std::sync::RwLock::new(PowMetrics::default()));
    let logs = Arc::new(std::sync::RwLock::new(Vec::<String>::new()));

    let miner_state = MinerWebState {
        node: node.clone(),
        config: Arc::new(std::sync::RwLock::new(config.clone())),
        logs: logs.clone(),
        validator_wallet: validator_wallet.clone(),
        started_at: Instant::now(),
        storage_metrics: storage_metrics.clone(),
        system_metrics: system_metrics.clone(),
        pow_metrics: pow_metrics.clone(),
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

    // ── Shard Repair Worker ─────────────────────────────────────────────
    if let Some(ref net) = network_handle {
        spawn_shard_repair_worker(
            node.clone(),
            net.clone(),
            validator_wallet.clone(),
            storage_metrics.clone(),
            log_tx.clone(),
        );
    }

    // ── System Metrics Worker ───────────────────────────────────────────
    spawn_system_metrics_worker(system_metrics.clone());

    // ── PoW Solver (Argon2id Mining) ────────────────────────────────────
    spawn_pow_solver(node.clone(), pow_metrics.clone(), log_tx.clone());

    // ── Mempool Sync (Pending TXs von Peers holen) ─────────────────────
    spawn_mempool_sync(node.clone(), config.seed_peers.clone(), api_key.clone());

    // ── Status Relay Push (an Bootstrap-Server) ─────────────────────────
    spawn_status_relay_push(
        node.clone(),
        pow_metrics.clone(),
        validator_wallet.clone(),
        config.seed_peers.clone(),
        miner_state.clone(),
    );

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

    // Post-Update Erfolg bestätigen (nach 120s gesundem Betrieb)
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        stone::updater::confirm_update_success(&data_dir());
    });

    // Audio-Room GC: Idle-Rooms alle 60s aufräumen (Rooms ohne Aktivität > 5 Min)
    {
        let audio_rooms = node_app_state.audio_rooms.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
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
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let n = node_res.clone();
                tokio::task::spawn_blocking(move || n.update_resource_cache()).await.ok();
            }
        });
    }

    // Main node API
    let main_router = build_router(node_app_state);

    // Miner-spezifische Routes (Dashboard + API)
    let miner_routes = Router::new()
        .route("/ui", get(handle_dashboard))
        .route("/api/miner/stats", get(handle_miner_stats))
        .route("/api/miner/mining/toggle", post(handle_toggle_mining))
        .route("/api/miner/mining/throttle", post(handle_set_throttle))
        .route("/api/miner/payout", post(handle_force_payout))
        .route("/api/miner/logs", get(handle_miner_logs))
        .route("/api/miner/config", post(handle_save_config))
        .with_state(miner_state.clone());

    // Dashboard-only Router (separate port: dashboard + miner API)
    let miner_router = Router::new()
        .route("/", get(handle_dashboard))
        .with_state(miner_state.clone())
        .merge(miner_routes.clone());

    // Node-Router: Standard-API + Miner-Endpoints auf einem Port
    let node_router = main_router.merge(miner_routes);

    // Miner verwendet eigene Port-ENV-Variablen, damit kein Konflikt mit stone-setup:
    //   STONE_MINER_PORT (default 8081) statt STONE_PORT (default 8080)
    //   STONE_DASHBOARD_PORT (default 6969)
    let http_port = port_arg
        .or_else(|| std::env::var("STONE_MINER_PORT").ok()?.parse().ok())
        .unwrap_or(config.http_port);

    let dashboard_port = std::env::var("STONE_DASHBOARD_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(config.dashboard_port);

    // Graceful Port-Binding: versuche konfigurierten Port, sonst Fallback
    let node_listener = try_bind_port(http_port, "Node-API").await?;
    let actual_http_port = node_listener.local_addr()?.port();

    let dashboard_listener = try_bind_port(dashboard_port, "Dashboard").await?;
    let actual_dashboard_port = dashboard_listener.local_addr()?.port();

    let network = NetworkMode::from_env();
    let net_label = if network.is_testnet() { "TESTNET" } else { "MAINNET" };

    miner_state.add_log(format!("Netzwerk: {net_label}"));
    miner_state.add_log(format!("Node: {node_id}"));
    miner_state.add_log(format!("Mining Wallet: {}...", &validator_wallet[..16.min(validator_wallet.len())]));
    miner_state.add_log(format!("Payout Wallet: {}...", &config.payout_wallet[..16.min(config.payout_wallet.len())]));
    miner_state.add_log(format!("Node-API auf Port {actual_http_port}"));
    miner_state.add_log(format!("Dashboard auf Port {actual_dashboard_port}"));
    miner_state.add_log(format!("P2P auf Port {miner_p2p_port}"));
    if network_handle.is_some() {
        miner_state.add_log("P2P-Netzwerk aktiv".into());
    }

    println!();
    println!("  Stone Miner v{} gestartet [{net_label}]", env!("CARGO_PKG_VERSION"));
    println!("  -------------------------------------");
    println!("  Netzwerk: {net_label}");
    println!("  Data:     {}", data_dir());
    println!("  Node:     {node_id}");
    println!("  Wallet:   {}...", &validator_wallet[..16.min(validator_wallet.len())]);
    println!("  Payout:   {}...", &config.payout_wallet[..16.min(config.payout_wallet.len())]);
    if !headless {
        println!();
        println!("  \x1b[36;1mDashboard: http://localhost:{actual_dashboard_port}/ui\x1b[0m");
        println!("  \x1b[2mNode-API:  http://localhost:{actual_http_port}\x1b[0m");
        println!("  \x1b[2mP2P-Port:  {miner_p2p_port}\x1b[0m");
    }
    println!("  -------------------------------------");
    println!();

    if headless {
        // === HEADLESS MODUS ===
        println!("[miner] Headless-Modus [{net_label}] (kein Dashboard)");
        println!("[miner] Node-API auf Port {actual_http_port}, Dashboard auf Port {actual_dashboard_port}, P2P auf Port {miner_p2p_port}");

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
                let height = node.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                let mined = node.metrics.blocks_mined.load(std::sync::atomic::Ordering::Relaxed);
                let balance = node.token_ledger.read().unwrap_or_else(|e| e.into_inner()).balance(&validator_wallet);
                let (h, t) = {
                    let peers = node.get_peers();
                    (peers.iter().filter(|p| p.is_healthy()).count(), peers.len())
                };
                let sm = storage_metrics.read().unwrap_or_else(|e| e.into_inner());
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
                let mut cfg = payout_config.write().unwrap_or_else(|e| e.into_inner()).clone();
                if let Some(msg) = try_daily_payout(&payout_node, &mut cfg, &payout_wallet) {
                    payout_state.add_log(msg);
                    *payout_config.write().unwrap_or_else(|e| e.into_inner()) = cfg;
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

/// Versucht an `port` zu binden. Falls belegt, versuche port+1, port+2, ...
/// bis maximal port+10. Gibt den TcpListener zurück.
async fn try_bind_port(
    port: u16,
    label: &str,
) -> Result<tokio::net::TcpListener, Box<dyn std::error::Error>> {
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => Ok(listener),
        Err(e) => {
            eprintln!("[miner] ⚠ {label}-Port {port} belegt: {e}");
            // Fallback: nächste 10 Ports durchprobieren
            for offset in 1..=10 {
                let fallback_port = port + offset;
                let fallback_addr = std::net::SocketAddr::from(([0, 0, 0, 0], fallback_port));
                if let Ok(listener) = tokio::net::TcpListener::bind(fallback_addr).await {
                    eprintln!("[miner] ℹ {label}: verwende Port {fallback_port} statt {port}");
                    return Ok(listener);
                }
            }
            Err(format!("{label}-Port {port} und Fallbacks {}-{} alle belegt", port + 1, port + 10).into())
        }
    }
}

fn print_banner() {
    let network = NetworkMode::from_env();
    let (color, label) = if network.is_testnet() {
        ("\x1b[36;1m", "TESTNET") // Cyan
    } else {
        ("\x1b[32;1m", "MAINNET") // Grün
    };
    eprintln!("{color}");
    eprintln!(r"  ███████╗████████╗ ██████╗ ███╗   ██╗███████╗");
    eprintln!(r"  ██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝");
    eprintln!(r"  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗  ");
    eprintln!(r"  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝  ");
    eprintln!(r"  ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗");
    eprintln!(r"  ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝");
    eprintln!("\x1b[0m");
    eprintln!("  \x1b[1mStone Miner — Standalone Mining Client [{label}]\x1b[0m");
    eprintln!("  \x1b[2m──────────────────────────────────────────────────\x1b[0m");
}
