//! Embedded Miner Manager
//!
//! Runs Argon2id PoW mining in-process using the local Stone node's HTTP API.
//! No separate binary needed — fetches templates from the node, submits solutions back.
//! Port-conflict free: uses the existing node's API endpoints.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::Algorithm;
use argon2::Version;
use argon2::Params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

// ── Miner Config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerConfig {
    pub cpu_cores: u32,
    pub priority: u32,   // 1-4 (currently informational)
    pub network: String, // "mainnet" or "testnet"
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub payout_wallet: String,
}

impl Default for MinerConfig {
    fn default() -> Self {
        MinerConfig { cpu_cores: 4, priority: 2, network: "mainnet".into(), autostart: false, payout_wallet: String::new() }
    }
}

// ── Miner Stats ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
pub struct MinerStats {
    pub active: bool,
    pub hashrate: f64,
    pub blocks_found: u64,
    pub earned: String,
    pub throttle_pct: u32,
    pub cpu_cores: u32,
    pub difficulty: u32,
    pub block_height: u64,
    pub autostart: bool,
}

// ── Miner State ──────────────────────────────────────────────────────────────

pub struct MinerState {
    pub config: MinerConfig,
    pub stats: MinerStats,
    cancel: Arc<AtomicBool>,
}

impl MinerState {
    pub fn new() -> Self {
        MinerState {
            config: MinerConfig::default(),
            stats: MinerStats::default(),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub type SharedMinerState = Arc<Mutex<MinerState>>;

// ── Node API helpers ─────────────────────────────────────────────────────────

fn node_base_url(app: &AppHandle) -> String {
    let shared = app.state::<crate::node_manager::SharedNodeState>();
    let s = shared.lock().unwrap_or_else(|e| e.into_inner());
    let port = s.config.port;
    format!("http://127.0.0.1:{}", port)
}

async fn fetch_template(client: &reqwest::Client, base_url: &str) -> Result<TemplateData, String> {
    let url = format!("{}/api/v1/mining/template", base_url);
    let resp = client.get(&url).send().await.map_err(|e| format!("Template: {e}"))?;
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("Parse: {e}"))?;

    let ok = body["ok"].as_bool().unwrap_or(false);
    if !ok {
        return Err(body["error"].as_str().unwrap_or("Template nicht verfügbar").into());
    }

    let t = &body["template"];
    Ok(TemplateData {
        template_id: t["template_id"].as_str().unwrap_or("").into(),
        previous_hash: t["previous_hash"].as_str().unwrap_or("").into(),
        block_index: t["block_index"].as_u64().unwrap_or(0),
        difficulty: t["difficulty"].as_u64().unwrap_or(20) as u32,
        effective_difficulty: t["effective_difficulty"].as_u64().unwrap_or(0) as u32,
        validator_pubkey: t["validator_pubkey"].as_str().unwrap_or("").into(),
        miner_wallet: t["miner_wallet"].as_str().unwrap_or("").into(),
    })
}

async fn submit_solution(
    client: &reqwest::Client,
    base_url: &str,
    template_id: &str,
    nonce: u64,
    pow_hash: &str,
) -> Result<u64, String> {
    let url = format!("{}/api/v1/mining/submit", base_url);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "template_id": template_id,
            "nonce": nonce,
            "pow_hash": pow_hash,
        }))
        .send()
        .await
        .map_err(|e| format!("Submit: {e}"))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("Parse: {e}"))?;
    let ok = body["ok"].as_bool().unwrap_or(false);
    if !ok {
        return Err(body["error"].as_str().unwrap_or("Unbekannter Fehler").into());
    }
    Ok(body["block_index"].as_u64().unwrap_or(0))
}

#[derive(Debug, Clone)]
struct TemplateData {
    template_id: String,
    previous_hash: String,
    block_index: u64,
    difficulty: u32,
    effective_difficulty: u32,
    validator_pubkey: String,
    #[allow(dead_code)]
    miner_wallet: String,
}

// ── Argon2id PoW (matches stone::consensus::compute_argon2_pow_hash) ────────

const ARGON2_MEMORY_KIB: u32 = 65_536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_PARALLELISM: u32 = 1;

fn compute_pow_hash(prev_hash: &str, block_index: u64, validator_pubkey: &str, nonce: u64) -> [u8; 32] {
    // Password = SHA256(prev_hash || block_index_LE || validator_pubkey || nonce_LE)
    let mut pw_hasher = Sha256::new();
    pw_hasher.update(prev_hash.as_bytes());
    pw_hasher.update(block_index.to_le_bytes());
    pw_hasher.update(validator_pubkey.as_bytes());
    pw_hasher.update(nonce.to_le_bytes());
    let password: [u8; 32] = pw_hasher.finalize().into();

    // Salt = SHA256("stone-pow" || block_index_LE || prev_hash)
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"stone-pow");
    salt_hasher.update(block_index.to_le_bytes());
    salt_hasher.update(prev_hash.as_bytes());
    let salt: [u8; 32] = salt_hasher.finalize().into();

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    ).expect("Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2.hash_password_into(&password, &salt, &mut output)
        .expect("Argon2 hash");
    output
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in hash.iter() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn miner_status(state: tauri::State<'_, SharedMinerState>) -> MinerStats {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let mut stats = s.stats.clone();
    stats.active = s.stats.active && !s.cancel.load(Ordering::Relaxed);
    stats.cpu_cores = s.config.cpu_cores;
    stats.autostart = s.config.autostart;
    stats
}

#[tauri::command]
pub async fn miner_start(
    state: tauri::State<'_, SharedMinerState>,
    app: AppHandle,
    config: MinerConfig,
) -> Result<(), String> {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());

    if s.stats.active && !s.cancel.load(Ordering::Relaxed) {
        return Err("Miner läuft bereits".into());
    }

    s.config = config.clone();
    s.cancel.store(false, Ordering::Relaxed);
    s.stats.active = true;
    s.stats.cpu_cores = config.cpu_cores;
    s.stats.hashrate = 0.0;
    s.stats.difficulty = 0;

    let cancel = s.cancel.clone();
    let base_url = node_base_url(&app);
    let cpu_cores = config.cpu_cores as usize;
    let shared = state.inner().clone();

    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        let num_threads = cpu_cores.max(1);

        loop {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let template = match fetch_template(&client, &base_url).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[miner] Template-Fehler: {e}");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
            };

            let eff_diff = if template.effective_difficulty > 0 {
                template.effective_difficulty
            } else {
                template.difficulty
            };

            {
                let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                st.stats.difficulty = eff_diff;
                st.stats.block_height = template.block_index;
            }

            let found = Arc::new(AtomicBool::new(false));
            let total_hashes = Arc::new(AtomicU64::new(0));
            let (result_tx, result_rx) = std::sync::mpsc::channel::<(u64, String)>();
            let start = Instant::now();

            let mut handles = Vec::with_capacity(num_threads);
            for thread_id in 0..num_threads {
                let found_c = found.clone();
                let total_c = total_hashes.clone();
                let result_tx_c = result_tx.clone();
                let cancel_c = cancel.clone();
                let prev_hash = template.previous_hash.clone();
                let block_idx = template.block_index;
                let vk = template.validator_pubkey.clone();

                handles.push(thread::Builder::new()
                    .name(format!("miner-w{}", thread_id))
                    .spawn(move || {
                        let mut nonce = thread_id as u64;
                        let stride = num_threads as u64;
                        loop {
                            if found_c.load(Ordering::Relaxed) || cancel_c.load(Ordering::Relaxed) {
                                break;
                            }
                            let hash = compute_pow_hash(&prev_hash, block_idx, &vk, nonce);
                            total_c.fetch_add(1, Ordering::Relaxed);
                            if leading_zero_bits(&hash) >= eff_diff {
                                found_c.store(true, Ordering::Relaxed);
                                let _ = result_tx_c.send((nonce, hex::encode(hash)));
                                break;
                            }
                            nonce = nonce.wrapping_add(stride);
                        }
                    })
                    .expect("spawn miner thread"));
            }
            drop(result_tx);

            let total_c = total_hashes.clone();
            let found_c = found.clone();
            let cancel_c = cancel.clone();
            let shared_c = shared.clone();
            let metrics_handle = thread::Builder::new()
                .name("miner-metrics".into())
                .spawn(move || loop {
                    thread::sleep(Duration::from_secs(3));
                    if found_c.load(Ordering::Relaxed) || cancel_c.load(Ordering::Relaxed) {
                        break;
                    }
                    let h = total_c.load(Ordering::Relaxed);
                    let elapsed = start.elapsed().as_secs_f64().max(0.001);
                    let mut st = shared_c.lock().unwrap_or_else(|e| e.into_inner());
                    st.stats.hashrate = h as f64 / elapsed;
                })
                .ok();

            let solution = result_rx.recv().ok();
            found.store(true, Ordering::Relaxed);
            for h in handles { let _ = h.join(); }
            if let Some(h) = metrics_handle { let _ = h.join(); }

            let total = total_hashes.load(Ordering::Relaxed);
            let elapsed = start.elapsed();

            if let Some((nonce, pow_hash)) = solution {
                let hr = total as f64 / elapsed.as_secs_f64().max(0.001);
                eprintln!("[miner] ✅ Block #{} gelöst! nonce={}, {:.1}s, {:.1} H/s",
                    template.block_index, nonce, elapsed.as_secs_f64(), hr);

                match submit_solution(&client, &base_url, &template.template_id, nonce, &pow_hash).await {
                    Ok(block_idx) => {
                        let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                        st.stats.blocks_found += 1;
                        st.stats.hashrate = hr;
                        eprintln!("[miner] 📦 Block #{} akzeptiert", block_idx);
                    }
                    Err(e) => {
                        eprintln!("[miner] ⚠ Submit fehlgeschlagen: {e}");
                    }
                }
            } else {
                break; // cancelled
            }
        }

        let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
        st.stats.active = false;
        st.stats.hashrate = 0.0;
        eprintln!("[miner] ⏹ Miner gestoppt");
    });

    Ok(())
}

#[tauri::command]
pub fn miner_stop(state: tauri::State<'_, SharedMinerState>) -> Result<(), String> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    if !s.stats.active {
        return Err("Miner läuft nicht".into());
    }
    s.cancel.store(true, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
pub fn miner_set_autostart(
    state: tauri::State<'_, SharedMinerState>,
    enable: bool,
) -> Result<(), String> {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.config.autostart = enable;
    Ok(())
}

#[tauri::command]
pub fn miner_set_payout_wallet(
    state: tauri::State<'_, SharedMinerState>,
    wallet: String,
) -> Result<(), String> {
    let w = wallet.trim().to_string();
    if w.is_empty() {
        return Err("Wallet-Adresse darf nicht leer sein".into());
    }
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.config.payout_wallet = w;
    Ok(())
}

#[tauri::command]
pub fn miner_get_config(state: tauri::State<'_, SharedMinerState>) -> MinerConfig {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.config.clone()
}
