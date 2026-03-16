//! Shared application state, constants, chunk helpers, and peer persistence.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use serde::{Deserialize, Serialize};
use stone::{
    auth::{User, ChallengeStore, QrLoginStore},
    blockchain::{ChunkRef, data_dir, CHUNK_SIZE, Document},
    chat::{ChatIndex, ContactList, ContactRequestStore, ChatGroupStore, CallSignalStore},
};
use super::handlers::audio_relay::AudioRooms;
use stone::{
    master_node::{MasterNodeState, PeerInfo, TrustEntry, TrustVote},
    network::NetworkHandle,
    organization::Organization,
    storage::{ChunkStore, StoneStore},
    updater::UpdateManager,
};

use super::rate_limiter::RateLimits;

// ─── Konstanten ──────────────────────────────────────────────────────────────

pub const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024; // 100 MiB
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
pub const AUTO_SYNC_INTERVAL: Duration = Duration::from_secs(30);
pub fn peers_file() -> String {
    format!("{}/peers.json", data_dir())
}

// ─── Shared App State ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<MasterNodeState>,
    pub users: Arc<Mutex<Vec<User>>>,
    pub api_key: Arc<String>,
    /// Separater Admin-Key (aus STONE_ADMIN_KEY). Falls nicht gesetzt, Fallback auf api_key.
    pub admin_key: Arc<String>,
    /// P2P-Netzwerk-Handle (None = P2P deaktiviert)
    pub network: Option<NetworkHandle>,
    /// Rate Limiter für verschiedene Endpoints
    pub rate_limits: Arc<RateLimits>,
    /// OTA Update Manager
    pub updater: Arc<RwLock<UpdateManager>>,
    /// Organisationen
    pub orgs: Arc<Mutex<Vec<Organization>>>,
    /// Globaler Chat-Index
    pub chat_index: Arc<Mutex<ChatIndex>>,
    /// Kontaktliste (Adding-Funktion)
    pub contacts: Arc<Mutex<ContactList>>,
    /// Kontaktanfragen (Friend Request System)
    pub contact_requests: Arc<Mutex<ContactRequestStore>>,
    /// Challenge-Store für Wallet-basierte Authentifizierung (Cross-Platform Login)
    pub challenge_store: ChallengeStore,
    /// QR-Login-Store für Cross-Device Authentifizierung (iOS App → Website)
    pub qr_login_store: QrLoginStore,
    /// Miner-Status-Relay: Miner pushen ihren Status, Apps pollen ihn
    pub miner_status_store: MinerStatusStore,
    /// Gruppenchats
    pub chat_groups: Arc<Mutex<ChatGroupStore>>,
    /// Call-Signaling (ephemeral, WebRTC)
    pub call_signals: Arc<CallSignalStore>,
    /// Audio-Relay Rooms (live calls)
    pub audio_rooms: AudioRooms,
}

// ─── Miner Status Relay Store ────────────────────────────────────────────────

/// TTL für Miner-Status-Reports (60 Sekunden)
const MINER_STATUS_TTL_SECS: u64 = 60;

/// Einzelner Miner-Status-Report (vom Miner signiert)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerStatusReport {
    pub wallet: String,
    pub timestamp: u64,
    pub hashrate: f64,
    pub block_height: u64,
    pub blocks_mined: u64,
    pub difficulty: u32,
    pub active: bool,
    pub throttle_pct: u64,
    pub total_rewards: String,
    pub peers_connected: u64,
    pub uptime_secs: u64,
    pub version: String,
    pub node_name: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct MinerStatusStore {
    inner: Arc<Mutex<HashMap<String, (MinerStatusReport, Instant)>>>,
}

impl MinerStatusStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Speichert einen Status-Report für eine Wallet
    pub fn insert(&self, report: MinerStatusReport) {
        let wallet = report.wallet.clone();
        let mut map = self.inner.lock().unwrap();
        map.insert(wallet, (report, Instant::now()));
        // Cleanup: Alte Einträge entfernen
        map.retain(|_, (_, ts)| ts.elapsed().as_secs() < MINER_STATUS_TTL_SECS * 5);
    }

    /// Holt den letzten Status für eine Wallet (falls noch nicht abgelaufen)
    pub fn get(&self, wallet: &str) -> Option<MinerStatusReport> {
        let map = self.inner.lock().unwrap();
        if let Some((report, ts)) = map.get(wallet) {
            if ts.elapsed().as_secs() < MINER_STATUS_TTL_SECS {
                return Some(report.clone());
            }
        }
        None
    }
}

// ─── API-Key laden ────────────────────────────────────────────────────────────

pub fn load_api_key() -> String {
    // Priorität 1: STONE_CLUSTER_API_KEY (gesetzt von stone_init.py via .env)
    // Priorität 2: STONE_API_KEY (Legacy/manuell)
    // Priorität 3: stone_data/token.bin
    // Priorität 4: Neu generieren und in token.bin speichern
    for var in ["STONE_CLUSTER_API_KEY", "STONE_API_KEY"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                println!("[auth] API-Key aus Umgebungsvariable {var}");
                return v;
            }
        }
    }
    let token_path = format!("{}/token.bin", data_dir());
    if let Ok(data) = std::fs::read_to_string(&token_path) {
        let t = data.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    // Erster Start: neuen Key generieren und speichern
    let key = generate_api_key();
    let _ = std::fs::create_dir_all(data_dir());
    if let Err(e) = std::fs::write(&token_path, &key) {
        eprintln!("[auth] WARNUNG: API-Key konnte nicht gespeichert werden: {e}");
    } else {
        println!("[auth] Neuer Admin-API-Key generiert und gespeichert: {token_path}");
        println!("[auth] ╔══════════════════════════════════════════════════════╗");
        println!("[auth] ║  Admin API-Key: {}…{}  ║", &key[..10], &key[key.len()-4..]);
        println!("[auth] ║  Vollständig in: {token_path:<36}  ║");
        println!("[auth] ╚══════════════════════════════════════════════════════╝");
    }
    key
}

/// Lädt den separaten Admin-Key aus `STONE_ADMIN_KEY`.
/// Falls nicht gesetzt, wird der normale API-Key als Fallback verwendet.
pub fn load_admin_key(fallback_api_key: &str) -> String {
    if let Ok(v) = std::env::var("STONE_ADMIN_KEY") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            println!("[auth] Separater Admin-Key aus STONE_ADMIN_KEY geladen");
            return v;
        }
    }
    println!("[auth] ⚠️  Kein STONE_ADMIN_KEY gesetzt – verwende API-Key als Admin-Key (unsicher!)");
    fallback_api_key.to_string()
}

pub fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("sk_{}", hex::encode(bytes))
}

// ─── Chunk-Verwaltung ─────────────────────────────────────────────────────────

pub fn chunk_data(data: &[u8]) -> Result<Vec<ChunkRef>, String> {
    let store = ChunkStore::new().map_err(|e| e.to_string())?;
    store.write_chunks(data, CHUNK_SIZE).map_err(|e| e.to_string())
}

pub fn reconstruct_document_data(doc: &Document) -> Result<Vec<u8>, String> {
    let store = ChunkStore::new().map_err(|e| e.to_string())?;
    store.reconstruct_document(doc).map_err(|e| e.to_string())
}

/// Erasure-Coded einen Satz ChunkRefs:
/// 1. Liest jeden Chunk-Inhalt
/// 2. Reed-Solomon Encoding
/// 3. Speichert alle Shards lokal
/// 4. Gibt aktualisierte ChunkRefs mit ShardRef-Infos zurück
pub fn erasure_code_document(
    raw_data: &[u8],
    chunk_refs: &[ChunkRef],
    local_peer_id: &str,
) -> Result<Vec<ChunkRef>, String> {
    let store = StoneStore::open().map_err(|e| e.to_string())?;
    let k = stone::shard::DEFAULT_EC_K;
    let m = stone::shard::DEFAULT_EC_M;
    store
        .erasure_code_chunks(raw_data, chunk_refs, local_peer_id, k, m)
        .map_err(|e| e.to_string())
}

// ─── Peer-Persistenz ─────────────────────────────────────────────────────────

pub fn save_peers(peers: &[PeerInfo]) {
    let _ = std::fs::create_dir_all(data_dir());
    if let Ok(json) = serde_json::to_string_pretty(peers) {
        let _ = std::fs::write(peers_file(), json);
    }
}

pub fn load_peers_from_disk() -> Vec<PeerInfo> {
    if let Ok(data) = std::fs::read_to_string(peers_file()) {
        if let Ok(list) = serde_json::from_str::<Vec<PeerInfo>>(&data) {
            return list;
        }
    }
    Vec::new()
}

// ─── Trust-Persistenz ────────────────────────────────────────────────────────

pub fn trust_file() -> String {
    format!("{}/trust.json", data_dir())
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct TrustPersist {
    registry: Vec<TrustEntry>,
    history: Vec<TrustVote>,
}

pub fn save_trust(state: &AppState) {
    let _ = std::fs::create_dir_all(data_dir());
    let data = TrustPersist {
        registry: state.node.trust_registry.read().unwrap_or_else(|e| e.into_inner()).clone(),
        history: state.node.trust_history_snapshot(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let _ = std::fs::write(trust_file(), json);
    }
}

pub fn load_trust_from_disk(state: &MasterNodeState) {
    if let Ok(raw) = std::fs::read_to_string(trust_file()) {
        if let Ok(data) = serde_json::from_str::<TrustPersist>(&raw) {
            *state.trust_registry.write().unwrap_or_else(|e| e.into_inner()) = data.registry;
            *state.trust_history.lock().unwrap_or_else(|e| e.into_inner()) = data.history;
        }
    }
}
