//! Shared application state, constants, chunk helpers, and peer persistence.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use stone::{
    auth::{User, ChallengeStore, QrLoginStore},
    blockchain::{ChunkRef, data_dir, CHUNK_SIZE, Document},
    chat::{ChatIndex, ContactList, ContactRequestStore, ChatGroupStore, CallSignalStore, AnnouncementStore},
    push::{PushTokenStore, FcmClient},
};
use super::handlers::audio_relay::AudioRooms;
use stone::{
    master::{MasterNodeState, PeerInfo, TrustEntry, TrustVote},
    network::NetworkHandle,
    organization::Organization,
    pop_mining::PopMiningState,
    storage::{ChunkStore, StoneStore},
    updater::UpdateManager,
    watchdog::WatchdogState,
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
    /// Community Announcements (read-only Channel)
    pub announcements: Arc<Mutex<AnnouncementStore>>,
    /// Call-Signaling (ephemeral, WebRTC)
    pub call_signals: Arc<CallSignalStore>,
    /// Audio-Relay Rooms (live calls)
    pub audio_rooms: AudioRooms,
    /// Push-Token-Store (FCM-Registrierungen)
    pub push_tokens: Arc<Mutex<PushTokenStore>>,
    /// FCM-Client (Google Service Account basiert)
    pub fcm_client: Arc<FcmClient>,
    /// Pending Mobile-Actions (z. B. Marketplace-Käufe mit App-Bestätigung)
    pub action_store: ActionStore,
    /// Proof-of-Play Drop-Tracker (Caps + Cooldowns pro Spiel/Spieler)
    pub play_drops: PlayDropTracker,
    /// Proof-of-Client-Hash Watchdog (verifiziert Plugin-Integrität)
    pub watchdog: WatchdogState,
    /// Proof-of-Play Mining (VRF-basiertes Gameplay-Mining)
    pub pop_mining: PopMiningState,
}

// ─── Mobile Action Store ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MobileActionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileAction {
    pub id: String,
    pub action_type: String,
    pub wallet: String,
    pub listing_id: Option<String>,
    pub item_id: Option<String>,
    pub game_id: Option<String>,
    pub amount: Option<String>,
    pub memo: Option<String>,
    pub buyer_discord_id: Option<String>,
    pub item_name: Option<String>,
    pub status: MobileActionStatus,
    pub created_at: u64,
    pub expires_at: u64,
    pub resolved_at: Option<u64>,
    pub tx_id: Option<String>,
    pub reject_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateMobileAction {
    pub action_type: String,
    pub wallet: String,
    pub listing_id: Option<String>,
    pub item_id: Option<String>,
    pub game_id: Option<String>,
    pub amount: Option<String>,
    pub memo: Option<String>,
    pub buyer_discord_id: Option<String>,
    pub item_name: Option<String>,
    pub ttl_seconds: u64,
}

#[derive(Clone)]
pub struct ActionStore {
    inner: Arc<Mutex<HashMap<String, MobileAction>>>,
}

impl ActionStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn cleanup_expired_locked(map: &mut HashMap<String, MobileAction>, now: u64) {
        for action in map.values_mut() {
            if action.status == MobileActionStatus::Pending && now > action.expires_at {
                action.status = MobileActionStatus::Expired;
                action.resolved_at = Some(now);
            }
        }
        // Alte finale Actions nach 24h entfernen.
        map.retain(|_, action| {
            if action.status == MobileActionStatus::Pending {
                return true;
            }
            now.saturating_sub(action.resolved_at.unwrap_or(now)) <= 24 * 60 * 60
        });
    }

    pub fn create(&self, req: CreateMobileAction) -> MobileAction {
        let now = Self::now_unix();
        let ttl = req.ttl_seconds.clamp(30, 900);
        let mut token_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let id = format!("act_{}", hex::encode(token_bytes));

        let action = MobileAction {
            id: id.clone(),
            action_type: req.action_type,
            wallet: req.wallet,
            listing_id: req.listing_id,
            item_id: req.item_id,
            game_id: req.game_id,
            amount: req.amount,
            memo: req.memo,
            buyer_discord_id: req.buyer_discord_id,
            item_name: req.item_name,
            status: MobileActionStatus::Pending,
            created_at: now,
            expires_at: now + ttl,
            resolved_at: None,
            tx_id: None,
            reject_reason: None,
        };

        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired_locked(&mut map, now);
        map.insert(id, action.clone());
        action
    }

    pub fn pending_for_wallet(&self, wallet: &str) -> Vec<MobileAction> {
        let now = Self::now_unix();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired_locked(&mut map, now);
        map.values()
            .filter(|a| a.status == MobileActionStatus::Pending && a.wallet == wallet)
            .cloned()
            .collect()
    }

    pub fn get(&self, action_id: &str) -> Option<MobileAction> {
        let now = Self::now_unix();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired_locked(&mut map, now);
        map.get(action_id).cloned()
    }

    pub fn approve(&self, action_id: &str, tx_id: String) -> Option<MobileAction> {
        let now = Self::now_unix();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired_locked(&mut map, now);
        let action = map.get_mut(action_id)?;
        if action.status != MobileActionStatus::Pending {
            return None;
        }
        action.status = MobileActionStatus::Approved;
        action.tx_id = Some(tx_id);
        action.resolved_at = Some(now);
        Some(action.clone())
    }

    pub fn reject(&self, action_id: &str, reason: Option<String>) -> Option<MobileAction> {
        let now = Self::now_unix();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired_locked(&mut map, now);
        let action = map.get_mut(action_id)?;
        if action.status != MobileActionStatus::Pending {
            return None;
        }
        action.status = MobileActionStatus::Rejected;
        action.reject_reason = reason;
        action.resolved_at = Some(now);
        Some(action.clone())
    }
}

impl Default for ActionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Proof-of-Play Drop Tracker ──────────────────────────────────────────────

/// Konfiguration pro Spiel: tägliches Emissions-Budget + Pro-Spieler-Limits.
#[derive(Debug, Clone)]
pub struct PlayDropConfig {
    /// Maximale Token-Menge pro Spiel pro UTC-Tag (in STONE).
    pub daily_game_cap: f64,
    /// Maximale Token-Menge pro Spieler pro UTC-Tag (in STONE).
    pub daily_player_cap: f64,
    /// Mindest-Abstand zwischen zwei Drops desselben Spielers (Sekunden).
    pub player_cooldown_secs: u64,
    /// Maximale Token-Menge pro Einzeldrop (Anti-Bug-Cap).
    pub max_drop_amount: f64,
}

impl PlayDropConfig {
    pub fn from_env() -> Self {
        fn f(env: &str, def: f64) -> f64 {
            std::env::var(env)
                .ok()
                .and_then(|v| v.trim().parse::<f64>().ok())
                .filter(|v| v.is_finite() && *v >= 0.0)
                .unwrap_or(def)
        }
        fn u(env: &str, def: u64) -> u64 {
            std::env::var(env).ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(def)
        }
        Self {
            daily_game_cap: f("STONE_PLAY_DAILY_GAME_CAP", 1000.0),
            daily_player_cap: f("STONE_PLAY_DAILY_PLAYER_CAP", 50.0),
            player_cooldown_secs: u("STONE_PLAY_PLAYER_COOLDOWN_SECS", 30),
            max_drop_amount: f("STONE_PLAY_MAX_DROP", 5.0),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct PlayDropDay {
    epoch_day: i64,
    game_total: f64,
    per_player: HashMap<String, f64>,
}

#[derive(Default)]
struct PlayDropInner {
    days: HashMap<String, PlayDropDay>,           // key: game_id
    last_drop: HashMap<(String, String), u64>,    // (game_id, player) -> ts
}

#[derive(Clone)]
pub struct PlayDropTracker {
    cfg: Arc<PlayDropConfig>,
    inner: Arc<Mutex<PlayDropInner>>,
}

#[derive(Debug)]
pub enum PlayDropError {
    InvalidAmount,
    Cooldown { remaining_secs: u64 },
    PlayerCapExceeded { used: f64, cap: f64 },
    GameCapExceeded { used: f64, cap: f64 },
    DropTooLarge { max: f64 },
}

impl std::fmt::Display for PlayDropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAmount => write!(f, "Ungültiger Betrag"),
            Self::Cooldown { remaining_secs } => write!(f, "Cooldown aktiv: noch {remaining_secs}s"),
            Self::PlayerCapExceeded { used, cap } =>
                write!(f, "Spieler-Tageslimit erreicht: {used:.4}/{cap:.4}"),
            Self::GameCapExceeded { used, cap } =>
                write!(f, "Spiel-Tagesbudget erschöpft: {used:.4}/{cap:.4}"),
            Self::DropTooLarge { max } => write!(f, "Drop überschreitet Maximum ({max:.4})"),
        }
    }
}

impl PlayDropTracker {
    pub fn new(cfg: PlayDropConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            inner: Arc::new(Mutex::new(PlayDropInner::default())),
        }
    }

    pub fn config(&self) -> &PlayDropConfig {
        &self.cfg
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn epoch_day(now: u64) -> i64 {
        (now / 86_400) as i64
    }

    /// Prüft alle Limits und reserviert den Betrag bei Erfolg.
    /// Bei Fehler wird nichts verändert.
    pub fn try_consume(
        &self,
        game_id: &str,
        player: &str,
        amount: f64,
    ) -> Result<(), PlayDropError> {
        if !amount.is_finite() || amount <= 0.0 {
            return Err(PlayDropError::InvalidAmount);
        }
        if amount > self.cfg.max_drop_amount {
            return Err(PlayDropError::DropTooLarge { max: self.cfg.max_drop_amount });
        }

        let now = Self::now();
        let today = Self::epoch_day(now);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let day = inner.days.entry(game_id.to_string()).or_default();
        if day.epoch_day != today {
            day.epoch_day = today;
            day.game_total = 0.0;
            day.per_player.clear();
        }

        let cooldown_key = (game_id.to_string(), player.to_string());
        if let Some(last_ts) = inner.last_drop.get(&cooldown_key).copied() {
            let elapsed = now.saturating_sub(last_ts);
            if elapsed < self.cfg.player_cooldown_secs {
                return Err(PlayDropError::Cooldown {
                    remaining_secs: self.cfg.player_cooldown_secs - elapsed,
                });
            }
        }

        let day = inner.days.get_mut(game_id).unwrap();
        let player_used = day.per_player.get(player).copied().unwrap_or(0.0);
        if player_used + amount > self.cfg.daily_player_cap {
            return Err(PlayDropError::PlayerCapExceeded {
                used: player_used,
                cap: self.cfg.daily_player_cap,
            });
        }
        if day.game_total + amount > self.cfg.daily_game_cap {
            return Err(PlayDropError::GameCapExceeded {
                used: day.game_total,
                cap: self.cfg.daily_game_cap,
            });
        }

        day.game_total += amount;
        *day.per_player.entry(player.to_string()).or_insert(0.0) += amount;
        inner.last_drop.insert(cooldown_key, now);

        Ok(())
    }

    pub fn snapshot(&self, game_id: &str) -> (f64, HashMap<String, f64>) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let today = Self::epoch_day(Self::now());
        if let Some(day) = inner.days.get(game_id) {
            if day.epoch_day == today {
                return (day.game_total, day.per_player.clone());
            }
        }
        (0.0, HashMap::new())
    }
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
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(wallet, (report, Instant::now()));
        // Cleanup: Alte Einträge entfernen
        map.retain(|_, (_, ts)| ts.elapsed().as_secs() < MINER_STATUS_TTL_SECS * 5);
    }

    /// Holt den letzten Status für eine Wallet (falls noch nicht abgelaufen)
    pub fn get(&self, wallet: &str) -> Option<MinerStatusReport> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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

/// Lädt den separaten Admin-Key.
/// Priorität: 1) STONE_ADMIN_KEY env  2) stone_data/admin_key.bin  3) Fallback auf api_key
pub fn load_admin_key(fallback_api_key: &str) -> String {
    // 1. Umgebungsvariable
    if let Ok(v) = std::env::var("STONE_ADMIN_KEY") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            println!("[auth] Separater Admin-Key aus STONE_ADMIN_KEY geladen");
            return v;
        }
    }
    // 2. admin_key.bin (generiert via stone-keygen --admin-key)
    let admin_path = format!("{}/admin_key.bin", data_dir());
    if let Ok(data) = std::fs::read_to_string(&admin_path) {
        let t = data.trim().to_string();
        if !t.is_empty() {
            println!("[auth] Admin-Key aus {admin_path} geladen");
            return t;
        }
    }
    // 3. Fallback
    println!("[auth] ⚠️  Kein separater Admin-Key – verwende API-Key als Fallback");
    println!("[auth]    Generiere einen mit: stone-keygen --admin-key");
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
    // Parallel in SQLite speichern
    if let Some(db) = stone::database::global_db() {
        let _ = db.save_peers(peers);
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
    // Parallel in SQLite speichern
    if let Some(db) = stone::database::global_db() {
        let _ = db.save_trust(&data.registry, &data.history);
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
