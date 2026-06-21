// ─── Swarm-Task ───────────────────────────────────────────────────────────────
//
// Aufgesplittet in Sub-Module:
//   events.rs      – Behaviour-Event-Handling (Identify, mDNS, Gossipsub, Kad, Relay, Shard, …)
//   gossip.rs      – Gossip Block- & TX-Verarbeitung mit Validierung
//   sync.rs        – Chain-Sync Handshake, Buffer-Flush, Range-Requests
//   commands.rs    – Externe Befehle (Broadcast, Dial, GetStatus, Shard-Ops, …)
//   relay.rs       – Relay-Reservierungen & Auto-Discovery
//   scoring.rs     – Peer-Scoring & Banning
//   maintenance.rs – Periodisches Cleanup, Keepalive-Pings, Latenz-Tracking

mod commands;
mod events;
mod gossip;
mod maintenance;
mod relay;
mod scoring;
mod sync;

use crate::blockchain::Block;
use futures_util::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    gossipsub::{self, IdentTopic},
    request_response,
    swarm::SwarmEvent,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};

use super::*;

/// Zustand des laufenden Swarm-Tasks.
pub(crate) struct SwarmTask {
    pub(crate) swarm: Swarm<StoneBehaviour>,
    pub(crate) event_tx: broadcast::Sender<NetworkEvent>,
    pub(crate) cmd_rx: mpsc::Receiver<NetworkCommand>,

    /// Bekannte Peers: PeerId → PeerInfo
    pub(crate) peers: HashMap<PeerId, PeerInfo>,

    /// Seen-Cache: Block-Hashes die bereits verarbeitet wurden (Duplicate-Filter).
    pub(crate) seen_hashes: HashSet<String>,
    pub(crate) seen_order: VecDeque<String>,

    /// Unsere aktuelle Chain-Länge (für Sync-Handshake)
    pub(crate) local_chain_count: u64,

    /// Bootstrap-Adressen für Reconnect
    pub(crate) bootstrap_addrs: Vec<String>,

    /// Zeitpunkt des letzten Reconnect-Versuchs
    pub(crate) last_reconnect: Instant,

    pub(crate) config: P2pConfig,

    /// Ausstehende Pings: request_id → (peer_id_str, start_instant, reply_channel)
    pub(crate) pending_pings: HashMap<
        request_response::OutboundRequestId,
        (String, std::time::Instant, tokio::sync::oneshot::Sender<PingResult>),
    >,

    // ─── NAT-Traversal Zustand ──────────────────────────────────────────────

    /// Erkannter NAT-Status
    pub(crate) nat_status: NatStatus,

    /// Relay-Nodes bei denen wir eine Reservation haben
    pub(crate) active_relays: HashSet<PeerId>,

    /// Relay-Adressen die wir versuchen sollen
    pub(crate) relay_addrs: Vec<String>,

    // ─── Sicherheit: Peer-Scoring ───────────────────────────────────────────

    /// Penalty-Score pro Peer: wenn > BAN_THRESHOLD → Peer wird gebannt
    pub(crate) peer_penalties: HashMap<PeerId, PeerPenalty>,

    // ─── P2P Rate Limiting ──────────────────────────────────────────────────

    /// Token-Bucket Rate Limiter pro Peer (DDoS-Protection)
    pub(crate) peer_rate_limiters: HashMap<PeerId, PeerRateLimiter>,

    // ─── Chain-Referenz für Block-Serving ────────────────────────────────────

    /// Optionale Referenz auf die Chain — wird nach Start per Command injiziert.
    /// Ermöglicht dem SwarmTask Blöcke direkt aus der lokalen Chain zu servieren.
    ///
    /// **Wichtig:** Dieser `Mutex` wird auf dem Block-Commit-Pfad vom
    /// HTTP-Handler/Mining-Pfad gehalten und kann den Async-Task für Dutzende
    /// ms blockieren. Hot-Path-Reads (Height, Genesis-Hash) gehen deshalb
    /// **nicht** über diesen Lock, sondern über `local_chain_count`
    /// (atomar via `SetLocalChainCount` aktualisiert) und
    /// `genesis_hash_cache` (einmalig bei `SetChainRef` gecached). Der Lock
    /// wird nur noch beim tatsächlichen Bedienen von Block-Daten in
    /// `events.rs` gehalten.
    pub(crate) chain_ref: Option<std::sync::Arc<std::sync::Mutex<crate::blockchain::StoneChain>>>,

    /// Genesis-Hash der lokalen Chain – einmalig bei `SetChainRef` gecached,
    /// danach lock-free lesbar. Der Genesis-Block ändert sich nach
    /// Initialisierung nicht mehr, deshalb ist Caching sicher.
    pub(crate) genesis_hash_cache: Option<std::sync::Arc<String>>,

    /// Shard-Speicher für eingehende Shard-Requests
    pub(crate) shard_store: crate::shard::ShardStore,

    /// Ausstehende Shard-Listen-Anfragen: request_id → reply
    pub(crate) pending_shard_lists: HashMap<
        request_response::OutboundRequestId,
        (String, tokio::sync::oneshot::Sender<Vec<u8>>),
    >,

    // ─── Netzwerk-Metriken ──────────────────────────────────────────────────

    /// Kumulative Traffic-Metriken
    pub(crate) net_metrics: NetworkMetrics,
    /// Zeitpunkt des Swarm-Starts (für Uptime-Berechnung)
    pub(crate) started_at: Instant,

    // ─── Peer-Storage-Tracking ──────────────────────────────────────────────

    /// Speicher-Ankündigungen von Peers: PeerId-String → StorageAnnouncement
    pub(crate) peer_storage: HashMap<String, StorageAnnouncement>,

    /// Ausstehende ChainInfo-Anfragen: request_id → PeerId
    /// Wird verwendet um die Antwort dem richtigen Peer zuzuordnen und Sync auszulösen.
    pub(crate) pending_chain_info: HashMap<request_response::OutboundRequestId, PeerId>,

    /// Sync-Buffer: Sammelt Blöcke aus parallelen Range-Responses und fügt sie
    /// geordnet ein. Key = Block-Index für schnellen Lookup.
    pub(crate) sync_buffer: std::collections::BTreeMap<u64, (Block, String)>,
    /// Zeitpunkt als zuletzt Blöcke in den sync_buffer kamen (für Flush-Timeout)
    pub(crate) sync_buffer_last_insert: Option<Instant>,
    /// Erwarteter nächster Block-Index für den Sync (= unsere Chain-Höhe beim Sync-Start)
    pub(crate) sync_expected_next: u64,
    /// Letzter Zeitpunkt mit messbarem Sync-Fortschritt
    pub(crate) sync_last_progress_at: Instant,
    /// Letzte lokale Chain-Höhe zum Progress-Vergleich
    pub(crate) sync_last_progress_height: u64,
    /// Derzeit bevorzugter Sync-Partner
    pub(crate) sync_target_peer: Option<PeerId>,
    /// Aktuelle Recovery-Stage
    pub(crate) sync_recovery_stage: SyncRecoveryStage,
    /// Anzahl Recovery-Aktionen seit Start
    pub(crate) sync_recovery_attempts: u32,
    /// Letzter Recovery-Grund
    pub(crate) sync_last_recovery_reason: String,
    /// Cooldown bis zur nächsten Recovery-Aktion
    pub(crate) sync_recovery_cooldown_until: Option<Instant>,
    /// Stage-Flags
    pub(crate) sync_recovery_stage1_enabled: bool,
    pub(crate) sync_recovery_stage2_enabled: bool,
    pub(crate) sync_recovery_stage3_enabled: bool,
    pub(crate) sync_recovery_stage4_enabled: bool,
    /// Timeout ohne Fortschritt bis Recovery
    pub(crate) sync_stall_timeout_secs: u64,
    /// Cooldown zwischen Recovery-Aktionen
    pub(crate) sync_recovery_cooldown_secs: u64,
    /// Langer Cooldown nach Stage4-Eskalation
    pub(crate) sync_snapshot_escalation_cooldown_secs: u64,

    // ─── Stake-basierte Relay-Priorität ──────────────────────────────────

    /// Eigener Stake-Level (wird von MasterNode periodisch gesetzt).
    /// 0=Observer, 100=Participant, 250=Guardian, 500=Validator
    pub(crate) local_stake_level: u64,

    // ─── Reconnect-Backoff ───────────────────────────────────────────────

    /// Per-Peer exponentieller Backoff für Reconnect-Versuche.
    /// PeerId → (frühester nächster Versuch, aktueller Backoff-Intervall)
    /// Verhindert Connect-Disconnect-Storms wenn beide Seiten gleichzeitig dialen.
    pub(crate) reconnect_backoff: HashMap<PeerId, (Instant, Duration)>,

    /// Zeitpunkt der ersten (stabilen) Verbindung pro Peer. Dient der Flap-
    /// Erkennung: bricht eine Verbindung nach <STABLE_CONNECTION_SECS wieder ab,
    /// behandeln wir den Peer als flappend und setzen Backoff statt ihn sofort
    /// erneut zu dialen (verhindert Connect-Disconnect-Storms).
    pub(crate) peer_connected_since: HashMap<PeerId, Instant>,

    /// Menge aller Bootstrap-PeerIds (aus konfigurierten Multiaddrs extrahiert).
    pub(crate) bootstrap_peer_ids: HashSet<PeerId>,

    /// Lernender Score pro Bootstrap-Peer.
    /// Positive Werte = erreichbar/stabil, negative Werte = häufige Dial-Fehler.
    pub(crate) bootstrap_peer_scores: HashMap<PeerId, i32>,

    /// Maximaler Jitter (Sekunden), der auf den Reconnect-Backoff addiert wird.
    pub(crate) reconnect_jitter_max_secs: u64,

    /// Aktiviert Priorisierung bereits erfolgreicher Bootstrap-Peers.
    pub(crate) prefer_successful_bootstrap: bool,

    // ─── Keepalive / Warm Peer Table ─────────────────────────────────────

    /// Laufende Keepalive-Pings: request_id → (PeerId, Sende-Zeitpunkt)
    /// Fire-and-forget: kein oneshot-Channel, nur Latenz-Recording.
    pub(crate) keepalive_pings: HashMap<request_response::OutboundRequestId, (PeerId, Instant)>,

    /// Rolling-Window Latenz-Historie pro Peer (letzte 10 Messungen, in ms)
    pub(crate) peer_latencies: HashMap<PeerId, VecDeque<u64>>,

    /// Grace-Zähler für aufeinanderfolgende Rate-Limit-Verletzungen pro Peer.
    /// Erst nach RATE_LIMIT_GRACE Verletzungen wird eine Penalty vergeben.
    pub(crate) rate_limit_grace: HashMap<PeerId, u32>,

    /// Cooldown für Peers mit Protokoll-Inkompatibilität.
    /// Während des Cooldowns werden aktive Sync/Shard-Requests gegen den Peer
    /// ausgesetzt, um Error-Stürme zu vermeiden.
    pub(crate) protocol_mismatch_cooldown: HashMap<PeerId, Instant>,

    // ─── Deterministischer Network Health Controller ─────────────────────

    /// Aktueller Health-Status der Node.
    pub(crate) health_state: NetworkHealthState,
    /// Zuletzt klassifizierte Fehlerklasse (falls vorhanden).
    pub(crate) health_failure: Option<FailureClass>,
    /// Aktuelle Recovery-Eskalationsstufe.
    pub(crate) health_recovery_level: RecoveryLevel,
    /// Letzter Transition-Zeitpunkt.
    pub(crate) health_last_transition: Instant,
    /// Letzter Controller-Grundtext (deterministisch berechnet).
    pub(crate) health_last_reason: String,
    /// Cooldown bis zur nächsten orchestrierten Health-Aktion.
    pub(crate) health_cooldown_until: Option<Instant>,
}

/// Tracking für Fehlverhalten eines Peers
pub(crate) struct PeerPenalty {
    pub(crate) score: u32,
    pub(crate) last_offense: Instant,
    pub(crate) reasons: Vec<String>,
    /// Wie oft dieser Peer bereits gebannt wurde (für eskalierende Ban-Dauer)
    pub(crate) ban_count: u32,
    /// Anzahl starker Evidenz-Offenses (z.B. ungültige Signaturen/Hashes).
    pub(crate) strong_evidence_count: u32,
}

/// Ab diesem Score wird ein Peer gebannt (Verbindung getrennt, kein Re-Dial)
pub(super) const BAN_THRESHOLD: u32 = 200;

/// Höherer Ban-Threshold für bekannte Bootstrap/Seed-Peers.
/// Diese Peers sind zentral für den Netzaufbau und dürfen bei Burst- oder
/// Übergangszuständen nicht zu schnell aus dem Mesh fallen.
pub(super) const BAN_THRESHOLD_BOOTSTRAP: u32 = 600;

/// Mindestanzahl starker Evidenz-Offenses bevor ein Ban greift.
pub(super) const BAN_MIN_STRONG_EVIDENCE: u32 = 1;

/// Für Bootstrap/Seed-Peers gilt eine strengere Evidenz-Anforderung,
/// damit sie nicht durch Soft-Offense-Kaskaden ausfallen.
pub(super) const BAN_MIN_STRONG_EVIDENCE_BOOTSTRAP: u32 = 2;

/// Penalty-Punkte verfallen nach dieser Zeit (Minuten)
pub(super) const PENALTY_DECAY_MINS: u64 = 30;

/// Aufeinanderfolgende Rate-Limit-Verletzungen bevor Penalty vergeben wird
pub(super) const RATE_LIMIT_GRACE: u32 = 15;

/// Mehr Toleranz für Rate-Limit-Bursts von Bootstrap-Peers.
pub(super) const RATE_LIMIT_GRACE_BOOTSTRAP: u32 = 60;

/// Zustandsmaschine des deterministischen Network Health Controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkHealthState {
    Healthy,
    Degraded,
    Isolated,
    Partitioned,
    Syncing,
    Recovering,
    SnapshotRecovery,
    Critical,
}

impl NetworkHealthState {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Isolated => "isolated",
            Self::Partitioned => "partitioned",
            Self::Syncing => "syncing",
            Self::Recovering => "recovering",
            Self::SnapshotRecovery => "snapshot_recovery",
            Self::Critical => "critical",
        }
    }
}

/// Deterministische Fehlerklassifikation für Recovery-Entscheidungen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureClass {
    DiscoveryFailure,
    BootstrapFailure,
    SyncDivergence,
    PeerPoisoning,
    HighChurn,
    RelayCollapse,
    DatabaseInconsistency,
    NetworkPartition,
}

impl FailureClass {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::DiscoveryFailure => "discovery_failure",
            Self::BootstrapFailure => "bootstrap_failure",
            Self::SyncDivergence => "sync_divergence",
            Self::PeerPoisoning => "peer_poisoning",
            Self::HighChurn => "high_churn",
            Self::RelayCollapse => "relay_collapse",
            Self::DatabaseInconsistency => "database_inconsistency",
            Self::NetworkPartition => "network_partition",
        }
    }
}

/// Eskalationsleiter des Controllers (Level 1..6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryLevel {
    None,
    Level1SoftReconnect,
    Level2PeerTableRefresh,
    Level3KadBootstrapReset,
    Level4PeerCacheInvalidation,
    Level5SnapshotSync,
    Level6CriticalIsolation,
}

impl RecoveryLevel {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Level1SoftReconnect => "level1_soft_reconnect",
            Self::Level2PeerTableRefresh => "level2_peer_table_refresh",
            Self::Level3KadBootstrapReset => "level3_kad_bootstrap_reset",
            Self::Level4PeerCacheInvalidation => "level4_peer_cache_invalidation",
            Self::Level5SnapshotSync => "level5_snapshot_sync",
            Self::Level6CriticalIsolation => "level6_critical_isolation",
        }
    }
}

// ─── Persistierte Ban-Liste ───────────────────────────────────────────────────

/// Eintrag in der persistierten Ban-Liste
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BannedPeerEntry {
    peer_id: String,
    score: u32,
    reasons: Vec<String>,
    banned_at: i64,
    /// Unix-Timestamp wann der Ban abläuft (0 = nach Decay)
    expires_at: i64,
    /// Wie oft dieser Peer bereits gebannt wurde
    #[serde(default)]
    ban_count: u32,
    /// Anzahl starker Evidenz-Offenses zum Ban-Zeitpunkt.
    #[serde(default)]
    strong_evidence_count: u32,
    /// Letzte bekannte Adressen (IP/Multiaddr) zum Ban-Zeitpunkt
    #[serde(default)]
    last_known_addresses: Vec<String>,
    /// Agent-Version des Peers (z.B. "stone/0.4.1")
    #[serde(default)]
    agent_version: String,
    /// Menschenlesbare Ban-Dauer (z.B. "2h", "24h")
    #[serde(default)]
    ban_duration: String,
}

/// Lädt die Ban-Liste aus `stone_data/banned_peers.json`
pub(crate) fn load_banned_peers() -> HashMap<PeerId, PeerPenalty> {
    let path = format!("{}/{}", data_dir(), BANNED_PEERS_FILENAME);
    let Ok(data) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<BannedPeerEntry>>(&data) else {
        eprintln!("[p2p] ⚠ Konnte Ban-Liste nicht parsen: {path}");
        return HashMap::new();
    };
    let now = chrono::Utc::now().timestamp();
    let mut map = HashMap::new();
    for entry in entries {
        // Abgelaufene Bans überspringen
        if entry.expires_at > 0 && entry.expires_at < now {
            continue;
        }
        if let Ok(peer_id) = entry.peer_id.parse::<PeerId>() {
            map.insert(peer_id, PeerPenalty {
                score: entry.score,
                last_offense: Instant::now(), // konservativ: als "gerade passiert" behandeln
                reasons: entry.reasons,
                ban_count: entry.ban_count,
                strong_evidence_count: entry.strong_evidence_count,
            });
        }
    }
    if !map.is_empty() {
        println!("[p2p] 🔨 {} gebannte Peers aus Datei geladen", map.len());
    }
    map
}

/// Formatiert Sekunden als menschenlesbare Dauer (z.B. "2h 30m", "24h")
pub(super) fn format_ban_duration(secs: i64) -> String {
    if secs <= 0 { return "0m".into(); }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h > 0 && m > 0 { format!("{h}h {m:02}m") }
    else if h > 0 { format!("{h}h") }
    else { format!("{m}m") }
}

/// Speichert die aktuelle Ban-Liste nach `stone_data/banned_peers.json`
pub(super) fn save_banned_peers_with_context(
    penalties: &HashMap<PeerId, PeerPenalty>,
    peers: &HashMap<PeerId, PeerInfo>,
) {
    let now = chrono::Utc::now().timestamp();
    let base_ban_secs = (PENALTY_DECAY_MINS * 60 * 2) as i64; // 1 Stunde Basis
    let entries: Vec<BannedPeerEntry> = penalties
        .iter()
        .filter(|(_, p)| p.score >= BAN_THRESHOLD)
        .map(|(peer_id, p)| {
            // Eskalierende Ban-Dauer: base × 2^ban_count (max 24h)
            let escalated = base_ban_secs * (1i64 << p.ban_count.min(5));
            let max_ban = 24 * 60 * 60; // 24 Stunden Maximum
            let ban_secs = escalated.min(max_ban);
            // Peer-Metadaten vom Zeitpunkt des Bans
            let (addrs, agent) = peers.get(peer_id)
                .map(|info| (
                    info.addresses.clone(),
                    info.agent_version.clone(),
                ))
                .unwrap_or_default();
            BannedPeerEntry {
                peer_id: peer_id.to_string(),
                score: p.score,
                reasons: p.reasons.clone(),
                banned_at: now,
                expires_at: now + ban_secs,
                ban_count: p.ban_count,
                strong_evidence_count: p.strong_evidence_count,
                last_known_addresses: addrs,
                agent_version: agent,
                ban_duration: format_ban_duration(ban_secs),
            }
        })
        .collect();
    let path = format!("{}/{}", data_dir(), BANNED_PEERS_FILENAME);
    if let Ok(json) = serde_json::to_string_pretty(&entries) {
        if let Err(e) = std::fs::write(&path, json) {
            eprintln!("[p2p] ⚠ Konnte Ban-Liste nicht speichern: {e}");
        }
    }
}

/// NAT-Status des Nodes
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NatStatus {
    Unknown,
    Public,
    Private,
}

/// Aktuelle Stage der Sync-Selbstheilung (WS-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncRecoveryStage {
    Idle,
    Stage1SoftReset,
    Stage2PeerSwitch,
    Stage3RebuildNetwork,
    Stage4SnapshotEscalation,
}

impl SyncRecoveryStage {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Stage1SoftReset => "stage1_soft_reset",
            Self::Stage2PeerSwitch => "stage2_peer_switch",
            Self::Stage3RebuildNetwork => "stage3_rebuild_network",
            Self::Stage4SnapshotEscalation => "stage4_snapshot_escalation",
        }
    }
}

/// Prüft ob eine IPv6-Adresse nicht global routbar ist (Link-Local, ULA, etc.)
pub(super) fn is_ipv6_non_global(ip: &std::net::Ipv6Addr) -> bool {
    let seg = ip.segments();
    // Link-Local: fe80::/10
    (seg[0] & 0xffc0) == 0xfe80
    // Unique Local (ULA): fc00::/7
    || (seg[0] & 0xfe00) == 0xfc00
    // Site-Local (deprecated): fec0::/10
    || (seg[0] & 0xffc0) == 0xfec0
}

/// Entfernt die `/p2p/<PeerId>`-Komponente am Ende einer Multiaddr.
/// mDNS liefert Adressen wie `/ip4/1.2.3.4/tcp/7654/p2p/12D3Koo…`.
/// libp2p lehnt es ab, wenn man diese an `DialOpts::peer_id(...).addresses(…)`
/// übergibt — die PeerId wäre dann doppelt vorhanden → EINVAL (os error 22).
pub(super) fn strip_p2p_suffix(addr: libp2p::Multiaddr) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let without: libp2p::Multiaddr = addr
        .into_iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect();
    without
}

// ─── Sync-Handshake Nachricht ─────────────────────────────────────────────────

pub static TOPIC_SYNC_HANDSHAKE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| format!(
        "stone/{}/sync/v1",
        if crate::network::is_mainnet() { "mainnet" } else { "testnet" },
    ));

/// Kurze Nachricht die beim Verbinden gesendet wird um Chain-Längen zu vergleichen.
/// Enthält Genesis-Hash und Protokoll-Version für Kompatibilitätsprüfung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SyncHandshake {
    pub(super) block_count: u64,
    pub(super) peer_id: String,
    /// Genesis-Block-Hash – Peers auf einer anderen Chain werden abgelehnt
    #[serde(default)]
    pub(super) genesis_hash: Option<String>,
    /// Protokoll-Version (z.B. "stone/0.7") – inkompatible Versionen werden abgelehnt
    #[serde(default)]
    pub(super) protocol_version: Option<String>,
    /// Stake-Level dieses Nodes (0/100/250/500) – höhere Stake = bevorzugter Sync-Partner
    #[serde(default)]
    pub(super) stake_level: u64,
}

// ─── Gossipsub: Topics abonnieren ─────────────────────────────────────────────

pub(crate) fn subscribe_all_topics(gossipsub: &mut gossipsub::Behaviour) -> Result<(), String> {
    let topics: [&str; 9] = [
        TOPIC_BLOCKS.as_str(),
        TOPIC_PEERS.as_str(),
        TOPIC_SYNC_HANDSHAKE.as_str(),
        TOPIC_MEMPOOL.as_str(),
        TOPIC_CHAT.as_str(),
        TOPIC_CHAT_CONTENT.as_str(),
        crate::updater::TOPIC_UPDATES.as_str(),
        TOPIC_STORAGE.as_str(),
        crate::network::TOPIC_MINERS.as_str(),
    ];
    for topic in topics {
        gossipsub.subscribe(&IdentTopic::new(topic))
            .map_err(|e| format!("Subscribe '{topic}': {e}"))?;
    }
    Ok(())
}

// ─── Wire-Encoding für Gossip-Payloads ────────────────────────────────────────
//
// Block, TokenTx und SyncHandshake werden seit Protokoll-Version 0.8 via
// bincode (statt JSON) über Gossipsub gesendet. Vorteile:
//   - ~2-4× kleinere Payloads
//   - ~5-10× schnellere Deserialisierung
//   - identisches Wire-Format wie der on-disk Storage (RocksDB) – kein
//     doppelter Codepfad mehr (vermeidet Klassen von Wire-Format-Bugs wie
//     dem TxType-rename_all-Issue).
//
// Andere Topics (Storage, Chat, Updates, Miners) bleiben vorerst auf JSON,
// damit die Umstellung minimal bleibt und Cross-Binary-Konsumenten (setup.rs,
// stone_miner, Master-API-Handler) nicht in einem Aufwasch gepatcht werden
// müssen.

pub(super) fn encode_gossip<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| format!("bincode encode: {e}"))
}

pub(super) fn decode_gossip<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, String> {
    bincode::serde::decode_from_slice(data, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| format!("bincode decode: {e}"))
}

// ─── SwarmTask: run() + Helfer ────────────────────────────────────────────────

impl SwarmTask {
    fn jitter_for_peer(&self, peer_id: &PeerId) -> Duration {
        if self.reconnect_jitter_max_secs == 0 {
            return Duration::from_secs(0);
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.swarm.local_peer_id().hash(&mut hasher);
        peer_id.hash(&mut hasher);

        // 5s-Zeit-Buckets verhindern synchrones Reconnect-Verhalten,
        // ohne dass der Jitter bei jedem Tick komplett neu springt.
        let bucket = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 5;
        bucket.hash(&mut hasher);

        let span = self.reconnect_jitter_max_secs.saturating_add(1);
        let jitter_secs = hasher.finish() % span;
        Duration::from_secs(jitter_secs)
    }

    fn update_bootstrap_score(&mut self, peer_id: PeerId, delta: i32, reason: &str) {
        if !self.bootstrap_peer_ids.contains(&peer_id) {
            return;
        }

        let entry = self.bootstrap_peer_scores.entry(peer_id).or_insert(0);
        *entry = (*entry + delta).clamp(-20, 50);

        println!(
            "[p2p] Seed-Score {} -> {} ({reason})",
            peer_id,
            *entry,
        );
    }

    pub(crate) async fn run(mut self) {
        let listen_addr: Multiaddr = match self.config.listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                let _ = self.event_tx.send(NetworkEvent::Error {
                    message: format!("Ungültige Listen-Adresse: {e}"),
                });
                return;
            }
        };

        // Port-Fallback: falls konfigurierter Port belegt → zufälligen Port nehmen
        if let Err(e) = self.swarm.listen_on(listen_addr.clone()) {
            eprintln!("[p2p] ⚠️  Konnte {listen_addr} nicht binden: {e}");
            let fallback: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
            if let Err(e2) = self.swarm.listen_on(fallback) {
                let _ = self.event_tx.send(NetworkEvent::Error {
                    message: format!("Kein P2P-Port verfügbar: {e2}"),
                });
                return;
            }
            eprintln!("[p2p] ℹ️  Nutze zufälligen P2P-Port (STONE_P2P_PORT setzen um festen Port zu erzwingen)");
        }

        // ── QUIC-Transport: UDP-Listener auf dem gleichen Port ────────────────
        // QUIC hat bessere NAT-Traversal-Eigenschaften als TCP, da UDP Hole-
        // Punching zuverlässiger funktioniert. Wir lauschen auf beiden Protokollen.
        {
            // Port aus der TCP-Adresse extrahieren
            let tcp_port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(DEFAULT_P2P_PORT);

            let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{tcp_port}/quic-v1")
                .parse()
                .unwrap();
            match self.swarm.listen_on(quic_addr.clone()) {
                Ok(_) => println!("[p2p] 🚀 QUIC-Transport aktiv auf UDP/{tcp_port}"),
                Err(e) => eprintln!("[p2p] ⚠️  QUIC konnte nicht gestartet werden: {e}"),
            }

            // Auch IPv6 QUIC wenn verfügbar
            let quic_v6: Multiaddr = format!("/ip6/::/udp/{tcp_port}/quic-v1")
                .parse()
                .unwrap();
            match self.swarm.listen_on(quic_v6) {
                Ok(_) => println!("[p2p] 🚀 QUIC-Transport aktiv auf UDP/{tcp_port} (IPv6)"),
                Err(e) => {
                    // IPv6 oft nicht verfügbar – nur Debug-Level
                    let _ = e; // kein Fehler-Log nötig
                }
            }
        }

        // Dual-Stack: Bei IPv4-Config zusätzlich IPv6 TCP versuchen (und umgekehrt)
        if self.config.listen_addr.starts_with("/ip6/") {
            // Port aus listen_addr extrahieren
            let port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(4001);
            let ipv4_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap();
            match self.swarm.listen_on(ipv4_addr.clone()) {
                Ok(_) => println!("[p2p] Dual-Stack: lausche zusätzlich auf {ipv4_addr}"),
                Err(e) => eprintln!("[p2p] ⚠️  IPv4-Dual-Stack fehlgeschlagen: {e}"),
            }
        } else {
            // IPv4-Config → auch IPv6-TCP versuchen (Dual-Stack)
            let port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(DEFAULT_P2P_PORT);
            let ipv6_addr: Multiaddr = format!("/ip6/::/tcp/{port}").parse().unwrap();
            match self.swarm.listen_on(ipv6_addr) {
                Ok(_) => println!("[p2p] Dual-Stack: lausche zusätzlich auf IPv6 TCP/{port}"),
                Err(_) => {} // IPv6 oft nicht verfügbar – kein Fehler
            }
        }

        // Bootstrap-Nodes einwählen
        for addr_str in self.bootstrap_addrs.clone() {
            self.dial_bootstrap(&addr_str);
        }

        if !self.bootstrap_addrs.is_empty() && self.config.kad_enabled {
            let _ = self.swarm.behaviour_mut().kad.bootstrap();
        }

        // Relay-Reservierungen herstellen (falls konfiguriert)
        if !self.relay_addrs.is_empty() {
            println!("[p2p] 📡 {} Relay-Node(s) konfiguriert – stelle Verbindungen her...", self.relay_addrs.len());
            self.establish_relay_reservations();
        }

        // Reconnect-Intervall (0 = deaktiviert)
        let reconnect_interval = if self.config.reconnect_interval_secs > 0 {
            Duration::from_secs(self.config.reconnect_interval_secs)
        } else {
            Duration::from_secs(u64::MAX / 2) // praktisch nie
        };

        let mut reconnect_ticker = tokio::time::interval(reconnect_interval);
        reconnect_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Periodischer Sync-Check: alle 30s prüfen ob verbundene Peers mehr Blöcke haben
        let mut sync_ticker = tokio::time::interval(Duration::from_secs(30));
        sync_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Sync-Buffer Flush-Ticker: alle 500ms prüfen ob gepufferte Blöcke geflusht werden können
        let mut flush_ticker = tokio::time::interval(Duration::from_millis(500));
        flush_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Cleanup-Ticker: alle 5 Minuten verwaiste rate_limiters, penalties, storage aufräumen
        let mut cleanup_ticker = tokio::time::interval(Duration::from_secs(300));
        cleanup_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Keepalive-Ticker: alle 45s Pings an verbundene Peers senden um NAT-Mappings warm zu halten
        let mut keepalive_ticker = tokio::time::interval(Duration::from_secs(45));
        keepalive_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Health-Controller-Ticker: alle 15s deterministische Zustandsermittlung + Recovery-Orchestrierung
        let mut health_ticker = tokio::time::interval(Duration::from_secs(15));
        health_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    match event {
                        Some(ev) => self.handle_swarm_event(ev).await,
                        None => break,
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => { if self.handle_command(c) { break; } }
                        None => break,
                    }
                }
                _ = reconnect_ticker.tick() => {
                    self.reconnect_bootstrap_nodes();
                }
                _ = sync_ticker.tick() => {
                    self.sync_with_connected_peers();
                }
                _ = flush_ticker.tick() => {
                    if !self.sync_buffer.is_empty() {
                        self.flush_sync_buffer();
                    }
                }
                _ = cleanup_ticker.tick() => {
                    self.periodic_cleanup();
                }
                _ = keepalive_ticker.tick() => {
                    self.keepalive_ping_peers();
                }
                _ = health_ticker.tick() => {
                    self.run_health_controller();
                }
            }
        }
        println!("[p2p] Swarm-Task beendet.");
    }

    // ── Duplicate-Filter ─────────────────────────────────────────────────────

    /// Gibt true zurück wenn der Hash bereits gesehen wurde (Duplikat).
    pub(super) fn is_duplicate(&mut self, hash: &str) -> bool {
        if self.seen_hashes.contains(hash) {
            return true;
        }
        // Neu: in Cache aufnehmen
        if self.seen_order.len() >= SEEN_CACHE_SIZE {
            // Ältesten Eintrag entfernen
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_hashes.remove(&oldest);
            }
        }
        self.seen_hashes.insert(hash.to_string());
        self.seen_order.push_back(hash.to_string());
        false
    }

    // ── Bootstrap / Reconnect ────────────────────────────────────────────────

    fn dial_bootstrap(&mut self, addr_str: &str) {
        // Placeholder-Adressen aus der Beispiel-Config überspringen
        if addr_str.contains("12D3KooW...") || addr_str.contains("1.2.3.4") {
            println!("[p2p] Bootstrap '{addr_str}' übersprungen (Placeholder) – bitte echte Adresse eintragen");
            return;
        }
        if addr_str.trim().is_empty() {
            return;
        }
        match addr_str.parse::<Multiaddr>() {
            Ok(addr) => {
                use libp2p::multiaddr::Protocol;
                let peer_id = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p { Some(pid) } else { None }
                });
                if let Some(pid) = peer_id {
                    // Eigene PeerId nicht anwählen (Seed-Node wählt sich sonst selbst an)
                    if pid == *self.swarm.local_peer_id() {
                        return;
                    }
                    self.swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    println!("[p2p] Bootstrap-Node: {pid} @ {addr}");
                }
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    eprintln!("[p2p] Dial {addr} fehlgeschlagen: {e}");
                }
            }
            Err(e) => eprintln!("[p2p] Ungültige Bootstrap-Adresse '{addr_str}': {e}"),
        }
    }

    fn reconnect_bootstrap_nodes(&mut self) {
        let now = Instant::now();
        let connected_peer_ids: HashSet<String> = self.peers.values()
            .filter(|p| p.connected)
            .map(|p| p.peer_id.clone())
            .collect();

        // Wenn wir gar keine Verbindungen haben → alle Bootstrap-Nodes anwählen
        // (priorisiert: SEED_NODES stehen am Anfang der Liste = VPS zuerst)
        let no_connections = connected_peer_ids.is_empty();

        if !no_connections {
            // Prüfen ob alle bekannten Peers bereits verbunden sind
            let disconnected_count = self.peers.values()
                .filter(|p| !p.connected)
                .count();
            if disconnected_count == 0 && !self.peers.is_empty() {
                return; // alle bereits verbunden
            }
        }

        // Backoff nur für STABIL verbundene Peers zurücksetzen (>= STABLE_CONNECTION_SECS).
        // Ein gerade erst (oder flappend) verbundener Peer behält seinen Backoff,
        // damit ein sofortiges erneutes Trennen keinen Reconnect-Storm auslöst.
        let connected: Vec<PeerId> = self.swarm.connected_peers().cloned().collect();
        for pid in connected {
            let stable = self.peer_connected_since.get(&pid)
                .map(|t| t.elapsed() >= Duration::from_secs(STABLE_CONNECTION_SECS))
                .unwrap_or(false);
            if stable {
                self.reconnect_backoff.remove(&pid);
            }
        }

        let mut attempted = 0u32;
        let mut candidates: Vec<(i32, String, Multiaddr, PeerId)> = Vec::new();
        for addr_str in self.bootstrap_addrs.clone() {
            use libp2p::multiaddr::Protocol;
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                let peer_id_opt = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p {
                        Some(pid)
                    } else {
                        None
                    }
                });
                if let Some(pid) = peer_id_opt {
                    let score = self.bootstrap_peer_scores.get(&pid).copied().unwrap_or(0);
                    candidates.push((score, addr_str.clone(), addr, pid));
                }
            }
        }

        if self.prefer_successful_bootstrap {
            candidates.sort_by(|a, b| {
                b.0.cmp(&a.0)
                    .then_with(|| a.1.cmp(&b.1))
            });
        }

        for (score, addr_str, addr, pid) in candidates {
            // Eigene PeerId nicht anwählen
            if pid == *self.swarm.local_peer_id() {
                continue;
            }
            if connected_peer_ids.contains(&pid.to_string()) {
                continue;
            }

            // ── Exponentieller Backoff pro Peer ──────────────────
            // Verhindert Connect-Disconnect-Storm wenn beide Seiten
            // gleichzeitig dialen und libp2p die doppelte Verbindung
            // sofort wieder schließt.
            const MIN_BACKOFF: Duration = Duration::from_secs(5);
            const MAX_BACKOFF: Duration = Duration::from_secs(300); // 5 min

            if let Some((next_try, _)) = self.reconnect_backoff.get(&pid) {
                if now < *next_try {
                    continue; // Backoff noch nicht abgelaufen
                }
            }

            // Backoff aktualisieren: verdoppeln (exponentiell), max 5 min + Jitter
            let current_backoff = self.reconnect_backoff
                .get(&pid)
                .map(|(_, d)| *d)
                .unwrap_or(MIN_BACKOFF);
            let next_backoff = (current_backoff * 2).min(MAX_BACKOFF);
            let jitter = self.jitter_for_peer(&pid);
            self.reconnect_backoff.insert(
                pid,
                (now + next_backoff + jitter, next_backoff),
            );

            println!(
                "[p2p] Reconnect-Versuch: {pid} ({addr_str}) [seed_score={score}, backoff={:.0}s, jitter={}s]",
                next_backoff.as_secs_f64(),
                jitter.as_secs(),
            );
            let _ = self.swarm.dial(addr);
            attempted += 1;
        }

        if self.prefer_successful_bootstrap && !self.bootstrap_peer_scores.is_empty() {
            let mut ranked: Vec<(PeerId, i32)> = self.bootstrap_peer_scores
                .iter()
                .map(|(pid, score)| (*pid, *score))
                .collect();
            ranked.sort_by(|a, b| b.1.cmp(&a.1));
            let top: Vec<String> = ranked
                .into_iter()
                .take(7)
                .map(|(pid, score)| format!("{}:{}", pid, score))
                .collect();
            if !top.is_empty() {
                println!("[p2p] Seed-Priorität (Top): {}", top.join(", "));
            }
        }

        if no_connections && attempted > 0 {
            // Bei null Verbindungen: auch Kademlia-Bootstrap anstoßen
            if self.config.kad_enabled {
                let _ = self.swarm.behaviour_mut().kad.bootstrap();
            }
            println!("[p2p] ⚠ Keine Verbindungen – {attempted} Bootstrap-Dial(s) gestartet");
        }

        self.last_reconnect = now;
    }

    // ── Swarm-Events ─────────────────────────────────────────────────────────

    async fn handle_swarm_event(&mut self, event: SwarmEvent<StoneBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
                // Gebannte Peers sofort trennen
                if self.is_peer_banned(&peer_id) {
                    eprintln!("[p2p] 🔨 Verbindung von gebantem Peer {peer_id} getrennt");
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                // Per-Peer-Connection-Cap: überzählige Verbindungen sofort schließen.
                // Schützt gegen Connection-Storms durch flappende/inkompatible Peers
                // (z. B. veraltete PeerId/Genesis), die sonst hunderte Parallel-
                // verbindungen aufbauen und FDs/Netz erschöpfen würden.
                if num_established.get() > MAX_CONNECTIONS_PER_PEER {
                    eprintln!(
                        "[p2p] ⚠ {peer_id}: {} Verbindungen > Limit {MAX_CONNECTIONS_PER_PEER} – schließe überzählige",
                        num_established.get(),
                    );
                    self.swarm.close_connection(connection_id);
                    return;
                }

                let addr = endpoint.get_remote_address().to_string();
                let now = chrono::Utc::now().timestamp();
                // Nur loggen wenn es die erste Verbindung zu diesem Peer ist
                if num_established.get() == 1 {
                    println!("[p2p] ✓ Verbunden: {peer_id} @ {addr}");
                }

                let entry = self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
                    peer_id: peer_id.to_string(),
                    addresses: vec![addr.clone()],
                    agent_version: String::new(),
                    connected: false,
                    last_seen: now,
                    blocks_received: 0,
                    stake_level: 0,
                });
                entry.connected = true;
                entry.last_seen = now;
                if !entry.addresses.contains(&addr) {
                    entry.addresses.push(addr.clone());
                }

                // Events + Sync nur bei erster Verbindung
                if num_established.get() == 1 {
                    self.peer_connected_since.insert(peer_id, Instant::now());
                    self.update_bootstrap_score(peer_id, 3, "connection established");
                    let _ = self.event_tx.send(NetworkEvent::PeerConnected {
                        peer_id: peer_id.to_string(),
                        addr,
                    });

                    // Chain-Sync anstoßen:
                    // 1) Direkte ChainInfo-Anfrage per Request/Response (sofort zuverlässig)
                    if self.config.auto_sync_on_connect {
                        let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                            &peer_id,
                            BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
                        );
                        self.pending_chain_info.insert(req_id, peer_id);
                        println!("[p2p] 🔄 ChainInfo-Anfrage an {peer_id} gesendet (Initial-Sync)");
                    }
                    // 2) GossipSub-Handshake zusätzlich (für Peers die später joinen)
                    if self.config.auto_sync_on_connect {
                        self.send_sync_handshake();
                    }
                }

                // Security Fix: Connection-Limit durchsetzen (Eclipse/Sybil-Mitigation).
                // Ohne diesen Check kann ein Angreifer mit 10.000 Fake-Peers den
                // Connection-Pool erschöpfen und legitime Peers verdrängen.
                let connected_count = self.swarm.connected_peers().count();
                if connected_count > self.config.max_peers {
                    // Finde den verbundenen Peer mit dem niedrigsten Penalty-Score
                    if let Some((lowest_id, _)) = self.peers.iter()
                        .filter(|(_, info)| info.connected)
                        .min_by_key(|(pid, _)| {
                            self.peer_penalties.get(pid)
                                .map(|p| p.score)
                                .unwrap_or(0)
                        })
                    {
                        eprintln!(
                            "[p2p] ⚠ Connection-Limit ({}) erreicht ({} verbunden) — \
                             trenne {lowest_id} (niedrigster Score)",
                            self.config.max_peers, connected_count,
                        );
                        let _ = self.swarm.disconnect_peer_id(*lowest_id);
                    }
                }
            }

            SwarmEvent::ConnectionClosed { peer_id, num_established, cause, .. } => {
                let reason = cause.map(|e| e.to_string()).unwrap_or_default();
                // Nur loggen wenn es die letzte Verbindung zu diesem Peer war
                if num_established == 0 {
                    println!("[p2p] ✗ Getrennt: {peer_id} ({reason})");
                    self.update_bootstrap_score(peer_id, -1, "connection closed");

                    // Flap-Erkennung: hielt die Verbindung <STABLE_CONNECTION_SECS,
                    // setzen wir exponentiellen Reconnect-Backoff statt sofort erneut
                    // zu dialen. Verhindert Hot-Loop-Reconnects (Storm) bei Peers, die
                    // uns sofort wieder trennen (z. B. inkompatible PeerId/Genesis).
                    let was_stable = self.peer_connected_since.remove(&peer_id)
                        .map(|t| t.elapsed() >= Duration::from_secs(STABLE_CONNECTION_SECS))
                        .unwrap_or(true);
                    if !was_stable {
                        let prev = self.reconnect_backoff.get(&peer_id)
                            .map(|(_, d)| *d)
                            .unwrap_or(Duration::from_secs(5));
                        let next = (prev * 2).min(Duration::from_secs(300));
                        let jitter = self.jitter_for_peer(&peer_id);
                        self.reconnect_backoff.insert(peer_id, (Instant::now() + next + jitter, next));
                        eprintln!(
                            "[p2p] ⚠ {peer_id} flappt (Verbindung <{STABLE_CONNECTION_SECS}s) – Reconnect-Backoff {}s",
                            next.as_secs(),
                        );
                    }
                    if Some(peer_id) == self.sync_target_peer {
                        self.sync_target_peer = None;
                        self.sync_last_recovery_reason = "sync target disconnected".to_string();
                    }

                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.connected = false;
                    }
                    let _ = self.event_tx.send(NetworkEvent::PeerDisconnected {
                        peer_id: peer_id.to_string(),
                    });
                }
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer = *self.swarm.local_peer_id();
                let full_addr = format!("{address}/p2p/{local_peer}");
                println!("[p2p] 🎧 Lausche auf: {full_addr}");
                let _ = self.event_tx.send(NetworkEvent::Listening { addr: full_addr.clone() });

                // Relay-Circuit-Adressen als externe Adresse bekanntgeben,
                // damit Identify sie an andere Peers verbreitet.
                let is_circuit = address.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit));
                if is_circuit {
                    let ext_addr = address.clone()
                        .with(libp2p::multiaddr::Protocol::P2p(local_peer));
                    self.swarm.add_external_address(ext_addr.clone());
                    // Auch in Kademlia eintragen
                    self.swarm.behaviour_mut().kad.add_address(&local_peer, ext_addr.clone());
                    println!("[p2p] 🌍 Circuit-Listen als externe Adresse: {ext_addr}");
                }
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let local = *self.swarm.local_peer_id();
                // Selbst-Dial-Fehler (eigene VPN/Multi-Interface-Adressen) unterdrücken
                if peer_id == Some(local) {
                    return;
                }
                let err_str = error.to_string();
                let is_harmless = err_str.contains("Already connected")
                    || err_str.contains("Pending connection")
                    || err_str.contains("WrongPeerId")
                    || err_str.contains("os error 48")   // EADDRINUSE (macOS)
                    || err_str.contains("os error 22")   // EINVAL
                    || err_str.contains("Address already in use")
                    || err_str.contains("Invalid argument");

                // Wenn der Peer jetzt bereits verbunden ist, war der Fehler eine Race-Condition
                let peer_now_connected = peer_id
                    .map(|id| self.swarm.is_connected(&id))
                    .unwrap_or(false);

                if is_harmless || peer_now_connected {
                    return;
                }
                if let Some(pid) = peer_id {
                    self.update_bootstrap_score(pid, -2, "outgoing connection error");
                }
                eprintln!("[p2p] Verbindungsfehler zu {:?}: {error}", peer_id);
            }

            SwarmEvent::Behaviour(bev) => self.handle_behaviour_event(bev),

            SwarmEvent::ExternalAddrConfirmed { address } => {
                println!("[p2p] 🌍 Externe Adresse bestätigt: {address}");
                // Adresse in Kademlia eintragen damit andere Nodes uns finden
                let local_peer = *self.swarm.local_peer_id();
                self.swarm.behaviour_mut().kad.add_address(
                    &local_peer,
                    address,
                );
            }

            _ => {}
        }
    }

    /// Durchschnittliche Latenz eines Peers (aus Rolling-Window), oder None.
    pub(super) fn avg_latency_ms(&self, peer_id: &PeerId) -> Option<u64> {
        let window = self.peer_latencies.get(peer_id)?;
        if window.is_empty() {
            return None;
        }
        let sum: u64 = window.iter().sum();
        Some(sum / window.len() as u64)
    }
}
