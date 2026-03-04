//! Stone P2P-Netzwerkschicht
//!
//! ## Architektur
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────┐
//!  │  StoneSwarm                                            │
//!  │                                                        │
//!  │  Transport: TCP + Noise (Ed25519) + Yamux              │
//!  │           + QUIC (UDP, native TLS 1.3)                 │
//!  │           + Relay (für NAT-Traversal)                  │
//!  │                                                        │
//!  │  Protokolle:                                           │
//!  │  ├── Identify   – Peer-Metadaten austauschen           │
//!  │  ├── Kademlia   – Bootstrap + Peer-Discovery           │
//!  │  ├── mDNS       – Lokale/private Netz-Discovery        │
//!  │  ├── Gossipsub  – Block-Broadcast (pub/sub)            │
//!  │  ├── RequestResponse – Block-/Chunk-Austausch          │
//!  │  ├── Relay (Client) – NAT-Traversal via Relay-Server   │
//!  │  ├── DCUtR      – Direct Connection Upgrade (Hole-     │
//!  │  │                Punching nach Relay-Verbindung)       │
//!  │  ├── AutoNAT    – Automatische NAT-Erkennung           │
//!  │  └── UPnP       – Automatisches Port-Forwarding        │
//!  │                                                        │
//!  │  Identität: Ed25519-Keypair (stone_data/p2p.key)       │
//!  └────────────────────────────────────────────────────────┘
//! ```
//!
//! ## NAT-Traversal Strategie
//!
//! Nodes hinter NAT/Firewall können sich **ohne Port-Freigabe** verbinden:
//!
//! 1. **UPnP** – Versucht automatisch den Router zu konfigurieren (funktioniert
//!    bei ca. 50% der Home-Router)
//! 2. **AutoNAT** – Erkennt automatisch ob wir hinter NAT sind
//! 3. **Relay** – Wenn hinter NAT: Verbindung über einen öffentlichen Relay-Node
//!    als Zwischenstation (langsamer, aber funktioniert immer)
//! 4. **DCUtR** (Hole-Punching) – Nach der Relay-Verbindung wird automatisch
//!    ein direkter UDP/TCP-Tunnel versucht (schneller als Relay)
//!
//! ## Sicherheitsmodell
//!
//! - Jeder Node besitzt ein Ed25519-Keypair (`stone_data/p2p.key`)
//! - Noise-Protokoll authentifiziert + verschlüsselt **jeden** TCP-Stream
//! - `PeerId` = SHA-256 des Public Keys → kryptographische Peer-Identität
//! - Bootstrap-Nodes sind fest konfiguriert (ENV oder Config-Datei)
//! - Kein unbekannter Peer kann sich ohne gültigen Noise-Handshake verbinden
//!
//! ## Topics (Gossipsub)
//!
//! | Topic              | Inhalt                               |
//! |--------------------|--------------------------------------|
//! | `stone/blocks/v1`  | Neue Blöcke (JSON-serialisiert)      |
//! | `stone/peers/v1`   | Peer-Ankündigungen                   |
//! | `stone/mempool/v1` | Token-TXs (Mempool-Broadcast)        |

use crate::blockchain::Block;
use futures_util::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    autonat,
    dcutr,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    noise,
    quic,
    relay,
    request_response::{self, ProtocolSupport},
    swarm::SwarmEvent,
    tcp,
    upnp,
    yamux,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};

// ─── Duplikat-Filter Kapazität ────────────────────────────────────────────────
/// Wie viele Block-Hashes im Seen-Cache behalten werden (LRU-Approximation via VecDeque)
const SEEN_CACHE_SIZE: usize = 2048;

// ─── Konstanten ───────────────────────────────────────────────────────────────

const DEFAULT_DATA_DIR: &str = "stone_data";
const P2P_KEY_FILENAME: &str = "p2p.key";
const P2P_CONFIG_FILENAME: &str = "p2p_config.json";

pub const TOPIC_BLOCKS: &str = "stone/blocks/v1";
pub const TOPIC_PEERS: &str = "stone/peers/v1";
pub const TOPIC_MEMPOOL: &str = "stone/mempool/v1";
pub const TOPIC_STORAGE: &str = "stone/storage/v1";

/// Protokoll-Version für den Sync-Handshake.
/// Peers mit einer anderen Major-Version werden abgelehnt.
pub const STONE_PROTOCOL_VERSION: &str = "stone/0.7";

/// Dateiname für die persistierte Ban-Liste
const BANNED_PEERS_FILENAME: &str = "banned_peers.json";

/// Standard-libp2p-Port des Stone-Netzwerks
pub const DEFAULT_P2P_PORT: u16 = 7654;

// ─── Built-in Seed-Nodes ──────────────────────────────────────────────────────
//
// Mindestens ein Seed-Node ist nötig damit neue Nodes das Netzwerk finden können.
// Die Seed-Nodes werden als Bootstrap UND als Relay genutzt.
// Weitere Nodes können per ENV (STONE_BOOTSTRAP_NODES) hinzugefügt werden.
//
// Format: "/ip4/<IP>/tcp/<PORT>/p2p/<PeerId>"
//
// HINWEIS: Diese Liste kann per `STONE_NO_SEED=1` deaktiviert werden.
//          Das ist nützlich für komplett private / isolierte Netzwerke.

/// Eingebaute Seed-Nodes – der erste Einstiegspunkt ins Stone-Netzwerk.
/// Jeder dieser Nodes ist gleichzeitig Relay-Server und Bootstrap-Node.
/// TCP und QUIC (UDP) Adressen – QUIC wird für NAT-Traversal bevorzugt.
const SEED_NODES: &[&str] = &[
    // ── VPS (212.227.54.241) – öffentlich erreichbar ─────────────────────────
    "/ip4/212.227.54.241/tcp/4001/p2p/12D3KooWAq975k49YZiCdaf3V96iJtU9fxqmoGRZW3e3Ceupv17k",
    "/ip4/212.227.54.241/udp/4001/quic-v1/p2p/12D3KooWAq975k49YZiCdaf3V96iJtU9fxqmoGRZW3e3Ceupv17k",
    // ── Server-Node (unrootles) – Öffentliche IPv6 ───────────────────────────
    "/ip6/2a0d:3341:b16b:4808:5054:ff:fea7:bab0/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
    "/ip6/2a0d:3341:b16b:4808:5054:ff:fea7:bab0/udp/4001/quic-v1/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
    // ── Server-Node (unrootles) – Tailscale (Fallback) ───────────────────────
    "/ip4/100.90.28.68/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
    "/ip4/100.90.28.68/udp/4001/quic-v1/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
];

/// Gibt das aktive Daten-Verzeichnis zurück.
/// Kann per `STONE_DATA_DIR` überschrieben werden.
fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string())
}

fn p2p_key_file() -> String {
    format!("{}/{}", data_dir(), P2P_KEY_FILENAME)
}

fn p2p_config_file() -> String {
    format!("{}/{}", data_dir(), P2P_CONFIG_FILENAME)
}

// ─── P2P-Konfiguration ────────────────────────────────────────────────────────

/// Persistente Konfiguration für das P2P-Netzwerk.
/// Wird in `stone_data/p2p_config.json` gespeichert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Feste Bootstrap-Nodes: `["/ip4/1.2.3.4/tcp/7654/p2p/<PeerId>", ...]`
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,

    /// Lokaler Listen-Adresse (Standard: `/ip4/0.0.0.0/tcp/7654`)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// mDNS aktivieren (für private / lokale Netzwerke)
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// Kademlia DHT aktivieren (für öffentliche Bootstrap-Nodes)
    #[serde(default = "default_true")]
    pub kad_enabled: bool,

    /// Maximale Peer-Anzahl
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,

    /// Verbindungs-Timeout in Sekunden
    #[serde(default = "default_timeout")]
    pub connection_timeout_secs: u64,

    /// Reconnect-Intervall für Bootstrap-Nodes in Sekunden (0 = kein Reconnect)
    #[serde(default = "default_reconnect")]
    pub reconnect_interval_secs: u64,

    /// Chain-Sync bei Connect: fehlende Blöcke automatisch nachladen
    #[serde(default = "default_true")]
    pub auto_sync_on_connect: bool,

    // ─── NAT-Traversal ──────────────────────────────────────────────────────

    /// Relay-Nodes für NAT-Traversal (Multiaddr mit PeerId).
    /// Nodes hinter NAT reservieren einen Platz auf diesen Relays,
    /// damit andere Nodes sie über den Relay erreichen können.
    /// Format: `["/ip4/1.2.3.4/tcp/7654/p2p/<PeerId>", ...]`
    #[serde(default)]
    pub relay_nodes: Vec<String>,

    /// AutoNAT aktivieren – erkennt automatisch ob wir hinter NAT sind
    #[serde(default = "default_true")]
    pub autonat_enabled: bool,

    /// UPnP aktivieren – versucht automatisches Port-Forwarding am Router
    #[serde(default = "default_true")]
    pub upnp_enabled: bool,

    /// DCUtR (Hole-Punching) aktivieren – direkter Tunnel nach Relay-Verbindung
    #[serde(default = "default_true")]
    pub dcutr_enabled: bool,

    /// Dieser Node fungiert als Relay-Server für andere Nodes.
    /// Standardmäßig aktiviert – jeder Node hilft dem Netzwerk indem er
    /// als Relay für Nodes hinter NAT fungiert.
    #[serde(default = "default_true")]
    pub relay_server_enabled: bool,
}

fn default_listen_addr() -> String {
    format!("/ip4/0.0.0.0/tcp/{DEFAULT_P2P_PORT}")
}
fn default_true() -> bool { true }
fn default_max_peers() -> usize { 50 }
fn default_timeout() -> u64 { 30 }
fn default_reconnect() -> u64 { 60 }

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            listen_addr: default_listen_addr(),
            mdns_enabled: true,
            kad_enabled: true,
            max_peers: 50,
            connection_timeout_secs: 30,
            reconnect_interval_secs: 60,
            auto_sync_on_connect: true,
            relay_nodes: Vec::new(),
            autonat_enabled: true,
            upnp_enabled: true,
            dcutr_enabled: true,
            relay_server_enabled: true,
        }
    }
}

impl P2pConfig {
    pub fn load_or_default() -> Self {
        if let Ok(data) = fs::read_to_string(p2p_config_file()) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            let cfg = Self::default();
            cfg.save();
            cfg
        }
    }

    pub fn save(&self) {
        let dir = data_dir();
        let _ = fs::create_dir_all(&dir);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(p2p_config_file(), json);
        }
    }

    /// Bootstrap-Nodes aus ENV `STONE_BOOTSTRAP_NODES` (kommagetrennt) laden
    /// und eingebaute Seed-Nodes hinzufügen.
    pub fn merge_env(&mut self) {
        // ── Seed-Nodes automatisch hinzufügen ─────────────────────────────────
        // Kann per STONE_NO_SEED=1 deaktiviert werden (für isolierte Netze)
        if std::env::var("STONE_NO_SEED").as_deref() != Ok("1") {
            for seed in SEED_NODES {
                let seed_str = seed.to_string();
                // Als Bootstrap-Node
                if !self.bootstrap_nodes.contains(&seed_str) {
                    self.bootstrap_nodes.push(seed_str.clone());
                }
                // Auch als Relay-Node (für NAT-Traversal)
                if !self.relay_nodes.contains(&seed_str) {
                    self.relay_nodes.push(seed_str);
                }
            }
        }

        if let Ok(raw) = std::env::var("STONE_BOOTSTRAP_NODES") {
            for addr in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if !self.bootstrap_nodes.contains(&addr.to_string()) {
                    self.bootstrap_nodes.push(addr.to_string());
                }
            }
        }
        // STONE_P2P_LISTEN: volle Multiaddr, z.B. /ip4/0.0.0.0/tcp/7655
        if let Ok(addr) = std::env::var("STONE_P2P_LISTEN") {
            self.listen_addr = addr;
        }
        // STONE_P2P_PORT: nur Portnummer – überschreibt Port in listen_addr
        if let Ok(port_str) = std::env::var("STONE_P2P_PORT") {
            if let Ok(port) = port_str.parse::<u16>() {
                // Schema (ip4/ip6) der bestehenden listen_addr beibehalten
                if self.listen_addr.starts_with("/ip6/") {
                    self.listen_addr = format!("/ip6/::/tcp/{port}");
                } else {
                    self.listen_addr = format!("/ip4/0.0.0.0/tcp/{port}");
                }
            }
        }
        // STONE_RELAY_NODES: kommagetrennte Relay-Node-Adressen
        if let Ok(raw) = std::env::var("STONE_RELAY_NODES") {
            for addr in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if !self.relay_nodes.contains(&addr.to_string()) {
                    self.relay_nodes.push(addr.to_string());
                }
            }
        }
        // STONE_RELAY_SERVER=1 → diesen Node als Relay-Server aktivieren
        if std::env::var("STONE_RELAY_SERVER").as_deref() == Ok("1") {
            self.relay_server_enabled = true;
        }
    }
}

// ─── Nachrichten zwischen Swarm-Task und AppState ─────────────────────────────

/// Events die der Swarm-Task an den Rest der Anwendung sendet.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Neuer Peer verbunden
    PeerConnected { peer_id: String, addr: String },
    /// Peer getrennt
    PeerDisconnected { peer_id: String },
    /// Neuer Block per Gossipsub empfangen (bereits dedupliziert)
    BlockReceived { block: Box<Block>, from_peer: String },
    /// Peer hat sich identifiziert
    PeerIdentified { peer_id: String, agent: String, addresses: Vec<String> },
    /// Chain-Sync gestartet: Peer hat mehr Blöcke als wir
    SyncStarted { peer_id: String, local_count: u64, remote_count: u64 },
    /// Chain-Sync abgeschlossen
    SyncCompleted { peer_id: String, blocks_added: u64 },
    /// Listener gestartet
    Listening { addr: String },
    /// Fehler
    Error { message: String },

    // ── Shard-Events ──────────────────────────────────────────────────────
    /// Ein angeforderter Shard wurde empfangen
    ShardReceived {
        chunk_hash: String,
        shard_index: u8,
        data: Vec<u8>,
        from_peer: String,
    },
    /// Ein Shard wurde erfolgreich auf einem Peer gespeichert
    ShardStored {
        chunk_hash: String,
        shard_index: u8,
        peer_id: String,
        success: bool,
        error: Option<String>,
    },
    /// Shard-Store-Anfrage fehlgeschlagen (Netzwerk)
    ShardRequestFailed {
        chunk_hash: String,
        shard_index: u8,
        peer_id: String,
        error: String,
    },

    // ── Token-Mempool-Events ──────────────────────────────────────────────
    /// Eine Token-TX wurde per Gossipsub von einem Peer empfangen
    TxReceived {
        tx: Box<crate::token::TokenTx>,
        from_peer: String,
    },

    // ── Update-Events ─────────────────────────────────────────────────────
    /// Ein Update-Manifest wurde per Gossipsub empfangen
    UpdateManifestReceived {
        manifest_json: Vec<u8>,
        from_peer: String,
    },

    // ── Storage-Events ────────────────────────────────────────────────────
    /// Ein Peer hat seinen Speicher-Status per Gossipsub gemeldet
    StorageAnnouncementReceived {
        announcement: StorageAnnouncement,
        from_peer: String,
    },
}

/// Befehle die von außen an den Swarm-Task gesendet werden.
pub enum NetworkCommand {
    /// Block an alle Peers broadcasten
    BroadcastBlock(Box<Block>),
    /// Token-TX an alle Peers broadcasten
    BroadcastTx(Box<crate::token::TokenTx>),
    /// Manuell einen Peer hinzufügen
    DialPeer(Multiaddr),
    /// Chain-Sync mit einem bestimmten Peer anstoßen
    SyncWithPeer { peer_id: PeerId, our_block_count: u64 },
    /// Aktuelle Peer-Liste abfragen
    GetPeers(tokio::sync::oneshot::Sender<Vec<PeerInfo>>),
    /// Anzahl der bekannten Blöcke mitteilen (für Sync-Handshake)
    SetLocalChainCount(u64),
    /// Einen Peer anpingen – Latenz messen via Request/Response
    Ping {
        peer_id: PeerId,
        reply: tokio::sync::oneshot::Sender<PingResult>,
    },
    /// Vollständigen Netzwerkstatus abfragen
    GetStatus(tokio::sync::oneshot::Sender<NetworkStatus>),
    /// Swarm beenden
    Shutdown,

    // ── Shard-Befehle ─────────────────────────────────────────────────────
    /// Shard von einem Peer anfordern
    RequestShard {
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
    },
    /// Shard an einen Peer zum Speichern senden
    StoreShard {
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    },
    /// Shard-Liste eines Peers für einen bestimmten Chunk abfragen
    ListPeerShards {
        peer_id: PeerId,
        chunk_hash: String,
        reply: tokio::sync::oneshot::Sender<Vec<u8>>,
    },

    /// Generische Gossipsub-Nachricht publizieren (z.B. Update-Manifest)
    PublishGossip {
        topic: gossipsub::TopicHash,
        data: Vec<u8>,
    },

    /// Chain-Referenz injizieren (nach Node-Start, damit der SwarmTask
    /// Block-Requests direkt aus der lokalen Chain beantworten kann).
    SetChainRef(std::sync::Arc<std::sync::Mutex<crate::blockchain::StoneChain>>),
}

impl std::fmt::Debug for NetworkCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BroadcastBlock(_) => write!(f, "BroadcastBlock(..)"),
            Self::BroadcastTx(_) => write!(f, "BroadcastTx(..)"),
            Self::DialPeer(addr) => write!(f, "DialPeer({addr})"),
            Self::SyncWithPeer { peer_id, our_block_count } => write!(f, "SyncWithPeer({peer_id}, {our_block_count})"),
            Self::GetPeers(_) => write!(f, "GetPeers(..)"),
            Self::SetLocalChainCount(c) => write!(f, "SetLocalChainCount({c})"),
            Self::Ping { peer_id, .. } => write!(f, "Ping({peer_id})"),
            Self::GetStatus(_) => write!(f, "GetStatus(..)"),
            Self::Shutdown => write!(f, "Shutdown"),
            Self::RequestShard { peer_id, chunk_hash, shard_index } => write!(f, "RequestShard({peer_id}, {chunk_hash}, {shard_index})"),
            Self::StoreShard { peer_id, chunk_hash, shard_index, .. } => write!(f, "StoreShard({peer_id}, {chunk_hash}, {shard_index})"),
            Self::ListPeerShards { peer_id, chunk_hash, .. } => write!(f, "ListPeerShards({peer_id}, {chunk_hash})"),
            Self::PublishGossip { topic, .. } => write!(f, "PublishGossip({topic})"),
            Self::SetChainRef(_) => write!(f, "SetChainRef(..)"),
        }
    }
}

/// Ergebnis eines Pings an einen Peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub peer_id: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Vollständiger Verbindungsstatus aller bekannten Peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub local_peer_id: String,
    pub connected_peers: usize,
    pub total_known_peers: usize,
    pub gossipsub_mesh_size: usize,
    pub chain_block_count: u64,
    pub peers: Vec<PeerStatus>,
    /// Netzwerk-Metriken (Traffic, Nachrichten, etc.)
    pub metrics: NetworkMetrics,
    /// Speicher-Ankündigungen aller bekannten Peers
    pub peer_storage: Vec<StorageAnnouncement>,
}

/// Netzwerk-Nutzungsmetriken (kumulativ seit Start)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Empfangene Bytes (Gossipsub + Request/Response)
    pub bytes_in: u64,
    /// Gesendete Bytes (Gossipsub + Request/Response)
    pub bytes_out: u64,
    /// Empfangene Nachrichten (alle Typen)
    pub messages_in: u64,
    /// Gesendete Nachrichten (alle Typen)
    pub messages_out: u64,
    /// Empfangene Blöcke per Gossipsub
    pub blocks_received: u64,
    /// Gesendete Blöcke per Gossipsub
    pub blocks_sent: u64,
    /// Empfangene TXs per Gossipsub
    pub txs_received: u64,
    /// Gesendete TXs per Gossipsub
    pub txs_sent: u64,
    /// Shard-Daten empfangen (Bytes)
    pub shard_bytes_in: u64,
    /// Shard-Daten gesendet (Bytes)
    pub shard_bytes_out: u64,
    /// Node-Uptime in Sekunden (seit Swarm-Start)
    pub uptime_secs: u64,
    /// Durchschnitt: Bytes/Sek empfangen
    pub avg_bytes_in_per_sec: f64,
    /// Durchschnitt: Bytes/Sek gesendet
    pub avg_bytes_out_per_sec: f64,
}

/// Speicher-Ankündigung: wird regelmäßig per Gossipsub gebroadcastet.
/// Jeder Node meldet wie viel Speicher er bereitstellt / nutzt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAnnouncement {
    /// PeerId des Absenders
    pub peer_id: String,
    /// Angebotener Speicher in GB (Konfiguration)
    pub offered_gb: u64,
    /// Belegter Speicher in Bytes
    pub used_bytes: u64,
    /// Freier Speicher in Bytes
    pub free_bytes: u64,
    /// Unix-Timestamp
    pub timestamp: i64,
    /// Node-Name (optional)
    pub node_name: String,
}

/// Detaillierter Status eines einzelnen Peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub agent_version: String,
    pub connected: bool,
    pub last_seen: i64,
    pub last_seen_ago_secs: i64,
    pub blocks_received: u64,
    pub in_gossipsub_mesh: bool,
}

/// Vereinfachte Peer-Info für die API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub agent_version: String,
    pub connected: bool,
    /// Zeitpunkt der letzten Verbindung (Unix-Sekunden)
    pub last_seen: i64,
    /// Anzahl empfangener Blöcke von diesem Peer
    pub blocks_received: u64,
}

// ─── Request/Response Typen ───────────────────────────────────────────────────

/// Anfrage an einen Peer – erweitert um Range-Queries und Chain-Info.
///
/// Konvention für Abwärtskompatibilität:
///   - `block_index == u64::MAX`          → Ping (keine Block-Daten)
///   - `block_index == u64::MAX - 1`      → GetChainInfo
///   - `block_index_end.is_some()`        → GetBlockRange(from..=to), max 50
///   - sonst                              → GetBlock(block_index)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub block_index: u64,
    /// Ende des Bereichs (inklusive). Wenn gesetzt → Range-Request.
    #[serde(default)]
    pub block_index_end: Option<u64>,
}

/// Antwort: einzelner Block, Block-Range, oder Chain-Info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub block: Option<Block>,
    /// Mehrere Blöcke (für Range-Requests)
    #[serde(default)]
    pub blocks: Vec<Block>,
    /// Chain-Info (für GetChainInfo)
    #[serde(default)]
    pub chain_height: Option<u64>,
    #[serde(default)]
    pub genesis_hash: Option<String>,
    #[serde(default)]
    pub latest_hash: Option<String>,
}

/// Sentinel-Wert: Ping-Request
pub const BLOCK_REQUEST_PING: u64 = u64::MAX;
/// Sentinel-Wert: ChainInfo-Request
pub const BLOCK_REQUEST_CHAIN_INFO: u64 = u64::MAX - 1;
/// Maximale Blöcke pro Range-Request
pub const MAX_BLOCKS_PER_RANGE: u64 = 50;

// ─── P2P Rate Limiter ─────────────────────────────────────────────────────────

/// Token-Bucket Rate Limiter pro Peer.
/// Jeder Peer hat separate Budgets für Gossip-Blocks, TXs und Requests.
#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    /// Gossip-Blocks pro Minute (Token-Bucket)
    pub gossip_blocks: TokenBucket,
    /// Gossip-TXs pro Minute
    pub gossip_txs: TokenBucket,
    /// Request/Response-Anfragen pro Minute
    pub requests: TokenBucket,
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub tokens: f64,
    pub max_tokens: f64,
    pub refill_rate: f64, // tokens pro Sekunde
    pub last_refill: Instant,
}

impl TokenBucket {
    pub fn new(max_tokens: f64, per_minute: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: per_minute / 60.0,
            last_refill: Instant::now(),
        }
    }

    /// Versucht ein Token zu konsumieren. Gibt `true` zurück wenn erlaubt.
    pub fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl PeerRateLimiter {
    pub fn new() -> Self {
        Self {
            // Max 10 Blocks/min (normal ~2/min bei 30s Block-Time, Burst bei Sync)
            gossip_blocks: TokenBucket::new(10.0, 10.0),
            // Max 120 TXs/min
            gossip_txs: TokenBucket::new(30.0, 120.0),
            // Max 300 Requests/min (Sync kann viele Requests erzeugen)
            requests: TokenBucket::new(60.0, 300.0),
        }
    }
}

// ─── Shard Exchange Typen ─────────────────────────────────────────────────────

/// Anfrage an einen Peer: Shard-Operationen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardRequest {
    /// Frage: Hast du diesen Shard? Gib mir die Daten.
    GetShard {
        chunk_hash: String,
        shard_index: u8,
    },
    /// Speichere diesen Shard für mich (bei Upload-Verteilung).
    StoreShard {
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    },
    /// Welche Shards hast du für diesen Chunk?
    ListShards {
        chunk_hash: String,
    },
}

/// Antwort auf eine Shard-Anfrage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardResponse {
    /// Shard-Daten (None wenn nicht vorhanden)
    ShardData {
        chunk_hash: String,
        shard_index: u8,
        data: Option<Vec<u8>>,
    },
    /// Bestätigung: Shard wurde gespeichert (oder Fehler)
    StoreResult {
        chunk_hash: String,
        shard_index: u8,
        success: bool,
        error: Option<String>,
    },
    /// Liste lokaler Shard-Indices für einen Chunk
    ShardList {
        chunk_hash: String,
        indices: Vec<u8>,
    },
}

// ─── Keypair-Persistenz ───────────────────────────────────────────────────────

/// Lädt das Ed25519-Keypair für die P2P-Identität oder erstellt ein neues.
///
/// Das Keypair wird unter `stone_data/p2p.key` gespeichert (protobuf-kodiert).
/// Der zugehörige `PeerId` ist der SHA-256 des Public Keys.
pub fn load_or_create_keypair() -> libp2p::identity::Keypair {
    let key_file = p2p_key_file();
    let dir = data_dir();
    fs::create_dir_all(&dir).unwrap_or(());

    if let Ok(bytes) = fs::read(&key_file) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }

    // Neues Keypair generieren
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let encoded = kp.to_protobuf_encoding().expect("Keypair-Kodierung fehlgeschlagen");

    if let Err(e) = fs::write(&key_file, &encoded) {
        eprintln!("[p2p] WARNUNG: Keypair konnte nicht gespeichert werden: {e}");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = fs::metadata(&key_file).map(|m| m.permissions()) {
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&key_file, perms);
            }
        }
        let peer_id = libp2p::PeerId::from_public_key(&kp.public());
        println!("[p2p] Neues P2P-Keypair generiert. PeerId: {peer_id}");
        println!("[p2p] Gespeichert: {key_file}");
    }

    kp
}

/// Liest die PeerId ohne den vollen Keypair zu laden (für Logging).
pub fn read_peer_id() -> Option<String> {
    let bytes = fs::read(p2p_key_file()).ok()?;
    let kp = libp2p::identity::Keypair::from_protobuf_encoding(&bytes).ok()?;
    Some(libp2p::PeerId::from_public_key(&kp.public()).to_string())
}

// ─── Swarm Behaviour ──────────────────────────────────────────────────────────

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct StoneBehaviour {
    pub identify: identify::Behaviour,
    pub kad: kad::Behaviour<MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub block_exchange: request_response::cbor::Behaviour<BlockRequest, BlockResponse>,
    pub shard_exchange: request_response::cbor::Behaviour<ShardRequest, ShardResponse>,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: relay::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
    pub upnp: upnp::tokio::Behaviour,
}

// ─── Swarm aufbauen ───────────────────────────────────────────────────────────

/// Erstellt den libp2p-Swarm mit allen Protokollen + NAT-Traversal.
///
/// Transport-Schichtung:
///   TCP → Noise → Yamux  (direkte Verbindungen)
///   +  Relay-Transport   (für Nodes hinter NAT)
///
/// Die Relay-Client-Behaviour wird automatisch mit dem Transport verknüpft.
/// DCUtR versucht nach einer Relay-Verbindung einen direkten Tunnel (Hole-Punch).
pub fn build_swarm(
    keypair: libp2p::identity::Keypair,
    config: &P2pConfig,
) -> Result<Swarm<StoneBehaviour>, Box<dyn std::error::Error>> {
    let peer_id = PeerId::from_public_key(&keypair.public());

    // ── Gossipsub ─────────────────────────────────────────────────────────────
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(4 * 1024 * 1024) // 4 MiB pro Block
        .build()
        .map_err(|e| format!("Gossipsub-Config: {e}"))?;

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| format!("Gossipsub init: {e}"))?;

    // ── Kademlia ──────────────────────────────────────────────────────────────
    let mut kad_config = kad::Config::new(
        libp2p::StreamProtocol::new("/stone/kad/1.0.0"),
    );
    kad_config.set_query_timeout(Duration::from_secs(config.connection_timeout_secs));
    let kad = kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

    // ── Identify ──────────────────────────────────────────────────────────────
    let mut identify_config = identify::Config::new(
        "/stone/id/1.0.0".to_string(),
        keypair.public(),
    );
    identify_config.agent_version = format!("stone/{}", env!("CARGO_PKG_VERSION"));
    let identify = identify::Behaviour::new(identify_config);

    // ── mDNS ──────────────────────────────────────────────────────────────────
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

    // ── Request/Response (Block-Austausch) ────────────────────────────────────
    let block_exchange = request_response::cbor::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/stone/block-exchange/1.0.0"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    // ── Request/Response (Shard-Austausch) ────────────────────────────────────
    let shard_exchange = request_response::cbor::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/stone/shard-exchange/1.0.0"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    // ── AutoNAT – erkennt ob wir hinter NAT sind ─────────────────────────────
    let autonat = autonat::Behaviour::new(peer_id, autonat::Config {
        boot_delay: Duration::from_secs(10),
        refresh_interval: Duration::from_secs(60),
        retry_interval: Duration::from_secs(30),
        throttle_server_period: Duration::from_secs(15),
        ..Default::default()
    });

    // ── UPnP – automatisches Port-Forwarding ──────────────────────────────────
    let upnp = upnp::tokio::Behaviour::default();

    // ── Relay Server – jeder Node ist potentiell ein Relay ────────────────────
    // Öffentlich erreichbare Nodes leiten Traffic für Nodes hinter NAT weiter.
    // Rate-Limiting schützt vor Missbrauch.
    let relay_server = relay::Behaviour::new(
        peer_id,
        relay::Config {
            max_reservations: 128,
            max_reservations_per_peer: 4,
            reservation_duration: Duration::from_secs(3600),   // 1h
            max_circuits: 64,
            max_circuits_per_peer: 4,
            max_circuit_duration: Duration::from_secs(600),    // 10min pro Circuit
            max_circuit_bytes: 16 * 1024 * 1024,               // 16 MiB pro Circuit
            ..Default::default()
        },
    );

    // ── Swarm mit Relay-Client-Transport aufbauen ─────────────────────────────
    //
    // SwarmBuilder.with_relay_client() gibt uns:
    //  1. Den Relay-Client-Transport (für eingehende relayed Verbindungen)
    //  2. Die Relay-Client-Behaviour (wird im StoneBehaviour gehalten)
    //
    // DCUtR baut auf dem Relay auf: nach einer Relay-Verbindung wird
    // automatisch versucht eine direkte Verbindung herzustellen (Hole-Punching).

    // Voller NAT-Traversal Stack: TCP + QUIC + Noise + Yamux + Relay-Client + DCUtR
    //
    // QUIC (UDP-basiert) verbessert NAT-Traversal erheblich:
    //  - UDP Hole-Punching hat höhere Erfolgsrate als TCP
    //  - Eingebautes TLS 1.3 (kein separater Noise-Handshake nötig)
    //  - Schnellerer Verbindungsaufbau (0-RTT möglich)
    //  - Multiplexing nativ (kein Yamux-Layer nötig)
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());
            StoneBehaviour {
                identify: identify,
                kad: kad,
                mdns: mdns,
                gossipsub: gossipsub,
                block_exchange: block_exchange,
                shard_exchange: shard_exchange,
                relay_client,
                relay_server,
                dcutr,
                autonat,
                upnp,
            }
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(
                config.connection_timeout_secs * 2,
            ))
        })
        .build();

    Ok(swarm)
}

// ─── Swarm-Task ───────────────────────────────────────────────────────────────

/// Zustand des laufenden Swarm-Tasks.
struct SwarmTask {
    swarm: Swarm<StoneBehaviour>,
    event_tx: broadcast::Sender<NetworkEvent>,
    cmd_rx: mpsc::Receiver<NetworkCommand>,

    /// Bekannte Peers: PeerId → PeerInfo
    peers: HashMap<PeerId, PeerInfo>,

    /// Seen-Cache: Block-Hashes die bereits verarbeitet wurden (Duplicate-Filter).
    seen_hashes: HashSet<String>,
    seen_order: VecDeque<String>,

    /// Unsere aktuelle Chain-Länge (für Sync-Handshake)
    local_chain_count: u64,

    /// Bootstrap-Adressen für Reconnect
    bootstrap_addrs: Vec<String>,

    /// Zeitpunkt des letzten Reconnect-Versuchs
    last_reconnect: Instant,

    config: P2pConfig,

    /// Ausstehende Pings: request_id → (peer_id_str, start_instant, reply_channel)
    pending_pings: HashMap<
        request_response::OutboundRequestId,
        (String, std::time::Instant, tokio::sync::oneshot::Sender<PingResult>),
    >,

    // ─── NAT-Traversal Zustand ──────────────────────────────────────────────

    /// Erkannter NAT-Status
    nat_status: NatStatus,

    /// Relay-Nodes bei denen wir eine Reservation haben
    active_relays: HashSet<PeerId>,

    /// Relay-Adressen die wir versuchen sollen
    relay_addrs: Vec<String>,

    // ─── Sicherheit: Peer-Scoring ───────────────────────────────────────────

    /// Penalty-Score pro Peer: wenn > BAN_THRESHOLD → Peer wird gebannt
    peer_penalties: HashMap<PeerId, PeerPenalty>,

    // ─── P2P Rate Limiting ──────────────────────────────────────────────────

    /// Token-Bucket Rate Limiter pro Peer (DDoS-Protection)
    peer_rate_limiters: HashMap<PeerId, PeerRateLimiter>,

    // ─── Chain-Referenz für Block-Serving ────────────────────────────────────

    /// Optionale Referenz auf die Chain — wird nach Start per Command injiziert.
    /// Ermöglicht dem SwarmTask Blöcke direkt aus der lokalen Chain zu servieren.
    chain_ref: Option<std::sync::Arc<std::sync::Mutex<crate::blockchain::StoneChain>>>,

    /// Shard-Speicher für eingehende Shard-Requests
    shard_store: crate::shard::ShardStore,

    /// Ausstehende Shard-Listen-Anfragen: request_id → reply
    pending_shard_lists: HashMap<
        request_response::OutboundRequestId,
        (String, tokio::sync::oneshot::Sender<Vec<u8>>),
    >,

    // ─── Netzwerk-Metriken ──────────────────────────────────────────────────

    /// Kumulative Traffic-Metriken
    net_metrics: NetworkMetrics,
    /// Zeitpunkt des Swarm-Starts (für Uptime-Berechnung)
    started_at: Instant,

    // ─── Peer-Storage-Tracking ──────────────────────────────────────────────

    /// Speicher-Ankündigungen von Peers: PeerId-String → StorageAnnouncement
    peer_storage: HashMap<String, StorageAnnouncement>,

    /// Ausstehende ChainInfo-Anfragen: request_id → PeerId
    /// Wird verwendet um die Antwort dem richtigen Peer zuzuordnen und Sync auszulösen.
    pending_chain_info: HashMap<request_response::OutboundRequestId, PeerId>,

    /// Sync-Buffer: Sammelt Blöcke aus parallelen Range-Responses und fügt sie
    /// geordnet ein. Key = Block-Index für schnellen Lookup.
    sync_buffer: std::collections::BTreeMap<u64, (Block, String)>,
    /// Zeitpunkt als zuletzt Blöcke in den sync_buffer kamen (für Flush-Timeout)
    sync_buffer_last_insert: Option<Instant>,
    /// Erwarteter nächster Block-Index für den Sync (= unsere Chain-Höhe beim Sync-Start)
    sync_expected_next: u64,
}

/// Tracking für Fehlverhalten eines Peers
struct PeerPenalty {
    score: u32,
    last_offense: Instant,
    reasons: Vec<String>,
}

/// Ab diesem Score wird ein Peer gebannt (Verbindung getrennt, kein Re-Dial)
const BAN_THRESHOLD: u32 = 200;

/// Penalty-Punkte verfallen nach dieser Zeit (Minuten)
const PENALTY_DECAY_MINS: u64 = 30;

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
}

/// Lädt die Ban-Liste aus `stone_data/banned_peers.json`
fn load_banned_peers() -> HashMap<PeerId, PeerPenalty> {
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
            });
        }
    }
    if !map.is_empty() {
        println!("[p2p] 🔨 {} gebannte Peers aus Datei geladen", map.len());
    }
    map
}

/// Speichert die aktuelle Ban-Liste nach `stone_data/banned_peers.json`
fn save_banned_peers(penalties: &HashMap<PeerId, PeerPenalty>) {
    let now = chrono::Utc::now().timestamp();
    let ban_duration_secs = (PENALTY_DECAY_MINS * 60 * 2) as i64;
    let entries: Vec<BannedPeerEntry> = penalties
        .iter()
        .filter(|(_, p)| p.score >= BAN_THRESHOLD)
        .map(|(peer_id, p)| BannedPeerEntry {
            peer_id: peer_id.to_string(),
            score: p.score,
            reasons: p.reasons.clone(),
            banned_at: now,
            expires_at: now + ban_duration_secs,
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
enum NatStatus {
    Unknown,
    Public,
    Private,
}

/// Entfernt die `/p2p/<PeerId>`-Komponente am Ende einer Multiaddr.
/// mDNS liefert Adressen wie `/ip4/1.2.3.4/tcp/7654/p2p/12D3Koo…`.
/// libp2p lehnt es ab, wenn man diese an `DialOpts::peer_id(...).addresses(…)`
/// übergibt — die PeerId wäre dann doppelt vorhanden → EINVAL (os error 22).
fn strip_p2p_suffix(addr: libp2p::Multiaddr) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let without: libp2p::Multiaddr = addr
        .into_iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect();
    without
}

impl SwarmTask {
    async fn run(mut self) {
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

        // Dual-Stack: wenn IPv6 konfiguriert, zusätzlich auf IPv4 lauschen
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
            }
        }
        println!("[p2p] Swarm-Task beendet.");
    }

    // ── Duplicate-Filter ─────────────────────────────────────────────────────

    /// Gibt true zurück wenn der Hash bereits gesehen wurde (Duplikat).
    fn is_duplicate(&mut self, hash: &str) -> bool {
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
        // Nur Bootstrap-Nodes reconnecten die gerade nicht verbunden sind
        let disconnected_count = self.peers.values()
            .filter(|p| !p.connected)
            .count();

        if disconnected_count == 0 && !self.peers.is_empty() {
            return; // alle bereits verbunden
        }

        let connected_peer_ids: HashSet<String> = self.peers.values()
            .filter(|p| p.connected)
            .map(|p| p.peer_id.clone())
            .collect();

        for addr_str in self.bootstrap_addrs.clone() {
            use libp2p::multiaddr::Protocol;
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                let peer_id_str = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p {
                        Some(pid.to_string())
                    } else {
                        None
                    }
                });
                if let Some(pid) = peer_id_str {
                    // Eigene PeerId nicht anwählen
                    let local = self.swarm.local_peer_id().to_string();
                    if pid == local {
                        continue;
                    }
                    if !connected_peer_ids.contains(&pid) {
                        println!("[p2p] Reconnect-Versuch: {pid}");
                        let _ = self.swarm.dial(addr);
                    }
                }
            }
        }
        self.last_reconnect = Instant::now();
    }

    // ── Swarm-Events ─────────────────────────────────────────────────────────

    async fn handle_swarm_event(&mut self, event: SwarmEvent<StoneBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } => {
                // Gebannte Peers sofort trennen
                if self.is_peer_banned(&peer_id) {
                    eprintln!("[p2p] 🔨 Verbindung von gebantem Peer {peer_id} getrennt");
                    let _ = self.swarm.disconnect_peer_id(peer_id);
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
                });
                entry.connected = true;
                entry.last_seen = now;
                if !entry.addresses.contains(&addr) {
                    entry.addresses.push(addr.clone());
                }

                // Events + Sync nur bei erster Verbindung
                if num_established.get() == 1 {
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
            }

            SwarmEvent::ConnectionClosed { peer_id, num_established, cause, .. } => {
                let reason = cause.map(|e| e.to_string()).unwrap_or_default();
                // Nur loggen wenn es die letzte Verbindung zu diesem Peer war
                if num_established == 0 {
                    println!("[p2p] ✗ Getrennt: {peer_id} ({reason})");

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
                let _ = self.event_tx.send(NetworkEvent::Listening { addr: full_addr });
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let local = *self.swarm.local_peer_id();
                // Selbst-Dial-Fehler (eigene VPN/Multi-Interface-Adressen) unterdrücken
                if peer_id == Some(local) {
                    return;
                }
                // Harmlose Race-Conditions komplett stumm schalten:
                // - "Already connected" / "Pending" → bereits verbunden, kein Problem
                // - os error 48 (EADDRINUSE, macOS) → TCP-Quelladresse kurz belegt, Peer
                //   verbindet sich gleichzeitig von der anderen Seite → ignorieren
                // - os error 22 (EINVAL) → /p2p/-Suffix im Dial-Addr, bereits gefixt aber
                //   kann noch aus alten Kademlia-Einträgen kommen → ignorieren
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
                    // Nur als Debug ausgeben, kein Fehler
                    return;
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

    // ── Behaviour-Events ─────────────────────────────────────────────────────

    fn handle_behaviour_event(&mut self, event: StoneBehaviourEvent) {
        match event {
            // ── Identify ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                let addrs: Vec<String> = info.listen_addrs.iter().map(|a| a.to_string()).collect();
                println!("[p2p] Identify: {peer_id} – agent={}", info.agent_version);

                for addr in &info.listen_addrs {
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                }

                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.agent_version = info.agent_version.clone();
                    entry.addresses = addrs.clone();
                }

                let _ = self.event_tx.send(NetworkEvent::PeerIdentified {
                    peer_id: peer_id.to_string(),
                    agent: info.agent_version.clone(),
                    addresses: addrs,
                });

                // ── Auto-Relay: Wenn wir hinter NAT sind und ein neuer Stone-Peer
                //    sich verbindet, versuche ihn als Relay zu nutzen.
                //    Stone-Nodes sind standardmäßig Relay-Server.
                if self.nat_status == NatStatus::Private
                    && info.agent_version.contains("stone")
                    && !self.active_relays.contains(&peer_id)
                    && self.active_relays.len() < 3
                {
                    // Öffentliche Adresse des Peers als Relay-Basis nutzen
                    if let Some(relay_addr) = info.listen_addrs.iter().find(|a| {
                        a.iter().any(|p| {
                            matches!(p,
                                libp2p::multiaddr::Protocol::Ip4(ip) if !ip.is_private() && !ip.is_loopback()
                            ) || matches!(p,
                                libp2p::multiaddr::Protocol::Ip6(ip) if !ip.is_loopback()
                            )
                        })
                    }) {
                        let circuit_addr = relay_addr
                            .clone()
                            .with(libp2p::multiaddr::Protocol::P2p(peer_id))
                            .with(libp2p::multiaddr::Protocol::P2pCircuit);
                        if let Ok(_) = self.swarm.listen_on(circuit_addr.clone()) {
                            println!(
                                "[p2p] 🔍 Auto-Relay: Neuer Stone-Peer {peer_id} als Relay-Kandidat"
                            );
                        }
                    }
                }
            }

            // ── mDNS ──────────────────────────────────────────────────────────
            StoneBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                let local_peer = *self.swarm.local_peer_id();

                // Adressen je Peer sammeln (Original-Addrs inkl. /p2p-Suffix behalten)
                let mut by_peer: std::collections::HashMap<
                    libp2p::PeerId,
                    Vec<libp2p::Multiaddr>,
                > = std::collections::HashMap::new();

                for (peer_id, addr) in list {
                    if peer_id == local_peer {
                        continue; // Selbst-Dial verhindern
                    }
                    println!("[p2p] mDNS entdeckt: {peer_id} @ {addr}");
                    // Kademlia bekommt die Adresse OHNE /p2p-Suffix
                    let addr_bare = strip_p2p_suffix(addr.clone());
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr_bare);
                    // Dial-Liste behält die Original-Adresse (mit /p2p wenn vorhanden)
                    by_peer.entry(peer_id).or_default().push(addr);
                }

                for (peer_id, addrs) in by_peer {
                    // Bereits verbunden (laut Swarm-State) → kein erneuter Dial
                    if self.swarm.is_connected(&peer_id) {
                        continue;
                    }
                    // Bereits verbunden (laut unserer Peer-Map) → überspringen
                    if self.peers.get(&peer_id).map(|p| p.connected).unwrap_or(false) {
                        continue;
                    }

                    // Bevorzuge LAN-Adressen (10.x / 192.168.x / 172.x)
                    fn is_lan(addr: &libp2p::Multiaddr) -> bool {
                        use libp2p::multiaddr::Protocol;
                        addr.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_private() && !ip.is_loopback()))
                    }

                    // Adressen sortieren: LAN-Adressen zuerst, dann Rest
                    let mut sorted_addrs = addrs.clone();
                    sorted_addrs.sort_by_key(|a| if is_lan(a) { 0u8 } else { 1u8 });

                    // Beste Adresse für das Log
                    let best_addr = sorted_addrs.first().cloned();

                    // DialOpts mit allen Adressen + NotDialing-Condition:
                    // - libp2p dedupliziert selbst (kein zweiter Dial wenn bereits pending)
                    // - strip_p2p_suffix: Kademlia braucht Adressen ohne /p2p-Suffix,
                    //   aber swarm.dial() braucht die vollständige Adresse MIT /p2p-Suffix
                    //   damit libp2p die PeerId verifizieren kann.
                    use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
                    let opts = DialOpts::peer_id(peer_id)
                        .addresses(sorted_addrs)
                        .condition(PeerCondition::NotDialing)
                        .build();

                    match self.swarm.dial(opts) {
                        Ok(_) => {
                            if let Some(a) = best_addr {
                                println!("[p2p] mDNS-Dial → {a}");
                            }
                        }
                        Err(e) => {
                            let s = e.to_string();
                            // Alle bekannten Race-Conditions stumm schalten
                            if !s.contains("condition")
                                && !s.contains("Already")
                                && !s.contains("connected")
                                && !s.contains("Pending")
                            {
                                eprintln!("[p2p] mDNS-Dial {peer_id}: {e}");
                            }
                        }
                    }
                }
            }

            StoneBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, addr) in list {
                    println!("[p2p] mDNS abgelaufen: {peer_id} @ {addr}");
                }
            }

            // ── Gossipsub ─────────────────────────────────────────────────────
            StoneBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                propagation_source,
                message_id,
                ..
            }) => {
                let topic = message.topic.as_str().to_string();
                let msg_len = message.data.len() as u64;

                // Metriken: eingehende Gossipsub-Nachricht
                self.net_metrics.bytes_in += msg_len;
                self.net_metrics.messages_in += 1;

                if topic == TOPIC_BLOCKS {
                    self.handle_gossip_block(message.data, propagation_source);
                } else if topic == TOPIC_SYNC_HANDSHAKE {
                    self.handle_sync_handshake(message.data, propagation_source);
                } else if topic == TOPIC_MEMPOOL {
                    self.handle_gossip_tx(message.data, propagation_source);
                } else if topic == crate::updater::TOPIC_UPDATES {
                    println!("[p2p] 🆕 Update-Manifest von {propagation_source} empfangen");
                    let _ = self.event_tx.send(NetworkEvent::UpdateManifestReceived {
                        manifest_json: message.data,
                        from_peer: propagation_source.to_string(),
                    });
                } else if topic == TOPIC_STORAGE {
                    if let Ok(ann) = serde_json::from_slice::<StorageAnnouncement>(&message.data) {
                        println!(
                            "[p2p] 💾 Storage-Announcement von {} – {} GB angeboten, {} bytes belegt",
                            &ann.peer_id[..12.min(ann.peer_id.len())], ann.offered_gb, ann.used_bytes
                        );
                        self.peer_storage.insert(ann.peer_id.clone(), ann.clone());
                        let _ = self.event_tx.send(NetworkEvent::StorageAnnouncementReceived {
                            announcement: ann,
                            from_peer: propagation_source.to_string(),
                        });
                    }
                } else {
                    let _ = message_id; // acknowledged
                }
            }

            StoneBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                println!("[p2p] {peer_id} hat '{topic}' abonniert");
            }

            StoneBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { peer_id }) => {
                eprintln!("[p2p] Gossipsub nicht unterstützt von: {peer_id}");
            }

            // ── Kademlia ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. }) => {
                println!("[p2p] Kademlia Routing: {peer}");
            }
            StoneBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })),
                ..
            }) => {
                if num_remaining == 0 {
                    println!("[p2p] ✓ Kademlia Bootstrap abgeschlossen");
                }
            }

            // ── Request/Response (Block-Sync + Ping) ──────────────────────
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::Message { peer, message }
            ) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    // ── Rate-Limit prüfen ──────────────────────────────────
                    let limiter = self.peer_rate_limiters
                        .entry(peer)
                        .or_insert_with(PeerRateLimiter::new);
                    if !limiter.requests.try_consume() {
                        eprintln!("[p2p] ⚠ Rate-Limit für Requests von {peer} erreicht – ignoriert");
                        self.add_peer_penalty(&peer, 10, "request rate limit");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                        return;
                    }

                    if request.block_index == BLOCK_REQUEST_PING {
                        // Ping-Marker → sofort leere Antwort senden
                        println!("[p2p] 🏓 Ping von {peer} – antworte");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                    } else if request.block_index == BLOCK_REQUEST_CHAIN_INFO {
                        // Chain-Info zurückgeben
                        let (height, genesis, latest) = if let Some(ref chain_arc) = self.chain_ref {
                            if let Ok(chain) = chain_arc.lock() {
                                let h = chain.blocks.len() as u64;
                                let g = chain.blocks.first().map(|b| b.hash.clone());
                                let l = chain.blocks.last().map(|b| b.hash.clone());
                                (Some(h), g, l)
                            } else {
                                (None, None, None)
                            }
                        } else {
                            (Some(self.local_chain_count), None, None)
                        };
                        println!("[p2p] 📊 ChainInfo-Anfrage von {peer} → height={height:?}");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: height, genesis_hash: genesis, latest_hash: latest,
                            },
                        );
                    } else if let Some(end) = request.block_index_end {
                        // Range-Request: block_index..=end (max MAX_BLOCKS_PER_RANGE)
                        let start = request.block_index;
                        let clamped_end = end.min(start + MAX_BLOCKS_PER_RANGE - 1);
                        println!("[p2p] 📦 Block-Range {start}..={clamped_end} von {peer}");
                        let mut blocks = Vec::new();
                        if let Some(ref chain_arc) = self.chain_ref {
                            if let Ok(chain) = chain_arc.lock() {
                                for idx in start..=clamped_end {
                                    if let Some(b) = chain.blocks.get(idx as usize) {
                                        blocks.push(b.clone());
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks,
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                    } else {
                        // Einzelner Block
                        let idx = request.block_index;
                        println!("[p2p] 📦 Block #{idx} angefragt von {peer}");
                        let block = if let Some(ref chain_arc) = self.chain_ref {
                            if let Ok(chain) = chain_arc.lock() {
                                chain.blocks.get(idx as usize).cloned()
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if block.is_none() {
                            eprintln!("[p2p] Block #{idx} nicht verfügbar (chain_ref={})" , self.chain_ref.is_some());
                        }
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block, blocks: vec![],
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                    }
                }
                request_response::Message::Response { request_id, response, .. } => {
                    // Ping-Antwort?
                    if let Some((peer_id_str, start, reply)) = self.pending_pings.remove(&request_id) {
                        let ms = start.elapsed().as_millis() as u64;
                        println!("[p2p] 🏓 Pong von {peer_id_str} – {ms}ms");
                        let _ = reply.send(PingResult {
                            peer_id: peer_id_str,
                            reachable: true,
                            latency_ms: Some(ms),
                            error: None,
                        });
                    } else if !response.blocks.is_empty() {
                        // Range-Response: Blöcke in Sync-Buffer sammeln
                        println!("[p2p] ← {} Blöcke via Range-Sync von {peer}", response.blocks.len());
                        for block in response.blocks {
                            let hash = block.hash.clone();
                            if !self.is_duplicate(&hash) {
                                if let Some(entry) = self.peers.get_mut(&peer) {
                                    entry.blocks_received += 1;
                                }
                                self.sync_buffer.insert(block.index, (block, peer.to_string()));
                            }
                        }
                        self.sync_buffer_last_insert = Some(Instant::now());
                        // Sofort versuchen die geordneten Blöcke zu flushen
                        self.flush_sync_buffer();
                    } else if let Some(block) = response.block {
                        // Einzelner Block-Sync
                        let hash = block.hash.clone();
                        if !self.is_duplicate(&hash) {
                            println!("[p2p] ← Block #{} via Sync von {peer}", block.index);
                            if let Some(entry) = self.peers.get_mut(&peer) {
                                entry.blocks_received += 1;
                            }
                            let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                                block: Box::new(block),
                                from_peer: peer.to_string(),
                            });
                        }
                    } else if response.chain_height.is_some() {
                        // ChainInfo-Antwort → prüfe ob wir Blöcke nachholen müssen
                        let remote_height = response.chain_height.unwrap_or(0);
                        println!(
                            "[p2p] 📊 ChainInfo von {peer}: height={remote_height}, genesis={:?}, lokal={}",
                            response.genesis_hash.as_deref().map(|h| &h[..12.min(h.len())]),
                            self.local_chain_count,
                        );

                        // Genesis-Prüfung falls beide Seiten eine Chain haben
                        if let Some(ref remote_genesis) = response.genesis_hash {
                            let our_genesis = self.chain_ref.as_ref().and_then(|arc| {
                                arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
                            });
                            if let Some(ref our_gen) = our_genesis {
                                if our_gen != remote_genesis {
                                    eprintln!(
                                        "[p2p] ⛔ Genesis-Mismatch mit {peer}: lokal={}… remote={}…",
                                        &our_gen[..12.min(our_gen.len())],
                                        &remote_genesis[..12.min(remote_genesis.len())],
                                    );
                                    // Nicht syncen bei Genesis-Mismatch
                                    self.pending_chain_info.remove(&request_id);
                                    return;
                                }
                            }
                        }

                        // Aktuelle lokale Höhe aus chain_ref lesen (genauer als local_chain_count)
                        let actual_local = self.chain_ref.as_ref()
                            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
                            .unwrap_or(self.local_chain_count);

                        if remote_height > actual_local {
                            println!(
                                "[p2p] 🔄 Sync: Peer {peer} hat {remote_height} Blöcke, wir haben {actual_local} → hole {} fehlende",
                                remote_height - actual_local
                            );
                            // Sync-Buffer vorbereiten
                            self.sync_buffer.clear(); // Alten Buffer leeren

                            let _ = self.event_tx.send(NetworkEvent::SyncStarted {
                                peer_id: peer.to_string(),
                                local_count: actual_local,
                                remote_count: remote_height,
                            });

                            // Bei kurzer lokaler Chain (< 50 Blöcke): von Block 1 starten
                            // um potentielle Forks aufzulösen (lokale Mining-Blöcke ersetzen)
                            let sync_from = if actual_local <= 50 { 1u64 } else { actual_local };
                            self.sync_expected_next = sync_from;

                            // Range-Requests für fehlende Blöcke
                            let mut idx = sync_from;
                            while idx < remote_height {
                                let end = (idx + MAX_BLOCKS_PER_RANGE - 1).min(remote_height - 1);
                                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                                    &peer,
                                    BlockRequest { block_index: idx, block_index_end: Some(end) },
                                );
                                idx = end + 1;
                            }
                        }
                        self.pending_chain_info.remove(&request_id);
                    }
                }
            },

            // Request-Fehler (Timeout, Verbindungsabbruch)
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                if let Some((peer_id_str, _, reply)) = self.pending_pings.remove(&request_id) {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id_str,
                        reachable: false,
                        latency_ms: None,
                        error: Some(error.to_string()),
                    });
                } else {
                    eprintln!("[p2p] Request-Fehler zu {peer}: {error}");
                }
            }

            // ── Relay-Client Events ──────────────────────────────────────────────

            StoneBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                ..
            }) => {
                self.active_relays.insert(relay_peer_id);
                println!("[p2p] ✅ Relay-Reservation akzeptiert von {relay_peer_id} ({} aktive Relays)", self.active_relays.len());
            }

            StoneBehaviourEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished {
                limit, ..
            }) => {
                println!("[p2p] 🔗 Ausgehender Relay-Circuit hergestellt (limit: {limit:?})");
            }

            StoneBehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
                src_peer_id,
                limit,
            }) => {
                println!("[p2p] 🔗 Eingehender Relay-Circuit von {src_peer_id} (limit: {limit:?})");
            }

            // ── DCUtR (Direct Connection Upgrade / Hole-Punching) ────────────────

            StoneBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => {
                match result {
                    Ok(_) => {
                        println!("[p2p] 🕳️  Hole-Punch erfolgreich zu {remote_peer_id}!");
                    }
                    Err(e) => {
                        eprintln!("[p2p] ⚠ Hole-Punch fehlgeschlagen zu {remote_peer_id}: {e:?}");
                    }
                }
            }

            // ── AutoNAT (NAT-Erkennung) ──────────────────────────────────────────

            StoneBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new }) => {
                println!("[p2p] 🌐 NAT-Status: {old:?} → {new:?}");
                match new {
                    autonat::NatStatus::Public(_addr) => {
                        self.nat_status = NatStatus::Public;
                        println!("[p2p] ✅ NAT-Status: Öffentlich erreichbar");
                    }
                    autonat::NatStatus::Private => {
                        self.nat_status = NatStatus::Private;
                        println!("[p2p] 🔒 NAT-Status: Privat – nutze Relay für Erreichbarkeit");
                        // Bei privatem NAT automatisch Relay-Reservierungen herstellen
                        self.establish_relay_reservations();
                        // Zusätzlich: Alle bereits verbundenen Peers als potentielle Relays nutzen
                        self.auto_discover_relays();
                    }
                    autonat::NatStatus::Unknown => {
                        self.nat_status = NatStatus::Unknown;
                    }
                }
            }

            StoneBehaviourEvent::Autonat(_) => {}

            // ── UPnP (Automatische Port-Weiterleitung) ──────────────────────────

            StoneBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr)) => {
                println!("[p2p] 🔌 UPnP: Externe Adresse hinzugefügt: {addr}");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::GatewayNotFound) => {
                println!("[p2p] ℹ️  UPnP: Kein Gateway gefunden – Relay wird genutzt");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::NonRoutableGateway) => {
                println!("[p2p] ℹ️  UPnP: Gateway ist nicht routbar");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr(addr)) => {
                println!("[p2p] ⏰ UPnP: Externe Adresse abgelaufen: {addr}");
            }

            // ── Relay-Server Events (wir leiten Traffic für andere weiter) ───────

            #[allow(deprecated)]
            StoneBehaviourEvent::RelayServer(relay::Event::ReservationReqAccepted {
                src_peer_id,
                ..
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} akzeptiert (wir sind Relay für diesen Node)");
            }

            StoneBehaviourEvent::RelayServer(relay::Event::ReservationReqDenied {
                src_peer_id,
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} abgelehnt (Limit erreicht)");
            }

            StoneBehaviourEvent::RelayServer(relay::Event::ReservationTimedOut {
                src_peer_id,
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} abgelaufen");
            }

            StoneBehaviourEvent::RelayServer(_) => {}

            // ── Shard-Exchange (Request/Response) ────────────────────────────
            StoneBehaviourEvent::ShardExchange(
                request_response::Event::Message { peer, message }
            ) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    match request {
                        ShardRequest::GetShard { chunk_hash, shard_index } => {
                            println!("[p2p] 📦 Shard-Anfrage: {chunk_hash}[{shard_index}] von {peer}");
                            let data = self.shard_store.read_shard(&chunk_hash, shard_index).ok();
                            let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                channel,
                                ShardResponse::ShardData { chunk_hash, shard_index, data },
                            );
                        }
                        ShardRequest::StoreShard { chunk_hash, shard_index, shard_hash, data } => {
                            let incoming_len = data.len() as u64;
                            println!("[p2p] 💾 Shard-Store: {chunk_hash}[{shard_index}] von {peer} ({} bytes)", data.len());
                            self.net_metrics.bytes_in += incoming_len;
                            self.net_metrics.messages_in += 1;
                            self.net_metrics.shard_bytes_in += incoming_len;
                            match self.shard_store.write_shard(&chunk_hash, shard_index, &data) {
                                Ok(written_hash) => {
                                    let ok = written_hash == shard_hash;
                                    if !ok {
                                        eprintln!("[p2p] ⚠ Shard-Hash Mismatch: erwartet {shard_hash}, got {written_hash}");
                                    }
                                    // Event an den Event-Loop senden, damit die Registry aktualisiert wird
                                    if ok {
                                        let _ = self.event_tx.send(NetworkEvent::ShardReceived {
                                            chunk_hash: chunk_hash.clone(),
                                            shard_index,
                                            data,
                                            from_peer: peer.to_string(),
                                        });
                                    }
                                    let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                        channel,
                                        ShardResponse::StoreResult {
                                            chunk_hash,
                                            shard_index,
                                            success: ok,
                                            error: if ok { None } else { Some("Hash mismatch".into()) },
                                        },
                                    );
                                }
                                Err(e) => {
                                    eprintln!("[p2p] ❌ Shard-Store Fehler: {e}");
                                    let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                        channel,
                                        ShardResponse::StoreResult {
                                            chunk_hash,
                                            shard_index,
                                            success: false,
                                            error: Some(e.to_string()),
                                        },
                                    );
                                }
                            }
                        }
                        ShardRequest::ListShards { chunk_hash } => {
                            let indices = self.shard_store.local_shard_indices(&chunk_hash);
                            println!("[p2p] 📋 Shard-Liste für {chunk_hash}: {:?} (an {peer})", indices);
                            let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                channel,
                                ShardResponse::ShardList { chunk_hash, indices },
                            );
                        }
                    }
                }
                request_response::Message::Response { request_id, response, .. } => {
                    match response {
                        ShardResponse::ShardData { chunk_hash, shard_index, data } => {
                            if let Some(data) = data {
                                let recv_len = data.len() as u64;
                                println!("[p2p] ← Shard empfangen: {chunk_hash}[{shard_index}] ({} bytes) von {peer}", data.len());
                                self.net_metrics.bytes_in += recv_len;
                                self.net_metrics.messages_in += 1;
                                self.net_metrics.shard_bytes_in += recv_len;
                                let _ = self.event_tx.send(NetworkEvent::ShardReceived {
                                    chunk_hash,
                                    shard_index,
                                    data,
                                    from_peer: peer.to_string(),
                                });
                            } else {
                                println!("[p2p] ← Shard nicht gefunden: {chunk_hash}[{shard_index}] bei {peer}");
                                let _ = self.event_tx.send(NetworkEvent::ShardRequestFailed {
                                    chunk_hash,
                                    shard_index,
                                    peer_id: peer.to_string(),
                                    error: "Shard nicht vorhanden".into(),
                                });
                            }
                        }
                        ShardResponse::StoreResult { chunk_hash, shard_index, success, error } => {
                            println!("[p2p] ← Shard-Store Ergebnis: {chunk_hash}[{shard_index}] bei {peer} → {success}");
                            let _ = self.event_tx.send(NetworkEvent::ShardStored {
                                chunk_hash,
                                shard_index,
                                peer_id: peer.to_string(),
                                success,
                                error,
                            });
                        }
                        ShardResponse::ShardList { chunk_hash, indices } => {
                            // Antwort auf ListPeerShards
                            if let Some((_, reply)) = self.pending_shard_lists.remove(&request_id) {
                                let _ = reply.send(indices);
                            } else {
                                println!("[p2p] Shard-Liste von {peer}: {chunk_hash} → {indices:?}");
                            }
                        }
                    }
                }
            },

            StoneBehaviourEvent::ShardExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                if let Some((_chunk_hash, reply)) = self.pending_shard_lists.remove(&request_id) {
                    eprintln!("[p2p] Shard-Liste Fehler zu {peer}: {error}");
                    let _ = reply.send(vec![]);
                } else {
                    eprintln!("[p2p] Shard-Request Fehler zu {peer}: {error}");
                }
            }

            StoneBehaviourEvent::ShardExchange(_) => {}

            _ => {}
        }
    }

    // ── Relay-Reservierungen ───────────────────────────────────────────────

    /// Stellt Relay-Reservierungen bei allen konfigurierten Relay-Nodes her.
    /// Wird automatisch aufgerufen wenn AutoNAT „Private" meldet.
    fn establish_relay_reservations(&mut self) {
        let addrs: Vec<String> = self.relay_addrs.clone();
        for addr_str in &addrs {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    // Versuche die Relay-PeerId aus der Multiaddr zu extrahieren
                    let relay_peer_id = addr.iter().find_map(|p| {
                        if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                            Some(peer_id)
                        } else {
                            None
                        }
                    });

                    if let Some(relay_peer_id) = relay_peer_id {
                        // Eigene PeerId überspringen
                        if relay_peer_id == *self.swarm.local_peer_id() {
                            continue;
                        }
                        if self.active_relays.contains(&relay_peer_id) {
                            continue; // Bereits reserviert
                        }
                        println!("[p2p] 📡 Verbinde mit Relay {relay_peer_id}...");

                        // Dial den Relay-Node
                        if let Err(e) = self.swarm.dial(addr.clone()) {
                            eprintln!("[p2p] Relay-Dial fehlgeschlagen für {addr}: {e}");
                            continue;
                        }

                        // Lausche auf der Relay-Circuit-Adresse
                        let circuit_addr = addr.clone()
                            .with(libp2p::multiaddr::Protocol::P2pCircuit);
                        if let Err(e) = self.swarm.listen_on(circuit_addr.clone()) {
                            eprintln!("[p2p] Relay-Listen fehlgeschlagen: {e}");
                        } else {
                            println!("[p2p] 📡 Lausche via Relay-Circuit: {circuit_addr}");
                        }
                    } else {
                        eprintln!("[p2p] ⚠ Relay-Adresse hat keine PeerId: {addr_str}");
                    }
                }
                Err(e) => {
                    eprintln!("[p2p] Ungültige Relay-Adresse '{addr_str}': {e}");
                }
            }
        }
    }

    /// Auto-Discovery: Versucht alle verbundenen Peers als Relay zu nutzen.
    ///
    /// Wird aufgerufen wenn AutoNAT „Private" erkennt. Anstatt nur auf
    /// konfigurierte Relay-Nodes zu warten, probiert Stone jeden verbundenen
    /// Peer als Relay — da jeder Stone-Node gleichzeitig Relay-Server ist.
    /// Das ermöglicht NAT-Traversal ohne manuelle Konfiguration.
    fn auto_discover_relays(&mut self) {
        let local = *self.swarm.local_peer_id();
        let max_relay_attempts = 3; // Maximal 3 Relays gleichzeitig versuchen
        let mut attempts = 0;

        // Alle aktuell verbundenen Peers als potentielle Relays sammeln
        let connected_peers: Vec<(PeerId, Vec<Multiaddr>)> = self
            .peers
            .iter()
            .filter(|(pid, info)| {
                info.connected
                    && **pid != local
                    && !self.active_relays.contains(pid)
            })
            .map(|(pid, info)| {
                let addrs: Vec<Multiaddr> = info
                    .addresses
                    .iter()
                    .filter_map(|a| a.parse().ok())
                    .collect();
                (*pid, addrs)
            })
            .collect();

        for (peer_id, addrs) in connected_peers {
            if attempts >= max_relay_attempts {
                break;
            }

            // Bevorzuge öffentliche IP-Adressen (nicht 10.x, 192.168.x, etc.)
            let public_addr = addrs.iter().find(|a| {
                a.iter().any(|p| {
                    matches!(p,
                        libp2p::multiaddr::Protocol::Ip4(ip) if !ip.is_private() && !ip.is_loopback()
                    ) || matches!(p, libp2p::multiaddr::Protocol::Ip6(ip) if !ip.is_loopback())
                })
            });

            // Fallback: nehme erste verfügbare Adresse
            let relay_base_addr = public_addr.or(addrs.first());

            if let Some(base_addr) = relay_base_addr {
                // Relay-Circuit-Adresse aufbauen: /ip4/.../tcp/.../p2p/<relayPeerId>/p2p-circuit
                let circuit_addr = base_addr
                    .clone()
                    .with(libp2p::multiaddr::Protocol::P2p(peer_id))
                    .with(libp2p::multiaddr::Protocol::P2pCircuit);

                match self.swarm.listen_on(circuit_addr.clone()) {
                    Ok(_) => {
                        println!(
                            "[p2p] 🔍 Auto-Relay: Versuche {peer_id} als Relay ({circuit_addr})"
                        );
                        attempts += 1;
                    }
                    Err(e) => {
                        // Kein Fehler-Log: Viele Peers unterstützen es nicht → erwartbar
                        let _ = e;
                    }
                }
            }
        }

        if attempts > 0 {
            println!(
                "[p2p] 🔍 Auto-Relay: {} verbundene Peers als Relay-Kandidaten probiert",
                attempts
            );
        }
    }

    // ── Peer-Scoring & Banning ────────────────────────────────────────────────

    /// Fügt einem Peer Penalty-Punkte hinzu. Bei Überschreitung des Schwellwerts
    /// wird der Peer gebannt (Verbindung getrennt).
    fn add_peer_penalty(&mut self, peer: &PeerId, points: u32, reason: &str) {
        let entry = self.peer_penalties.entry(*peer).or_insert_with(|| PeerPenalty {
            score: 0,
            last_offense: Instant::now(),
            reasons: Vec::new(),
        });

        // Penalty-Verfall: wenn letzte Offense > PENALTY_DECAY_MINS her → Score halbieren
        if entry.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60) {
            entry.score /= 2;
            entry.reasons.clear();
        }

        entry.score += points;
        entry.last_offense = Instant::now();
        entry.reasons.push(reason.to_string());

        eprintln!(
            "[p2p] 🚨 Penalty für {peer}: +{points} = {} (Grund: {reason})",
            entry.score
        );

        if entry.score >= BAN_THRESHOLD {
            eprintln!(
                "[p2p] 🔨 BANNED: {peer} (Score: {}, Gründe: {:?})",
                entry.score,
                entry.reasons,
            );
            // Verbindung trennen
            let _ = self.swarm.disconnect_peer_id(*peer);
            // Aus Peer-Liste entfernen
            if let Some(info) = self.peers.get_mut(peer) {
                info.connected = false;
            }
            // Ban-Liste persistieren
            save_banned_peers(&self.peer_penalties);
        }
    }

    /// Prüft ob ein Peer gebannt ist.
    fn is_peer_banned(&self, peer: &PeerId) -> bool {
        self.peer_penalties
            .get(peer)
            .map(|p| {
                // Ban verfällt nach dem doppelten Decay-Zeitraum
                if p.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60 * 2) {
                    false
                } else {
                    p.score >= BAN_THRESHOLD
                }
            })
            .unwrap_or(false)
    }

    // ── Gossip Block verarbeiten ──────────────────────────────────────────────

    fn handle_gossip_block(&mut self, data: Vec<u8>, source: PeerId) {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return;
        }

        // ── Rate-Limit: Gossip-Blocks ─────────────────────────────────────────
        let limiter = self.peer_rate_limiters
            .entry(source)
            .or_insert_with(PeerRateLimiter::new);
        if !limiter.gossip_blocks.try_consume() {
            eprintln!("[p2p] ⚠ Rate-Limit für Gossip-Blocks von {source} erreicht – ignoriert");
            self.add_peer_penalty(&source, 15, "gossip block rate limit");
            return;
        }

        // ── Größenlimit: Blöcke > 10 MiB sind verdächtig ──────────────────────
        const MAX_GOSSIP_BLOCK_BYTES: usize = 10 * 1024 * 1024;
        if data.len() > MAX_GOSSIP_BLOCK_BYTES {
            eprintln!(
                "[p2p] ⚠ Block von {source} zu groß ({} Bytes) – ignoriert + Penalty",
                data.len()
            );
            self.add_peer_penalty(&source, 50, "oversized block");
            return;
        }

        match serde_json::from_slice::<Block>(&data) {
            Ok(block) => {
                // ── Duplicate-Filter ──────────────────────────────────────────
                if self.is_duplicate(&block.hash) {
                    return;
                }

                // ── Hash-Integrität ───────────────────────────────────────────
                let expected_hash = crate::blockchain::calculate_hash(&block);
                if expected_hash != block.hash {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Hash – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid hash");
                    return;
                }

                // ── Merkle-Root-Verifikation ──────────────────────────────────
                let expected_merkle = crate::blockchain::compute_merkle_root(
                    &block.documents,
                    &block.tombstones,
                    &block.transactions,
                );
                if expected_merkle != block.merkle_root {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Merkle-Root – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid merkle root");
                    return;
                }

                // ── Timestamp-Drift-Check ─────────────────────────────────────
                // Block-Timestamp darf nicht > 5 Minuten in der Zukunft liegen
                // und nicht > 24 Stunden in der Vergangenheit (außer Genesis)
                let now = chrono::Utc::now().timestamp();
                let max_future = 5 * 60;       // 5 Minuten Toleranz
                let max_past = 24 * 60 * 60;   // 24 Stunden
                if block.index > 0 {
                    if block.timestamp > now + max_future {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} liegt {} Sek. in der Zukunft – ignoriert",
                            block.index,
                            block.timestamp - now,
                        );
                        self.add_peer_penalty(&source, 30, "future timestamp");
                        return;
                    }
                    if block.timestamp < now - max_past {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} ist {} Stunden alt – ignoriert",
                            block.index,
                            (now - block.timestamp) / 3600,
                        );
                        self.add_peer_penalty(&source, 10, "stale timestamp");
                        return;
                    }
                }

                // ── Signer darf nicht leer sein ───────────────────────────────
                if block.signer.is_empty() && block.index > 0 {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat keinen Signer – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 50, "missing signer");
                    return;
                }

                // ── Block-Größe vs. data_size Plausibilität ───────────────────
                let actual_data_size: u64 = block.documents.iter().map(|d| d.size).sum();
                if block.data_size > 0 && actual_data_size == 0 && !block.documents.is_empty() {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source}: data_size Mismatch – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 30, "data_size mismatch");
                    return;
                }

                println!("[p2p] 📦 Block #{} von {source} (hash={}...) ✓ validiert", block.index, &block.hash[..8]);

                if let Some(entry) = self.peers.get_mut(&source) {
                    entry.blocks_received += 1;
                    entry.last_seen = chrono::Utc::now().timestamp();
                }
                self.net_metrics.blocks_received += 1;

                // Aktuelle Chain-Höhe lesen um zu entscheiden ob gebuffert werden muss
                let actual_local = self.chain_ref.as_ref()
                    .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
                    .unwrap_or(self.local_chain_count);

                if block.index < actual_local {
                    // Block liegt hinter unserer Chain → veraltet, ignorieren
                    return;
                }

                // Block ist voraus ODER Sync-Buffer ist aktiv → puffern
                // Dies fängt auch Gossip-Blöcke die VOR dem Sync-Start ankommen!
                if block.index > actual_local || !self.sync_buffer.is_empty() {
                    self.sync_buffer.insert(block.index, (block, source.to_string()));
                    self.sync_buffer_last_insert = Some(Instant::now());
                    self.flush_sync_buffer();
                } else {
                    // Normalfall: Block ist der nächste erwartete und kein Sync aktiv
                    let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                        block: Box::new(block),
                        from_peer: source.to_string(),
                    });
                }
            }
            Err(e) => {
                eprintln!("[p2p] Gossip Block-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 20, "malformed block");
            }
        }
    }

    // ── Gossipsub: Token-TX empfangen ─────────────────────────────────────────

    fn handle_gossip_tx(&mut self, data: Vec<u8>, source: PeerId) {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return;
        }

        // ── Rate-Limit: Gossip-TXs ────────────────────────────────────────────
        let limiter = self.peer_rate_limiters
            .entry(source)
            .or_insert_with(PeerRateLimiter::new);
        if !limiter.gossip_txs.try_consume() {
            eprintln!("[p2p] ⚠ Rate-Limit für Gossip-TXs von {source} erreicht – ignoriert");
            self.add_peer_penalty(&source, 10, "gossip tx rate limit");
            return;
        }

        // Größenlimit: TXs > 64 KiB sind verdächtig
        const MAX_TX_BYTES: usize = 64 * 1024;
        if data.len() > MAX_TX_BYTES {
            eprintln!(
                "[p2p] ⚠ TX von {source} zu groß ({} Bytes) – ignoriert",
                data.len()
            );
            self.add_peer_penalty(&source, 20, "oversized tx");
            return;
        }

        match serde_json::from_slice::<crate::token::TokenTx>(&data) {
            Ok(tx) => {
                // Duplikat-Filter (tx_id basiert)
                let key = format!("tx:{}", tx.tx_id);
                if self.is_duplicate(&key) {
                    return;
                }

                // Signatur prüfen
                if let Err(e) = crate::token::validate_tx(&tx) {
                    eprintln!(
                        "[p2p] ⚠ TX {} von {source} ungültige Signatur: {e} – ignoriert",
                        tx.tx_id
                    );
                    self.add_peer_penalty(&source, 30, "invalid tx signature");
                    return;
                }

                println!("[p2p] 💸 TX {} von {source} empfangen", &tx.tx_id[..12.min(tx.tx_id.len())]);

                self.net_metrics.txs_received += 1;

                let _ = self.event_tx.send(NetworkEvent::TxReceived {
                    tx: Box::new(tx),
                    from_peer: source.to_string(),
                });
            }
            Err(e) => {
                eprintln!("[p2p] Gossip TX-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 10, "malformed tx");
            }
        }
    }

    // ── Chain-Sync Handshake ──────────────────────────────────────────────────

    /// Flusht geordnete Blöcke aus dem Sync-Buffer in den Event-Channel.
    /// Nur zusammenhängende Blöcke ab `sync_expected_next` werden gesendet.
    fn flush_sync_buffer(&mut self) {
        // Aktuelle Chain-Höhe aus chain_ref lesen (genauer als sync_expected_next)
        let actual_local = self.chain_ref.as_ref()
            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
            .unwrap_or(self.local_chain_count);

        // sync_expected_next auf Chain-Höhe setzen falls höher
        if actual_local > self.sync_expected_next {
            self.sync_expected_next = actual_local;
        }

        let mut flushed = 0u64;
        loop {
            let next = self.sync_expected_next;
            if let Some((_, (block, from_peer))) = self.sync_buffer.remove_entry(&next) {
                let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                    block: Box::new(block),
                    from_peer,
                });
                self.sync_expected_next = next + 1;
                flushed += 1;
            } else {
                break;
            }
        }
        if flushed > 0 {
            println!("[p2p] 🔄 Sync-Buffer: {flushed} Blöcke geordnet eingefügt (nächster erwartet: #{})", self.sync_expected_next);
            // NICHT local_chain_count hier setzen – master_server aktualisiert
            // es über SetLocalChainCount wenn Blöcke tatsächlich akzeptiert werden
        }

        // Aufräumen: Blöcke die unter der aktuellen Chain-Höhe liegen entfernen (veraltet)
        let stale_keys: Vec<u64> = self.sync_buffer.range(..actual_local).map(|(k, _)| *k).collect();
        for k in stale_keys {
            self.sync_buffer.remove(&k);
        }

        // Timeout: Wenn > 30s lang keine neuen Blöcke kamen und Buffer nicht leer
        // → wahrscheinlich Lücke → Buffer leeren und Resync triggern
        if !self.sync_buffer.is_empty() {
            if let Some(last) = self.sync_buffer_last_insert {
                if last.elapsed() > Duration::from_secs(30) {
                    let remaining = self.sync_buffer.len();
                    eprintln!("[p2p] ⚠ Sync-Buffer Timeout: {remaining} Blöcke verwaist (nächster erwartet: #{}, erster im Buffer: #{})" ,
                        self.sync_expected_next,
                        self.sync_buffer.keys().next().unwrap_or(&0),
                    );
                    self.sync_buffer.clear();
                    self.sync_buffer_last_insert = None;
                }
            }
        } else {
            self.sync_buffer_last_insert = None;
        }
    }

    /// Sendet ChainInfo-Anfragen an alle verbundenen Peers per Request/Response.
    /// Zuverlässiger als GossipSub (braucht keinen Mesh).
    fn sync_with_connected_peers(&mut self) {
        let connected: Vec<PeerId> = self.peers.iter()
            .filter(|(_, info)| info.connected)
            .map(|(pid, _)| *pid)
            .collect();

        if connected.is_empty() {
            return;
        }

        // Aktuelle Chain-Höhe aus chain_ref lesen
        let actual_local = self.chain_ref.as_ref()
            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
            .unwrap_or(self.local_chain_count);

        // Nur syncen wenn wir möglicherweise hinterher sind
        // (auch GossipSub-Handshake senden für Peers die hinter UNS sind)
        self.send_sync_handshake();

        for peer_id in connected {
            // Nicht doppelt anfragen wenn schon eine Anfrage läuft
            if self.pending_chain_info.values().any(|p| *p == peer_id) {
                continue;
            }
            let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                &peer_id,
                BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
            );
            self.pending_chain_info.insert(req_id, peer_id);
        }
    }

    /// Sendet unsere Chain-Länge an alle Peers (Gossipsub).
    /// Peers die mehr Blöcke haben werden uns antworten.
    fn send_sync_handshake(&mut self) {
        // Genesis-Hash aus chain_ref lesen
        let genesis_hash = self.chain_ref.as_ref().and_then(|arc| {
            arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
        });
        let msg = SyncHandshake {
            block_count: self.local_chain_count,
            peer_id: self.swarm.local_peer_id().to_string(),
            genesis_hash,
            protocol_version: Some(STONE_PROTOCOL_VERSION.to_string()),
        };
        if let Ok(data) = serde_json::to_vec(&msg) {
            let topic = IdentTopic::new(TOPIC_SYNC_HANDSHAKE);
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                // InsufficientPeers ist kein Fehler beim Start
                if !e.to_string().contains("InsufficientPeers") {
                    eprintln!("[p2p] Sync-Handshake fehlgeschlagen: {e}");
                }
            }
        }
    }

    /// Empfängt einen Sync-Handshake von einem Peer.
    /// Falls der Peer mehr Blöcke hat → fehlende per Request/Response abrufen.
    fn handle_sync_handshake(&mut self, data: Vec<u8>, source: PeerId) {
        let Ok(msg) = serde_json::from_slice::<SyncHandshake>(&data) else {
            return;
        };

        if msg.peer_id == self.swarm.local_peer_id().to_string() {
            return; // eigene Nachricht
        }

        // ── Protokoll-Version prüfen ──────────────────────────────────────
        if let Some(ref remote_ver) = msg.protocol_version {
            // Major-Version vergleichen (z.B. "stone/0.7" vs "stone/0.7")
            let local_major = STONE_PROTOCOL_VERSION.split('.').next().unwrap_or("");
            let remote_major = remote_ver.split('.').next().unwrap_or("");
            if local_major != remote_major {
                eprintln!(
                    "[p2p] ⚠ Peer {source} hat inkompatible Protokoll-Version: {remote_ver} (wir: {STONE_PROTOCOL_VERSION}) – Verbindung trennen"
                );
                self.add_peer_penalty(&source, 200, "incompatible protocol version");
                let _ = self.swarm.disconnect_peer_id(source);
                return;
            }
        }

        // ── Genesis-Hash prüfen ───────────────────────────────────────────
        if let Some(ref remote_genesis) = msg.genesis_hash {
            let our_genesis = self.chain_ref.as_ref().and_then(|arc| {
                arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
            });
            if let Some(ref our_gen) = our_genesis {
                if our_gen != remote_genesis {
                    eprintln!(
                        "[p2p] ⛔ Genesis-Mismatch mit {source}: lokal={}… remote={}… – Peer getrennt",
                        &our_gen[..12.min(our_gen.len())],
                        &remote_genesis[..12.min(remote_genesis.len())],
                    );
                    self.add_peer_penalty(&source, 200, "genesis mismatch");
                    let _ = self.swarm.disconnect_peer_id(source);
                    return;
                }
            }
        }

        if msg.block_count > self.local_chain_count {
            // Aktuelle lokale Höhe aus chain_ref lesen (genauer als local_chain_count)
            let actual_local = self.chain_ref.as_ref()
                .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
                .unwrap_or(self.local_chain_count);

            if msg.block_count <= actual_local {
                return; // chain_ref ist aktueller, kein Sync nötig
            }

            println!(
                "[p2p] 🔄 Sync: Peer {source} hat {} Blöcke, wir haben {actual_local}",
                msg.block_count,
            );

            // Sync-Buffer vorbereiten
            self.sync_buffer.clear();

            let _ = self.event_tx.send(NetworkEvent::SyncStarted {
                peer_id: source.to_string(),
                local_count: actual_local,
                remote_count: msg.block_count,
            });

            // Bei kurzer lokaler Chain: von Block 1 starten (Fork-Auflösung)
            let sync_from = if actual_local <= 50 { 1u64 } else { actual_local };
            self.sync_expected_next = sync_from;

            // Fehlende Blöcke per Range-Requests abrufen
            let mut idx = sync_from;
            while idx < msg.block_count {
                let end = (idx + MAX_BLOCKS_PER_RANGE - 1).min(msg.block_count - 1);
                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                    &source,
                    BlockRequest { block_index: idx, block_index_end: Some(end) },
                );
                idx = end + 1;
            }
        } else if msg.block_count < self.local_chain_count {
            // Wir haben mehr Blöcke → eigenen Handshake senden damit der Peer synct
            self.send_sync_handshake();
        }
    }

    // ── Externe Befehle ───────────────────────────────────────────────────────

    fn handle_command(&mut self, cmd: NetworkCommand) -> bool {
        match cmd {
            NetworkCommand::BroadcastBlock(block) => {
                let hash = block.hash.clone();

                // Eigenen Block sofort als "gesehen" markieren (kein Re-Broadcast)
                if !self.is_duplicate(&hash) {
                    // Duplicate-Filter hat ihn gerade neu eingetragen → gut
                }

                match serde_json::to_vec(&*block) {
                    Ok(data) => {
                        let data_len = data.len() as u64;
                        let topic = IdentTopic::new(TOPIC_BLOCKS);
                        match self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            Ok(_) => {
                                println!("[p2p] 📡 Block #{} gebroadcastet (hash={}...)", block.index, &hash[..8.min(hash.len())]);
                                // Metriken
                                self.net_metrics.bytes_out += data_len;
                                self.net_metrics.messages_out += 1;
                                self.net_metrics.blocks_sent += 1;
                                // Chain-Count aktualisieren
                                if block.index + 1 > self.local_chain_count {
                                    self.local_chain_count = block.index + 1;
                                }
                            }
                            Err(gossipsub::PublishError::InsufficientPeers) => {
                                // Kein Peer verbunden – kein Fehler, nur Info
                                println!("[p2p] Block #{} – keine Peers verbunden, Broadcast übersprungen", block.index);
                            }
                            Err(e) => eprintln!("[p2p] Broadcast-Fehler: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[p2p] Block-Serialisierung: {e}"),
                }
                false
            }

            NetworkCommand::BroadcastTx(tx) => {
                let tx_id = tx.tx_id.clone();

                // Deduplizierung: eigene TX sofort als gesehen markieren
                if !self.is_duplicate(&format!("tx:{tx_id}")) {
                    // hat gerade eingetragen → gut
                }

                match serde_json::to_vec(&*tx) {
                    Ok(data) => {
                        let data_len = data.len() as u64;
                        let topic = IdentTopic::new(TOPIC_MEMPOOL);
                        match self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            Ok(_) => {
                                println!("[p2p] 💸 TX {tx_id} gebroadcastet");
                                self.net_metrics.bytes_out += data_len;
                                self.net_metrics.messages_out += 1;
                                self.net_metrics.txs_sent += 1;
                            }
                            Err(gossipsub::PublishError::InsufficientPeers) => {
                                // Kein Peer – kein Fehler
                            }
                            Err(e) => eprintln!("[p2p] TX-Broadcast-Fehler: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[p2p] TX-Serialisierung: {e}"),
                }
                false
            }

            NetworkCommand::DialPeer(addr) => {
                println!("[p2p] Manueller Dial: {addr}");
                if let Err(e) = self.swarm.dial(addr) {
                    eprintln!("[p2p] Dial fehlgeschlagen: {e}");
                }
                false
            }

            NetworkCommand::SyncWithPeer { peer_id, our_block_count } => {
                // Expliziten Sync-Handshake an einen Peer senden
                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                    &peer_id,
                    BlockRequest { block_index: our_block_count, block_index_end: None },
                );
                false
            }

            NetworkCommand::SetLocalChainCount(count) => {
                self.local_chain_count = count;
                false
            }

            NetworkCommand::SetChainRef(chain_arc) => {
                println!("[p2p] Chain-Referenz gesetzt");
                self.chain_ref = Some(chain_arc);
                false
            }

            NetworkCommand::GetPeers(tx) => {
                let list: Vec<PeerInfo> = self.peers.values().cloned().collect();
                let _ = tx.send(list);
                false
            }

            NetworkCommand::Ping { peer_id, reply } => {
                let connected = self.peers.get(&peer_id).map(|p| p.connected).unwrap_or(false);
                if !connected {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id.to_string(),
                        reachable: false,
                        latency_ms: None,
                        error: Some("Peer nicht verbunden".to_string()),
                    });
                    return false;
                }
                // Ping-Marker: block_index = u64::MAX
                let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                    &peer_id,
                    BlockRequest { block_index: BLOCK_REQUEST_PING, block_index_end: None },
                );
                self.pending_pings.insert(req_id, (peer_id.to_string(), std::time::Instant::now(), reply));
                false
            }

            NetworkCommand::GetStatus(reply) => {
                let now = chrono::Utc::now().timestamp();
                let mesh_peers: HashSet<String> = self.swarm
                    .behaviour()
                    .gossipsub
                    .mesh_peers(&gossipsub::TopicHash::from_raw(TOPIC_BLOCKS))
                    .map(|p| p.to_string())
                    .collect();

                // Direkt aus dem Swarm die verbundenen Peers holen —
                // das ist die einzig zuverlässige Quelle, unabhängig von peers-Map.
                let swarm_connected: HashSet<String> = self.swarm
                    .connected_peers()
                    .map(|p| p.to_string())
                    .collect();

                // peers-Map mit Swarm-Status synchronisieren
                for (peer_id, info) in self.peers.iter_mut() {
                    info.connected = swarm_connected.contains(&peer_id.to_string());
                }
                // Peers die im Swarm verbunden sind aber noch nicht in unserer Map
                for peer_str in &swarm_connected {
                    if let Ok(peer_id) = peer_str.parse::<libp2p::PeerId>() {
                        self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
                            peer_id: peer_str.clone(),
                            addresses: vec![],
                            agent_version: String::new(),
                            connected: true,
                            last_seen: now,
                            blocks_received: 0,
                        });
                    }
                }

                let peers: Vec<PeerStatus> = self.peers.values().map(|p| PeerStatus {
                    peer_id: p.peer_id.clone(),
                    addresses: p.addresses.clone(),
                    agent_version: p.agent_version.clone(),
                    connected: p.connected,
                    last_seen: p.last_seen,
                    last_seen_ago_secs: now - p.last_seen,
                    blocks_received: p.blocks_received,
                    in_gossipsub_mesh: mesh_peers.contains(&p.peer_id),
                }).collect();

                let connected = swarm_connected.len(); // direkt aus Swarm

                // Metriken mit Uptime & Durchschnittswerten berechnen
                let uptime = self.started_at.elapsed().as_secs().max(1);
                let mut metrics = self.net_metrics.clone();
                metrics.uptime_secs = uptime;
                metrics.avg_bytes_in_per_sec = metrics.bytes_in as f64 / uptime as f64;
                metrics.avg_bytes_out_per_sec = metrics.bytes_out as f64 / uptime as f64;

                let _ = reply.send(NetworkStatus {
                    local_peer_id: self.swarm.local_peer_id().to_string(),
                    connected_peers: connected,
                    total_known_peers: self.peers.len(),
                    gossipsub_mesh_size: mesh_peers.len(),
                    chain_block_count: self.local_chain_count,
                    peers,
                    metrics,
                    peer_storage: self.peer_storage.values().cloned().collect(),
                });
                false
            }

            NetworkCommand::Shutdown => {
                println!("[p2p] Shutdown.");
                true
            }

            // ── Shard-Befehle ─────────────────────────────────────────────────

            NetworkCommand::RequestShard { peer_id, chunk_hash, shard_index } => {
                println!("[p2p] → Shard anfordern: {chunk_hash}[{shard_index}] von {peer_id}");
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::GetShard { chunk_hash, shard_index },
                );
                false
            }

            NetworkCommand::StoreShard { peer_id, chunk_hash, shard_index, shard_hash, data } => {
                let data_len = data.len() as u64;
                println!("[p2p] → Shard senden: {chunk_hash}[{shard_index}] an {peer_id} ({} bytes)", data.len());
                self.net_metrics.bytes_out += data_len;
                self.net_metrics.messages_out += 1;
                self.net_metrics.shard_bytes_out += data_len;
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::StoreShard { chunk_hash, shard_index, shard_hash, data },
                );
                false
            }

            NetworkCommand::ListPeerShards { peer_id, chunk_hash, reply } => {
                println!("[p2p] → Shard-Liste anfordern: {chunk_hash} von {peer_id}");
                let req_id = self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::ListShards { chunk_hash: chunk_hash.clone() },
                );
                self.pending_shard_lists.insert(req_id, (chunk_hash, reply));
                false
            }

            NetworkCommand::PublishGossip { topic, data } => {
                let data_len = data.len() as u64;
                match self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                    Ok(_) => {
                        println!("[p2p] 📡 Gossip auf Topic {topic} gesendet");
                        self.net_metrics.bytes_out += data_len;
                        self.net_metrics.messages_out += 1;
                    }
                    Err(gossipsub::PublishError::InsufficientPeers) => {
                        println!("[p2p] Gossip {topic} – keine Peers, übersprungen");
                    }
                    Err(e) => {
                        eprintln!("[p2p] Gossip-Fehler auf {topic}: {e}");
                    }
                }
                false
            }
        }
    }
}

// ─── Sync-Handshake Nachricht ─────────────────────────────────────────────────

pub const TOPIC_SYNC_HANDSHAKE: &str = "stone/sync/v1";

/// Kurze Nachricht die beim Verbinden gesendet wird um Chain-Längen zu vergleichen.
/// Enthält Genesis-Hash und Protokoll-Version für Kompatibilitätsprüfung.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncHandshake {
    block_count: u64,
    peer_id: String,
    /// Genesis-Block-Hash – Peers auf einer anderen Chain werden abgelehnt
    #[serde(default)]
    genesis_hash: Option<String>,
    /// Protokoll-Version (z.B. "stone/0.7") – inkompatible Versionen werden abgelehnt
    #[serde(default)]
    protocol_version: Option<String>,
}

// ─── Gossipsub: Topics abonnieren ─────────────────────────────────────────────

fn subscribe_all_topics(gossipsub: &mut gossipsub::Behaviour) -> Result<(), String> {
    for topic in [TOPIC_BLOCKS, TOPIC_PEERS, TOPIC_SYNC_HANDSHAKE, TOPIC_MEMPOOL, crate::updater::TOPIC_UPDATES, TOPIC_STORAGE] {
        gossipsub.subscribe(&IdentTopic::new(topic))
            .map_err(|e| format!("Subscribe '{topic}': {e}"))?;
    }
    Ok(())
}

// ─── Öffentliche API ──────────────────────────────────────────────────────────

/// Handle für den laufenden P2P-Swarm-Task.
///
/// Wird als `AppState.network` gehalten. Alle Methoden sind `async` und
/// kommunizieren über den `mpsc`-Kanal mit dem Swarm-Task.
#[derive(Clone)]
pub struct NetworkHandle {
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    pub event_rx: broadcast::Sender<NetworkEvent>,
    pub local_peer_id: String,
}

impl NetworkHandle {
    /// Broadcastet einen Block per Gossipsub an alle Peers.
    pub async fn broadcast_block(&self, block: Block) {
        let _ = self.cmd_tx.send(NetworkCommand::BroadcastBlock(Box::new(block))).await;
    }

    /// Broadcastet eine Token-TX per Gossipsub an alle Peers.
    pub async fn broadcast_tx(&self, tx: crate::token::TokenTx) {
        let _ = self.cmd_tx.send(NetworkCommand::BroadcastTx(Box::new(tx))).await;
    }

    /// Publiziert eine generische Nachricht auf einem Gossipsub-Topic.
    pub async fn publish_gossip(&self, topic: &str, data: Vec<u8>) {
        let topic_hash = IdentTopic::new(topic).hash();
        let _ = self.cmd_tx.send(NetworkCommand::PublishGossip { topic: topic_hash, data }).await;
    }

    /// Wählt einen Peer manuell an.
    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::DialPeer(addr)).await;
    }

    /// Teilt dem Swarm unsere aktuelle Chain-Länge mit (z.B. nach jedem neuen Block).
    pub async fn set_chain_count(&self, count: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SetLocalChainCount(count)).await;
    }

    /// Setzt die Chain-Referenz, damit der SwarmTask Blöcke direkt servieren kann.
    pub async fn set_chain_ref(&self, chain: std::sync::Arc<std::sync::Mutex<crate::blockchain::StoneChain>>) {
        let _ = self.cmd_tx.send(NetworkCommand::SetChainRef(chain)).await;
    }

    /// Startet einen expliziten Chain-Sync mit einem bestimmten Peer.
    pub async fn sync_with(&self, peer_id: PeerId, our_block_count: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SyncWithPeer { peer_id, our_block_count }).await;
    }

    /// Gibt die aktuelle Peer-Liste zurück.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd_tx.send(NetworkCommand::GetPeers(tx)).await;
        rx.await.unwrap_or_default()
    }

    /// Gibt alle verbundenen Peers zurück.
    pub async fn connected_peers(&self) -> Vec<PeerInfo> {
        self.get_peers().await.into_iter().filter(|p| p.connected).collect()
    }

    /// Subscribt auf Network-Events (broadcast channel).
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_rx.subscribe()
    }

    /// Pingt einen Peer via Request/Response und misst die Latenz.
    /// Timeout: 5 Sekunden. Gibt `PingResult.reachable = false` bei Fehler zurück.
    pub async fn ping(&self, peer_id: PeerId) -> PingResult {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(NetworkCommand::Ping { peer_id: peer_id.clone(), reply: tx }).await.is_err() {
            return PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("P2P-Task nicht erreichbar".to_string()),
            };
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Interner Fehler".to_string()),
            },
            Err(_) => PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Timeout (5s)".to_string()),
            },
        }
    }

    /// Gibt den vollständigen Netzwerkstatus zurück (alle Peers, Mesh, Chain-Count).
    pub async fn get_status(&self) -> Option<NetworkStatus> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx.send(NetworkCommand::GetStatus(tx)).await.ok()?;
        tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await.ok()?.ok()
    }

    /// Gibt nur die Netzwerk-Metriken zurück.
    pub async fn get_metrics(&self) -> Option<NetworkMetrics> {
        self.get_status().await.map(|s| s.metrics)
    }

    /// Beendet den Swarm-Task.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
    }

    // ── Shard-API ─────────────────────────────────────────────────────────────

    /// Fordert einen bestimmten Shard von einem Peer an.
    /// Die Antwort kommt asynchron als `NetworkEvent::ShardReceived`.
    pub async fn request_shard(&self, peer_id: PeerId, chunk_hash: String, shard_index: u8) {
        let _ = self.cmd_tx.send(NetworkCommand::RequestShard {
            peer_id,
            chunk_hash,
            shard_index,
        }).await;
    }

    /// Sendet einen Shard an einen Peer zum Speichern.
    /// Die Bestätigung kommt als `NetworkEvent::ShardStored`.
    pub async fn store_shard_on_peer(
        &self,
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    ) {
        let _ = self.cmd_tx.send(NetworkCommand::StoreShard {
            peer_id,
            chunk_hash,
            shard_index,
            shard_hash,
            data,
        }).await;
    }

    /// Fragt ab welche Shards ein Peer für einen bestimmten Chunk hat.
    /// Timeout: 5 Sekunden.
    pub async fn list_peer_shards(&self, peer_id: PeerId, chunk_hash: String) -> Vec<u8> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(NetworkCommand::ListPeerShards {
            peer_id,
            chunk_hash,
            reply: tx,
        }).await.is_err() {
            return vec![];
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(indices)) => indices,
            _ => vec![],
        }
    }
}

// ─── start_network ────────────────────────────────────────────────────────────

/// Startet den P2P-Swarm-Task und gibt ein `NetworkHandle` zurück.
pub async fn start_network(
    config_override: Option<P2pConfig>,
) -> Result<NetworkHandle, Box<dyn std::error::Error>> {
    let mut config = config_override.unwrap_or_else(P2pConfig::load_or_default);
    config.merge_env();

    let keypair = load_or_create_keypair();
    let local_peer_id = PeerId::from_public_key(&keypair.public()).to_string();

    println!("[p2p] Stone P2P-Netzwerk startet");
    println!("[p2p] PeerId: {local_peer_id}");
    println!("[p2p] Listen: {}", config.listen_addr);
    if config.bootstrap_nodes.is_empty() {
        println!("[p2p] Keine Bootstrap-Nodes – nur mDNS/lokale Discovery");
    } else {
        for b in &config.bootstrap_nodes {
            println!("[p2p] Bootstrap: {b}");
        }
    }

    // NAT-Traversal Konfiguration loggen
    println!("[p2p] NAT-Traversal:");
    println!("[p2p]   QUIC:     ✅ (UDP, native TLS 1.3)");
    println!("[p2p]   AutoNAT:  {}", if config.autonat_enabled { "✅" } else { "❌" });
    println!("[p2p]   UPnP:     {}", if config.upnp_enabled { "✅" } else { "❌" });
    println!("[p2p]   DCUtR:    {}", if config.dcutr_enabled { "✅" } else { "❌" });
    println!("[p2p]   Relay:    ✅ (Auto-Discovery + Server)");
    if !config.relay_nodes.is_empty() {
        for r in &config.relay_nodes {
            println!("[p2p]   Relay:    {r}");
        }
    }

    let mut swarm = build_swarm(keypair, &config)?;

    // Gossipsub: alle Topics abonnieren
    subscribe_all_topics(&mut swarm.behaviour_mut().gossipsub)
        .map_err(|e| format!("Gossipsub-Subscribe: {e}"))?;

    let (event_tx, _) = broadcast::channel(512);
    let (cmd_tx, cmd_rx) = mpsc::channel(128);

    let bootstrap_addrs = config.bootstrap_nodes.clone();

    let relay_addrs = config.relay_nodes.clone();

    let task = SwarmTask {
        swarm,
        event_tx: event_tx.clone(),
        cmd_rx,
        peers: HashMap::new(),
        seen_hashes: HashSet::new(),
        seen_order: VecDeque::new(),
        local_chain_count: 0,
        bootstrap_addrs,
        last_reconnect: Instant::now(),
        config,
        pending_pings: HashMap::new(),
        nat_status: NatStatus::Unknown,
        active_relays: HashSet::new(),
        relay_addrs,
        peer_penalties: load_banned_peers(),
        shard_store: crate::shard::ShardStore::new().expect("ShardStore erstellen"),
        pending_shard_lists: HashMap::new(),
        net_metrics: NetworkMetrics::default(),
        started_at: Instant::now(),
        peer_storage: HashMap::new(),
        peer_rate_limiters: HashMap::new(),
        chain_ref: None,
        pending_chain_info: HashMap::new(),
        sync_buffer: std::collections::BTreeMap::new(),
        sync_buffer_last_insert: None,
        sync_expected_next: 0,
    };

    tokio::spawn(task.run());

    Ok(NetworkHandle {
        cmd_tx,
        event_rx: event_tx,
        local_peer_id,
    })
}

// ─── Hilfsfunktionen für die REST-API ─────────────────────────────────────────

/// Parst eine Multiaddr aus einem String.
pub fn parse_multiaddr(s: &str) -> Result<Multiaddr, String> {
    s.parse::<Multiaddr>().map_err(|e| format!("Ungültige Multiaddr: {e}"))
}

/// Gibt die vollständige eigene P2P-Adresse zurück (für Bootstrap-Konfiguration anderer Nodes).
pub fn local_p2p_addr(port: u16) -> Option<String> {
    let peer_id = read_peer_id()?;
    let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Some(format!("/ip4/{ip}/tcp/{port}/p2p/{peer_id}"))
}

/// Gibt die QUIC-Adresse zurück (UDP-basiert, für NAT-Traversal).
pub fn local_quic_addr(port: u16) -> Option<String> {
    let peer_id = read_peer_id()?;
    let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Some(format!("/ip4/{ip}/udp/{port}/quic-v1/p2p/{peer_id}"))
}

fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}
