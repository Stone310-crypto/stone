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

pub mod swarm_task;
pub mod handle;

pub use handle::NetworkHandle;
pub use handle::start_network;
pub use handle::{parse_multiaddr, local_p2p_addr, local_quic_addr};

use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    autonat,
    dcutr,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    noise,
    relay,
    request_response::{self, ProtocolSupport},
    tcp,
    upnp,
    yamux,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    fs,
    time::{Duration, Instant},
};

// ─── Duplikat-Filter Kapazität ────────────────────────────────────────────────
/// Wie viele Block-Hashes im Seen-Cache behalten werden (LRU-Approximation via VecDeque)
const SEEN_CACHE_SIZE: usize = 2048;

/// Maximale Anzahl gleichzeitiger Verbindungen zu EINEM Peer. Überzählige
/// Verbindungen werden sofort geschlossen. Verhindert, dass ein flappender
/// oder inkompatibler Peer (z. B. mit veralteter PeerId/Genesis) den Node mit
/// hunderten Parallelverbindungen flutet. 3 lässt TCP+QUIC sowie Relay→DCUtR-
/// Upgrades zu, kappt aber jeden Storm hart.
pub(crate) const MAX_CONNECTIONS_PER_PEER: u32 = 3;

/// Mindestdauer (Sekunden), die eine Verbindung halten muss, um als „stabil"
/// zu gelten. Bricht sie früher ab, wird der Peer als flappend behandelt.
pub(crate) const STABLE_CONNECTION_SECS: u64 = 10;

// ─── Konstanten ───────────────────────────────────────────────────────────────

const DEFAULT_DATA_DIR: &str = "stone_data";
const DEFAULT_DATA_DIR_MAINNET: &str = "stone_data_mainnet";
const P2P_KEY_FILENAME: &str = "p2p.key";
const P2P_CONFIG_FILENAME: &str = "p2p_config.json";

// ─── Netzwerk-Tag in Wire-Identifiern ─────────────────────────────────────────
//
// Alle Gossipsub-Topics, libp2p-StreamProtocols und der Handshake-Version-String
// tragen ein Netzwerk-Tag (`mainnet`/`testnet`). Dadurch scheitern Cross-Net-
// Verbindungen bereits beim libp2p-Protocol-Negotiation, bevor irgendein
// Datenaustausch stattfindet. Keine Kademlia-Pollution, keine Gossipsub-
// Subscription, keine Identify-Round-Trips.
//
// Hinweis: `is_mainnet()` liest die Env-Var; per `LazyLock` wird das Tag genau
// einmal beim ersten Zugriff aufgelöst und danach gecached. Eine
// Laufzeit-Umschaltung des Netzes ist nicht möglich (auch nicht erwünscht).

use std::sync::LazyLock;

fn net_tag() -> &'static str {
    if is_mainnet() { "mainnet" } else { "testnet" }
}

pub static TOPIC_BLOCKS: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/blocks/v1", net_tag()));
pub static TOPIC_PEERS: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/peers/v1", net_tag()));
pub static TOPIC_MEMPOOL: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/mempool/v1", net_tag()));
pub static TOPIC_STORAGE: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/storage/v1", net_tag()));
pub static TOPIC_CHAT: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/chat/v1", net_tag()));
/// Off-chain Content-Sync für DSGVO-Chat (nur encrypted_content, kein PoW nötig)
pub static TOPIC_CHAT_CONTENT: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/chat-content/v1", net_tag()));
/// Miner-Identity & Heartbeats (Auto-Block-Timer Cluster-Awareness)
pub static TOPIC_MINERS: LazyLock<String> =
    LazyLock::new(|| format!("stone/{}/miners/v1", net_tag()));

/// Protokoll-Version für den Sync-Handshake.
/// Peers mit einer anderen Major-Version werden abgelehnt.
///
/// **Hinweis zur Netzwerk-Isolation:** Diese Version ist netzwerk-unabhängig.
/// Cross-Net-Verbindungen scheitern bereits eine Stufe früher, weil alle
/// libp2p-StreamProtocols (`/stone/<tag>/kad/...`, `/stone/<tag>/id/...`,
/// Block-/Shard-Exchange) und alle Gossipsub-Topics ein Netzwerk-Tag
/// enthalten – ein Mainnet-Node spricht ein Testnet-Node also gar nicht erst
/// an. Der Handshake-Versionscheck bleibt damit eine reine Major-Version-
/// Migrationsgrenze (z.B. 0.7 ↔ 0.8 Wire-Format).
///
/// **0.8** — Wire-Format für Block-/TX-/SyncHandshake-Gossip auf bincode
/// (statt JSON) umgestellt. Mischbetrieb mit 0.7-Peers ist nicht möglich.
pub const STONE_PROTOCOL_VERSION: &str = "stone/0.8";

/// Dateiname für die persistierte Ban-Liste
const BANNED_PEERS_FILENAME: &str = "banned_peers.json";

/// Standard-libp2p-Port des Stone-Netzwerks
pub const DEFAULT_P2P_PORT: u16 = 7654;

// ─── Netzwerk-Erkennung ────────────────────────────────────────────────────────

/// Prüft ob wir im Mainnet laufen (STONE_NETWORK=mainnet|main).
pub fn is_mainnet() -> bool {
    let mode = std::env::var("STONE_NETWORK")
        .unwrap_or_default()
        .to_lowercase();
    mode == "mainnet" || mode == "main"
}

// ─── Built-in Seed-Nodes ──────────────────────────────────────────────────────
//
// Mainnet und Testnet haben **getrennte** Seed-Nodes und Ports.
// Dadurch können sie auf denselben VPS laufen ohne sich gegenseitig zu stören.
//
// Format: "/ip4/<IP>/tcp/<PORT>/p2p/<PeerId>"
//
// HINWEIS: Diese Liste kann per `STONE_NO_SEED=1` deaktiviert werden.
//          Das ist nützlich für komplett private / isolierte Netzwerke.

/// Testnet Seed-Nodes (Port 4001) – Standard-Netzwerk für Entwicklung.
///
/// Bewusst NUR TCP (kein quic-v1): Die öffentlichen VPS verbinden sich über
/// eine interkontinentale Strecke (DE↔US). QUIC/UDP riss dort periodisch ab
/// (Paketverlust / Stateful-Firewall-UDP-Timeout) → Reconnect-Schleife. TCP
/// ist über diese Strecke stabil. Die Nodes LAUSCHEN weiterhin auf QUIC (für
/// NAT-Peers); wir dialen die Seeds nur nicht mehr über QUIC.
const SEED_NODES_TESTNET: &[&str] = &[
    // ── VPS1 (212.227.54.241) – primärer Testnet-Bootstrap + Relay ───
    "/ip4/212.227.54.241/tcp/4001/p2p/12D3KooWECEPy5EnZ7HwvwnABBwnJwU4jSMh5U1HpzRBaXK9kmoP",
    "/ip6/2a02:2479:a0:fa00::1/tcp/4001/p2p/12D3KooWECEPy5EnZ7HwvwnABBwnJwU4jSMh5U1HpzRBaXK9kmoP",
    // ── VPS2 (69.48.200.255) – sekundärer Testnet-Bootstrap + Relay ───
    "/ip4/69.48.200.255/tcp/4001/p2p/12D3KooWFkXVx4zBFMmsdC6Qr5pAn5FdPLbeyCFTsFhsn2CW39Tw",
    "/ip6/2607:f1c0:f074:4300::1/tcp/4001/p2p/12D3KooWFkXVx4zBFMmsdC6Qr5pAn5FdPLbeyCFTsFhsn2CW39Tw",
];

/// Mainnet Seed-Nodes (Port 5001) – Produktionsnetzwerk.
/// Dieselben VPS, aber auf separaten Ports → komplette Netzwerk-Isolation.
const SEED_NODES_MAINNET: &[&str] = &[
    // ── VPS1 (212.227.54.241) – primärer Mainnet-Bootstrap + Relay ───
    // NUR TCP (siehe Begründung bei SEED_NODES_TESTNET).
    // HINWEIS: PeerIds hier sind noch die ALTEN – bei Mainnet-Reaktivierung
    //          mit den aktuellen PeerIds der Mainnet-Nodes ersetzen.
    "/ip4/212.227.54.241/tcp/5001/p2p/12D3KooWJvLC6jmFoHr5JFbH4XFomdGMCGHnFWKGgEmMSS4KcSjN",
    "/ip6/2a02:2479:a0:fa00::1/tcp/5001/p2p/12D3KooWJvLC6jmFoHr5JFbH4XFomdGMCGHnFWKGgEmMSS4KcSjN",
    // ── VPS2 (69.48.200.255) – sekundärer Mainnet-Bootstrap + Relay ───
    "/ip4/69.48.200.255/tcp/5001/p2p/12D3KooWJ1VKWsboQB5mf8w4iLCSJYCB1xxGTUPySm2tAwN4Uwyz",
    "/ip6/2607:f1c0:f074:4300::1/tcp/5001/p2p/12D3KooWJ1VKWsboQB5mf8w4iLCSJYCB1xxGTUPySm2tAwN4Uwyz",
];

/// Gibt die Seed-Nodes für das aktive Netzwerk zurück.
fn active_seed_nodes() -> &'static [&'static str] {
    if is_mainnet() { SEED_NODES_MAINNET } else { SEED_NODES_TESTNET }
}

/// Kompakter Bericht zur Seed-/Bootstrap-Diversität.
#[derive(Debug, Clone, Default)]
pub struct BootstrapDiversityReport {
    pub total_entries: usize,
    pub unique_peer_ids: usize,
    pub unique_ipv4_prefixes_16: usize,
}

/// Analysiert Bootstrap-Nodes auf Identitäts-/Netzwerk-Diversität.
pub fn analyze_bootstrap_diversity(nodes: &[String]) -> BootstrapDiversityReport {
    let mut peer_ids: HashSet<String> = HashSet::new();
    let mut ipv4_prefixes: HashSet<String> = HashSet::new();

    for raw in nodes {
        let Ok(addr) = raw.parse::<Multiaddr>() else { continue };
        for p in addr.iter() {
            match p {
                libp2p::multiaddr::Protocol::P2p(pid) => {
                    peer_ids.insert(pid.to_string());
                }
                libp2p::multiaddr::Protocol::Ip4(ip) => {
                    let o = ip.octets();
                    ipv4_prefixes.insert(format!("{}.{}", o[0], o[1]));
                }
                _ => {}
            }
        }
    }

    BootstrapDiversityReport {
        total_entries: nodes.len(),
        unique_peer_ids: peer_ids.len(),
        unique_ipv4_prefixes_16: ipv4_prefixes.len(),
    }
}

fn seed_host_from_multiaddr(seed: &str) -> Option<String> {
    let addr = seed.parse::<Multiaddr>().ok()?;
    for p in addr.iter() {
        match p {
            libp2p::multiaddr::Protocol::Ip4(ip) => return Some(ip.to_string()),
            libp2p::multiaddr::Protocol::Ip6(ip) => return Some(ip.to_string()),
            _ => {}
        }
    }
    None
}

/// Liefert die Standard-HTTP-Bootstrap-URLs (pro Host eindeutig) aus den
/// eingebauten Seed-Nodes für das aktive Netzwerk.
///
/// Port-Override: `STONE_BOOTSTRAP_HTTP_PORT` (Default: 8080)
pub fn default_bootstrap_http_urls() -> Vec<String> {
    let port = std::env::var("STONE_BOOTSTRAP_HTTP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8080);

    let mut hosts: HashSet<String> = HashSet::new();
    for seed in active_seed_nodes() {
        if let Some(host) = seed_host_from_multiaddr(seed) {
            hosts.insert(host);
        }
    }

    let mut urls: Vec<String> = hosts
        .into_iter()
        .map(|host| {
            if host.contains(':') {
                format!("http://[{host}]:{port}")
            } else {
                format!("http://{host}:{port}")
            }
        })
        .collect();
    urls.sort();
    urls
}

/// Gibt das aktive Daten-Verzeichnis zurück.
/// Kann per `STONE_DATA_DIR` überschrieben werden.
/// Mainnet: `stone_data_mainnet/`, Testnet: `stone_data/`.
fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| {
        if is_mainnet() {
            DEFAULT_DATA_DIR_MAINNET.to_string()
        } else {
            DEFAULT_DATA_DIR.to_string()
        }
    })
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

    /// Bootstrap-Nodes aus ENV `STONE_BOOTSTRAP_NODES` / `STONE_SEED_NODES` (kommagetrennt)
    /// laden und eingebaute Seed-Nodes hinzufügen.
    /// Wählt automatisch die Seeds für Mainnet oder Testnet (STONE_NETWORK).
    pub fn merge_env(&mut self) {
        // ── Seed-Nodes automatisch hinzufügen ─────────────────────────────────
        // Kann per STONE_NO_SEED=1 deaktiviert werden (für isolierte Netze)
        if std::env::var("STONE_NO_SEED").as_deref() != Ok("1") {
            for seed in active_seed_nodes() {
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

        // Beide ENV-Variablen unterstützen (STONE_BOOTSTRAP_NODES + STONE_SEED_NODES)
        for env_key in ["STONE_BOOTSTRAP_NODES", "STONE_SEED_NODES"] {
            if let Ok(raw) = std::env::var(env_key) {
                for addr in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if !self.bootstrap_nodes.contains(&addr.to_string()) {
                        self.bootstrap_nodes.push(addr.to_string());
                    }
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

        // Guardrail: exakte Duplikate entfernen.
        {
            let mut seen = HashSet::new();
            self.bootstrap_nodes.retain(|addr| seen.insert(addr.clone()));
        }

        // Guardrail: mehrere Addrs mit gleicher PeerId zählen nicht als Seed-Diversität.
        {
            let mut preferred: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let mut order: Vec<String> = Vec::new();

            for addr in &self.bootstrap_nodes {
                let Ok(ma) = addr.parse::<Multiaddr>() else { continue };
                let pid = ma.iter().find_map(|p| {
                    if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                        Some(pid.to_string())
                    } else {
                        None
                    }
                });
                let Some(pid) = pid else { continue };
                let has_quic = ma.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::QuicV1));

                if !preferred.contains_key(&pid) {
                    order.push(pid.clone());
                    preferred.insert(pid, addr.clone());
                    continue;
                }

                let current_has_quic = preferred
                    .get(&pid)
                    .and_then(|current| current.parse::<Multiaddr>().ok())
                    .map(|current| current.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::QuicV1)))
                    .unwrap_or(false);

                if has_quic && !current_has_quic {
                    preferred.insert(pid, addr.clone());
                }
            }

            self.bootstrap_nodes = order
                .into_iter()
                .filter_map(|pid| preferred.remove(&pid))
                .collect();
        }

        let diversity = analyze_bootstrap_diversity(&self.bootstrap_nodes);
        if diversity.total_entries > 0 {
            println!(
                "[p2p] Seed-Diversität: total={} unique_peer_ids={} unique_ipv4_/16={}",
                diversity.total_entries,
                diversity.unique_peer_ids,
                diversity.unique_ipv4_prefixes_16,
            );
            if diversity.unique_peer_ids < 2 {
                eprintln!(
                    "[p2p] ⚠ Niedrige Seed-Diversität: nur {} eindeutige PeerId(s)",
                    diversity.unique_peer_ids,
                );
            }
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

    // ── Chat-Pool-Events ──────────────────────────────────────────────────
    /// Eine Chat-Nachricht wurde per Gossipsub von einem Peer empfangen
    ChatMessageReceived {
        message: crate::message_pool::PooledMessage,
        from_peer: String,
    },

    /// Off-chain Chat-Content empfangen (DSGVO: nur encrypted_content, nicht on-chain)
    ChatContentReceived {
        content: crate::chat::ChatContentSync,
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

    /// Batch-Blöcke aus Range-Sync (Fork-Reorg-fähig).
    /// Enthält die vollständige Block-Range vom Peer — wird als Batch
    /// verarbeitet um Fork-Punkt zu finden und Chain zu reorgen.
    RangeSyncReceived {
        blocks: Vec<Block>,
        from_peer: String,
    },

    /// Miner-Identity/Heartbeat über Gossipsub (für Cluster-weite
    /// Sichtbarkeit aktiver Miner und damit den BlockTimer pausieren).
    MinerGossipReceived {
        /// "connect" oder "heartbeat"
        kind: String,
        /// JSON-serialisierte MinerConnectMsg oder MinerHeartbeat
        payload: Vec<u8>,
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

    /// Penalty für einen Peer melden (aus den Binaries/Handlern heraus)
    ReportPenalty {
        peer_id_str: String,
        points: u32,
        reason: String,
    },

    /// Eigenen Stake-Level setzen (wird von MasterNode periodisch aufgerufen).
    /// Beeinflusst Relay-Priorität: höherer Stake = Peers bevorzugen uns als Sync-Quelle.
    SetStakeLevel(u64),
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
            Self::ReportPenalty { peer_id_str, points, .. } => write!(f, "ReportPenalty({peer_id_str}, {points})"),
            Self::SetStakeLevel(level) => write!(f, "SetStakeLevel({level})"),
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
    /// Selbstheilungsstatus des Sync-Pfads (WS-C)
    pub sync_recovery: SyncRecoveryStatus,
    /// Zustand des deterministischen Health-Controllers
    pub health_controller: HealthControllerStatus,
}

/// Laufzeitstatus der Sync-Selbstheilung (WS-C Stage 1/2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecoveryStatus {
    /// "idle", "stage1_soft_reset" oder "stage2_peer_switch"
    pub stage: String,
    /// Anzahl ausgeführter Recovery-Aktionen seit Start
    pub attempts: u32,
    /// Sekunden seit letztem messbaren Sync-Fortschritt
    pub seconds_since_progress: u64,
    /// Aktueller Sync-Target-Peer (falls aktiv)
    pub target_peer: Option<String>,
    /// Letzter Recovery-Grund (menschenlesbar)
    pub last_reason: String,
}

/// Laufzeitstatus des deterministischen Health-Controllers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthControllerStatus {
    /// "healthy", "degraded", "isolated", ...
    pub state: String,
    /// Klassifizierte Fehlerklasse oder "none"
    pub failure: String,
    /// Aktuelle Recovery-Eskalation oder "none"
    pub recovery_level: String,
    /// Sekunden seit letzter Zustands-Transition
    pub seconds_since_transition: u64,
    /// Cooldown bis zur nächsten Health-Aktion
    pub cooldown_remaining_secs: u64,
    /// Letzter Controller-Grundtext
    pub last_reason: String,
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
    /// Durchschnittliche Latenz in ms (aus Keepalive-Pings, None wenn noch kein Ping)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_latency_ms: Option<u64>,
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
    /// Stake-Level des Peers (0=Observer, 100=Participant, 250=Guardian, 500=Validator)
    /// Wird via SyncHandshake bekanntgegeben.
    #[serde(default)]
    pub stake_level: u64,
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
            // Max 1800 Requests/min, Burst 300 (Initial-Sync kann hunderte Range-Requests erzeugen)
            requests: TokenBucket::new(300.0, 1800.0),
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

/// PeerIds der eingebauten Seed/Bootstrap-Nodes (aus SEED_NODES extrahiert).
const BOOTSTRAP_PEER_IDS: &[&str] = &[
    "12D3KooWECEPy5EnZ7HwvwnABBwnJwU4jSMh5U1HpzRBaXK9kmoP", // VPS1
    "12D3KooWFkXVx4zBFMmsdC6Qr5pAn5FdPLbeyCFTsFhsn2CW39Tw", // VPS2
];

/// Prüft ob dieser Node ein Bootstrap-/Seed-Node ist.
///
/// Erkennung:
/// 1. `STONE_IS_BOOTSTRAP=1` Env-Variable (explizit gesetzt)
/// 2. Lokale PeerId stimmt mit einem der eingebauten SEED_NODES überein
pub fn is_bootstrap_node() -> bool {
    // Env-Override (für Tests oder manuelle Zuweisung)
    if std::env::var("STONE_IS_BOOTSTRAP").as_deref() == Ok("1") {
        return true;
    }
    // PeerId-basierte Erkennung
    if let Some(local_id) = read_peer_id() {
        return BOOTSTRAP_PEER_IDS.iter().any(|&id| id == local_id);
    }
    false
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
    //
    // - `validate_messages()` aktiviert manuelle Validierung: empfangene
    //   Nachrichten werden NICHT automatisch weitergeleitet, sondern müssen vom
    //   Anwendungscode via `report_message_validation_result(...)` mit
    //   Accept/Reject/Ignore quittiert werden. Reject zieht zusätzlich
    //   PeerScore-Punkte ab (P4-Penalty), was Mesh-Pruning auslöst.
    // - `max_transmit_size = 8 MiB` deckt bincode-kodierte Blöcke bis nahe ans
    //   `MAX_BLOCK_SIZE`-Limit (16 MiB JSON ≈ 4-8 MiB bincode) ab, ohne den
    //   Gossip-Pfad als DoS-Vektor zu öffnen.
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages()
        .max_transmit_size(10 * 1024 * 1024)  // muss == MAX_GOSSIP_BLOCK_BYTES (10 MiB) sein
        .build()
        .map_err(|e| format!("Gossipsub-Config: {e}"))?;

    let mut gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| format!("Gossipsub init: {e}"))?;

    // ── Gossipsub PeerScore ──────────────────────────────────────────────────
    //
    // Aktiviert Mesh-Scoring mit den libp2p-Defaults. Wirkt zusätzlich zu
    // unserem Custom-Penalty-System: Peers die invalid messages
    // (`MessageAcceptance::Reject`) liefern bekommen P4-Penalty und werden aus
    // dem Mesh gepruned. Verhindert dass ein einzelner böser Peer den
    // Block-Broadcast-Pfad blockiert.
    let score_params = gossipsub::PeerScoreParams::default();
    let score_thresholds = gossipsub::PeerScoreThresholds::default();
    gossipsub
        .with_peer_score(score_params, score_thresholds)
        .map_err(|e| format!("Gossipsub PeerScore: {e}"))?;

    // ── Kademlia ──────────────────────────────────────────────────────────────
    //
    // StreamProtocol-Name enthält Netzwerk-Tag. Mainnet- und Testnet-Nodes
    // teilen daher keine Routing-Tabellen.
    let kad_proto: &'static str = Box::leak(
        format!("/stone/{}/kad/1.0.0", net_tag()).into_boxed_str(),
    );
    let mut kad_config = kad::Config::new(
        libp2p::StreamProtocol::new(kad_proto),
    );
    kad_config.set_query_timeout(Duration::from_secs(config.connection_timeout_secs));
    // Security Fix: DHT-Poisoning-Mitigation via S/Kademlia.
    // FilterBoth = nur Records von Peers in der eigenen Routing-Tabelle akzeptieren.
    kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
    let kad = kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

    // ── Identify ──────────────────────────────────────────────────────────────
    //
    // Identify-Protocol-Name enthält Netzwerk-Tag (Cross-Net-Isolation).
    // agent_version bleibt netzunabhängig – wird für Major-Version-Check
    // genutzt.
    let identify_config = identify::Config::new(
        format!("/stone/{}/id/1.0.0", net_tag()),
        keypair.public(),
    ).with_agent_version(format!("stone/{}", env!("CARGO_PKG_VERSION")));
    let identify = identify::Behaviour::new(identify_config);

    // ── mDNS ──────────────────────────────────────────────────────────────────
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

    // ── Request/Response (Block-Austausch) ────────────────────────────────────
    let block_proto: &'static str = Box::leak(
        format!("/stone/{}/block-exchange/1.0.0", net_tag()).into_boxed_str(),
    );
    let block_exchange = request_response::cbor::Behaviour::new(
        [(
            libp2p::StreamProtocol::new(block_proto),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    // ── Request/Response (Shard-Austausch) ────────────────────────────────────
    let shard_proto: &'static str = Box::leak(
        format!("/stone/{}/shard-exchange/1.0.0", net_tag()).into_boxed_str(),
    );
    let shard_exchange = request_response::cbor::Behaviour::new(
        [(
            libp2p::StreamProtocol::new(shard_proto),
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
