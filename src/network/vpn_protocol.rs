//! VPN Protocol — Mesh-VPN direkt im libp2p-Swarm.
//!
//! ## Architektur
//!
//! Der VPN läuft nicht mehr als separater UDP-Dienst, sondern als
//! libp2p-Protokoll auf demselben Port, mit derselben Identität und
//! demselben NAT-Traversal wie der Rest des Stone-Netzwerks.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │  libp2p Swarm (ein Port, eine Identity)              │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
//! │  │ Gossipsub│ │ Kademlia │ │ VpnProtocol (NEU)    │ │
//! │  │ Blocks   │ │ Peers    │ │ Chat, Friends, ID    │ │
//! │  └──────────┘ └──────────┘ └──────────────────────┘ │
//! │  ┌──────────────────────────────────────────────────┐│
//! │  │ Transport: TCP+Noise / QUIC / Relay              ││
//! │  └──────────────────────────────────────────────────┘│
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Protokolle
//!
//! | Protokoll                    | Typ            | Zweck                        |
//! |------------------------------|----------------|------------------------------|
//! | `/stone/<net>/vpn-id/1.0.0`  | Gossipsub      | VPN-ID Ankündigung + Suche   |
//! | `/stone/<net>/vpn-chat/1.0.0`| RequestResponse| Direkte Chat-Nachrichten      |
//! | `/stone/<net>/vpn-friend/1.0.0`| RequestResponse| Freundschaftsanfragen       |
//!
//! ## VPN-ID
//!
//! Die VPN-ID ist eine zufällige 8-stellige Hex-ID (4 Bytes), die mit dem
//! Account des Nutzers verknüpft wird. Sie wird NICHT aus dem Keypair
//! abgeleitet (Privacy: bei Key-Rotation bleibt die ID gleich).
//!
//! Rotation: Alle 24h oder manuell. Alte IDs bleiben 24h gültig für
//! nahtlose Übergänge.

use libp2p::{
    gossipsub::{self, IdentTopic},
    request_response::{self, ProtocolSupport},
    PeerId, StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── VPN-ID ──────────────────────────────────────────────────────────────────

/// Zufällige 8-stellige Hex-VPN-ID (4 Bytes).
pub fn generate_vpn_id() -> String {
    use rand::Rng;
    let bytes: [u8; 4] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// VPN-ID-Manager (State pro Node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnIdState {
    /// Aktuelle aktive VPN-ID
    pub current_id: String,
    /// Zähler für Rotationen
    pub rotation_count: u32,
    /// Frühere IDs (max 5, 24h gültig)
    pub previous_ids: Vec<PreviousVpnId>,
    /// Unix-Timestamp der letzten Rotation
    pub last_rotation: u64,
    /// Verknüpfter Wallet-Address-Hash (SHA256, nur erste 16 Bytes als Hex)
    pub linked_wallet_hash: Option<String>,
    /// Anzeigename des Nutzers
    pub display_name: String,
    /// VPN-Modus: "relay" (öffentlich), "client" (hinter NAT), "unknown"
    #[serde(default = "default_vpn_mode")]
    pub mode: String,
}

fn default_vpn_mode() -> String { "unknown".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousVpnId {
    pub id: String,
    pub rotated_at: u64,
}

impl VpnIdState {
    pub fn new() -> Self {
        VpnIdState {
            current_id: generate_vpn_id(),
            rotation_count: 0,
            previous_ids: Vec::new(),
            last_rotation: now_secs(),
            linked_wallet_hash: None,
            display_name: String::new(),
            mode: "unknown".into(),
        }
    }

    /// Prüft ob eine ID aktuell gültig ist.
    pub fn is_valid(&self, id: &str) -> bool {
        if id == self.current_id {
            return true;
        }
        let now = now_secs();
        self.previous_ids.iter().any(|p| {
            p.id == id && now.saturating_sub(p.rotated_at) < 86400
        })
    }

    /// Rotiert die VPN-ID.
    pub fn rotate(&mut self) -> String {
        let now = now_secs();
        self.previous_ids.push(PreviousVpnId {
            id: self.current_id.clone(),
            rotated_at: now,
        });
        // Max 5 alte IDs behalten
        while self.previous_ids.len() > 5 {
            self.previous_ids.remove(0);
        }
        // Abgelaufene entfernen
        self.previous_ids.retain(|p| now.saturating_sub(p.rotated_at) < 86400);

        self.current_id = generate_vpn_id();
        self.rotation_count += 1;
        self.last_rotation = now;
        self.current_id.clone()
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Gossipsub: VPN-ID Announce ──────────────────────────────────────────────

/// VPN-ID-Ankündigung die per Gossipsub verteilt wird.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnIdAnnounce {
    /// VPN-ID des Ankündigenden
    pub vpn_id: String,
    /// PeerId (für direkte Verbindung)
    pub peer_id: String,
    /// Wallet-Hash (zur Account-Verknüpfung)
    pub wallet_hash: Option<String>,
    /// Anzeigename
    pub display_name: String,
    /// Anzahl verbundener VPN-Peers
    pub peer_count: u32,
    /// Ist dieser Node als Relay nutzbar? (öffentlich erreichbar)
    pub relay_available: bool,
    /// VPN-Modus: "relay" (öffentlich), "client" (hinter NAT), "unknown"
    pub mode: String,
    /// Unix-Timestamp
    pub timestamp: u64,
}

/// VPN-Modus — wird aus dem NAT-Status + Relay-Reservierungen abgeleitet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VpnMode {
    /// Öffentlich erreichbar, kann als Relay dienen
    Relay,
    /// Hinter NAT, verbindet sich über Relays
    Client,
    /// Noch nicht ermittelt
    Unknown,
}

impl VpnMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            VpnMode::Relay => "relay",
            VpnMode::Client => "client",
            VpnMode::Unknown => "unknown",
        }
    }
}

// ─── RequestResponse: VPN Chat ────────────────────────────────────────────────

/// Eine direkte Chat-Nachricht via libp2p RequestResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnChatMessage {
    /// Eindeutige Nachrichten-ID
    pub message_id: String,
    /// Absender VPN-ID
    pub from_id: String,
    /// Empfänger VPN-ID
    pub to_id: String,
    /// Inhalt (verschlüsselt mit Empfänger-Public-Key)
    pub encrypted_content: Vec<u8>,
    /// Nonce für ChaCha20Poly1305 (12 Bytes)
    pub nonce: Vec<u8>,
    /// Unix-Timestamp
    pub timestamp: u64,
    /// Optional: Referenz auf vorherige Nachricht
    pub reply_to: Option<String>,
}

/// Chat-Request: Sende Nachricht an einen Peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnChatRequest {
    pub message: VpnChatMessage,
}

/// Chat-Response: Bestätigung oder Fehler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnChatResponse {
    pub accepted: bool,
    pub error: Option<String>,
}

// ─── RequestResponse: VPN Friend ──────────────────────────────────────────────

/// Freundschaftsanfrage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnFriendRequest {
    /// UUID für diese Anfrage
    pub request_id: String,
    /// Absender VPN-ID
    pub from_id: String,
    /// Empfänger VPN-ID
    pub to_id: String,
    /// Anzeigename des Anfragenden
    pub display_name: String,
    /// Wallet-Hash des Anfragenden
    pub wallet_hash: String,
    /// Unix-Timestamp
    pub timestamp: u64,
}

/// Antwort auf Freundschaftsanfrage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnFriendResponse {
    pub request_id: String,
    pub accepted: bool,
    pub from_id: String,
    pub display_name: String,
    pub wallet_hash: String,
    pub timestamp: u64,
}

// ─── Known VPN Peers (via Gossipsub Discovery) ────────────────────────────────

/// Ein via Gossipsub entdeckter VPN-Peer.
#[derive(Debug, Clone)]
pub struct VpnPeer {
    pub vpn_id: String,
    pub peer_id: PeerId,
    pub display_name: String,
    pub wallet_hash: Option<String>,
    pub last_seen: u64,
}

/// Registry für via Gossipsub entdeckte VPN-Peers.
pub struct VpnPeerRegistry {
    /// vpn_id → VpnPeer
    peers: HashMap<String, VpnPeer>,
    /// peer_id → vpn_id (reverse lookup)
    peer_to_vpn: HashMap<PeerId, String>,
}

impl VpnPeerRegistry {
    pub fn new() -> Self {
        VpnPeerRegistry {
            peers: HashMap::new(),
            peer_to_vpn: HashMap::new(),
        }
    }

    pub fn upsert(&mut self, announce: &VpnIdAnnounce, peer_id: PeerId) {
        let peer = VpnPeer {
            vpn_id: announce.vpn_id.clone(),
            peer_id,
            display_name: announce.display_name.clone(),
            wallet_hash: announce.wallet_hash.clone(),
            last_seen: announce.timestamp,
        };
        self.peer_to_vpn.insert(peer_id, announce.vpn_id.clone());
        self.peers.insert(announce.vpn_id.clone(), peer);
    }

    pub fn by_vpn_id(&self, vpn_id: &str) -> Option<&VpnPeer> {
        self.peers.get(vpn_id)
    }

    pub fn by_peer_id(&self, peer_id: &PeerId) -> Option<&VpnPeer> {
        self.peer_to_vpn
            .get(peer_id)
            .and_then(|id| self.peers.get(id))
    }

    pub fn all(&self) -> Vec<&VpnPeer> {
        self.peers.values().collect()
    }

    pub fn count(&self) -> usize {
        self.peers.len()
    }

    /// Peers die länger als `timeout_secs` nicht gesehen wurden entfernen.
    pub fn cleanup(&mut self, timeout_secs: u64) {
        let now = now_secs();
        self.peers.retain(|_, p| now.saturating_sub(p.last_seen) < timeout_secs);
        self.peer_to_vpn.retain(|_, id| self.peers.contains_key(id));
    }
}

// ─── NetworkEvents für VPN ───────────────────────────────────────────────────

/// VPN-spezifische Network-Events.
#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// Ein VPN-Peer hat sich via Gossipsub angekündigt.
    VpnPeerAnnounced {
        vpn_id: String,
        peer_id: String,
        display_name: String,
    },
    /// Eine Chat-Nachricht wurde empfangen.
    ChatReceived {
        message: VpnChatMessage,
        from_peer: String,
    },
    /// Eine Freundschaftsanfrage wurde empfangen.
    FriendRequestReceived {
        request: VpnFriendRequest,
        from_peer: String,
    },
    /// Eine Freundschaftsanfrage wurde beantwortet.
    FriendResponseReceived {
        response: VpnFriendResponse,
        from_peer: String,
    },
}

// ─── Codec für RequestResponse ────────────────────────────────────────────────

/// CBOR-Codec für VPN-Nachrichten (nutzt serde für kompakte Kodierung).
/// libp2p's `request_response::cbor` verwendet intern serde_cbor.
/// Wir deklarieren die Behaviour-Typen direkt.

pub type VpnChatBehaviour = request_response::cbor::Behaviour<VpnChatRequest, VpnChatResponse>;
pub type VpnFriendBehaviour = request_response::cbor::Behaviour<VpnFriendRequest, VpnFriendResponse>;

// ─── Gossipsub Topic für VPN-ID Announcements ─────────────────────────────────

use std::sync::LazyLock;

/// VPN-ID Announce Topic (netzwerk-spezifisch).
pub static TOPIC_VPN_ID: LazyLock<String> = LazyLock::new(|| {
    let tag = if crate::network::is_mainnet() { "mainnet" } else { "testnet" };
    format!("stone/{}/vpn-id/v1", tag)
});

/// Erstellt das VPN-ID-Ankündigungs-Topic als IdentTopic.
pub fn vpn_id_topic() -> IdentTopic {
    IdentTopic::new(TOPIC_VPN_ID.as_str())
}

// ─── Helper: Standard RequestResponse Config ──────────────────────────────────

pub fn vpn_request_response_config() -> request_response::Config {
    request_response::Config::default()
}
