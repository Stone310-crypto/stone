//! Freundesliste & Kontakte — Off-Chain mit DB-Synchronisation.
//!
//! ## Design
//! - Freundesliste wird **lokal** in einer SQLite-DB gespeichert
//! - Sync zwischen eigenen Geräten via Stone-P2P (optional)
//! - Jeder Kontakt hat: VPN-ID, Wallet-Hash (zur Verifikation), Anzeigename
//! - ID-Wechsel wird automatisch erkannt (via Wallet-Hash-Match)
//!
//! ## Privacy
//! - Die Freundesliste verlässt NIE das lokale Gerät
//! - Nur Freundschaftsanfragen werden übers Netzwerk gesendet
//! - Wallet-Hash wird nur bei ID-Wechsel mit Freunden geteilt

use crate::vpn_id::VpnIdManager;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// ── Datenstrukturen ──────────────────────────────────────────────────────────

/// Ein Freund/Kontakt in der Freundesliste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendInfo {
    /// Aktuelle VPN-ID (kann sich ändern bei Rotation)
    pub vpn_id: String,
    /// Anzeigename (frei wählbar, nur für Freunde sichtbar)
    pub display_name: String,
    /// Wallet-Hash (zur Verifikation bei ID-Wechsel)
    pub wallet_hash: [u8; 32],
    /// Seit wann befreundet (Unix-Timestamp)
    pub since: u64,
    /// Letzter bekannter ID-Wechsel (Unix-Timestamp, 0 = nie)
    pub last_id_change: u64,
    /// Status der Freundschaft
    pub status: FriendStatus,
    /// Öffentliche Notiz (optional)
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FriendStatus {
    /// Aktiv befreundet
    Active,
    /// Blockiert
    Blocked,
    /// Ausgehende Anfrage wartet
    PendingSent,
    /// Eingehende Anfrage wartet
    PendingReceived,
}

/// Eine Freundschaftsanfrage (wird übers Netzwerk gesendet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendRequest {
    /// UUID für diese Anfrage (16 bytes)
    pub request_id: [u8; 16],
    /// Von welcher VPN-ID
    pub from_id: String,
    /// An welche VPN-ID (Empfänger)
    pub to_id: String,
    /// Anzeigename des Anfragenden
    pub display_name: String,
    /// Wallet-Hash des Anfragenden (für spätere ID-Wechsel-Erkennung)
    pub wallet_hash: [u8; 32],
    /// Ed25519-Signatur über (from_id || to_id || request_id || timestamp)
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Ed25519 Public Key des Anfragenden
    pub public_key: [u8; 32],
    /// Unix-Timestamp
    pub timestamp: u64,
}

/// Antwort auf eine Freundschaftsanfrage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendResponse {
    /// UUID der ursprünglichen Anfrage
    pub request_id: [u8; 16],
    /// Von welcher VPN-ID (der Antwortende)
    pub from_id: String,
    /// An welche VPN-ID (der Anfragende)
    pub to_id: String,
    /// Akzeptiert?
    pub accepted: bool,
    /// Anzeigename des Antwortenden (falls akzeptiert)
    pub display_name: String,
    /// Wallet-Hash des Antwortenden
    pub wallet_hash: [u8; 32],
    /// Signatur (wie bei Request)
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Public Key
    pub public_key: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

/// Benachrichtigung über ID-Wechsel an alle Freunde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdChangeNotify {
    /// Alte VPN-ID
    pub old_id: String,
    /// Neue VPN-ID
    pub new_id: String,
    /// Wallet-Hash (muss mit bekanntem Hash übereinstimmen)
    pub wallet_hash: [u8; 32],
    /// Ed25519-Signatur über (old_id || new_id || wallet_hash || timestamp)
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Ed25519 Public Key
    pub public_key: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

// ── FriendRegistry ───────────────────────────────────────────────────────────

/// Verwaltet die Freundesliste inkl. ausstehender Anfragen.
pub struct FriendRegistry {
    /// Eigene VPN-ID (für Signatur-Prüfung)
    my_current_id: String,
    /// Eigener Wallet-Hash
    my_wallet_hash: [u8; 32],
    /// Eigener Ed25519 Public Key
    my_public_key: [u8; 32],
    /// Freundesliste: VPN-ID → FriendInfo
    friends: HashMap<String, FriendInfo>,
    /// Ausgehende Anfragen (Request-ID → Request)
    pending_sent: HashMap<[u8; 16], FriendRequest>,
    /// Eingehende Anfragen (Request-ID → Request)
    pending_received: HashMap<[u8; 16], FriendRequest>,
}

impl FriendRegistry {
    /// Erstellt eine neue FriendRegistry.
    pub fn new(
        my_current_id: String,
        my_wallet_hash: [u8; 32],
        my_public_key: [u8; 32],
    ) -> Self {
        FriendRegistry {
            my_current_id,
            my_wallet_hash,
            my_public_key,
            friends: HashMap::new(),
            pending_sent: HashMap::new(),
            pending_received: HashMap::new(),
        }
    }

    /// Aktualisiert die eigene VPN-ID (nach Rotation).
    pub fn update_my_id(&mut self, new_id: String) {
        self.my_current_id = new_id;
    }

    // ── Freundesliste ────────────────────────────────────────────────────

    /// Fügt einen Freund hinzu (nach akzeptierter Anfrage).
    pub fn add_friend(&mut self, info: FriendInfo) {
        self.friends.insert(info.vpn_id.clone(), info);
    }

    /// Entfernt einen Freund.
    pub fn remove_friend(&mut self, vpn_id: &str) -> Option<FriendInfo> {
        self.friends.remove(vpn_id)
    }

    /// Findet einen Freund anhand der VPN-ID.
    pub fn find_by_id(&self, vpn_id: &str) -> Option<&FriendInfo> {
        self.friends.get(vpn_id)
    }

    /// Findet einen Freund anhand des Wallet-Hashes (für ID-Wechsel-Erkennung).
    pub fn find_by_wallet_hash(&self, wallet_hash: &[u8; 32]) -> Option<&FriendInfo> {
        self.friends.values().find(|f| &f.wallet_hash == wallet_hash)
    }

    /// Aktualisiert die VPN-ID eines Freundes (nach ID-Wechsel-Benachrichtigung).
    /// Nur erfolgreich wenn der Wallet-Hash übereinstimmt.
    pub fn update_friend_id(
        &mut self,
        old_id: &str,
        new_id: &str,
        wallet_hash: &[u8; 32],
    ) -> Result<(), String> {
        let friend = self.friends.get(old_id)
            .ok_or_else(|| format!("Freund mit ID {old_id} nicht gefunden"))?;

        if &friend.wallet_hash != wallet_hash {
            return Err("Wallet-Hash stimmt nicht überein — ID-Wechsel abgelehnt.".into());
        }

        let mut updated = friend.clone();
        updated.vpn_id = new_id.to_string();
        updated.last_id_change = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.friends.remove(old_id);
        self.friends.insert(new_id.to_string(), updated);
        Ok(())
    }

    /// Gibt alle aktiven Freunde zurück.
    pub fn all_friends(&self) -> Vec<&FriendInfo> {
        self.friends.values()
            .filter(|f| f.status == FriendStatus::Active)
            .collect()
    }

    /// Prüft ob jemand bereits ein Freund ist (egal unter welcher ID).
    pub fn is_friend_by_wallet(&self, wallet_hash: &[u8; 32]) -> bool {
        self.friends.values()
            .any(|f| &f.wallet_hash == wallet_hash && f.status == FriendStatus::Active)
    }

    // ── Anfragen ──────────────────────────────────────────────────────────

    /// Erstellt eine neue ausgehende Freundschaftsanfrage.
    pub fn create_request(
        &mut self,
        request_id: [u8; 16],
        to_id: String,
        display_name: String,
        signature: Vec<u8>,
    ) -> FriendRequest {
        let req = FriendRequest {
            request_id,
            from_id: self.my_current_id.clone(),
            to_id,
            display_name,
            wallet_hash: self.my_wallet_hash,
            signature,
            public_key: self.my_public_key,
            timestamp: now_secs(),
        };
        self.pending_sent.insert(request_id, req.clone());
        req
    }

    /// Empfängt eine eingehende Freundschaftsanfrage.
    pub fn receive_request(&mut self, req: FriendRequest) {
        self.pending_received.insert(req.request_id, req);
    }

    /// Akzeptiert eine eingehende Anfrage.
    pub fn accept_request(&mut self, request_id: &[u8; 16]) -> Option<FriendInfo> {
        let req = self.pending_received.remove(request_id)?;
        let friend = FriendInfo {
            vpn_id: req.from_id,
            display_name: req.display_name,
            wallet_hash: req.wallet_hash,
            since: now_secs(),
            last_id_change: 0,
            status: FriendStatus::Active,
            note: String::new(),
        };
        self.friends.insert(friend.vpn_id.clone(), friend.clone());
        Some(friend)
    }

    /// Lehnt eine eingehende Anfrage ab.
    pub fn reject_request(&mut self, request_id: &[u8; 16]) {
        self.pending_received.remove(request_id);
    }

    /// Markiert eine ausgehende Anfrage als akzeptiert.
    pub fn mark_sent_accepted(&mut self, request_id: &[u8; 16], display_name: String, wallet_hash: [u8; 32]) -> Option<FriendInfo> {
        let req = self.pending_sent.remove(request_id)?;
        let friend = FriendInfo {
            vpn_id: req.to_id,
            display_name,
            wallet_hash,
            since: now_secs(),
            last_id_change: 0,
            status: FriendStatus::Active,
            note: String::new(),
        };
        self.friends.insert(friend.vpn_id.clone(), friend.clone());
        Some(friend)
    }

    /// Gibt alle ausstehenden eingehenden Anfragen zurück.
    pub fn pending_received_requests(&self) -> Vec<&FriendRequest> {
        self.pending_received.values().collect()
    }

    /// Gibt alle ausstehenden ausgehenden Anfragen zurück.
    pub fn pending_sent_requests(&self) -> Vec<&FriendRequest> {
        self.pending_sent.values().collect()
    }

    // ── Zugriff ───────────────────────────────────────────────────────────

    pub fn my_id(&self) -> &str { &self.my_current_id }
    pub fn my_wallet_hash(&self) -> [u8; 32] { self.my_wallet_hash }
    pub fn my_public_key(&self) -> [u8; 32] { self.my_public_key }
    pub fn friend_count(&self) -> usize {
        self.friends.values().filter(|f| f.status == FriendStatus::Active).count()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ids() -> (String, [u8; 32], [u8; 32]) {
        let id = VpnIdManager::new().current_id;
        let wallet_hash = [1u8; 32];
        let pubkey = [2u8; 32];
        (id, wallet_hash, pubkey)
    }

    #[test]
    fn test_add_and_find_friend() {
        let (my_id, my_wh, my_pk) = make_ids();
        let mut reg = FriendRegistry::new(my_id, my_wh, my_pk);

        let friend = FriendInfo {
            vpn_id: "abcdef01".into(),
            display_name: "Alice".into(),
            wallet_hash: [3u8; 32],
            since: now_secs(),
            last_id_change: 0,
            status: FriendStatus::Active,
            note: String::new(),
        };
        reg.add_friend(friend);
        assert_eq!(reg.friend_count(), 1);
        assert!(reg.find_by_id("abcdef01").is_some());
    }

    #[test]
    fn test_friend_request_flow() {
        let (my_id, my_wh, my_pk) = make_ids();
        let mut reg = FriendRegistry::new(my_id, my_wh, my_pk);

        // Create outgoing request
        let rid = [4u8; 16];
        let sig = vec![5u8; 64];
        let req = reg.create_request(rid, "target01".into(), "Bob".into(), sig);
        assert_eq!(reg.pending_sent_requests().len(), 1);

        // Simulate acceptance
        let friend = reg.mark_sent_accepted(&rid, "Bob".into(), [6u8; 32]).unwrap();
        assert_eq!(friend.display_name, "Bob");
        assert_eq!(reg.friend_count(), 1);
        assert_eq!(reg.pending_sent_requests().len(), 0);
    }

    #[test]
    fn test_id_change_update() {
        let (my_id, my_wh, my_pk) = make_ids();
        let mut reg = FriendRegistry::new(my_id, my_wh, my_pk);

        let friend_wallet = [7u8; 32];
        let friend = FriendInfo {
            vpn_id: "old12345".into(),
            display_name: "Charlie".into(),
            wallet_hash: friend_wallet,
            since: now_secs(),
            last_id_change: 0,
            status: FriendStatus::Active,
            note: String::new(),
        };
        reg.add_friend(friend);

        // ID change
        reg.update_friend_id("old12345", "new67890", &friend_wallet).unwrap();
        assert!(reg.find_by_id("old12345").is_none());
        assert!(reg.find_by_id("new67890").is_some());
    }

    #[test]
    fn test_id_change_wrong_wallet_rejected() {
        let (my_id, my_wh, my_pk) = make_ids();
        let mut reg = FriendRegistry::new(my_id, my_wh, my_pk);

        let friend = FriendInfo {
            vpn_id: "old12345".into(),
            display_name: "Eve".into(),
            wallet_hash: [7u8; 32],
            since: now_secs(),
            last_id_change: 0,
            status: FriendStatus::Active,
            note: String::new(),
        };
        reg.add_friend(friend);

        // Wrong wallet hash → rejected
        let result = reg.update_friend_id("old12345", "malicious", &[9u8; 32]);
        assert!(result.is_err());
    }
}
