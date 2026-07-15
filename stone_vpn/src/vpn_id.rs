//! VPN-ID Manager — Zufällige 8-stellige Hex-IDs mit Rotation.
//!
//! ## Design
//! - VPN-IDs sind zufällig (4 Bytes = 8 Hex), z.B. `0ac5f21e`
//! - Bei Rotation wird eine neue ID generiert, die alte bleibt 24h gültig
//! - IDs werden über den `IdentityStore` persistiert
//! - Die Verknüpfung mit der Wallet erfolgt über Signatur (nicht deterministisch)
//!
//! ## Warum zufällig (nicht deterministisch)?
//! Deterministische IDs (aus Seed + Counter) wären vorhersagbar.
//! Ein Angreifer könnte alle möglichen IDs einer Wallet durchprobieren.
//! Zufällige IDs + Signatur-basierte Verifikation bei ID-Wechsel
//! geben mehr Privacy und Forward-Secrecy.

use rand::Rng;
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximale Anzahl alter IDs, die für die Übergangsphase behalten werden.
const MAX_PREVIOUS_IDS: usize = 5;
/// Wie lange alte IDs gültig bleiben (in Sekunden). Default: 24 Stunden.
const ID_TRANSITION_PERIOD_SECS: u64 = 86400;

/// Eine frühere VPN-ID (für Übergangsphase nach Rotation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousId {
    pub id: String,
    /// Unix-Timestamp der Rotation
    pub rotated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnIdManager {
    /// Aktuelle (aktive) VPN-ID
    pub current_id: String,
    /// Counter für ID-Generierung (nur für Logging/Metriken)
    pub rotation_count: u32,
    /// Frühere IDs (max 5, Übergangsphase 24h)
    pub previous_ids: VecDeque<PreviousId>,
    /// Unix-Timestamp der letzten Rotation
    pub last_rotation: u64,
}

impl VpnIdManager {
    /// Erstellt einen neuen ID-Manager mit einer frischen zufälligen ID.
    pub fn new() -> Self {
        let id = Self::generate_random_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        VpnIdManager {
            current_id: id,
            rotation_count: 0,
            previous_ids: VecDeque::new(),
            last_rotation: now,
        }
    }

    /// Rotiert die VPN-ID: Neue ID generieren, alte in previous_ids verschieben.
    /// Gibt die neue ID zurück.
    pub fn rotate(&mut self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Alte ID in previous_ids verschieben
        self.previous_ids.push_back(PreviousId {
            id: self.current_id.clone(),
            rotated_at: now,
        });

        // Alte IDs aufräumen
        self.cleanup_expired(now);

        // Neue ID generieren
        self.current_id = Self::generate_random_id();
        self.rotation_count += 1;
        self.last_rotation = now;

        self.current_id.clone()
    }

    /// Prüft ob eine ID aktuell gültig ist (aktuelle ID oder in Übergangsphase).
    pub fn is_valid(&self, id: &str) -> bool {
        if id == self.current_id {
            return true;
        }
        self.previous_ids.iter().any(|p| p.id == id)
    }

    /// Entfernt abgelaufene alte IDs (> 24h).
    pub fn cleanup_expired(&mut self, now: u64) {
        while let Some(front) = self.previous_ids.front() {
            if now.saturating_sub(front.rotated_at) > ID_TRANSITION_PERIOD_SECS {
                self.previous_ids.pop_front();
            } else {
                break;
            }
        }
    }

    /// Generiert eine zufällige 8-stellige Hex-ID.
    fn generate_random_id() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 4] = rng.gen();
        hex::encode(bytes)
    }
}

impl Default for VpnIdManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_format() {
        let id = VpnIdManager::generate_random_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_new_id_manager() {
        let mgr = VpnIdManager::new();
        assert_eq!(mgr.current_id.len(), 8);
        assert_eq!(mgr.rotation_count, 0);
        assert!(mgr.previous_ids.is_empty());
        assert!(mgr.is_valid(&mgr.current_id));
        assert!(!mgr.is_valid("deadbeef"));
    }

    #[test]
    fn test_rotate_id() {
        let mut mgr = VpnIdManager::new();
        let old_id = mgr.current_id.clone();
        let new_id = mgr.rotate();

        assert_ne!(old_id, new_id);
        assert_eq!(mgr.rotation_count, 1);
        assert!(mgr.is_valid(&new_id));
        assert!(mgr.is_valid(&old_id)); // noch in Übergangsphase
        assert_eq!(mgr.previous_ids.len(), 1);
        assert_eq!(mgr.previous_ids[0].id, old_id);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut mgr = VpnIdManager::new();
        // Fake eine alte Rotation
        let old_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let very_old = old_now - ID_TRANSITION_PERIOD_SECS - 100;

        mgr.previous_ids.push_back(PreviousId {
            id: "aaaaaaaa".to_string(),
            rotated_at: very_old,
        });
        mgr.previous_ids.push_back(PreviousId {
            id: "bbbbbbbb".to_string(),
            rotated_at: old_now - 100, // noch nicht abgelaufen
        });

        mgr.cleanup_expired(old_now);
        assert_eq!(mgr.previous_ids.len(), 1);
        assert_eq!(mgr.previous_ids[0].id, "bbbbbbbb");
    }
}
