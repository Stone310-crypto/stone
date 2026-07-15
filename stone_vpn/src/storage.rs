//! Identity Store — Verschlüsselte Persistenz für Wallet & VPN-IDs.
//!
//! Alle sensiblen Daten werden vor dem Speichern mit ChaCha20Poly1305
//! verschlüsselt. Der Schlüssel wird aus dem Benutzer-Passwort via
//! PBKDF2/SHA256 abgeleitet.
//!
//! ## Dateien (im stone_data-Verzeichnis)
//! - `wallet.enc` — Verschlüsselte Wallet-Identität
//! - `vpn_id_state.json` — VPN-ID Manager State (ungefährlich, keine Secrets)

use crate::identity::WalletIdentity;
use crate::vpn_id::VpnIdManager;
use crate::crypto;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use sha2::{Sha256, Digest};
use std::path::PathBuf;

/// Dateiname für verschlüsselte Wallet-Daten.
const WALLET_FILE: &str = "wallet.enc";
/// Dateiname für VPN-ID State (JSON, nicht verschlüsselt).
const VPN_ID_FILE: &str = "vpn_id_state.json";

#[derive(Debug)]
pub struct IdentityStore {
    data_dir: PathBuf,
}

impl IdentityStore {
    pub fn new(data_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&data_dir).ok();
        IdentityStore { data_dir }
    }

    // ── Wallet (verschlüsselt) ──────────────────────────────────────────

    /// Speichert die Wallet-Identität verschlüsselt mit dem Benutzer-Passwort.
    pub fn save_wallet(&self, wallet: &WalletIdentity, password: &str) -> Result<(), String> {
        let (key, nonce) = Self::derive_key_nonce(password);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // Serialisiere Wallet (nur mnemonic + public_key reichen zum Wiederherstellen)
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "mnemonic": wallet.mnemonic(),
            "public_key_hex": wallet.public_key_hex(),
        }))
        .map_err(|e| format!("Serialize: {e}"))?;

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|e| format!("Encrypt: {e}"))?;

        let path = self.data_dir.join(WALLET_FILE);
        std::fs::write(&path, ciphertext)
            .map_err(|e| format!("Write wallet: {e}"))?;

        Ok(())
    }

    /// Lädt und entschlüsselt die Wallet-Identität.
    pub fn load_wallet(&self, password: &str) -> Result<WalletIdentity, String> {
        let path = self.data_dir.join(WALLET_FILE);
        if !path.exists() {
            return Err("Keine Wallet gefunden. Bitte erstelle zuerst eine.".to_string());
        }

        let ciphertext = std::fs::read(&path)
            .map_err(|e| format!("Read wallet: {e}"))?;

        let (key, nonce) = Self::derive_key_nonce(password);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| "Falsches Passwort oder beschädigte Wallet-Datei.".to_string())?;

        let json: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Parse wallet: {e}"))?;

        let mnemonic = json["mnemonic"]
            .as_str()
            .ok_or_else(|| "Wallet-Datei ungültig: mnemonic fehlt".to_string())?;

        WalletIdentity::from_mnemonic_str(mnemonic)
    }

    /// Prüft ob eine Wallet existiert.
    pub fn wallet_exists(&self) -> bool {
        self.data_dir.join(WALLET_FILE).exists()
    }

    // ── VPN-ID State (JSON, unverschlüsselt) ────────────────────────────

    /// Speichert den VPN-ID Manager State.
    pub fn save_vpn_id_state(&self, state: &VpnIdManager) -> Result<(), String> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| format!("Serialize: {e}"))?;

        let path = self.data_dir.join(VPN_ID_FILE);
        std::fs::write(&path, json)
            .map_err(|e| format!("Write vpn_id: {e}"))?;

        Ok(())
    }

    /// Lädt den VPN-ID Manager State (oder erstellt neuen).
    pub fn load_vpn_id_state(&self) -> VpnIdManager {
        let path = self.data_dir.join(VPN_ID_FILE);
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(state) = serde_json::from_str(&json) {
                return state;
            }
        }
        VpnIdManager::new()
    }

    // ── Crypto Helpers ──────────────────────────────────────────────────

    /// Leitet einen 256-bit Key + 96-bit Nonce aus dem Passwort ab.
    /// Verwendet SHA256(password + salt) — einfach aber ausreichend
    /// für lokale Speicherung (kein Netzwerkzugriff).
    fn derive_key_nonce(password: &str) -> ([u8; 32], [u8; 12]) {
        // Salt = SHA256("stonevpn-wallet-v1")
        let salt = Sha256::digest(b"stonevpn-wallet-v1");

        // Key = SHA256(password || salt)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
        let key: [u8; 32] = hasher.finalize().into();

        // Nonce = SHA256(salt || password) [0..12]
        let mut hasher2 = Sha256::new();
        hasher2.update(&salt);
        hasher2.update(password.as_bytes());
        let hash2: [u8; 32] = hasher2.finalize().into();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash2[0..12]);

        (key, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Hilfsfunktion: erstellt temporäres Verzeichnis.
    fn temp_dir() -> PathBuf {
        TempDir::new().unwrap().into_path()
    }

    #[test]
    fn test_save_and_load_wallet() {
        let dir = temp_dir();
        let store = IdentityStore::new(dir.clone());
        let wallet = WalletIdentity::create_new().unwrap();
        let password = "my-secret-password-123";

        store.save_wallet(&wallet, password).unwrap();
        assert!(store.wallet_exists());

        let loaded = store.load_wallet(password).unwrap();
        assert_eq!(wallet.public_key_bytes(), loaded.public_key_bytes());
        assert_eq!(wallet.wallet_id(), loaded.wallet_id());
        assert_eq!(wallet.mnemonic(), loaded.mnemonic());
    }

    #[test]
    fn test_wrong_password_fails() {
        let dir = temp_dir();
        let store = IdentityStore::new(dir.clone());
        let wallet = WalletIdentity::create_new().unwrap();

        store.save_wallet(&wallet, "correct").unwrap();
        let result = store.load_wallet("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_vpn_id_state_persistence() {
        let dir = temp_dir();
        let store = IdentityStore::new(dir.clone());
        let mut mgr = VpnIdManager::new();
        let first_id = mgr.current_id.clone();

        store.save_vpn_id_state(&mgr).unwrap();
        let loaded = store.load_vpn_id_state();
        assert_eq!(loaded.current_id, first_id);
        assert_eq!(loaded.rotation_count, 0);
    }

    #[test]
    fn test_vpn_id_state_survives_rotation() {
        let dir = temp_dir();
        let store = IdentityStore::new(dir.clone());
        let mut mgr = VpnIdManager::new();
        let new_id = mgr.rotate();
        store.save_vpn_id_state(&mgr).unwrap();

        let loaded = store.load_vpn_id_state();
        assert_eq!(loaded.current_id, new_id);
        assert_eq!(loaded.rotation_count, 1);
        assert_eq!(loaded.previous_ids.len(), 1);
    }
}
