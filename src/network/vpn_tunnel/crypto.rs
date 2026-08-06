//! Kryptographie für den VPN-Tunnel: X25519 + ChaCha20Poly1305.
//!
//! Kompatibel mit dem Stone-VPN Protokoll (stonevpn-core).
//! Jede Node hat ein X25519-Keypair. Datenpakete werden mit
//! ChaCha20Poly1305 (AEAD) verschlüsselt.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Sha256, Digest};
use std::path::Path;

const VPN_KEY_FILE: &str = "vpn_key.bin";

/// X25519-Keypair einer VPN-Node.
#[derive(Clone)]
pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    /// Lädt das Keypair aus dem stone_data-Verzeichnis oder generiert ein neues.
    pub fn load_or_create(stone_data: &str) -> Result<Self, String> {
        let path = Path::new(stone_data).join(VPN_KEY_FILE);

        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| format!("VPN-Key lesen: {e}"))?;
            if bytes.len() != 32 {
                return Err("VPN-Keyfile korrupt (nicht 32 Bytes)".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let secret = StaticSecret::from(arr);
            let public = PublicKey::from(&secret);
            return Ok(Keypair { secret, public });
        }

        // Neues Keypair generieren und speichern
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let bytes = secret.to_bytes();
        std::fs::create_dir_all(stone_data).map_err(|e| format!("Verzeichnis: {e}"))?;
        std::fs::write(&path, bytes).map_err(|e| format!("VPN-Key schreiben: {e}"))?;
        eprintln!("[vpn-tunnel] 🔑 Neues VPN-Keypair: {}", path.display());
        Ok(Keypair { secret, public })
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public_bytes())
    }

    /// ECDH: Shared Secret mit einem anderen Public Key ableiten.
    pub fn shared_secret(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_pk = PublicKey::from(*their_public);
        *self.secret.diffie_hellman(&their_pk).as_bytes()
    }

    /// ChaCha20Poly1305 verschlüsseln (AEAD).
    pub fn encrypt(&self, plaintext: &[u8], nonce_bytes: &[u8; 12], shared_key: &[u8; 32]) -> Vec<u8> {
        let key = Key::from_slice(shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.encrypt(nonce, plaintext).unwrap_or_else(|_| vec![])
    }

    /// ChaCha20Poly1305 entschlüsseln (AEAD).
    pub fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8; 12], shared_key: &[u8; 32]) -> Option<Vec<u8>> {
        let key = Key::from_slice(shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext).ok()
    }
}

/// Generiert eine 96-bit Nonce aus einem Counter (monoton steigend).
pub fn make_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Hashed ein Passwort mit SHA-256.
pub fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Unix-Timestamp in Sekunden.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
