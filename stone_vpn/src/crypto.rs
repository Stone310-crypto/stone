//! Kryptographie: X25519-Keypair + ChaCha20Poly1305-Verschlüsselung.
//!
//! Jede Node hat ein X25519-Keypair. Der Public Key dient als Identität.
//! Der Stone P2P-Ed25519-Key wird NICHT wiederverwendet — X25519 ist ein
//! separates Keypair (aber wir speichern es im gleichen stone_data/ Verzeichnis).

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use std::path::Path;

const VPN_KEY_FILE: &str = "vpn_key.bin";

pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    /// Lädt das Keypair aus stone_data/ oder generiert ein neues.
    pub fn load_or_create(stone_data: &str) -> Result<Self, String> {
        let path = Path::new(stone_data).join(VPN_KEY_FILE);

        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| format!("Read: {e}"))?;
            if bytes.len() != 32 {
                return Err("Keyfile korrupt".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let secret = StaticSecret::from(arr);
            let public = PublicKey::from(&secret);
            return Ok(Keypair { secret, public });
        }

        // Neues Keypair generieren
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let bytes = secret.to_bytes();
        std::fs::create_dir_all(stone_data).map_err(|e| format!("Mkdir: {e}"))?;
        std::fs::write(&path, bytes).map_err(|e| format!("Write: {e}"))?;
        eprintln!("🔑 Neues VPN-Keypair generiert: {}", path.display());
        Ok(Keypair { secret, public })
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// ECDH: Shared Secret mit einem anderen Public Key ableiten.
    pub fn shared_secret(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_pk = PublicKey::from(*their_public);
        *self.secret.diffie_hellman(&their_pk).as_bytes()
    }

    /// ChaCha20Poly1305 verschlüsseln.
    pub fn encrypt(&self, plaintext: &[u8], nonce_bytes: &[u8; 12], shared_key: &[u8; 32]) -> Vec<u8> {
        let key = Key::from_slice(shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.encrypt(nonce, plaintext).unwrap_or_else(|_| vec![])
    }

    /// ChaCha20Poly1305 entschlüsseln.
    pub fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8; 12], shared_key: &[u8; 32]) -> Option<Vec<u8>> {
        let key = Key::from_slice(shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext).ok()
    }
}
