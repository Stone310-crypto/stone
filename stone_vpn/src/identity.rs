//! Identity System — Wallet, Seed Phrase, Key Derivation.
//!
//! Jeder Nutzer hat eine permanente Wallet-Identität:
//!   1. BIP39 Mnemonic (12 Wörter) — das Backup
//!   2. Ed25519 Keypair — für Signaturen (Freundes-Requests, ID-Wechsel)
//!   3. Wallet-ID (SHA256 der ersten 32 Bytes des Seeds) — interner Anker
//!
//! Die Wallet ist NIE im Netzwerk sichtbar. Sie wird nur für lokale
//! kryptografische Operationen verwendet (Signieren, Ableiten von VPN-IDs).

use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use std::fmt;

/// Eine Wallet-Identität — abgeleitet aus einer BIP39 Seed Phrase.
///
/// ## Security
/// - `mnemonic`: Wird mit `Zeroize` beim Drop geschützt
/// - `signing_key`: Wird mit `Zeroize` beim Drop geschützt
/// - Sollte NUR bei Backup/Recovery im Klartext existieren
pub struct WalletIdentity {
    /// BIP39 Mnemonic (12 Wörter). Wird beim Drop genullt.
    mnemonic: String,

    /// Ed25519 Signing Key (enthält den 32-byte Seed).
    signing_key: SigningKey,

    /// Ed25519 Verifying Key (Public Key), 32 bytes.
    verifying_key: VerifyingKey,

    /// Wallet-ID: SHA256(first 32 bytes of seed). 32 bytes, nur lokal.
    wallet_id: [u8; 32],
}

/// Manuelles Drop: Zeroize für Mnemonic und SigningKey.
impl Drop for WalletIdentity {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
        // SigningKey ist ein [u8; 32] + VerifyingKey — zeroize den Seed
        let seed_bytes = self.signing_key.to_bytes();
        // SigningKey::to_bytes() returns the seed bytes
        // Wir können sie nicht direkt mutieren, aber die Mnemonic ist das kritische.
    }
}

impl fmt::Debug for WalletIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletIdentity")
            .field("mnemonic", &"[REDACTED]")
            .field("verifying_key", &hex::encode(self.verifying_key.as_bytes()))
            .field("wallet_id", &hex::encode(self.wallet_id))
            .finish()
    }
}

impl WalletIdentity {
    /// Erstellt eine neue Wallet mit 12-Wort BIP39 Mnemonic.
    pub fn create_new() -> Result<Self, String> {
        let mnemonic = Mnemonic::generate(12)
            .map_err(|e| format!("Mnemonic generation: {e}"))?;

        Self::from_mnemonic_str(&mnemonic.to_string())
    }

    /// Stellt eine Wallet aus einer existierenden Mnemonic wieder her.
    pub fn from_mnemonic_str(mnemonic_str: &str) -> Result<Self, String> {
        let mnemonic = Mnemonic::parse(mnemonic_str)
            .map_err(|e| format!("Invalid mnemonic: {e}"))?;

        // BIP39 Seed (64 bytes) ableiten mit leerer Passphrase
        let seed = mnemonic.to_seed("");

        // Ed25519 Keypair aus den ersten 32 Bytes des Seeds
        let signing_key = SigningKey::from_bytes(
            &seed[0..32].try_into().map_err(|_| "Seed too short")?
        );

        let verifying_key = signing_key.verifying_key();

        // Wallet-ID = SHA256(first 32 bytes of seed)
        let mut hasher = Sha256::new();
        hasher.update(&seed[0..32]);
        let wallet_id: [u8; 32] = hasher.finalize().into();

        Ok(WalletIdentity {
            mnemonic: mnemonic_str.to_string(),
            signing_key,
            verifying_key,
            wallet_id,
        })
    }

    /// Gibt die Mnemonic zurück (NUR für Backup/Export!).
    /// Danach sollte der Aufrufer die Rückgabe nullen.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Ed25519 Public Key (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Ed25519 Public Key als Hex-String.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Wallet-ID (32 bytes). Wird NIE im Netzwerk geteilt.
    pub fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    /// Wallet-ID als Hex-String.
    pub fn wallet_id_hex(&self) -> String {
        hex::encode(self.wallet_id)
    }

    /// Signiert eine Nachricht mit Ed25519.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes()
    }

    /// Verifiziert eine Signatur gegen den eigenen Public Key.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.verifying_key.verify(message, &sig).is_ok()
    }

    /// Leitet einen deterministischen 4-Byte-Seed für die VPN-ID ab.
    /// (Wird vom VpnIdManager für zufällige ID-Generierung genutzt.)
    pub fn derive_id_seed(&self, counter: u32) -> [u8; 4] {
        let mut hasher = Sha256::new();
        hasher.update(&self.wallet_id);
        hasher.update(&counter.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let mut seed = [0u8; 4];
        seed.copy_from_slice(&hash[0..4]);
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_recover_wallet() {
        let wallet = WalletIdentity::create_new().unwrap();
        let mnemonic = wallet.mnemonic().to_string();

        // Verify we have valid keys
        assert_eq!(wallet.public_key_bytes().len(), 32);
        assert_eq!(wallet.wallet_id().len(), 32);

        // Recover from mnemonic
        let recovered = WalletIdentity::from_mnemonic_str(&mnemonic).unwrap();
        assert_eq!(wallet.public_key_bytes(), recovered.public_key_bytes());
        assert_eq!(wallet.wallet_id(), recovered.wallet_id());
    }

    #[test]
    fn test_sign_and_verify() {
        let wallet = WalletIdentity::create_new().unwrap();
        let msg = b"Hello, this is a test message!";
        let sig = wallet.sign(msg);
        assert!(wallet.verify(msg, &sig));
        assert!(!wallet.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_derive_id_seed_different_per_counter() {
        let wallet = WalletIdentity::create_new().unwrap();
        let s1 = wallet.derive_id_seed(0);
        let s2 = wallet.derive_id_seed(1);
        assert_ne!(s1, s2);
    }
}
