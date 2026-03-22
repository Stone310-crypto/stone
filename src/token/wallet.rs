//! StoneCoin Wallet – Ed25519 Schlüsselverwaltung
//!
//! Ein Wallet kapselt ein Ed25519-Schlüsselpaar und bietet:
//!
//! - **Generierung** aus kryptographisch sicherer Entropy (16 oder 32 Byte → 12- oder 24-Wort BIP39-Mnemonic)
//! - **Recovery** aus einem BIP39-Mnemonic (12 oder 24 Wörter)
//! - **TX-Signierung** über `sign_tx()` (erzeugt vollständig signierte `TokenTx`)
//! - **Adresse** = intern Hex (64 Zeichen), extern Bech32m (`stone1...`)
//!
//! ## Key-Derivation
//!
//! - **24 Wörter** (32 Byte Entropy): Entropy wird direkt als Ed25519-Key verwendet
//! - **12 Wörter** (16 Byte Entropy): SHA-256(entropy) → 32 Byte → Ed25519-Key
//!
//! ## Sicherheitshinweis
//!
//! Der `SigningKey` (Private Key) wird **niemals** persistiert oder über das Netzwerk
//! gesendet.  Das Wallet existiert nur im RAM des Aufrufers.  Der einzige Weg zur
//! Wiederherstellung ist der Mnemonic, den der Nutzer sicher aufbewahren muss.
//!
//! ## Beispiel
//!
//! ```rust,no_run
//! use stone::token::wallet::Wallet;
//! use stone::token::{TxType};
//! use rust_decimal::Decimal;
//!
//! // Neues Wallet generieren
//! let wallet = Wallet::generate().unwrap();
//! println!("Adresse:  {}", wallet.address());
//! println!("Mnemonic: {}", wallet.mnemonic());
//!
//! // Wallet aus Mnemonic wiederherstellen
//! let recovered = Wallet::from_mnemonic(wallet.mnemonic()).unwrap();
//! assert_eq!(wallet.address(), recovered.address());
//!
//! // Transaktion signieren
//! let tx = wallet.sign_tx(
//!     TxType::Transfer,
//!     "recipient_pubkey_hex".to_string(),
//!     Decimal::new(100, 0),   // 100 STONE
//!     Decimal::ZERO,          // keine Fee
//!     0,                      // Nonce
//!     "Test-Transfer".to_string(),
//! ).unwrap();
//! ```

use bip39::{Language, Mnemonic};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use super::transaction::{TokenTx, TxError, TxType, create_signed_tx};

// ─── Wallet-Fehler ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum WalletError {
    /// Mnemonic ist ungültig oder hat falsche Wortanzahl
    InvalidMnemonic(String),
    /// Entropy-Erzeugung fehlgeschlagen
    EntropyError(String),
    /// TX-Erstellung fehlgeschlagen
    TxError(TxError),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::InvalidMnemonic(s) => write!(f, "Ungültiger Mnemonic: {s}"),
            WalletError::EntropyError(s) => write!(f, "Entropy-Fehler: {s}"),
            WalletError::TxError(e) => write!(f, "TX-Fehler: {e}"),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<TxError> for WalletError {
    fn from(e: TxError) -> Self {
        WalletError::TxError(e)
    }
}

// ─── Wallet-Info (serialisierbar, ohne Private Key) ──────────────────────────

/// Öffentliche Wallet-Informationen (sicher zu serialisieren).
///
/// Enthält **keinen** Private Key – nur die Adresse und den Mnemonic-Hinweis.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletInfo {
    /// Public-Key-Hex (interne Adresse)
    pub address: String,
    /// Bech32m-Adresse (`stone1...`) für Anzeige
    pub display_address: String,
    /// BIP39-Mnemonic (12 oder 24 Wörter) – nur bei Erstgenerierung zurückgeben!
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// Anzahl der Mnemonic-Wörter (12 oder 24)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub word_count: Option<u16>,
}

// ─── Wallet ──────────────────────────────────────────────────────────────────

/// Ed25519-Wallet für die StoneCoin Token-Economy.
///
/// Enthält das vollständige Schlüsselpaar + den BIP39-Mnemonic zur Recovery.
/// Lebt nur im RAM – wird **nie** auf der Festplatte oder im Netzwerk gespeichert.
pub struct Wallet {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    mnemonic_phrase: String,
}

impl Wallet {
    // ── Erzeugung ─────────────────────────────────────────────────────────

    /// Generiert ein neues Wallet mit 24-Wort-Mnemonic (Standard).
    ///
    /// - 32 Byte Entropy → 24-Wort BIP39-Mnemonic
    /// - Ed25519-Schlüsselpaar aus der gleichen Entropy
    pub fn generate() -> Result<Self, WalletError> {
        Self::generate_with_words(24)
    }

    /// Generiert ein neues Wallet mit wählbarer Mnemonic-Länge.
    ///
    /// - `word_count = 12` → 16 Byte Entropy → 12-Wort BIP39-Mnemonic → SHA-256 → Ed25519-Key
    /// - `word_count = 24` → 32 Byte Entropy → 24-Wort BIP39-Mnemonic → Ed25519-Key direkt
    ///
    /// Bei 12 Wörtern wird die 16-Byte-Entropy über SHA-256 auf 32 Byte expandiert,
    /// damit ein Ed25519-Schlüsselpaar erzeugt werden kann. Die Key-Derivation ist
    /// deterministisch, sodass `from_mnemonic()` den gleichen Key wiederherstellt.
    pub fn generate_with_words(word_count: u16) -> Result<Self, WalletError> {
        let entropy_len = match word_count {
            12 => 16,
            24 => 32,
            _ => return Err(WalletError::EntropyError(
                format!("Ungültige Wortanzahl: {}. Erlaubt sind 12 oder 24.", word_count),
            )),
        };

        let mut entropy = vec![0u8; entropy_len];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| WalletError::EntropyError(format!("Mnemonic-Erzeugung: {e}")))?;

        // Key-Derivation: 16 Byte → SHA-256 → 32 Byte, 32 Byte → direkt
        let key_bytes = Self::derive_key_bytes(&entropy);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Wallet {
            signing_key,
            verifying_key,
            mnemonic_phrase: mnemonic.to_string(),
        })
    }

    /// Leitet 32 Byte Ed25519-Key-Material aus der Mnemonic-Entropy ab.
    ///
    /// - 32 Byte Entropy (24 Wörter): wird direkt verwendet
    /// - 16 Byte Entropy (12 Wörter): SHA-256-Hash → 32 Byte
    fn derive_key_bytes(entropy: &[u8]) -> [u8; 32] {
        if entropy.len() == 32 {
            entropy.try_into().unwrap()
        } else {
            // SHA-256 expandiert 16 Byte deterministisch auf 32 Byte
            let mut hasher = Sha256::new();
            hasher.update(entropy);
            hasher.finalize().into()
        }
    }

    /// Stellt ein Wallet aus einem BIP39-Mnemonic wieder her.
    ///
    /// Akzeptiert 12-Wort (128 Bit) und 24-Wort (256 Bit) Mnemonics.
    /// Bei 12 Wörtern wird die 16-Byte-Entropy über SHA-256 auf 32 Byte expandiert.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| WalletError::InvalidMnemonic(format!("{e}")))?;

        let entropy = mnemonic.to_entropy();
        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(WalletError::InvalidMnemonic(format!(
                "Entropy muss 16 oder 32 Byte sein, ist aber {} Byte (nur 12- und 24-Wort-Mnemonics werden unterstützt)",
                entropy.len()
            )));
        }

        let key_bytes = Self::derive_key_bytes(&entropy);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Wallet {
            signing_key,
            verifying_key,
            mnemonic_phrase: mnemonic.to_string(),
        })
    }

    /// Erstellt ein Wallet direkt aus einem 32-Byte Private Key (ohne Mnemonic).
    ///
    /// Nützlich für programmatische Nutzung wenn der Mnemonic nicht benötigt wird.
    pub fn from_private_key(key_bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(key_bytes);
        let verifying_key = signing_key.verifying_key();

        Wallet {
            signing_key,
            verifying_key,
            mnemonic_phrase: String::new(), // kein Mnemonic bekannt
        }
    }

    // ── Getter ────────────────────────────────────────────────────────────

    /// Gibt die Wallet-Adresse als Hex-String zurück (intern, 64 Zeichen).
    ///
    /// Für die user-facing `stone1...` Darstellung: [`display_address()`].
    pub fn address(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Gibt die Wallet-Adresse im `stone1...` Bech32m-Format zurück (Display/API).
    pub fn display_address(&self) -> String {
        super::address::encode(self.verifying_key.as_bytes())
    }

    /// Gibt die Wallet-Adresse als 64-Zeichen Hex-String zurück.
    ///
    /// Alias für [`address()`] – explizit für Stellen die Hex erwarten.
    pub fn address_hex(&self) -> String {
        self.address()
    }

    /// Gibt den BIP39-Mnemonic zurück (12 oder 24 Wörter).
    ///
    /// ⚠ Nur dem Nutzer bei Erstgenerierung zeigen!
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic_phrase
    }

    /// Gibt den Public Key als Byte-Array zurück.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Gibt eine Referenz auf den Signing Key zurück.
    ///
    /// ⚠ Nur für TX-Signierung verwenden – niemals exportieren!
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Gibt öffentliche Wallet-Info zurück (serialisierbar).
    ///
    /// Bei `include_mnemonic = true` wird der Mnemonic inkludiert
    /// (nur bei Erstgenerierung verwenden!).
    pub fn info(&self, include_mnemonic: bool) -> WalletInfo {
        let wc = self.mnemonic_phrase.split_whitespace().count() as u16;
        WalletInfo {
            address: self.address(),
            display_address: self.display_address(),
            mnemonic: if include_mnemonic && !self.mnemonic_phrase.is_empty() {
                Some(self.mnemonic_phrase.clone())
            } else {
                None
            },
            word_count: if include_mnemonic && !self.mnemonic_phrase.is_empty() {
                Some(wc)
            } else {
                None
            },
        }
    }

    // ── TX-Signierung ─────────────────────────────────────────────────────

    /// Erstellt und signiert eine Token-Transaktion mit diesem Wallet.
    ///
    /// Der `from`-Feld wird automatisch auf die Wallet-Adresse gesetzt.
    pub fn sign_tx(
        &self,
        tx_type: TxType,
        to: String,
        amount: Decimal,
        fee: Decimal,
        nonce: u64,
        memo: String,
    ) -> Result<TokenTx, WalletError> {
        let tx = create_signed_tx(
            &self.signing_key,
            tx_type,
            self.address(),
            to,
            amount,
            fee,
            nonce,
            memo,
            super::transaction::FeeTier::Standard,
        )?;
        Ok(tx)
    }

    /// Signiert eine TX mit explizitem Fee-Tier.
    ///
    /// Die `fee` wird automatisch aus dem Tier berechnet.
    pub fn sign_tx_with_tier(
        &self,
        tx_type: TxType,
        to: String,
        amount: Decimal,
        nonce: u64,
        memo: String,
        tier: super::transaction::FeeTier,
    ) -> Result<TokenTx, WalletError> {
        let fee = tier.fee();
        let tx = create_signed_tx(
            &self.signing_key,
            tx_type,
            self.address(),
            to,
            amount,
            fee,
            nonce,
            memo,
            tier,
        )?;
        Ok(tx)
    }

    // ── Key-Rotation ──────────────────────────────────────────────────────

    /// Generiert ein neues Wallet und erstellt eine signierte RotateKey-TX.
    ///
    /// Die TX wird mit dem **alten** (aktuellen) Key signiert, um zu beweisen
    /// dass der Besitzer die Rotation autorisiert.
    ///
    /// Rückgabe: `(neues_wallet, signierte_rotate_tx)`
    ///
    /// ## Ablauf
    ///
    /// 1. Neues Ed25519-Keypair generieren (neues Wallet)
    /// 2. RotateKey-TX erstellen: `from = alter_key, to = neuer_key, amount = 0`
    /// 3. TX mit dem **alten** Key signieren
    /// 4. (neues Wallet, TX) zurückgeben
    ///
    /// Der Aufrufer muss die TX dann über `/api/v1/token/transfer` einreichen
    /// und das neue Wallet sicher aufbewahren.
    pub fn rotate_key(&self, nonce: u64, fee: Decimal) -> Result<(Wallet, TokenTx), WalletError> {
        // Neues Wallet generieren
        let new_wallet = Wallet::generate()?;

        // RotateKey-TX mit dem ALTEN Key signieren
        let tx = create_signed_tx(
            &self.signing_key,
            TxType::RotateKey,
            self.address(),          // from = alter Key
            new_wallet.address(),    // to   = neuer Key
            Decimal::ZERO,           // keine Token-Bewegung (wird intern im Ledger gemacht)
            fee,
            nonce,
            "Key-Rotation".to_string(),
            super::transaction::FeeTier::Priority,
        )?;

        Ok((new_wallet, tx))
    }
}

// ─── Debug (ohne Private Key!) ───────────────────────────────────────────────

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address())
            .field("has_mnemonic", &!self.mnemonic_phrase.is_empty())
            .finish()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::transaction::validate_tx;

    #[test]
    fn test_generate_and_address() {
        let wallet = Wallet::generate().unwrap();
        let addr = wallet.address();

        // Adresse = 64 Hex-Zeichen (32 Byte Ed25519 Public Key)
        assert_eq!(addr.len(), 64);
        assert!(addr.chars().all(|c| c.is_ascii_hexdigit()));

        // Display-Adresse = stone1... Bech32m-Format
        let display = wallet.display_address();
        assert!(display.starts_with("stone1"), "Display-Adresse muss mit stone1 beginnen: {display}");

        // Display-Adresse = stone1... Bech32m-Format
        let display = wallet.display_address();
        assert!(display.starts_with("stone1"), "Display-Adresse muss mit stone1 beginnen: {display}");

        // Roundtrip: display → hex
        let normalized = crate::token::address::normalize_to_hex(&display).unwrap();
        assert_eq!(normalized, addr);

        // Mnemonic = 24 Wörter (Default)
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_generate_12_words() {
        let wallet = Wallet::generate_with_words(12).unwrap();
        let addr = wallet.address();

        // Adresse = 64 Hex-Zeichen
        assert_eq!(addr.len(), 64);
        assert!(addr.chars().all(|c| c.is_ascii_hexdigit()));

        // Mnemonic = 12 Wörter
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12);

        // Info gibt word_count = 12 zurück
        let info = wallet.info(true);
        assert_eq!(info.word_count, Some(12));
    }

    #[test]
    fn test_generate_24_words() {
        let wallet = Wallet::generate_with_words(24).unwrap();
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 24);

        let info = wallet.info(true);
        assert_eq!(info.word_count, Some(24));
    }

    #[test]
    fn test_generate_invalid_word_count() {
        assert!(Wallet::generate_with_words(15).is_err());
        assert!(Wallet::generate_with_words(6).is_err());
        assert!(Wallet::generate_with_words(0).is_err());
    }

    #[test]
    fn test_mnemonic_recovery() {
        // 24-Wort Recovery
        let wallet = Wallet::generate().unwrap();
        let mnemonic = wallet.mnemonic().to_string();
        let address = wallet.address();

        let recovered = Wallet::from_mnemonic(&mnemonic).unwrap();
        assert_eq!(recovered.address(), address);
        assert_eq!(recovered.mnemonic(), mnemonic);
    }

    #[test]
    fn test_12_word_mnemonic_recovery() {
        // 12-Wort Recovery
        let wallet = Wallet::generate_with_words(12).unwrap();
        let mnemonic = wallet.mnemonic().to_string();
        let address = wallet.address();

        let recovered = Wallet::from_mnemonic(&mnemonic).unwrap();
        assert_eq!(recovered.address(), address);
        assert_eq!(recovered.mnemonic(), mnemonic);

        // Mnemonic hat 12 Wörter
        let words: Vec<&str> = recovered.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_from_private_key() {
        let wallet = Wallet::generate().unwrap();
        let key_bytes = wallet.signing_key.to_bytes();

        let from_key = Wallet::from_private_key(&key_bytes);
        assert_eq!(from_key.address(), wallet.address());
        assert!(from_key.mnemonic().is_empty()); // kein Mnemonic
    }

    #[test]
    fn test_sign_tx_valid() {
        let wallet = Wallet::generate().unwrap();
        let tx = wallet.sign_tx(
            TxType::Transfer,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            Decimal::new(50, 0),  // 50 STONE
            Decimal::ZERO,
            0,
            "Test".to_string(),
        ).unwrap();

        // TX-Felder korrekt
        assert_eq!(tx.from, wallet.address());
        assert!(!tx.tx_id.is_empty());
        assert!(!tx.signature.is_empty());

        // Signatur muss valide sein
        assert!(validate_tx(&tx).is_ok());
    }

    #[test]
    fn test_sign_tx_12_word_wallet() {
        // 12-Wort-Wallet muss auch valide TXs signieren können
        let wallet = Wallet::generate_with_words(12).unwrap();
        let tx = wallet.sign_tx(
            TxType::Transfer,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            Decimal::new(25, 0),
            Decimal::ZERO,
            0,
            "12-Wort Test".to_string(),
        ).unwrap();

        assert_eq!(tx.from, wallet.address());
        assert!(validate_tx(&tx).is_ok());

        // Recovery und erneute Signatur muss gleichen Key nutzen
        let recovered = Wallet::from_mnemonic(wallet.mnemonic()).unwrap();
        assert_eq!(recovered.address(), wallet.address());
    }

    #[test]
    fn test_sign_tx_sequential_nonces() {
        let wallet = Wallet::generate().unwrap();
        let to = "aaaa".repeat(16); // 64 Zeichen

        for nonce in 0..5 {
            let tx = wallet.sign_tx(
                TxType::Transfer,
                to.clone(),
                Decimal::new(10, 0),
                Decimal::ZERO,
                nonce,
                String::new(),
            ).unwrap();

            assert_eq!(tx.nonce, nonce);
            assert!(validate_tx(&tx).is_ok());
        }
    }

    #[test]
    fn test_wallet_info() {
        let wallet = Wallet::generate().unwrap();

        // Ohne Mnemonic
        let info = wallet.info(false);
        assert_eq!(info.address, wallet.address());
        assert!(info.mnemonic.is_none());

        // Mit Mnemonic
        let info_full = wallet.info(true);
        assert_eq!(info_full.mnemonic.unwrap(), wallet.mnemonic());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = Wallet::from_mnemonic("this is not a valid mnemonic");
        assert!(result.is_err());
    }

    #[test]
    fn test_12_word_known_mnemonic() {
        // 12 Wörter = 16 Byte Entropy → SHA-256 → 32 Byte Ed25519-Key → funktioniert!
        let result = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert!(result.is_ok());
        let wallet = result.unwrap();
        assert_eq!(wallet.address().len(), 64);
        // Recovery muss deterministisch sein
        let recovered = Wallet::from_mnemonic(wallet.mnemonic()).unwrap();
        assert_eq!(recovered.address(), wallet.address());
    }

    // ── Key-Rotation Tests ───────────────────────────────────────────────

    #[test]
    fn test_rotate_key_generates_new_wallet() {
        let wallet = Wallet::generate().unwrap();
        let (new_wallet, tx) = wallet.rotate_key(0, Decimal::ZERO).unwrap();

        // Neues Wallet hat andere Adresse
        assert_ne!(wallet.address(), new_wallet.address());
        assert_eq!(new_wallet.address().len(), 64);

        // TX-Felder korrekt
        assert_eq!(tx.tx_type, TxType::RotateKey);
        assert_eq!(tx.from, wallet.address());    // alter Key
        assert_eq!(tx.to, new_wallet.address());  // neuer Key
        assert_eq!(tx.amount, Decimal::ZERO);
        assert_eq!(tx.nonce, 0);

        // Signatur muss mit dem alten Key verifizierbar sein
        assert!(validate_tx(&tx).is_ok());
    }

    #[test]
    fn test_rotate_key_preserves_mnemonic() {
        let wallet = Wallet::generate().unwrap();
        let (new_wallet, _) = wallet.rotate_key(0, Decimal::ZERO).unwrap();

        // Neues Wallet hat eigenen Mnemonic
        assert!(!new_wallet.mnemonic().is_empty());
        assert_ne!(wallet.mnemonic(), new_wallet.mnemonic());

        // Recovery des neuen Wallets funktioniert
        let recovered = Wallet::from_mnemonic(new_wallet.mnemonic()).unwrap();
        assert_eq!(recovered.address(), new_wallet.address());
    }

    #[test]
    fn test_chain_id_in_tx() {
        let wallet = Wallet::generate().unwrap();
        let tx = wallet.sign_tx(
            TxType::Transfer,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            Decimal::new(10, 0),
            Decimal::ZERO,
            0,
            String::new(),
        ).unwrap();

        // chain_id muss gesetzt sein
        assert!(!tx.chain_id.is_empty());
        assert!(tx.chain_id.starts_with("stone-"));

        // TX muss trotzdem valide sein
        assert!(validate_tx(&tx).is_ok());
    }

    #[test]
    fn test_chain_id_mismatch_rejected() {
        let wallet = Wallet::generate().unwrap();
        let mut tx = wallet.sign_tx(
            TxType::Transfer,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            Decimal::new(10, 0),
            Decimal::ZERO,
            0,
            String::new(),
        ).unwrap();

        // Chain-ID manipulieren → Replay von einem anderen Netzwerk
        tx.chain_id = "stone-mainnet-fake".to_string();

        // Muss abgelehnt werden (chain_id Mismatch ODER Signatur ungültig)
        assert!(validate_tx(&tx).is_err());
    }
}
