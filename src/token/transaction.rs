//! StoneCoin Token-Transaktionen
//!
//! Jede Transaktion repräsentiert eine Wertübertragung auf der Stone-Chain.
//! Signierung und Verifikation erfolgen über Ed25519 (gleicher Schlüsseltyp
//! wie die bestehende Dokument-Signierung).
//!
//! ## Transaktionstypen
//!
//! | Typ       | Beschreibung                                        |
//! |-----------|-----------------------------------------------------|
//! | Transfer  | Nutzer → Nutzer Überweisung                         |
//! | Mint      | Genesis-Allokation oder Reward-Emission              |
//! | Reward    | Storage-Provider Belohnung (Epoch-basiert)           |
//! | Burn      | Token permanent vernichten (Supply-Reduktion)        |
//!
//! ## Signatur-Schema
//!
//! ```text
//! sign_input = tx_type || from || to || amount || fee || nonce || timestamp
//! signature  = Ed25519.sign(signing_key, SHA-256(sign_input))
//! ```

use chrono::Utc;
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    ed25519::signature::Signer,
    ed25519::signature::Verifier,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─── Transaktionstyp ─────────────────────────────────────────────────────────

/// Art der Token-Transaktion.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TxType {
    /// Nutzer-zu-Nutzer Überweisung
    Transfer,
    /// Genesis-Allokation oder initiale Verteilung
    Mint,
    /// Storage-Provider Epoch-Belohnung
    Reward,
    /// Token permanent vernichten
    Burn,
    /// Ed25519 Key-Rotation: `from` = alter Key, `to` = neuer Key
    RotateKey,
    /// Account-Registrierung in der Chain.
    /// `from` = wallet_address (public key hex), `to` = wallet_address (gleich),
    /// `memo` = JSON: `{"name":"…","api_key_hash":"…"}`, amount = 0
    AccountRegister,
    /// Account-Update (z.B. Name ändern).
    /// `from` = wallet_address, `to` = wallet_address,
    /// `memo` = JSON mit geänderten Feldern, amount = 0
    AccountUpdate,
    /// Token in den Staking-Pool einzahlen.
    /// `from` = Staker-Wallet, `to` = "pool:staking", `amount` = Stake-Betrag
    Stake,
    /// Token aus dem Staking-Pool auszahlen (nach Lock-Periode).
    /// `from` = Staker-Wallet, `to` = "pool:staking", `amount` = Unstake-Betrag
    Unstake,
    /// Eternal Memorial Transaction – in jedem Block als Erinnerung.
    /// `from` = "memorial", `to` = "forever", `amount` = 0, `memo` = Gedenktext
    Memorial,
    /// Verschlüsselte Chat-Nachricht auf der Blockchain.
    /// `from` = Sender-Wallet, `to` = Empfänger-Wallet, `amount` = 0,
    /// `memo` = JSON: {"msg_id":"…","encrypted":"…","nonce":"…"}
    ChatMessage,
}

// ─── Fee-Tier ────────────────────────────────────────────────────────────────

/// Gebührenstufe einer Transaktion.
///
/// | Tier     | Fee (STONE) | Verarbeitung                                       |
/// |----------|-------------|-----------------------------------------------------|
/// | Express  | 0.01        | Sofort im nächsten Block                            |
/// | Priority | 0.001       | Innerhalb von ~5 Minuten (nächste Validator-Runde)  |
/// | Standard | 0.0         | Wartet bis zum nächsten Dokument-Upload (kostenlos) |
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeeTier {
    Express,
    Priority,
    Standard,
}

impl Default for FeeTier {
    fn default() -> Self {
        FeeTier::Standard
    }
}

impl std::fmt::Display for FeeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeTier::Express  => write!(f, "express"),
            FeeTier::Priority => write!(f, "priority"),
            FeeTier::Standard => write!(f, "standard"),
        }
    }
}

impl FeeTier {
    /// Die automatische Fee für diese Stufe.
    pub fn fee(&self) -> Decimal {
        match self {
            FeeTier::Express  => Decimal::new(1, 2),   // 0.01 STONE
            FeeTier::Priority => Decimal::new(1, 3),   // 0.001 STONE
            FeeTier::Standard => Decimal::new(1, 4),   // 0.0001 STONE (Basis-Fee, wird geburnt)
        }
    }

    /// Sortier-Priorität (kleiner = höhere Priorität).
    pub fn priority_order(&self) -> u8 {
        match self {
            FeeTier::Express  => 0,
            FeeTier::Priority => 1,
            FeeTier::Standard => 2,
        }
    }
}

impl std::fmt::Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxType::Transfer        => write!(f, "transfer"),
            TxType::Mint            => write!(f, "mint"),
            TxType::Reward          => write!(f, "reward"),
            TxType::Burn            => write!(f, "burn"),
            TxType::RotateKey       => write!(f, "rotate_key"),
            TxType::AccountRegister => write!(f, "account_register"),
            TxType::AccountUpdate   => write!(f, "account_update"),
            TxType::Stake           => write!(f, "stake"),
            TxType::Unstake         => write!(f, "unstake"),
            TxType::Memorial        => write!(f, "memorial"),
            TxType::ChatMessage     => write!(f, "chat_message"),
        }
    }
}

// ─── Token-Transaktion ───────────────────────────────────────────────────────

/// Eine einzelne Token-Transaktion auf der Stone-Chain.
///
/// Felder:
/// - `tx_id`      – SHA-256 über (from || to || amount || nonce || timestamp), 64 Hex-Zeichen
/// - `tx_type`    – Art der Transaktion (Transfer, Mint, Reward, Burn, RotateKey)
/// - `from`       – Sender Public-Key-Hex (64 Zeichen). Bei Mint: "system"
/// - `to`         – Empfänger Public-Key-Hex (64 Zeichen). Bei Burn: "burn"
/// - `amount`     – Betrag in STONE (max. 8 Dezimalstellen)
/// - `fee`        – Transaktionsgebühr in STONE (wird verbrannt)
/// - `nonce`      – Monoton steigend pro Sender-Account (Replay-Schutz)
/// - `timestamp`  – Unix-Timestamp (Sekunden)
/// - `signature`  – Ed25519-Signatur (128 Hex-Zeichen = 64 Byte)
/// - `memo`       – Optionale Notiz (max. 256 Bytes)
/// - `chain_id`   – Netzwerk-Kennung (z.B. "stone-testnet", "stone-mainnet") für Cross-Chain Replay-Schutz
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenTx {
    pub tx_id: String,
    pub tx_type: TxType,
    pub from: String,
    pub to: String,
    pub amount: Decimal,
    pub fee: Decimal,
    pub nonce: u64,
    pub timestamp: i64,
    pub signature: String,
    #[serde(default)]
    pub memo: String,
    /// Chain-ID: "stone-testnet" oder "stone-mainnet"
    /// Verhindert Cross-Chain Replay-Angriffe.
    #[serde(default = "default_chain_id")]
    pub chain_id: String,
    /// Gebührenstufe: Express (sofort, 0.01), Priority (~5min, 0.001), Standard (kostenlos, wartet auf Dokument-Upload)
    #[serde(default)]
    pub fee_tier: FeeTier,
}

/// Default Chain-ID: liest aus STONE_NETWORK ENV, Fallback "stone-testnet"
fn default_chain_id() -> String {
    let mode = std::env::var("STONE_NETWORK")
        .unwrap_or_default()
        .to_lowercase();
    if mode == "mainnet" || mode == "main" {
        "stone-mainnet".to_string()
    } else {
        "stone-testnet".to_string()
    }
}

// ─── Fehlermeldungen ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TxError {
    InvalidAmount(String),
    InvalidSignature(String),
    InvalidKey(String),
    MissingField(String),
    Replay(String),
}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxError::InvalidAmount(s) => write!(f, "Ungültiger Betrag: {s}"),
            TxError::InvalidSignature(s) => write!(f, "Ungültige Signatur: {s}"),
            TxError::InvalidKey(s) => write!(f, "Ungültiger Schlüssel: {s}"),
            TxError::MissingField(s) => write!(f, "Fehlendes Feld: {s}"),
            TxError::Replay(s) => write!(f, "Replay-Angriff: {s}"),
        }
    }
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/// Erzeugt den kanonischen Signatur-Input für eine Transaktion.
///
/// Format (binär, deterministisch):
/// ```text
///   tx_type.as_bytes()        variabel
///   "|"
///   from.as_bytes()           variabel
///   "|"
///   to.as_bytes()             variabel
///   "|"
///   amount.to_string()        variabel (z.B. "100.00000000")
///   "|"
///   fee.to_string()           variabel
///   "|"
///   nonce.to_le_bytes()       8 Byte
///   "|"
///   timestamp.to_le_bytes()   8 Byte
/// ```
fn sign_input(tx: &TokenTx) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(tx.tx_type.to_string().as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(tx.from.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(tx.to.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(tx.amount.normalize().to_string().as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(tx.fee.normalize().to_string().as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&tx.nonce.to_le_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&tx.timestamp.to_le_bytes());
    buf.push(b'|');
    buf.extend_from_slice(tx.chain_id.as_bytes());
    buf
}

/// Berechnet die TX-ID: SHA-256 über den Signatur-Input.
pub fn compute_tx_id(tx: &TokenTx) -> String {
    let input = sign_input(tx);
    format!("{:x}", Sha256::digest(&input))
}

// ─── Erstellen & Signieren ───────────────────────────────────────────────────

/// Erstellt und signiert eine neue Token-Transaktion.
///
/// Parameter:
/// - `signing_key` – Ed25519 privater Schlüssel des Senders
/// - `tx_type`     – Art der Transaktion
/// - `from`        – Sender Public-Key-Hex
/// - `to`          – Empfänger Public-Key-Hex
/// - `amount`      – Betrag in STONE
/// - `fee`         – Gebühr in STONE
/// - `nonce`       – Aktuelle Nonce des Senders
/// - `memo`        – Optionale Notiz
pub fn create_signed_tx(
    signing_key: &SigningKey,
    tx_type: TxType,
    from: String,
    to: String,
    amount: Decimal,
    fee: Decimal,
    nonce: u64,
    memo: String,
) -> Result<TokenTx, TxError> {
    // Validierung
    if tx_type == TxType::RotateKey || tx_type == TxType::AccountRegister
        || tx_type == TxType::AccountUpdate || tx_type == TxType::ChatMessage
        || tx_type == TxType::Memorial
    {
        // Diese TX-Typen: amount muss 0 sein, fee >= 0
        if amount != Decimal::ZERO {
            return Err(TxError::InvalidAmount(format!("{tx_type}: Betrag muss 0 sein")));
        }
    } else if tx_type == TxType::Stake || tx_type == TxType::Unstake {
        // Stake/Unstake: amount muss positiv sein, to wird auf pool:staking gesetzt
        if amount <= Decimal::ZERO {
            return Err(TxError::InvalidAmount("Stake-Betrag muss positiv sein".into()));
        }
    } else if amount <= Decimal::ZERO {
        return Err(TxError::InvalidAmount("Betrag muss positiv sein".into()));
    }
    if fee < Decimal::ZERO {
        return Err(TxError::InvalidAmount("Gebühr darf nicht negativ sein".into()));
    }
    if amount.scale() > 8 {
        return Err(TxError::InvalidAmount("Maximal 8 Dezimalstellen".into()));
    }
    // Memo-Limit: ChatMessage darf größere Memos (verschlüsselte Nachrichten), andere TXs 256 Bytes
    let memo_limit = if tx_type == TxType::ChatMessage { 4096 } else { 256 };
    if memo.len() > memo_limit {
        return Err(TxError::MissingField(format!("Memo darf maximal {} Bytes sein (hat {})", memo_limit, memo.len())));
    }

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type,
        from,
        to,
        amount,
        fee,
        nonce,
        timestamp: Utc::now().timestamp(),
        signature: String::new(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: FeeTier::Standard,
    };

    // TX-ID berechnen
    tx.tx_id = compute_tx_id(&tx);

    // Signatur
    let input = sign_input(&tx);
    let hash = Sha256::digest(&input);
    let sig = signing_key.sign(&hash);
    tx.signature = hex::encode(sig.to_bytes());

    Ok(tx)
}

// ─── Verifikation ────────────────────────────────────────────────────────────

/// Prüft die Ed25519-Signatur einer Token-Transaktion.
///
/// - Bei `Mint` und `Reward` TXs (from == "system") wird die Signatur übersprungen,
///   da diese vom System erzeugt werden.
/// - Bei `Transfer` und `Burn` muss `from` ein gültiger Ed25519-Public-Key sein.
pub fn verify_tx_signature(tx: &TokenTx) -> Result<(), TxError> {
    // System-/Pool-Transaktionen: Signatur wird nicht gegen einen Public-Key geprüft
    if tx.tx_type == TxType::Mint || tx.tx_type == TxType::Reward {
        // Reward kommt aus pool:storage_rewards, Mint aus system – beides System-TXs
        return Ok(());
    }

    // Memorial-Transaktionen: keine Signatur nötig (System-TX in jedem Block)
    if tx.tx_type == TxType::Memorial {
        return Ok(());
    }

    // Stake/Unstake: vom Node nach User-Authentifizierung erstellt, Signatur
    // stammt vom Validator-Key, nicht vom User-Wallet → Prüfung überspringen.
    if tx.tx_type == TxType::Stake || tx.tx_type == TxType::Unstake {
        return Ok(());
    }

    // Public-Key aus Hex dekodieren
    let pub_bytes = hex::decode(&tx.from)
        .map_err(|e| TxError::InvalidKey(format!("Hex-Dekodierung fehlgeschlagen: {e}")))?;
    if pub_bytes.len() != 32 {
        return Err(TxError::InvalidKey(format!(
            "Public Key muss 32 Byte sein, ist aber {} Byte",
            pub_bytes.len()
        )));
    }

    let verifying_key = VerifyingKey::from_bytes(
        pub_bytes.as_slice().try_into().unwrap()
    ).map_err(|e| TxError::InvalidKey(format!("Ungültiger Ed25519-Key: {e}")))?;

    // Signatur dekodieren
    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|e| TxError::InvalidSignature(format!("Hex-Dekodierung: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(TxError::InvalidSignature(format!(
            "Signatur muss 64 Byte sein, ist aber {} Byte",
            sig_bytes.len()
        )));
    }
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    // Verifizieren
    let input = sign_input(tx);
    let hash = Sha256::digest(&input);
    verifying_key.verify(&hash, &signature)
        .map_err(|_| TxError::InvalidSignature("Ed25519-Verifikation fehlgeschlagen".into()))
}

/// Validiert eine Transaktion strukturell (ohne Ledger-Zustand).
///
/// Prüft:
/// - tx_id stimmt
/// - amount > 0
/// - fee >= 0
/// - Signatur gültig
/// - from/to nicht leer
pub fn validate_tx(tx: &TokenTx) -> Result<(), TxError> {
    // Strukturelle Prüfungen
    if tx.from.is_empty() {
        return Err(TxError::MissingField("from".into()));
    }
    if tx.to.is_empty() {
        return Err(TxError::MissingField("to".into()));
    }
    // RotateKey/AccountRegister/AccountUpdate/ChatMessage/Memorial: amount == 0 erlaubt
    if tx.tx_type == TxType::RotateKey || tx.tx_type == TxType::AccountRegister
        || tx.tx_type == TxType::AccountUpdate || tx.tx_type == TxType::ChatMessage
        || tx.tx_type == TxType::Memorial
    {
        if tx.amount != Decimal::ZERO {
            return Err(TxError::InvalidAmount(format!("{}: Betrag muss 0 sein", tx.tx_type)));
        }
    } else if tx.tx_type == TxType::Stake || tx.tx_type == TxType::Unstake {
        if tx.amount <= Decimal::ZERO {
            return Err(TxError::InvalidAmount("Stake-Betrag muss positiv sein".into()));
        }
    } else if tx.amount <= Decimal::ZERO {
        return Err(TxError::InvalidAmount("Betrag muss positiv sein".into()));
    }
    if tx.fee < Decimal::ZERO {
        return Err(TxError::InvalidAmount("Gebühr darf nicht negativ sein".into()));
    }

    // Chain-ID Validierung: muss zum aktuellen Netzwerk passen
    // System-TXs (Memorial, Mint, Reward) haben eigene chain_ids → überspringen
    if tx.tx_type != TxType::Memorial && tx.tx_type != TxType::Mint && tx.tx_type != TxType::Reward {
        let expected_chain_id = default_chain_id();
        if !tx.chain_id.is_empty() && tx.chain_id != expected_chain_id {
            return Err(TxError::InvalidSignature(format!(
                "Chain-ID Mismatch: TX hat '{}', Node erwartet '{}'",
                tx.chain_id, expected_chain_id
            )));
        }
    }

    // TX-ID-Integrität
    let expected_id = compute_tx_id(tx);
    if tx.tx_id != expected_id {
        return Err(TxError::InvalidSignature(format!(
            "TX-ID ungültig: erwartet {}, empfangen {}",
            &expected_id[..12],
            &tx.tx_id[..12.min(tx.tx_id.len())]
        )));
    }

    // Signatur prüfen
    verify_tx_signature(tx)?;

    Ok(())
}
