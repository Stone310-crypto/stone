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
//! tx_id_input = tx_type || from || to || amount || fee || nonce || timestamp || chain_id
//! sign_input  = tx_id_input || memo || fee_tier
//! signature   = Ed25519.sign(signing_key, SHA-256(sign_input))
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
    /// Onboarding: 0.5 STONE aus pool:onboarding → neue Wallet (gesperrt).
    /// Gesperrte Coins können NUR für Message-Fees (0.0001 STONE) verwendet werden.
    /// `from` = "pool:onboarding", `to` = Empfänger-Wallet, `amount` = 0.5
    Onboard,
    /// Delegation: Coins an eine Validator-Node delegieren (Split-Validator).
    /// Delegator stellt Kapital, Node-Betreiber die Infrastruktur.
    /// Fee-Rewards werden nach vereinbartem Split geteilt.
    /// `from` = Delegator-Wallet, `to` = Validator-Wallet, `amount` = Delegationsbetrag
    /// `memo` = JSON: {"validator":"<pubkey>","split_pct":<0-100>}
    Delegate,
    /// Undelegation: Delegation zurückziehen → 7-Tage Escrow.
    /// `from` = Delegator-Wallet, `to` = Validator-Wallet, `amount` = Betrag
    Undelegate,
    /// HTLC erstellen: Coins in Escrow sperren.
    /// `from` = Sender-Wallet, `to` = "pool:htlc_escrow", `amount` = Sperrbetrag
    /// `memo` = JSON: {"hash_lock":"...","time_lock":1234567890,"receiver":"..."}
    HtlcCreate,
    /// HTLC claimen: Preimage enthüllen, Coins an Empfänger.
    /// `from` = "pool:htlc_escrow", `to` = Empfänger-Wallet, `amount` = HTLC-Betrag
    /// `memo` = JSON: {"htlc_id":"...","preimage":"..."}
    HtlcClaim,
    /// HTLC refunden: Timeout abgelaufen, Coins zurück an Sender.
    /// `from` = "pool:htlc_escrow", `to` = Sender-Wallet, `amount` = HTLC-Betrag
    /// `memo` = JSON: {"htlc_id":"..."}
    HtlcRefund,
}

// ─── Fee-Tier ────────────────────────────────────────────────────────────────

/// Gebührenstufe einer Transaktion.
///
/// | Tier     | Fee (STONE) | Verarbeitung                         |
/// |----------|-------------|--------------------------------------|
/// | Priority | 0.001       | Bevorzugt im nächsten Block          |
/// | Standard | 0.0001      | Basis-Fee (wird geburnt)             |
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeeTier {
    /// Bevorzugte Verarbeitung im nächsten Block.
    #[serde(alias = "express")]
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
            FeeTier::Priority => write!(f, "priority"),
            FeeTier::Standard => write!(f, "standard"),
        }
    }
}

impl FeeTier {
    /// Die automatische Fee für diese Stufe.
    pub fn fee(&self) -> Decimal {
        match self {
            FeeTier::Priority => Decimal::new(1, 3),   // 0.001 STONE
            FeeTier::Standard => Decimal::new(1, 4),   // 0.0001 STONE (Basis-Fee, wird geburnt)
        }
    }

    /// Sortier-Priorität (kleiner = höhere Priorität).
    pub fn priority_order(&self) -> u8 {
        match self {
            FeeTier::Priority => 0,
            FeeTier::Standard => 1,
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
            TxType::Onboard         => write!(f, "onboard"),
            TxType::Delegate        => write!(f, "delegate"),
            TxType::Undelegate      => write!(f, "undelegate"),
            TxType::HtlcCreate      => write!(f, "htlc_create"),
            TxType::HtlcClaim       => write!(f, "htlc_claim"),
            TxType::HtlcRefund      => write!(f, "htlc_refund"),
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
    /// Gebührenstufe: Priority (0.001, bevorzugt), Standard (0.0001, Basis-Fee)
    #[serde(default)]
    pub fee_tier: FeeTier,
}

/// Default Chain-ID: liest aus STONE_NETWORK ENV, Fallback "stone-testnet"
pub fn default_chain_id() -> String {
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
/// Stabiler Input für TX-ID-Berechnung – ändert sich nicht zwischen Versionen.
fn tx_id_input(tx: &TokenTx) -> Vec<u8> {
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

/// Signatur-Payload inkl. `memo` und `fee_tier` (verhindert Manipulation dieser Felder).
fn sign_input(tx: &TokenTx) -> Vec<u8> {
    let mut buf = tx_id_input(tx);
    buf.push(b'|');
    buf.extend_from_slice(tx.memo.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(tx.fee_tier.to_string().as_bytes());
    buf
}

/// Berechnet die TX-ID: SHA-256 über den stabilen TX-Input.
pub fn compute_tx_id(tx: &TokenTx) -> String {
    let input = tx_id_input(tx);
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
    fee_tier: FeeTier,
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
    } else if tx_type == TxType::Stake || tx_type == TxType::Unstake
        || tx_type == TxType::Delegate || tx_type == TxType::Undelegate
        || tx_type == TxType::Onboard
        || tx_type == TxType::HtlcCreate
    {
        // Stake/Unstake/Delegate/Undelegate/Onboard/HtlcCreate: amount muss positiv sein
        if amount <= Decimal::ZERO {
            return Err(TxError::InvalidAmount("Betrag muss positiv sein".into()));
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
    // Memo-Limit: ChatMessage 4096, HTLC 512 (JSON mit hash_lock/preimage), andere 256 Bytes
    let memo_limit = if tx_type == TxType::ChatMessage { 4096 }
        else if tx_type == TxType::HtlcCreate || tx_type == TxType::HtlcClaim || tx_type == TxType::HtlcRefund { 512 }
        else { 256 };
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
        fee_tier,
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
        // Reward kommt aus pool:mining_rewards, Mint aus system – beides System-TXs
        return Ok(());
    }

    // Pool-Konten (pool:community, pool:staking, pool:onboarding, etc.) haben keine privaten Schlüssel.
    // Transfers von Pool-Konten werden nur serverseitig erstellt (z.B. Faucet, Onboarding).
    if tx.from.starts_with("pool:") {
        return Ok(());
    }

    // Onboard-Transaktionen: System-TX, keine User-Signatur
    if tx.tx_type == TxType::Onboard {
        return Ok(());
    }

    // Memorial-Transaktionen: keine Signatur nötig (System-TX in jedem Block)
    if tx.tx_type == TxType::Memorial {
        return Ok(());
    }

    // Testnet-Markt: Sell-TXs werden serverseitig erstellt (nach API-Auth).
    // Signatur "market-sell" ist ein Platzhalter — kein User-Key nötig.
    if tx.signature == "market-sell" && tx.memo.starts_with("Market Sell:") {
        return Ok(());
    }

    // HTLC Claim/Refund: System-TXs von pool:htlc_escrow (serverseitig erstellt).
    if tx.tx_type == TxType::HtlcClaim || tx.tx_type == TxType::HtlcRefund {
        return Ok(());
    }

    // Stake/Unstake/Delegate/Undelegate: Diese TXs werden serverseitig nach User-Authentifizierung
    // (Bearer + FaceID/TOTP) erstellt und mit dem Validator-Key signiert.
    // Die Memo enthält den Validator-PubKey zur Verifikation.
    if tx.tx_type == TxType::Stake || tx.tx_type == TxType::Unstake
        || tx.tx_type == TxType::Delegate || tx.tx_type == TxType::Undelegate
    {
        // Validator-PubKey aus Memo extrahieren; Fallback auf `from` (Staker-Wallet).
        // KEIN Überspringen der Signaturprüfung — das war eine Sicherheitslücke.
        let pubkey_hex = serde_json::from_str::<serde_json::Value>(&tx.memo)
            .ok()
            .and_then(|m| m.get("validator").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_else(|| tx.from.clone());

        let pub_bytes = hex::decode(&pubkey_hex)
            .map_err(|e| TxError::InvalidKey(format!("Validator/Staker-Key Hex ungültig: {e}")))?;
        if pub_bytes.len() != 32 {
            return Err(TxError::InvalidKey("Key muss 32 Byte sein".into()));
        }
        let verifying_key = VerifyingKey::from_bytes(
            pub_bytes.as_slice().try_into().unwrap()
        ).map_err(|e| TxError::InvalidKey(format!("Ungültiger Key: {e}")))?;

        let sig_bytes = hex::decode(&tx.signature)
            .map_err(|e| TxError::InvalidSignature(format!("Signatur Hex ungültig: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(TxError::InvalidSignature("Signatur muss 64 Byte sein".into()));
        }
        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        return verify_with_fallback(&verifying_key, &signature, tx,
            "Stake/Unstake: Signatur ungültig");
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

    verify_with_fallback(&verifying_key, &signature, tx,
        "Ed25519-Verifikation fehlgeschlagen")
}

/// Verifiziert Ed25519-Signatur: erst neues Format (inkl. memo + fee_tier),
/// bei Fehlschlag Fallback auf Legacy-Format (bestehende Chain-Daten).
fn verify_with_fallback(
    verifying_key: &VerifyingKey,
    signature: &Signature,
    tx: &TokenTx,
    error_msg: &str,
) -> Result<(), TxError> {
    // Neues Format (inkl. memo + fee_tier)
    let input = sign_input(tx);
    let hash = Sha256::digest(&input);
    if verifying_key.verify(&hash, signature).is_ok() {
        return Ok(());
    }
    // Legacy-Fallback: alte TXs signiert ohne memo + fee_tier
    let legacy = tx_id_input(tx);
    let legacy_hash = Sha256::digest(&legacy);
    verifying_key.verify(&legacy_hash, signature)
        .map_err(|_| TxError::InvalidSignature(error_msg.to_string()))
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
    } else if tx.tx_type == TxType::Stake || tx.tx_type == TxType::Unstake
        || tx.tx_type == TxType::Delegate || tx.tx_type == TxType::Undelegate
        || tx.tx_type == TxType::Onboard
        || tx.tx_type == TxType::HtlcCreate
    {
        if tx.amount <= Decimal::ZERO {
            return Err(TxError::InvalidAmount("Betrag muss positiv sein".into()));
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
