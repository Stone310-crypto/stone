//! On-Chain Game-Registry — Phase A
//!
//! Erlaubt es Developer-Wallets, sich als **Firma** zu registrieren und
//! darunter **Spiele** on-chain anzumelden. Im Gegensatz zum reinen SDK
//! (`game_economy/registry.rs`) wird hier der Zustand über reguläre
//! Token-Transaktionen aufgebaut (TxType::CompanyRegister / GameRegister)
//! und ist damit konsens-gesichert, snapshotbar und replay-fähig.
//!
//! ## Datenmodell
//!
//! ```text
//! Wallet ──owns──► CompanyProfile ──owns──► OnChainGame*
//!                                            ↑ optional: eigener coin
//! ```
//!
//! ## TX-Memos
//!
//! - `CompanyRegister`: `{"name":"…","country":"DE","website":"…"}`
//! - `GameRegister`:    `{"game_id":"…","name":"…","version":"1.0.0","icon_uri":"…","coin_address":"…"}`
//!
//! Alle Felder außer `name`/`game_id` sind optional.

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Account-Klassifikation eines Wallets.
///
/// Wallets sind defaultmäßig `Personal`. Sobald eine `CompanyRegister`-TX
/// erfolgreich angewendet wurde, gilt das Wallet als `Company`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    Personal,
    Company,
}

impl Default for AccountType {
    fn default() -> Self { AccountType::Personal }
}

/// Status einer Firma.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompanyStatus {
    Active,
    /// Vom Founder/DAO gesperrt (Begründung + Zeitstempel).
    Suspended { reason: String, since: i64 },
}

impl Default for CompanyStatus {
    fn default() -> Self { CompanyStatus::Active }
}

/// On-Chain Firmen-Profil.
///
/// Wird durch `TxType::CompanyRegister` angelegt. Die `owner_wallet` ist
/// gleichzeitig der Signing-Key — `register_game()` muss von genau dieser
/// Wallet signiert werden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyProfile {
    /// Wallet-Adresse des Firmen-Eigentümers (Public-Key-Hex).
    pub owner_wallet: String,
    /// Anzeigename der Firma.
    pub name: String,
    /// ISO-3166-1 alpha-2 Ländercode (z.B. "DE"). Leer wenn nicht angegeben.
    pub country: String,
    /// Optionale Website-URL (max. 200 Zeichen).
    pub website: String,
    /// Block-Index bei Registrierung.
    pub registered_at_block: u64,
    /// Unix-Timestamp der Registrierung.
    pub registered_at: i64,
    /// Hat die Firma einen Verifizierungs-Status durchlaufen?
    /// Initial `false`; setzt sich später durch separate DAO/Founder-TX.
    #[serde(default)]
    pub verified: bool,
    /// Status (Active/Suspended).
    #[serde(default)]
    pub status: CompanyStatus,
}

/// Status eines registrierten Spiels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GameStatus {
    Active,
    /// Wartet auf Verifizierung durch Founder/DAO.
    Pending,
    /// Vom Owner als veraltet markiert.
    Deprecated,
    /// Gesperrt (Reason + Timestamp).
    Suspended { reason: String, since: i64 },
}

impl Default for GameStatus {
    fn default() -> Self { GameStatus::Active }
}

/// On-Chain Game-Eintrag.
///
/// Wird durch `TxType::GameRegister` angelegt. Eine Firma kann beliebig viele
/// Spiele registrieren. Die `game_id` muss netzwerkweit eindeutig sein.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainGame {
    /// Globale Game-ID (3–64 Zeichen, [a-z0-9_-]).
    pub game_id: String,
    /// Wallet der besitzenden Firma (`CompanyProfile.owner_wallet`).
    pub owner_company: String,
    /// Anzeigename.
    pub name: String,
    /// Semver-Version (z.B. "1.0.0").
    pub version: String,
    /// Optionale Icon-URI (IPFS/HTTPS, max. 256 Zeichen).
    #[serde(default)]
    pub icon_uri: String,
    /// Optionale Adresse eines eigenen In-Game-Coin-Contracts (für Phase 2).
    #[serde(default)]
    pub coin_address: String,
    /// Block-Index bei Registrierung.
    pub registered_at_block: u64,
    /// Unix-Timestamp der Registrierung.
    pub registered_at: i64,
    /// Status.
    #[serde(default)]
    pub status: GameStatus,
    /// Founder-verifiziert? Initial `false`; setzt sich durch `GameVerify`-TX.
    #[serde(default)]
    pub verified: bool,
    /// Genres des Spiels (z.B. ["minecraft", "survival", "crafting"]).
    #[serde(default)]
    pub genres: Vec<String>,
}

// ─── Validierung ─────────────────────────────────────────────────────────────

/// Fehler bei der Validierung von Game-Chain-Payloads.
#[derive(Debug, Clone)]
pub enum GameChainError {
    InvalidCompanyName(String),
    InvalidGameId(String),
    InvalidGameName(String),
    InvalidVersion(String),
    InvalidUrl(String),
    InvalidCountry(String),
    CompanyExists(String),
    CompanyNotFound(String),
    GameExists(String),
    InvalidMemo(String),
}

impl std::fmt::Display for GameChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GameChainError::InvalidCompanyName(m) => write!(f, "Ungültiger Firmenname: {m}"),
            GameChainError::InvalidGameId(m)      => write!(f, "Ungültige Game-ID: {m}"),
            GameChainError::InvalidGameName(m)    => write!(f, "Ungültiger Spielname: {m}"),
            GameChainError::InvalidVersion(m)     => write!(f, "Ungültige Version: {m}"),
            GameChainError::InvalidUrl(m)         => write!(f, "Ungültige URL: {m}"),
            GameChainError::InvalidCountry(m)     => write!(f, "Ungültiger Ländercode: {m}"),
            GameChainError::CompanyExists(m)      => write!(f, "Firma bereits registriert: {m}"),
            GameChainError::CompanyNotFound(m)    => write!(f, "Firma nicht gefunden: {m}"),
            GameChainError::GameExists(m)         => write!(f, "Spiel-ID bereits vergeben: {m}"),
            GameChainError::InvalidMemo(m)        => write!(f, "Memo-JSON ungültig: {m}"),
        }
    }
}

impl std::error::Error for GameChainError {}

/// Validiert einen Firmennamen.
pub fn validate_company_name(name: &str) -> Result<(), GameChainError> {
    let trimmed = name.trim();
    if trimmed.len() < 2 || trimmed.len() > 64 {
        return Err(GameChainError::InvalidCompanyName(
            format!("Länge muss 2–64 Zeichen sein (ist {})", trimmed.len())
        ));
    }
    if !trimmed.chars().all(|c| c.is_alphanumeric() || " .,&'_-()".contains(c)) {
        return Err(GameChainError::InvalidCompanyName(
            "Nur Buchstaben, Ziffern und . , & ' _ - ( ) erlaubt".into()
        ));
    }
    Ok(())
}

/// Validiert eine Game-ID.
pub fn validate_game_id(id: &str) -> Result<(), GameChainError> {
    if id.len() < 3 || id.len() > 64 {
        return Err(GameChainError::InvalidGameId(
            format!("Länge muss 3–64 Zeichen sein (ist {})", id.len())
        ));
    }
    if !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        return Err(GameChainError::InvalidGameId(
            "Nur a-z, 0-9, '_' und '-' erlaubt".into()
        ));
    }
    Ok(())
}

/// Validiert einen Spielnamen.
pub fn validate_game_name(name: &str) -> Result<(), GameChainError> {
    let trimmed = name.trim();
    if trimmed.len() < 2 || trimmed.len() > 96 {
        return Err(GameChainError::InvalidGameName(
            format!("Länge muss 2–96 Zeichen sein (ist {})", trimmed.len())
        ));
    }
    Ok(())
}

/// Validiert eine Semver-Version (strikt: MAJOR.MINOR.PATCH).
pub fn validate_version(v: &str) -> Result<(), GameChainError> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return Err(GameChainError::InvalidVersion(
            "Format MAJOR.MINOR.PATCH erwartet".into()
        ));
    }
    for p in &parts {
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return Err(GameChainError::InvalidVersion(
                format!("Teil '{p}' ist keine reine Zahl")
            ));
        }
    }
    Ok(())
}

/// Validiert eine URL (rudimentär: nur https://… oder ipfs://…).
pub fn validate_url(url: &str) -> Result<(), GameChainError> {
    if url.is_empty() { return Ok(()); }
    if url.len() > 256 {
        return Err(GameChainError::InvalidUrl("max. 256 Zeichen".into()));
    }
    if !(url.starts_with("https://") || url.starts_with("ipfs://")) {
        return Err(GameChainError::InvalidUrl(
            "muss mit https:// oder ipfs:// beginnen".into()
        ));
    }
    Ok(())
}

/// Validiert einen ISO-3166-1 alpha-2 Ländercode (z.B. "DE").
pub fn validate_country(c: &str) -> Result<(), GameChainError> {
    if c.is_empty() { return Ok(()); }
    if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_uppercase()) {
        return Err(GameChainError::InvalidCountry(
            "muss 2 Großbuchstaben sein".into()
        ));
    }
    Ok(())
}

// ─── Memo-Helfer ─────────────────────────────────────────────────────────────

/// Payload für `TxType::CompanyRegister` im `memo`-Feld.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyRegisterMemo {
    pub name: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub website: String,
}

/// Payload für `TxType::GameRegister` im `memo`-Feld.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameRegisterMemo {
    pub game_id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub icon_uri: String,
    #[serde(default)]
    pub coin_address: String,
    /// Genres des Spiels (z.B. ["minecraft", "survival"]).
    #[serde(default)]
    pub genres: Vec<String>,
}

/// Payload für `TxType::CompanyUpdate` im `memo`-Feld.
/// Nur gesetzte Felder werden angewendet. Name ist immutable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompanyUpdateMemo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
}

/// Payload für `TxType::GameUpdate` im `memo`-Feld.
/// `game_id` identifiziert das Spiel, restliche Felder optional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameUpdateMemo {
    pub game_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coin_address: Option<String>,
    /// Genres aktualisieren (komplette Liste). Leer = nicht updaten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genres: Option<Vec<String>>,
}

/// Payload für `TxType::GameDeprecate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameDeprecateMemo {
    pub game_id: String,
}

// ─── Phase C: Verify + Sub-Keys ──────────────────────────────────────────────

/// Rolle eines Sub-Keys innerhalb einer Firma.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CompanyRole {
    /// Lesen + Game-Updates signieren (Version-Bumps).
    Developer,
    /// Treasury-Operationen (Auszahlungen, Coin-Mint später).
    Finance,
    /// Refunds + Support-TXs.
    Support,
}

impl CompanyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            CompanyRole::Developer => "developer",
            CompanyRole::Finance   => "finance",
            CompanyRole::Support   => "support",
        }
    }

    /// Prüft, ob diese Rolle den gegebenen TxType im Namen der Firma ausführen darf.
    ///
    /// Whitelist (additiv):
    /// - Developer: GameRegister/Update/Deprecate, GameCoinMint
    /// - Finance:   Transfer (bis Daily-Limit), GameCoinTransfer, GameCoinBurn
    /// - Support:   GameCoinTransfer (Refunds, bis Daily-Limit gespiegelt auf STONE-equiv)
    ///
    /// CompanyUpdate, RoleGrant/Revoke und alle Verify-TXs sind ausschließlich
    /// dem Owner vorbehalten.
    pub fn allows(&self, tx_type: &crate::token::TxType) -> bool {
        use crate::token::TxType::*;
        match self {
            CompanyRole::Developer => matches!(
                tx_type,
                GameRegister | GameUpdate | GameDeprecate | GameCoinMint
            ),
            CompanyRole::Finance => matches!(
                tx_type,
                Transfer | GameCoinTransfer | GameCoinBurn
            ),
            CompanyRole::Support => matches!(tx_type, GameCoinTransfer),
        }
    }
}

/// Sub-Key einer Firma: erweitert die Berechtigungen ohne den Owner-Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubKey {
    /// Wallet-Adresse des Sub-Keys (Public-Key-Hex).
    pub wallet: String,
    /// Rolle.
    pub role: CompanyRole,
    /// Granted-Timestamp.
    pub granted_at: i64,
    /// Granted-Block.
    pub granted_at_block: u64,
    /// Optional: max. STONE pro Tag (für Finance/Support). 0 = unlimitiert.
    #[serde(default)]
    pub daily_limit_stone: String,
}

/// Memo für `TxType::CompanyVerify` / `GameVerify`.
/// Founder-signed. Target ist die zu verifizierende Wallet (Company) bzw. Game-ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyMemo {
    /// Bei CompanyVerify: Wallet der zu verifizierenden Firma.
    /// Bei GameVerify: Game-ID.
    pub target: String,
    /// Optional: Begründungstext (max 256 Zeichen).
    #[serde(default)]
    pub reason: String,
}

/// Memo für `TxType::RoleGrant`.
/// `from`==`to`==Owner-Wallet einer Firma. Sub-Key wird hinzugefügt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleGrantMemo {
    /// Wallet-Adresse des Sub-Keys.
    pub sub_wallet: String,
    /// Rolle.
    pub role: CompanyRole,
    /// Optional: tägliches STONE-Limit (Decimal-String). Leer = unlimitiert.
    #[serde(default)]
    pub daily_limit_stone: String,
}

/// Memo für `TxType::RoleRevoke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRevokeMemo {
    pub sub_wallet: String,
}

/// Memo für `TxType::GameCoinMint`.
/// `to` = Empfänger-Wallet, `amount` = Decimal-String.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameCoinMintMemo {
    pub game_id: String,
    pub to: String,
    pub amount: String,
}

/// Memo für `TxType::GameCoinTransfer`.
/// STONE-`amount` der TX selbst ist 0. Coin-`amount` steht hier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameCoinTransferMemo {
    pub game_id: String,
    pub amount: String,
}

/// Memo für `TxType::GameCoinBurn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameCoinBurnMemo {
    pub game_id: String,
    pub amount: String,
}

impl CompanyRegisterMemo {
    /// Parst & validiert das memo-JSON.
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_company_name(&p.name)?;
        validate_country(&p.country)?;
        validate_url(&p.website)?;
        Ok(p)
    }
}

impl GameRegisterMemo {
    /// Parst & validiert das memo-JSON.
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.game_id)?;
        validate_game_name(&p.name)?;
        validate_version(&p.version)?;
        validate_url(&p.icon_uri)?;
        // coin_address: optional, wenn gesetzt → 64-Zeichen-Hex-Check
        if !p.coin_address.is_empty() {
            if p.coin_address.len() != 64
                || !p.coin_address.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(GameChainError::InvalidMemo(
                    "coin_address muss 64-Zeichen Hex oder leer sein".into()
                ));
            }
        }
        // Genres validieren (falls gesetzt): nur bekannte Genre-Namen
        for genre in &p.genres {
            if crate::token::game_economy::GameGenre::from_str(genre).is_none() {
                return Err(GameChainError::InvalidMemo(
                    format!("Unbekanntes Genre: '{genre}'")
                ));
            }
        }
        Ok(p)
    }
}

impl CompanyUpdateMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        if p.country.is_none() && p.website.is_none() {
            return Err(GameChainError::InvalidMemo(
                "Mindestens ein Feld (country/website) erforderlich".into()
            ));
        }
        if let Some(c) = &p.country { validate_country(c)?; }
        if let Some(w) = &p.website { validate_url(w)?; }
        Ok(p)
    }
}

impl GameUpdateMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.game_id)?;
        if p.version.is_none() && p.icon_uri.is_none() && p.coin_address.is_none() && p.genres.is_none() {
            return Err(GameChainError::InvalidMemo(
                "Mindestens ein Feld (version/icon_uri/coin_address/genres) erforderlich".into()
            ));
        }
        if let Some(v) = &p.version { validate_version(v)?; }
        if let Some(u) = &p.icon_uri { validate_url(u)?; }
        if let Some(c) = &p.coin_address {
            if !c.is_empty() && (c.len() != 64 || !c.chars().all(|x| x.is_ascii_hexdigit())) {
                return Err(GameChainError::InvalidMemo(
                    "coin_address muss 64-Zeichen Hex oder leer sein".into()
                ));
            }
        }
        // Genres validieren (falls gesetzt)
        if let Some(genres) = &p.genres {
            for genre in genres {
                if crate::token::game_economy::GameGenre::from_str(genre).is_none() {
                    return Err(GameChainError::InvalidMemo(
                        format!("Unbekanntes Genre: '{genre}'")
                    ));
                }
            }
        }
        Ok(p)
    }
}

impl GameDeprecateMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.game_id)?;
        Ok(p)
    }
}

// ─── Phase C parsers ─────────────────────────────────────────────────────────

fn validate_pubkey_hex(hex: &str) -> Result<(), GameChainError> {
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GameChainError::InvalidMemo(
            "Wallet muss 64-Zeichen Hex sein".into()
        ));
    }
    Ok(())
}

fn validate_decimal_str(s: &str) -> Result<(), GameChainError> {
    if s.is_empty() { return Ok(()); }
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(GameChainError::InvalidMemo(
            "daily_limit_stone: nur Ziffern und '.'".into()
        ));
    }
    if s.parse::<rust_decimal::Decimal>().is_err() {
        return Err(GameChainError::InvalidMemo(
            "daily_limit_stone: nicht parsebar".into()
        ));
    }
    Ok(())
}

impl VerifyMemo {
    pub fn parse_company(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_pubkey_hex(&p.target)?;
        if p.reason.len() > 256 {
            return Err(GameChainError::InvalidMemo("reason zu lang (>256)".into()));
        }
        Ok(p)
    }
    pub fn parse_game(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.target)?;
        if p.reason.len() > 256 {
            return Err(GameChainError::InvalidMemo("reason zu lang (>256)".into()));
        }
        Ok(p)
    }
}

impl RoleGrantMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_pubkey_hex(&p.sub_wallet)?;
        validate_decimal_str(&p.daily_limit_stone)?;
        Ok(p)
    }
}

impl RoleRevokeMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_pubkey_hex(&p.sub_wallet)?;
        Ok(p)
    }
}

/// Validiert einen positiven Decimal-Betrag (string-codiert, max 8 Nachkommastellen).
pub(crate) fn parse_positive_amount(s: &str) -> Result<rust_decimal::Decimal, GameChainError> {
    let d = s.parse::<rust_decimal::Decimal>()
        .map_err(|_| GameChainError::InvalidMemo(format!("Betrag '{s}' nicht parsebar")))?;
    if d <= rust_decimal::Decimal::ZERO {
        return Err(GameChainError::InvalidMemo("Betrag muss > 0 sein".into()));
    }
    if d.scale() > 8 {
        return Err(GameChainError::InvalidMemo("Maximal 8 Nachkommastellen".into()));
    }
    Ok(d)
}

impl GameCoinMintMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.game_id)?;
        validate_pubkey_hex(&p.to)?;
        parse_positive_amount(&p.amount)?;
        Ok(p)
    }
}

impl GameCoinTransferMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.game_id)?;
        parse_positive_amount(&p.amount)?;
        Ok(p)
    }
}

impl GameCoinBurnMemo {
    pub fn parse(memo: &str) -> Result<Self, GameChainError> {
        let p: Self = serde_json::from_str(memo)
            .map_err(|e| GameChainError::InvalidMemo(e.to_string()))?;
        validate_game_id(&p.game_id)?;
        parse_positive_amount(&p.amount)?;
        Ok(p)
    }
}

// ─── Founder-Set ─────────────────────────────────────────────────────────────

/// Lädt das Founder-Pubkey-Set aus:
/// 1. ENV `STONE_FOUNDER_PUBKEYS` (Komma-getrennt, 64-hex Einträge)
/// 2. `stone_data/founder.pub` (eine Wallet, eine Zeile)
///
/// Beide Quellen werden vereint. Leeres Set ist erlaubt — dann sind Verify-TXs
/// nicht möglich (Sicherheits-Fail-Safe).
pub fn load_founder_pubkeys() -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if let Ok(env) = std::env::var("STONE_FOUNDER_PUBKEYS") {
        for k in env.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()) {
                out.insert(k.to_lowercase());
            }
        }
    }
    let path = format!("{}/founder.pub", crate::blockchain::data_dir());
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines().map(|l| l.trim()) {
            if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                out.insert(line.to_lowercase());
            }
        }
    }
    out
}

/// Baut ein `CompanyProfile` aus geparstem Memo + Owner + Block-Kontext.
pub fn build_company(
    memo: &CompanyRegisterMemo,
    owner_wallet: &str,
    block_index: u64,
) -> CompanyProfile {
    CompanyProfile {
        owner_wallet: owner_wallet.to_string(),
        name: memo.name.trim().to_string(),
        country: memo.country.clone(),
        website: memo.website.clone(),
        registered_at_block: block_index,
        registered_at: Utc::now().timestamp(),
        verified: false,
        status: CompanyStatus::Active,
    }
}

/// Baut einen `OnChainGame`-Eintrag aus geparstem Memo + Owner + Block-Kontext.
pub fn build_game(
    memo: &GameRegisterMemo,
    owner_company: &str,
    block_index: u64,
) -> OnChainGame {
    OnChainGame {
        game_id: memo.game_id.clone(),
        owner_company: owner_company.to_string(),
        name: memo.name.trim().to_string(),
        version: memo.version.clone(),
        icon_uri: memo.icon_uri.clone(),
        coin_address: memo.coin_address.clone(),
        registered_at_block: block_index,
        registered_at: Utc::now().timestamp(),
        status: GameStatus::Active,
        verified: false,
        genres: memo.genres.clone(),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn company_name_validation() {
        assert!(validate_company_name("Stone Games GmbH").is_ok());
        assert!(validate_company_name("A&B Studios").is_ok());
        assert!(validate_company_name("X").is_err()); // zu kurz
        assert!(validate_company_name("Bad<Name>").is_err()); // Sonderzeichen
        assert!(validate_company_name(&"A".repeat(65)).is_err()); // zu lang
    }

    #[test]
    fn game_id_validation() {
        assert!(validate_game_id("chain_empires").is_ok());
        assert!(validate_game_id("stone-dungeon-v2").is_ok());
        assert!(validate_game_id("ab").is_err()); // zu kurz
        assert!(validate_game_id("Has Space").is_err());
        assert!(validate_game_id("UPPER").is_err()); // nur lowercase
    }

    #[test]
    fn version_validation() {
        assert!(validate_version("1.0.0").is_ok());
        assert!(validate_version("0.7.7").is_ok());
        assert!(validate_version("1.0").is_err());
        assert!(validate_version("1.0.0-rc1").is_err()); // pre-release verboten
        assert!(validate_version("v1.0.0").is_err());
    }

    #[test]
    fn url_validation() {
        assert!(validate_url("").is_ok()); // leer = optional
        assert!(validate_url("https://stone.games").is_ok());
        assert!(validate_url("ipfs://QmFoo").is_ok());
        assert!(validate_url("http://insecure.com").is_err());
        assert!(validate_url(&format!("https://{}", "a".repeat(260))).is_err());
    }

    #[test]
    fn country_validation() {
        assert!(validate_country("").is_ok());
        assert!(validate_country("DE").is_ok());
        assert!(validate_country("de").is_err());
        assert!(validate_country("DEU").is_err());
    }

    #[test]
    fn company_memo_parse_roundtrip() {
        let json = r#"{"name":"Stone Games","country":"DE","website":"https://stone.games"}"#;
        let memo = CompanyRegisterMemo::parse(json).expect("parse");
        assert_eq!(memo.name, "Stone Games");
        assert_eq!(memo.country, "DE");
    }

    #[test]
    fn company_memo_rejects_bad_url() {
        let json = r#"{"name":"X Games","website":"http://bad"}"#;
        assert!(CompanyRegisterMemo::parse(json).is_err());
    }

    #[test]
    fn game_memo_parse_roundtrip() {
        let json = r#"{"game_id":"stone-dungeon","name":"Stone Dungeon","version":"1.0.0"}"#;
        let memo = GameRegisterMemo::parse(json).expect("parse");
        assert_eq!(memo.game_id, "stone-dungeon");
        assert_eq!(memo.version, "1.0.0");
        assert!(memo.icon_uri.is_empty());
    }

    #[test]
    fn game_memo_rejects_bad_coin_address() {
        let json = r#"{"game_id":"abc","name":"Abc","version":"1.0.0","coin_address":"shortkey"}"#;
        assert!(GameRegisterMemo::parse(json).is_err());
    }

    #[test]
    fn build_company_uses_owner_and_block() {
        let m = CompanyRegisterMemo {
            name: "Stone Games".into(),
            country: "DE".into(),
            website: String::new(),
        };
        let c = build_company(&m, "abc123", 42);
        assert_eq!(c.owner_wallet, "abc123");
        assert_eq!(c.registered_at_block, 42);
        assert!(matches!(c.status, CompanyStatus::Active));
        assert!(!c.verified);
    }

    #[test]
    fn build_game_uses_owner_company() {
        let m = GameRegisterMemo {
            game_id: "stone-dungeon".into(),
            name: "Stone Dungeon".into(),
            version: "1.0.0".into(),
            icon_uri: String::new(),
            coin_address: String::new(),
        };
        let g = build_game(&m, "owner_wallet", 100);
        assert_eq!(g.owner_company, "owner_wallet");
        assert_eq!(g.registered_at_block, 100);
        assert!(matches!(g.status, GameStatus::Active));
    }

    // ── End-to-End: signierte TX → apply_tx → Ledger-State ────────────────

    use crate::token::{
        FeeTier, TokenLedger,
        transaction::{TxType, create_signed_tx},
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rust_decimal::Decimal;

    fn fresh_keypair() -> (SigningKey, String) {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    #[test]
    fn e2e_register_company_then_game() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();

        // 1) CompanyRegister
        let company_memo = serde_json::json!({
            "name": "Stone Games",
            "country": "DE",
            "website": "https://stone.games"
        }).to_string();
        let tx1 = create_signed_tx(
            &sk,
            TxType::CompanyRegister,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, company_memo, FeeTier::Standard,
        ).expect("sign company");
        ledger.apply_tx(&tx1, 1).expect("apply company");

        assert!(ledger.is_company(&addr));
        let c = ledger.company(&addr).expect("company present");
        assert_eq!(c.name, "Stone Games");
        assert_eq!(c.country, "DE");
        assert_eq!(c.registered_at_block, 1);
        assert_eq!(ledger.account_type(&addr), AccountType::Company);

        // 2) GameRegister
        let game_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "name": "Stone Dungeon",
            "version": "1.0.0"
        }).to_string();
        let tx2 = create_signed_tx(
            &sk,
            TxType::GameRegister,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            1, game_memo, FeeTier::Standard,
        ).expect("sign game");
        ledger.apply_tx(&tx2, 2).expect("apply game");

        let g = ledger.game("stone-dungeon").expect("game present");
        assert_eq!(g.name, "Stone Dungeon");
        assert_eq!(g.owner_company, addr);
        assert_eq!(ledger.game_count(), 1);
        assert_eq!(ledger.games_of_company(&addr).len(), 1);
    }

    #[test]
    fn e2e_game_register_without_company_fails() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();

        let memo = serde_json::json!({
            "game_id": "abc-game",
            "name": "Abc Game",
            "version": "1.0.0"
        }).to_string();
        let tx = create_signed_tx(
            &sk,
            TxType::GameRegister,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, memo, FeeTier::Standard,
        ).expect("sign");
        assert!(ledger.apply_tx(&tx, 1).is_err(), "must fail: no company");
        assert!(ledger.game("abc-game").is_none());
    }

    #[test]
    fn e2e_duplicate_company_register_fails() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        let memo = serde_json::json!({ "name": "Stone Games" }).to_string();

        let tx1 = create_signed_tx(
            &sk, TxType::CompanyRegister,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, memo.clone(), FeeTier::Standard,
        ).expect("sign 1");
        ledger.apply_tx(&tx1, 1).expect("apply 1");

        let tx2 = create_signed_tx(
            &sk, TxType::CompanyRegister,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            1, memo, FeeTier::Standard,
        ).expect("sign 2");
        assert!(ledger.apply_tx(&tx2, 2).is_err(), "duplicate must fail");
    }

    #[test]
    fn e2e_duplicate_game_id_fails() {
        let (sk_a, addr_a) = fresh_keypair();
        let (sk_b, addr_b) = fresh_keypair();
        let mut ledger = TokenLedger::new();

        // Beide registrieren Firmen
        let c_memo = serde_json::json!({ "name": "Studio A" }).to_string();
        let tx = create_signed_tx(
            &sk_a, TxType::CompanyRegister,
            addr_a.clone(), addr_a.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 1).unwrap();
        let c_memo_b = serde_json::json!({ "name": "Studio B" }).to_string();
        let tx = create_signed_tx(
            &sk_b, TxType::CompanyRegister,
            addr_b.clone(), addr_b.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo_b, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 1).unwrap();

        // A registriert Spiel
        let g_memo = serde_json::json!({
            "game_id": "shared-id", "name": "Game A", "version": "1.0.0"
        }).to_string();
        let tx = create_signed_tx(
            &sk_a, TxType::GameRegister,
            addr_a.clone(), addr_a.clone(),
            Decimal::ZERO, Decimal::ZERO,
            1, g_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 2).expect("first game ok");

        // B versucht dieselbe game_id
        let g_memo2 = serde_json::json!({
            "game_id": "shared-id", "name": "Game B", "version": "1.0.0"
        }).to_string();
        let tx = create_signed_tx(
            &sk_b, TxType::GameRegister,
            addr_b.clone(), addr_b.clone(),
            Decimal::ZERO, Decimal::ZERO,
            1, g_memo2, FeeTier::Standard,
        ).unwrap();
        assert!(ledger.apply_tx(&tx, 2).is_err(), "duplicate game_id must fail");
    }

    // ── Update / Deprecate flows ──────────────────────────────────────────

    fn setup_company_and_game(sk: &SigningKey, addr: &str, ledger: &mut TokenLedger) {
        let c_memo = serde_json::json!({ "name": "Stone Games" }).to_string();
        let tx = create_signed_tx(
            sk, TxType::CompanyRegister,
            addr.to_string(), addr.to_string(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 1).unwrap();
        let g_memo = serde_json::json!({
            "game_id": "stone-dungeon", "name": "Stone Dungeon", "version": "1.0.0"
        }).to_string();
        let tx = create_signed_tx(
            sk, TxType::GameRegister,
            addr.to_string(), addr.to_string(),
            Decimal::ZERO, Decimal::ZERO,
            1, g_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 2).unwrap();
    }

    #[test]
    fn e2e_company_update_changes_fields() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk, &addr, &mut ledger);

        let memo = serde_json::json!({
            "country": "AT", "website": "https://stone.at"
        }).to_string();
        let tx = create_signed_tx(
            &sk, TxType::CompanyUpdate,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        let c = ledger.company(&addr).unwrap();
        assert_eq!(c.country, "AT");
        assert_eq!(c.website, "https://stone.at");
        assert_eq!(c.name, "Stone Games"); // immutable
    }

    #[test]
    fn e2e_game_update_bumps_version() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk, &addr, &mut ledger);

        let memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "version": "1.1.0",
            "icon_uri": "ipfs://Qm123"
        }).to_string();
        let tx = create_signed_tx(
            &sk, TxType::GameUpdate,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        let g = ledger.game("stone-dungeon").unwrap();
        assert_eq!(g.version, "1.1.0");
        assert_eq!(g.icon_uri, "ipfs://Qm123");
    }

    #[test]
    fn e2e_game_update_by_non_owner_fails() {
        let (sk_a, addr_a) = fresh_keypair();
        let (sk_b, addr_b) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_a, &addr_a, &mut ledger);

        // B als Firma registrieren (sonst scheitert es schon an account_type)
        let c_memo = serde_json::json!({ "name": "Studio B" }).to_string();
        let tx = create_signed_tx(
            &sk_b, TxType::CompanyRegister,
            addr_b.clone(), addr_b.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        // B versucht A's Spiel zu updaten
        let memo = serde_json::json!({
            "game_id": "stone-dungeon", "version": "9.9.9"
        }).to_string();
        let tx = create_signed_tx(
            &sk_b, TxType::GameUpdate,
            addr_b.clone(), addr_b.clone(),
            Decimal::ZERO, Decimal::ZERO,
            1, memo, FeeTier::Standard,
        ).unwrap();
        assert!(ledger.apply_tx(&tx, 4).is_err(), "non-owner update must fail");
        assert_eq!(ledger.game("stone-dungeon").unwrap().version, "1.0.0");
    }

    #[test]
    fn e2e_game_deprecate() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk, &addr, &mut ledger);

        let memo = serde_json::json!({ "game_id": "stone-dungeon" }).to_string();
        let tx = create_signed_tx(
            &sk, TxType::GameDeprecate,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        let g = ledger.game("stone-dungeon").unwrap();
        assert!(matches!(g.status, GameStatus::Deprecated));
    }

    #[test]
    fn state_root_changes_with_companies() {
        let (sk, addr) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        let root_empty = ledger.state_root();

        let c_memo = serde_json::json!({ "name": "Stone Games" }).to_string();
        let tx = create_signed_tx(
            &sk, TxType::CompanyRegister,
            addr.clone(), addr.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 1).unwrap();

        let root_after = ledger.state_root();
        assert_ne!(root_empty, root_after, "state_root must change after company register");
    }

    // ─── Phase C Tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_verify_memo_company() {
        let valid = serde_json::json!({
            "target": "a".repeat(64),
            "reason": "KYC ok"
        }).to_string();
        let m = VerifyMemo::parse_company(&valid).unwrap();
        assert_eq!(m.reason, "KYC ok");

        let bad_hex = serde_json::json!({
            "target": "zzz",
            "reason": "x"
        }).to_string();
        assert!(VerifyMemo::parse_company(&bad_hex).is_err());
    }

    #[test]
    fn parse_role_grant_memo() {
        let m = serde_json::json!({
            "sub_wallet": "b".repeat(64),
            "role": "developer",
            "daily_limit_stone": "100.5"
        }).to_string();
        let p = RoleGrantMemo::parse(&m).unwrap();
        assert!(matches!(p.role, CompanyRole::Developer));
        assert_eq!(p.daily_limit_stone, "100.5");
    }

    #[test]
    fn e2e_founder_verifies_company() {
        let (sk_owner, owner) = fresh_keypair();
        let (sk_founder, founder) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        ledger.add_founder_for_test(&founder);

        // Owner registriert Firma
        let c_memo = serde_json::json!({ "name": "Stone Games" }).to_string();
        let tx1 = create_signed_tx(
            &sk_owner, TxType::CompanyRegister,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx1, 1).unwrap();
        assert!(!ledger.company(&owner).unwrap().verified);

        // Founder verifiziert
        let v_memo = serde_json::json!({
            "target": owner.clone(),
            "reason": "approved"
        }).to_string();
        let tx2 = create_signed_tx(
            &sk_founder, TxType::CompanyVerify,
            founder.clone(), founder.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, v_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx2, 2).unwrap();

        assert!(ledger.company(&owner).unwrap().verified);
    }

    #[test]
    fn e2e_non_founder_verify_fails() {
        let (sk_owner, owner) = fresh_keypair();
        let (sk_attacker, attacker) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        // Aus stone_data/founder.pub potentiell geladene Pubkeys leeren,
        // damit der Test reproduzierbar ist (attacker ist garantiert kein Founder).
        ledger.clear_founders_for_test();

        let c_memo = serde_json::json!({ "name": "XX" }).to_string();
        let tx1 = create_signed_tx(
            &sk_owner, TxType::CompanyRegister,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx1, 1).unwrap();

        let v_memo = serde_json::json!({
            "target": owner.clone(),
            "reason": "hax"
        }).to_string();
        let tx2 = create_signed_tx(
            &sk_attacker, TxType::CompanyVerify,
            attacker.clone(), attacker.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, v_memo, FeeTier::Standard,
        ).unwrap();
        assert!(ledger.apply_tx(&tx2, 2).is_err());
        assert!(!ledger.company(&owner).unwrap().verified);
    }

    #[test]
    fn e2e_founder_verifies_game() {
        let (sk_owner, owner) = fresh_keypair();
        let (sk_founder, founder) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        ledger.add_founder_for_test(&founder);
        setup_company_and_game(&sk_owner, &owner, &mut ledger);
        assert!(!ledger.game("stone-dungeon").unwrap().verified);

        let v_memo = serde_json::json!({
            "target": "stone-dungeon",
            "reason": "audit pass"
        }).to_string();
        let tx = create_signed_tx(
            &sk_founder, TxType::GameVerify,
            founder.clone(), founder.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, v_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        assert!(ledger.game("stone-dungeon").unwrap().verified);
    }

    #[test]
    fn e2e_role_grant_and_revoke() {
        let (sk_owner, owner) = fresh_keypair();
        let (_sk_sub, sub) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);

        // Grant
        let g_memo = serde_json::json!({
            "sub_wallet": sub.clone(),
            "role": "developer",
            "daily_limit_stone": "10"
        }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::RoleGrant,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, g_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        let keys = ledger.sub_keys_of(&owner);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].wallet, sub);

        // Revoke
        let r_memo = serde_json::json!({ "sub_wallet": sub.clone() }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::RoleRevoke,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            3, r_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 4).unwrap();
        assert!(ledger.sub_keys_of(&owner).is_empty());
    }

    #[test]
    fn role_grant_by_non_company_fails() {
        let (sk_personal, personal) = fresh_keypair();
        let (_sk_sub, sub) = fresh_keypair();
        let mut ledger = TokenLedger::new();

        let memo = serde_json::json!({
            "sub_wallet": sub,
            "role": "developer",
            "daily_limit_stone": "1"
        }).to_string();
        let tx = create_signed_tx(
            &sk_personal, TxType::RoleGrant,
            personal.clone(), personal.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, memo, FeeTier::Standard,
        ).unwrap();
        assert!(ledger.apply_tx(&tx, 1).is_err());
    }

    #[test]
    fn state_root_changes_with_subkeys() {
        let (sk, owner) = fresh_keypair();
        let (_sk2, sub) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk, &owner, &mut ledger);
        let r0 = ledger.state_root();

        let memo = serde_json::json!({
            "sub_wallet": sub,
            "role": "finance",
            "daily_limit_stone": "50"
        }).to_string();
        let tx = create_signed_tx(
            &sk, TxType::RoleGrant,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();
        assert_ne!(r0, ledger.state_root());
    }

    // ─── Phase D Tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_gamecoin_mint_memo() {
        let m = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": "c".repeat(64),
            "amount": "100.5"
        }).to_string();
        let p = GameCoinMintMemo::parse(&m).unwrap();
        assert_eq!(p.game_id, "stone-dungeon");
        assert_eq!(p.amount, "100.5");

        // invalid: amount=0
        let bad = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": "c".repeat(64),
            "amount": "0"
        }).to_string();
        assert!(GameCoinMintMemo::parse(&bad).is_err());
    }

    #[test]
    fn role_allows_check() {
        use crate::token::TxType;
        assert!(CompanyRole::Developer.allows(&TxType::GameRegister));
        assert!(CompanyRole::Developer.allows(&TxType::GameCoinMint));
        assert!(!CompanyRole::Developer.allows(&TxType::Transfer));
        assert!(CompanyRole::Finance.allows(&TxType::Transfer));
        assert!(!CompanyRole::Finance.allows(&TxType::GameRegister));
        assert!(CompanyRole::Support.allows(&TxType::GameCoinTransfer));
        assert!(!CompanyRole::Support.allows(&TxType::Transfer));
    }

    #[test]
    fn e2e_game_coin_mint_and_transfer() {
        let (sk_owner, owner) = fresh_keypair();
        let (_sk_player, player) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);

        let mint_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": player.clone(),
            "amount": "1000"
        }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::GameCoinMint,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, mint_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        assert_eq!(ledger.game_coin_balance("stone-dungeon", &player), Decimal::new(1000, 0));
        assert_eq!(ledger.game_coin_supply("stone-dungeon"), Decimal::new(1000, 0));
    }

    #[test]
    fn e2e_game_coin_mint_by_foreign_company_fails() {
        let (sk_owner, owner) = fresh_keypair();
        let (sk_other, other) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);
        // Andere Firma registrieren
        let c_memo = serde_json::json!({ "name": "Evil Co" }).to_string();
        let tx = create_signed_tx(
            &sk_other, TxType::CompanyRegister,
            other.clone(), other.clone(),
            Decimal::ZERO, Decimal::ZERO,
            0, c_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 1).unwrap();

        // 'other' versucht zu minten für 'stone-dungeon' (Owner = owner)
        let mint_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": other.clone(),
            "amount": "100"
        }).to_string();
        let tx = create_signed_tx(
            &sk_other, TxType::GameCoinMint,
            other.clone(), other.clone(),
            Decimal::ZERO, Decimal::ZERO,
            1, mint_memo, FeeTier::Standard,
        ).unwrap();
        assert!(ledger.apply_tx(&tx, 2).is_err());
    }

    #[test]
    fn e2e_game_coin_burn() {
        let (sk_owner, owner) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);

        // Mint an Owner selbst
        let m_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": owner.clone(),
            "amount": "500"
        }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::GameCoinMint,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, m_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        // Burn 200
        let b_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "amount": "200"
        }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::GameCoinBurn,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            3, b_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 4).unwrap();

        assert_eq!(ledger.game_coin_balance("stone-dungeon", &owner), Decimal::new(300, 0));
        assert_eq!(ledger.game_coin_supply("stone-dungeon"), Decimal::new(300, 0));
    }

    #[test]
    fn e2e_subkey_developer_can_mint_gamecoin() {
        use crate::token::create_signed_tx_as_subkey;
        let (sk_owner, owner) = fresh_keypair();
        let (sk_dev, dev_wallet) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);

        // RoleGrant dev
        let g_memo = serde_json::json!({
            "sub_wallet": dev_wallet.clone(),
            "role": "developer",
            "daily_limit_stone": ""
        }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::RoleGrant,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, g_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        // Dev signiert GameCoinMint im Namen der Firma
        let (_sk_player, player) = fresh_keypair();
        let mint_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": player.clone(),
            "amount": "42"
        }).to_string();
        // Owner-Nonce ist 3 (CompanyRegister=0, GameRegister=1, RoleGrant=2 → nächste = 3)
        let tx = create_signed_tx_as_subkey(
            &sk_dev, TxType::GameCoinMint,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            3, mint_memo, FeeTier::Standard,
        ).unwrap();
        assert_eq!(tx.signed_by.as_deref(), Some(dev_wallet.as_str()));
        ledger.apply_tx(&tx, 4).unwrap();
        assert_eq!(ledger.game_coin_balance("stone-dungeon", &player), Decimal::new(42, 0));
    }

    #[test]
    fn e2e_subkey_support_cannot_mint() {
        use crate::token::create_signed_tx_as_subkey;
        let (sk_owner, owner) = fresh_keypair();
        let (sk_sup, sup_wallet) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);

        let g_memo = serde_json::json!({
            "sub_wallet": sup_wallet.clone(),
            "role": "support",
            "daily_limit_stone": ""
        }).to_string();
        let tx = create_signed_tx(
            &sk_owner, TxType::RoleGrant,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, g_memo, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();

        let mint_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": owner.clone(),
            "amount": "1"
        }).to_string();
        let tx = create_signed_tx_as_subkey(
            &sk_sup, TxType::GameCoinMint,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            3, mint_memo, FeeTier::Standard,
        ).unwrap();
        // Support hat keine GameCoinMint-Rechte → Ledger lehnt ab
        assert!(ledger.apply_tx(&tx, 4).is_err());
    }

    #[test]
    fn e2e_subkey_unknown_signer_rejected() {
        use crate::token::create_signed_tx_as_subkey;
        let (sk_owner, owner) = fresh_keypair();
        let (sk_attacker, _attacker) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk_owner, &owner, &mut ledger);

        // attacker hat KEINEN Grant
        let mint_memo = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": owner.clone(),
            "amount": "1"
        }).to_string();
        let tx = create_signed_tx_as_subkey(
            &sk_attacker, TxType::GameCoinMint,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, mint_memo, FeeTier::Standard,
        ).unwrap();
        assert!(ledger.apply_tx(&tx, 3).is_err());
    }

    #[test]
    fn state_root_changes_with_gamecoins() {
        let (sk, owner) = fresh_keypair();
        let (_sk2, player) = fresh_keypair();
        let mut ledger = TokenLedger::new();
        setup_company_and_game(&sk, &owner, &mut ledger);
        let r0 = ledger.state_root();

        let m = serde_json::json!({
            "game_id": "stone-dungeon",
            "to": player,
            "amount": "1"
        }).to_string();
        let tx = create_signed_tx(
            &sk, TxType::GameCoinMint,
            owner.clone(), owner.clone(),
            Decimal::ZERO, Decimal::ZERO,
            2, m, FeeTier::Standard,
        ).unwrap();
        ledger.apply_tx(&tx, 3).unwrap();
        assert_ne!(r0, ledger.state_root());
    }
}
