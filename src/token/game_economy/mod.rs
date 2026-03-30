 //! Game Economy SDK – Datenmodelle & Business-Logik
//!
//! Architektur:  Chain ↔ SDK ↔ Spiele
//!
//! - Die Chain kümmert sich NUR um Coins & Assets
//! - Das SDK gibt Entwicklern die Werkzeuge
//! - Jedes Spiel integriert das SDK, baut eigene Logik
//!
//! ## Kernkonzepte
//!
//! | Konzept            | Beschreibung                                            |
//! |--------------------|---------------------------------------------------------|
//! | Game Registry      | Spiele registrieren sich, erhalten API-Key              |
//! | Permission-System  | 5 Stufen: Basic, Marketplace, Assets, Tournament, Social|
//! | User Consent       | Nutzer genehmigen Spiel-Wallets (wie iOS-Permissions)   |
//! | Daily Limits       | Nutzer kontrollieren max. Ausgaben pro Spiel/Tag        |
//! | Isolation          | Spiel A sieht nie Spiel B                               |
//! | Audit-Log          | Jede SDK-Aktion wird transparent geloggt                |
//! | Blacklisting       | Gemeldete Spiele werden gesperrt                        |

use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
//  Konstanten
// ═══════════════════════════════════════════════════════════════════════════════

pub const MAX_LISTINGS_PER_WALLET: usize = 50;
pub const MARKETPLACE_FEE_PCT: u64 = 25;  // 2.5% (Basis 1000)
pub const MARKETPLACE_FEE_BASE: u64 = 1000;
pub const SESSION_TTL_SECS: i64 = 24 * 3600;
pub const MAX_BATCH_SIZE: usize = 20;
pub const MARKETPLACE_POOL: &str = "pool:marketplace";
pub const CONSENT_TTL_SECS: i64 = 7 * 24 * 3600; // 7 Tage
pub const MAX_AUDIT_ENTRIES: usize = 50_000;

// ═══════════════════════════════════════════════════════════════════════════════
//  Permission-System
// ═══════════════════════════════════════════════════════════════════════════════

/// Die 5 Permission-Stufen die ein Spiel beantragen kann.
///
/// Ein Casual-Game braucht nur `Basic`.
/// Ein MMO wie Chain Empires braucht alle fünf.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GamePermission {
    /// Coins empfangen/senden, Kontostand abfragen
    Basic,
    /// Items listen, kaufen, Escrow-Transaktionen
    Marketplace,
    /// On-Chain Items erstellen (mint), Items verbrennen (burn)
    Assets,
    /// Preisgelder verteilen, Treasury-Wallet nutzen
    Tournament,
    /// Coins an andere Spieler senden, Geschenke, Trades
    Social,
}

impl std::fmt::Display for GamePermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Marketplace => write!(f, "marketplace"),
            Self::Assets => write!(f, "assets"),
            Self::Tournament => write!(f, "tournament"),
            Self::Social => write!(f, "social"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Game Registry
// ═══════════════════════════════════════════════════════════════════════════════

/// Status eines registrierten Spiels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GameStatus {
    /// Spiel ist aktiv und kann SDK nutzen
    Active,
    /// Temporär gesperrt (z.B. verdächtiges Verhalten)
    Suspended { reason: String, until: Option<i64> },
    /// Permanent gesperrt (z.B. Betrug)
    Blacklisted { reason: String },
}

/// Ein registriertes Spiel mit API-Key und Berechtigungen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredGame {
    /// Eindeutige Game-ID (z.B. "chain-empires")
    pub game_id: String,
    /// Anzeigename
    pub name: String,
    /// Beschreibung
    pub description: String,
    /// Website des Spiels
    pub website: String,
    /// Wallet des Entwicklers (Eigentümer)
    pub developer_wallet: String,
    /// SHA-256 Hash des API-Keys (Key wird nur einmalig angezeigt)
    pub api_key_hash: String,
    /// Maximales tägliches Wallet-Limit das das Spiel anfragen darf
    pub max_wallet_limit: Decimal,
    /// Genehmigte Berechtigungen
    pub permissions: Vec<GamePermission>,
    /// Status
    pub status: GameStatus,
    /// Registriert am
    pub created_at: i64,
    /// Letzte Änderung
    pub updated_at: i64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  User Consent – Nutzer-Zustimmung
// ═══════════════════════════════════════════════════════════════════════════════

/// Status der Nutzer-Zustimmung für ein Spiel-Wallet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    /// Warte auf Nutzer-Entscheidung
    Pending,
    /// Nutzer hat genehmigt
    Approved { at: i64 },
    /// Nutzer hat abgelehnt
    Rejected { at: i64 },
    /// Nutzer hat widerrufen (Wallet eingefroren)
    Revoked { at: i64, reason: String },
}

/// Status einer Consent-Anfrage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentRequestStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Consent-Anfrage: Ein Spiel möchte eine Wallet für einen Nutzer erstellen.
///
/// ```text
/// ┌─────────────────────────────────┐
/// │ "Chain Empires" möchte          │
/// │ eine Spiel-Wallet erstellen     │
/// │                                 │
/// │ Maximales Limit: 100 Coins/Tag  │
/// │ Erlaubte Aktionen: Kaufen,      │
/// │ Verkaufen, Turniere             │
/// │                                 │
/// │ [Ablehnen]  [Genehmigen]        │
/// └─────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequest {
    /// Eindeutige Request-ID
    pub request_id: String,
    /// Game-ID
    pub game_id: String,
    /// Anzeigename des Spiels (für UI)
    pub game_name: String,
    /// Wallet-Adresse des Spielers
    pub player_wallet: String,
    /// Angefragtes tägliches Limit
    pub requested_limit: Decimal,
    /// Angefragte Berechtigungen
    pub requested_permissions: Vec<GamePermission>,
    /// Status
    pub status: ConsentRequestStatus,
    /// Erstellt am
    pub created_at: i64,
    /// Läuft ab am (7 Tage)
    pub expires_at: i64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Game Wallet – Isolierte Spiel-Wallets mit Limits
// ═══════════════════════════════════════════════════════════════════════════════

/// Ein Game-Wallet ist ein isoliertes Sub-Wallet pro Spiel pro Nutzer.
///
/// ```text
/// NUTZER
/// └── Haupt-Wallet (gehört nur ihm, nie einem Spiel)
///     ├── Spiel-Wallet: Chain Empires
///     │   └── Limit: 100 Coins/Tag
///     ├── Spiel-Wallet: Spiel XY
///     │   └── Limit: 50 Coins/Tag
///     └── Spiel-Wallet: Spiel Z
///         └── Limit: 200 Coins/Tag
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameWallet {
    /// Haupt-Wallet-Adresse des Spielers
    pub owner_wallet: String,
    /// Deterministisch abgeleitete Game-Wallet-Adresse
    pub game_wallet: String,
    /// Game-ID
    pub game_id: String,
    /// Anzeigename des Spielers im Spiel
    pub display_name: String,
    /// Tägliches Ausgabelimit (vom Nutzer gesetzt)
    pub daily_limit: Decimal,
    /// Heute bereits ausgegeben
    pub spent_today: Decimal,
    /// Nächster Limit-Reset (Mitternacht UTC)
    pub limit_reset_at: i64,
    /// Consent-Status
    pub consent: ConsentStatus,
    /// Vom Nutzer genehmigte Berechtigungen (Teilmenge der Spiel-Permissions)
    pub allowed_permissions: Vec<GamePermission>,
    /// Vom Nutzer eingefroren? (Spiel kann nicht mehr zugreifen)
    pub frozen: bool,
    /// Erstellt am
    pub created_at: i64,
    /// Letzter Zugriff
    pub last_active: i64,
}

impl GameWallet {
    /// Prüft ob eine Berechtigung für dieses Wallet genehmigt wurde.
    pub fn has_permission(&self, perm: GamePermission) -> bool {
        self.allowed_permissions.contains(&perm)
    }

    /// Prüft und resettet das tägliche Limit falls ein neuer Tag begonnen hat.
    pub fn check_and_reset_daily_limit(&mut self) {
        let now = Utc::now().timestamp();
        if now >= self.limit_reset_at {
            self.spent_today = Decimal::ZERO;
            self.limit_reset_at = next_midnight_utc(now);
        }
    }

    /// Prüft ob ein Betrag noch im Tageslimit ist.
    pub fn can_spend(&mut self, amount: Decimal) -> bool {
        self.check_and_reset_daily_limit();
        self.spent_today + amount <= self.daily_limit
    }

    /// Registriert eine Ausgabe.
    pub fn record_spend(&mut self, amount: Decimal) {
        self.check_and_reset_daily_limit();
        self.spent_today += amount;
        self.last_active = Utc::now().timestamp();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  NFT Items
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ItemRarity {
    Common,
    Uncommon,
    Rare,
    Epic,
    Legendary,
}

impl std::fmt::Display for ItemRarity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Common => write!(f, "common"),
            Self::Uncommon => write!(f, "uncommon"),
            Self::Rare => write!(f, "rare"),
            Self::Epic => write!(f, "epic"),
            Self::Legendary => write!(f, "legendary"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameItem {
    pub item_id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub rarity: ItemRarity,
    pub owner: String,
    pub game_id: String,
    pub creator: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: i64,
    pub transferable: bool,
    pub burned: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Marktplatz
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListingStatus {
    Active,
    Sold { buyer: String, sold_at: i64 },
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketListing {
    pub listing_id: String,
    pub item_id: String,
    pub seller: String,
    pub price: Decimal,
    pub status: ListingStatus,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketOffer {
    pub offer_id: String,
    pub listing_id: String,
    pub bidder: String,
    pub amount: Decimal,
    pub created_at: i64,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceHistoryEntry {
    pub item_id: String,
    pub price: Decimal,
    pub seller: String,
    pub buyer: String,
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SDK Session
// ═══════════════════════════════════════════════════════════════════════════════

/// Eine SDK-Session – authentifiziert ein Spiel für einen Nutzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkSession {
    pub token: String,
    pub game_id: String,
    pub wallet: String,
    pub permissions: Vec<GamePermission>,
    pub created_at: i64,
    pub expires_at: i64,
    pub active: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Wallet-Link
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletLink {
    pub player_id: String,
    pub game_id: String,
    pub wallet: String,
    pub linked_at: i64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Audit-Log
// ═══════════════════════════════════════════════════════════════════════════════

/// Jede SDK-Aktion wird transparent geloggt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub entry_id: String,
    pub timestamp: i64,
    pub game_id: String,
    pub wallet: String,
    pub action: String,
    pub details: serde_json::Value,
    pub success: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper-Structs
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingWithItem {
    pub listing: MarketListing,
    pub item: GameItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub wallet: String,
    pub item_count: usize,
    pub estimated_value: Decimal,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  In-Game Shop – Katalog-Items die direkt gekauft werden können
// ═══════════════════════════════════════════════════════════════════════════════

/// Ein Shop-Item das der Entwickler definiert hat.
/// Spieler können es kaufen, indem sie Stone an die Treasury-Wallet senden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShopItem {
    pub shop_item_id: String,
    pub game_id: String,
    pub name: String,
    pub description: String,
    pub price: Decimal,
    /// `None` = unbegrenzt, `Some(n)` = maximal n Stück
    pub stock: Option<u64>,
    pub sold: u64,
    pub category: String,
    pub rarity: ItemRarity,
    pub metadata: serde_json::Value,
    pub active: bool,
    pub created_at: i64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Game Economy Store
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameEconomyStore {
    /// Registrierte Spiele: game_id → RegisteredGame
    pub registered_games: HashMap<String, RegisteredGame>,
    /// Consent-Requests: request_id → ConsentRequest
    pub consent_requests: HashMap<String, ConsentRequest>,
    /// Game-Wallets: game_wallet_address → GameWallet
    pub game_wallets: HashMap<String, GameWallet>,
    /// NFT-Items: item_id → GameItem
    pub items: HashMap<String, GameItem>,
    /// Marketplace-Listings: listing_id → MarketListing
    pub listings: HashMap<String, MarketListing>,
    /// Gebote: offer_id → MarketOffer
    pub offers: HashMap<String, MarketOffer>,
    /// Preishistorie: item_id → Vec<PriceHistoryEntry>
    pub price_history: HashMap<String, Vec<PriceHistoryEntry>>,
    /// SDK-Sessions: token → SdkSession
    pub sessions: HashMap<String, SdkSession>,
    /// Wallet-Links: "game_id:player_id" → WalletLink
    pub wallet_links: HashMap<String, WalletLink>,
    /// In-Game Shop: shop_item_id → ShopItem
    #[serde(default)]
    pub shop_items: HashMap<String, ShopItem>,
    /// Audit-Log (letzte MAX_AUDIT_ENTRIES Einträge)
    pub audit_log: Vec<AuditLogEntry>,
}

pub mod registry;
pub mod wallet;
pub mod marketplace;
pub mod session;
pub mod persistence;

impl GameEconomyStore {
    pub fn new() -> Self {
        Self {
            registered_games: HashMap::new(),
            consent_requests: HashMap::new(),
            game_wallets: HashMap::new(),
            items: HashMap::new(),
            listings: HashMap::new(),
            offers: HashMap::new(),
            price_history: HashMap::new(),
            sessions: HashMap::new(),
            wallet_links: HashMap::new(),
            shop_items: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

}

impl Default for GameEconomyStore {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Error Type
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GameEconomyError {
    NotFound { what: String },
    AlreadyExists { what: String },
    NotOwner { item_id: String, expected: String, actual: String },
    NotTransferable { item_id: String },
    ItemBurned { item_id: String },
    InvalidAmount { reason: String },
    InvalidInput { reason: String },
    InvalidState { reason: String },
    LimitReached { limit: usize },
    Unauthorized { reason: String },
    PermissionDenied { action: String },
    WalletFrozen { game_id: String },
    DailyLimitExceeded { limit: Decimal, spent: Decimal, requested: Decimal },
    GameSuspended { game_id: String, reason: String },
    GameBlacklisted { game_id: String, reason: String },
}

impl std::fmt::Display for GameEconomyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { what } => write!(f, "{what} nicht gefunden"),
            Self::AlreadyExists { what } => write!(f, "{what} existiert bereits"),
            Self::NotOwner { item_id, expected, actual } => {
                write!(f, "Item {item_id}: erwartet Besitzer {expected}, ist {actual}")
            }
            Self::NotTransferable { item_id } => write!(f, "Item {item_id} nicht transferierbar"),
            Self::ItemBurned { item_id } => write!(f, "Item {item_id} wurde verbrannt"),
            Self::InvalidAmount { reason } => write!(f, "Ungültiger Betrag: {reason}"),
            Self::InvalidInput { reason } => write!(f, "Ungültige Eingabe: {reason}"),
            Self::InvalidState { reason } => write!(f, "Ungültiger Zustand: {reason}"),
            Self::LimitReached { limit } => write!(f, "Limit erreicht ({limit})"),
            Self::Unauthorized { reason } => write!(f, "Nicht autorisiert: {reason}"),
            Self::PermissionDenied { action } => write!(f, "Keine Berechtigung: {action}"),
            Self::WalletFrozen { game_id } => write!(f, "Game-Wallet für '{game_id}' ist eingefroren"),
            Self::DailyLimitExceeded { limit, spent, requested } => {
                write!(f, "Tageslimit überschritten: {spent}+{requested} > {limit}")
            }
            Self::GameSuspended { game_id, reason } => write!(f, "Spiel '{game_id}' gesperrt: {reason}"),
            Self::GameBlacklisted { game_id, reason } => write!(f, "Spiel '{game_id}' blacklisted: {reason}"),
        }
    }
}

impl std::error::Error for GameEconomyError {}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Deterministisch Game-Wallet-Adresse ableiten (SHA-256).
pub fn derive_game_wallet(owner: &str, game_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("stone:game-wallet:{owner}:{game_id}").as_bytes());
    let result = hasher.finalize();
    format!("game:{}", hex::encode(&result[..16]))
}

/// API-Key generieren. Gibt (api_key, sha256_hash) zurück.
fn generate_api_key(game_id: &str, wallet: &str) -> (String, String) {
    let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(format!("stone:sdk-key:{game_id}:{wallet}:{now}").as_bytes());
    let key_bytes = hasher.finalize();
    let api_key = format!("sk_{}", hex::encode(key_bytes));

    (api_key.clone(), hash_api_key(&api_key))
}

/// SHA-256 Hash eines API-Keys.
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Eindeutige ID mit Prefix generieren.
fn generate_id(prefix: &str, seed: &str) -> String {
    let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(format!("{seed}:{now}").as_bytes());
    let hash = hasher.finalize();
    format!("{}-{}", prefix, hex::encode(&hash[..8]))
}

/// Nächste Mitternacht UTC.
fn next_midnight_utc(now: i64) -> i64 {
    (now / 86400 + 1) * 86400
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> GameEconomyStore {
        GameEconomyStore::new()
    }

    #[test]
    fn test_game_registration() {
        let mut store = test_store();
        let (game, api_key) = store.register_game(
            "chain-empires", "Chain Empires", "Ein MMO",
            "https://example.com", "dev_wallet_abc",
            Decimal::from(500),
            vec![GamePermission::Basic, GamePermission::Marketplace, GamePermission::Tournament],
        ).unwrap();

        assert_eq!(game.game_id, "chain-empires");
        assert!(api_key.starts_with("sk_"));
        assert_eq!(game.status, GameStatus::Active);

        // API-Key validieren
        let found = store.validate_api_key(&api_key).unwrap();
        assert_eq!(found.game_id, "chain-empires");

        // Ungültiger Key
        assert!(store.validate_api_key("sk_invalid").is_err());

        // Doppelte Registrierung
        assert!(store.register_game(
            "chain-empires", "X", "X", "X", "X",
            Decimal::from(100), vec![],
        ).is_err());
    }

    #[test]
    fn test_consent_flow() {
        let mut store = test_store();
        store.register_game(
            "test-game", "Test", "", "", "dev1",
            Decimal::from(200),
            vec![GamePermission::Basic, GamePermission::Social],
        ).unwrap();

        // Consent anfragen
        let cr = store.request_consent(
            "test-game", "player_wallet_1",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();
        assert_eq!(cr.status, ConsentRequestStatus::Pending);

        // Spieler sieht Anfrage
        let pending = store.pending_consents("player_wallet_1");
        assert_eq!(pending.len(), 1);

        // Spieler genehmigt
        let gw = store.approve_consent("player_wallet_1", &cr.request_id).unwrap();
        assert_eq!(gw.daily_limit, Decimal::from(100));
        assert!(gw.has_permission(GamePermission::Basic));
        assert!(!gw.frozen);

        // Kein zweites Wallet möglich
        assert!(store.request_consent(
            "test-game", "player_wallet_1",
            Decimal::from(50), vec![GamePermission::Basic],
        ).is_err());
    }

    #[test]
    fn test_consent_rejection() {
        let mut store = test_store();
        store.register_game(
            "game-x", "Game X", "", "", "dev2",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        let cr = store.request_consent(
            "game-x", "player2",
            Decimal::from(50),
            vec![GamePermission::Basic],
        ).unwrap();

        store.reject_consent("player2", &cr.request_id).unwrap();

        // Kein Wallet erstellt
        assert!(store.find_game_wallet("player2", "game-x").is_none());
    }

    #[test]
    fn test_daily_limit() {
        let mut store = test_store();
        store.register_game(
            "limit-game", "Limit", "", "", "dev3",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        store.create_game_wallet(
            "player3", "limit-game", "Player3",
            Decimal::from(50),
            vec![GamePermission::Basic],
        ).unwrap();

        let addr = derive_game_wallet("player3", "limit-game");

        // 30 ausgeben → OK
        assert!(store.enforce_daily_limit(&addr, Decimal::from(30)).is_ok());

        // 25 weitere → über Limit (30+25=55 > 50)
        assert!(store.enforce_daily_limit(&addr, Decimal::from(25)).is_err());

        // 20 weitere → OK (30+20=50 ≤ 50)
        assert!(store.enforce_daily_limit(&addr, Decimal::from(20)).is_ok());
    }

    #[test]
    fn test_wallet_freeze_unfreeze() {
        let mut store = test_store();
        store.register_game(
            "freeze-game", "FG", "", "", "dev4",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        store.create_game_wallet(
            "player4", "freeze-game", "P4",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        let addr = derive_game_wallet("player4", "freeze-game");

        // Einfrieren
        store.freeze_wallet("player4", "freeze-game").unwrap();
        assert!(store.game_wallets.get(&addr).unwrap().frozen);

        // Aktion sollte fehlschlagen
        assert!(store.check_wallet_action(&addr, GamePermission::Basic).is_err());

        // Auftauen
        store.unfreeze_wallet("player4", "freeze-game").unwrap();
        assert!(!store.game_wallets.get(&addr).unwrap().frozen);
        assert!(store.check_wallet_action(&addr, GamePermission::Basic).is_ok());
    }

    #[test]
    fn test_permission_system() {
        let mut store = test_store();
        store.register_game(
            "perm-game", "PG", "", "", "dev5",
            Decimal::from(100),
            vec![GamePermission::Basic, GamePermission::Marketplace],
        ).unwrap();

        // Spiel versucht Tournament-Permission zu beantragen → Fehler
        let err = store.request_consent(
            "perm-game", "player5",
            Decimal::from(50),
            vec![GamePermission::Basic, GamePermission::Tournament],
        );
        assert!(err.is_err());

        // Nur Basic beantragen → OK
        let cr = store.request_consent(
            "perm-game", "player5",
            Decimal::from(50),
            vec![GamePermission::Basic],
        ).unwrap();

        let gw = store.approve_consent("player5", &cr.request_id).unwrap();
        assert!(gw.has_permission(GamePermission::Basic));
        assert!(!gw.has_permission(GamePermission::Tournament));

        let addr = derive_game_wallet("player5", "perm-game");
        // Basic → OK
        assert!(store.check_wallet_action(&addr, GamePermission::Basic).is_ok());
        // Marketplace → Fehler (Nutzer hat nur Basic genehmigt)
        assert!(store.check_wallet_action(&addr, GamePermission::Marketplace).is_err());
    }

    #[test]
    fn test_blacklisting() {
        let mut store = test_store();
        let (_, api_key) = store.register_game(
            "bad-game", "Bad", "", "", "dev6",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        store.create_game_wallet(
            "player6", "bad-game", "P6",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        // Blacklisten
        store.blacklist_game("bad-game", "Betrug").unwrap();

        // API-Key sollte nicht mehr funktionieren
        assert!(store.validate_api_key(&api_key).is_err());

        // Wallet sollte eingefroren sein
        let addr = derive_game_wallet("player6", "bad-game");
        assert!(store.game_wallets.get(&addr).unwrap().frozen);
    }

    #[test]
    fn test_audit_log() {
        let mut store = test_store();
        store.register_game(
            "audit-game", "AG", "", "", "dev7",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        // Audit-Einträge vorhanden
        let log = store.audit_log_for_game("audit-game", 10);
        assert!(!log.is_empty());
        assert_eq!(log[0].action, "register_game");
    }

    #[test]
    fn test_marketplace_flow() {
        let mut store = test_store();

        store.mint_item(
            "item-100", "Shield", "Ein Schild", "armor",
            ItemRarity::Epic, "seller1", "game1", "server1",
            HashMap::new(), true,
        ).unwrap();

        let listing = store.list_item("seller1", "item-100", Decimal::from(50), None).unwrap();
        assert_eq!(listing.status, ListingStatus::Active);

        let (fee, seller_amount, seller) = store.buy_item(&listing.listing_id, "buyer1").unwrap();
        assert_eq!(seller, "seller1");
        assert!(fee > Decimal::ZERO);
        assert_eq!(fee + seller_amount, Decimal::from(50));
        assert_eq!(store.items.get("item-100").unwrap().owner, "buyer1");
    }

    #[test]
    fn test_session_lifecycle() {
        let mut store = test_store();
        let session = store.create_session("w1", "g1", vec![GamePermission::Basic]);
        assert!(store.validate_session(&session.token).is_some());
        store.revoke_session(&session.token).unwrap();
        assert!(store.validate_session(&session.token).is_none());
    }

    #[test]
    fn test_set_daily_limit() {
        let mut store = test_store();
        store.register_game(
            "lim-game", "LG", "", "", "dev8",
            Decimal::from(200),
            vec![GamePermission::Basic],
        ).unwrap();

        store.create_game_wallet(
            "player8", "lim-game", "P8",
            Decimal::from(100),
            vec![GamePermission::Basic],
        ).unwrap();

        // Limit erhöhen (aber unter Game-Max)
        store.set_daily_limit("player8", "lim-game", Decimal::from(150)).unwrap();
        let addr = derive_game_wallet("player8", "lim-game");
        assert_eq!(store.game_wallets.get(&addr).unwrap().daily_limit, Decimal::from(150));

        // Über Game-Max → Fehler
        assert!(store.set_daily_limit("player8", "lim-game", Decimal::from(300)).is_err());
    }
}
