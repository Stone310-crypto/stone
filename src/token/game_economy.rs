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

    // ═════════════════════════════════════════════════════════════════════
    //  §1 Game Registry
    // ═════════════════════════════════════════════════════════════════════

    /// Registriert ein neues Spiel. Gibt den API-Key zurück (wird nur EINMAL angezeigt).
    pub fn register_game(
        &mut self,
        game_id: &str,
        name: &str,
        description: &str,
        website: &str,
        developer_wallet: &str,
        max_wallet_limit: Decimal,
        permissions: Vec<GamePermission>,
    ) -> Result<(RegisteredGame, String), GameEconomyError> {
        if self.registered_games.contains_key(game_id) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Spiel '{game_id}'"),
            });
        }

        if game_id.len() < 3 || game_id.len() > 64 {
            return Err(GameEconomyError::InvalidInput {
                reason: "Game-ID muss 3-64 Zeichen lang sein".into(),
            });
        }

        if max_wallet_limit <= Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount {
                reason: "Max-Wallet-Limit muss positiv sein".into(),
            });
        }

        let (api_key, api_key_hash) = generate_api_key(game_id, developer_wallet);
        let now = Utc::now().timestamp();

        let game = RegisteredGame {
            game_id: game_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            website: website.to_string(),
            developer_wallet: developer_wallet.to_string(),
            api_key_hash,
            max_wallet_limit,
            permissions,
            status: GameStatus::Active,
            created_at: now,
            updated_at: now,
        };

        self.registered_games.insert(game_id.to_string(), game.clone());
        self.audit(game_id, developer_wallet, "register_game", serde_json::json!({
            "name": name, "permissions_count": game.permissions.len(),
        }), true);

        Ok((game, api_key))
    }

    /// Validiert einen API-Key und gibt das zugehörige Spiel zurück.
    pub fn validate_api_key(&self, api_key: &str) -> Result<&RegisteredGame, GameEconomyError> {
        let hash = hash_api_key(api_key);
        let game = self.registered_games.values()
            .find(|g| g.api_key_hash == hash)
            .ok_or_else(|| GameEconomyError::Unauthorized {
                reason: "Ungültiger API-Key".into(),
            })?;

        match &game.status {
            GameStatus::Active => Ok(game),
            GameStatus::Suspended { reason, .. } => Err(GameEconomyError::GameSuspended {
                game_id: game.game_id.clone(),
                reason: reason.clone(),
            }),
            GameStatus::Blacklisted { reason } => Err(GameEconomyError::GameBlacklisted {
                game_id: game.game_id.clone(),
                reason: reason.clone(),
            }),
        }
    }

    /// Gibt ein registriertes Spiel zurück (public info, kein API-Key nötig).
    pub fn get_game(&self, game_id: &str) -> Option<&RegisteredGame> {
        self.registered_games.get(game_id)
    }

    /// Prüft ob ein Spiel eine bestimmte Berechtigung hat.
    pub fn game_has_permission(&self, game_id: &str, perm: GamePermission) -> bool {
        self.registered_games.get(game_id)
            .map(|g| g.permissions.contains(&perm))
            .unwrap_or(false)
    }

    /// Spiel suspendieren (Admin).
    pub fn suspend_game(
        &mut self,
        game_id: &str,
        reason: &str,
        until: Option<i64>,
    ) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        game.status = GameStatus::Suspended { reason: reason.to_string(), until };
        game.updated_at = Utc::now().timestamp();
        self.audit(game_id, "", "suspend_game", serde_json::json!({ "reason": reason }), true);
        Ok(())
    }

    /// Spiel permanent blacklisten (Admin).
    pub fn blacklist_game(
        &mut self,
        game_id: &str,
        reason: &str,
    ) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        game.status = GameStatus::Blacklisted { reason: reason.to_string() };
        game.updated_at = Utc::now().timestamp();
        // Alle Wallets dieses Spiels einfrieren
        for gw in self.game_wallets.values_mut() {
            if gw.game_id == game_id {
                gw.frozen = true;
            }
        }
        self.audit(game_id, "", "blacklist_game", serde_json::json!({ "reason": reason }), true);
        Ok(())
    }

    /// Spiel reaktivieren (Admin).
    pub fn reactivate_game(&mut self, game_id: &str) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        game.status = GameStatus::Active;
        game.updated_at = Utc::now().timestamp();
        Ok(())
    }

    /// Prüft ob das Wallet der registrierte Game-Server ist.
    pub fn is_game_server(&self, game_id: &str, wallet: &str) -> bool {
        self.registered_games.get(game_id)
            .map(|g| g.developer_wallet == wallet)
            .unwrap_or(false)
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §2 User Consent
    // ═════════════════════════════════════════════════════════════════════

    /// Spiel stellt Consent-Anfrage an einen Nutzer.
    ///
    /// Der Nutzer sieht in seiner App einen Dialog:
    /// "Chain Empires möchte eine Spiel-Wallet erstellen.
    ///  Limit: 100 Coins/Tag. Aktionen: Kaufen, Verkaufen."
    pub fn request_consent(
        &mut self,
        game_id: &str,
        player_wallet: &str,
        requested_limit: Decimal,
        requested_permissions: Vec<GamePermission>,
    ) -> Result<ConsentRequest, GameEconomyError> {
        let game = self.registered_games.get(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;

        if !matches!(game.status, GameStatus::Active) {
            return Err(GameEconomyError::GameSuspended {
                game_id: game_id.to_string(),
                reason: "Spiel ist nicht aktiv".into(),
            });
        }

        // Limit darf nicht höher als das Game-Maximum sein
        if requested_limit > game.max_wallet_limit {
            return Err(GameEconomyError::InvalidAmount {
                reason: format!(
                    "Angefragtes Limit ({}) überschreitet Game-Maximum ({})",
                    requested_limit, game.max_wallet_limit
                ),
            });
        }

        // Nur Permissions beantragen, die das Spiel selbst hat
        for perm in &requested_permissions {
            if !game.permissions.contains(perm) {
                return Err(GameEconomyError::PermissionDenied {
                    action: format!("Spiel hat keine '{}' Berechtigung", perm),
                });
            }
        }

        // Bereits offene Anfrage oder existierendes Wallet?
        let wallet_addr = derive_game_wallet(player_wallet, game_id);
        if self.game_wallets.contains_key(&wallet_addr) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Game-Wallet für diesen Spieler in '{game_id}'"),
            });
        }

        // Offene Anfrage?
        let has_pending = self.consent_requests.values().any(|cr| {
            cr.game_id == game_id
                && cr.player_wallet == player_wallet
                && cr.status == ConsentRequestStatus::Pending
                && cr.expires_at > Utc::now().timestamp()
        });
        if has_pending {
            return Err(GameEconomyError::AlreadyExists {
                what: "Offene Consent-Anfrage".into(),
            });
        }

        let now = Utc::now().timestamp();
        let request_id = generate_id("CSR", &format!("{game_id}:{player_wallet}"));

        let request = ConsentRequest {
            request_id: request_id.clone(),
            game_id: game_id.to_string(),
            game_name: game.name.clone(),
            player_wallet: player_wallet.to_string(),
            requested_limit,
            requested_permissions,
            status: ConsentRequestStatus::Pending,
            created_at: now,
            expires_at: now + CONSENT_TTL_SECS,
        };

        self.consent_requests.insert(request_id, request.clone());
        self.audit(game_id, player_wallet, "consent_requested", serde_json::json!({
            "limit": requested_limit.to_string(),
        }), true);

        Ok(request)
    }

    /// Nutzer sieht seine offenen Consent-Anfragen.
    pub fn pending_consents(&self, player_wallet: &str) -> Vec<&ConsentRequest> {
        let now = Utc::now().timestamp();
        self.consent_requests.values()
            .filter(|cr| {
                cr.player_wallet == player_wallet
                    && cr.status == ConsentRequestStatus::Pending
                    && cr.expires_at > now
            })
            .collect()
    }

    /// Nutzer genehmigt Consent-Anfrage → Game-Wallet wird erstellt.
    pub fn approve_consent(
        &mut self,
        player_wallet: &str,
        request_id: &str,
    ) -> Result<GameWallet, GameEconomyError> {
        let cr = self.consent_requests.get_mut(request_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Consent-Request '{request_id}'"),
            })?;

        if cr.player_wallet != player_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Consent gehört einem anderen Spieler".into(),
            });
        }

        if cr.status != ConsentRequestStatus::Pending {
            return Err(GameEconomyError::InvalidState {
                reason: "Consent-Anfrage ist nicht mehr offen".into(),
            });
        }

        if cr.expires_at <= Utc::now().timestamp() {
            cr.status = ConsentRequestStatus::Expired;
            return Err(GameEconomyError::InvalidState {
                reason: "Consent-Anfrage ist abgelaufen".into(),
            });
        }

        cr.status = ConsentRequestStatus::Approved;

        let game_id = cr.game_id.clone();
        let limit = cr.requested_limit;
        let permissions = cr.requested_permissions.clone();

        // Game-Wallet erstellen
        let now = Utc::now().timestamp();
        let wallet_addr = derive_game_wallet(player_wallet, &game_id);

        let gw = GameWallet {
            owner_wallet: player_wallet.to_string(),
            game_wallet: wallet_addr.clone(),
            game_id: game_id.clone(),
            display_name: String::new(),
            daily_limit: limit,
            spent_today: Decimal::ZERO,
            limit_reset_at: next_midnight_utc(now),
            consent: ConsentStatus::Approved { at: now },
            allowed_permissions: permissions,
            frozen: false,
            created_at: now,
            last_active: now,
        };

        self.game_wallets.insert(wallet_addr, gw.clone());
        self.audit(&game_id, player_wallet, "consent_approved", serde_json::json!({
            "limit": limit.to_string(),
            "game_wallet": &gw.game_wallet,
        }), true);

        Ok(gw)
    }

    /// Nutzer lehnt Consent-Anfrage ab.
    pub fn reject_consent(
        &mut self,
        player_wallet: &str,
        request_id: &str,
    ) -> Result<(), GameEconomyError> {
        let cr = self.consent_requests.get_mut(request_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Consent-Request '{request_id}'"),
            })?;

        if cr.player_wallet != player_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Consent gehört einem anderen Spieler".into(),
            });
        }

        if cr.status != ConsentRequestStatus::Pending {
            return Err(GameEconomyError::InvalidState {
                reason: "Consent-Anfrage ist nicht mehr offen".into(),
            });
        }

        cr.status = ConsentRequestStatus::Rejected;
        let game_id = cr.game_id.clone();
        self.audit(&game_id, player_wallet, "consent_rejected", serde_json::json!({}), true);
        Ok(())
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §3 Game Wallet Verwaltung
    // ═════════════════════════════════════════════════════════════════════

    /// Erstellt ein Game-Wallet direkt (ohne Consent-Flow, z.B. für eigene Spiele).
    pub fn create_game_wallet(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
        display_name: &str,
        daily_limit: Decimal,
        permissions: Vec<GamePermission>,
    ) -> Result<GameWallet, GameEconomyError> {
        let wallet_addr = derive_game_wallet(owner_wallet, game_id);

        if self.game_wallets.contains_key(&wallet_addr) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Game-Wallet für {} in {}", &owner_wallet[..12.min(owner_wallet.len())], game_id),
            });
        }

        // Wenn Spiel registriert ist, Limit prüfen
        if let Some(game) = self.registered_games.get(game_id) {
            if daily_limit > game.max_wallet_limit {
                return Err(GameEconomyError::InvalidAmount {
                    reason: format!("Limit ({}) > Game-Maximum ({})", daily_limit, game.max_wallet_limit),
                });
            }
        }

        let now = Utc::now().timestamp();
        let gw = GameWallet {
            owner_wallet: owner_wallet.to_string(),
            game_wallet: wallet_addr.clone(),
            game_id: game_id.to_string(),
            display_name: display_name.to_string(),
            daily_limit,
            spent_today: Decimal::ZERO,
            limit_reset_at: next_midnight_utc(now),
            consent: ConsentStatus::Approved { at: now },
            allowed_permissions: permissions,
            frozen: false,
            created_at: now,
            last_active: now,
        };

        self.game_wallets.insert(wallet_addr, gw.clone());
        self.audit(game_id, owner_wallet, "wallet_created", serde_json::json!({
            "game_wallet": &gw.game_wallet,
            "daily_limit": daily_limit.to_string(),
        }), true);

        Ok(gw)
    }

    /// Alle Game-Wallets eines Besitzers.
    pub fn wallets_of(&self, owner_wallet: &str) -> Vec<&GameWallet> {
        self.game_wallets.values()
            .filter(|gw| gw.owner_wallet == owner_wallet)
            .collect()
    }

    /// Game-Wallet nach Adresse abrufen.
    pub fn get_game_wallet(&self, game_wallet_addr: &str) -> Option<&GameWallet> {
        self.game_wallets.get(game_wallet_addr)
    }

    /// Game-Wallet eines Spielers in einem bestimmten Spiel.
    pub fn find_game_wallet(&self, owner: &str, game_id: &str) -> Option<&GameWallet> {
        let addr = derive_game_wallet(owner, game_id);
        self.game_wallets.get(&addr)
    }

    /// Nutzer friert sein Game-Wallet ein.
    pub fn freeze_wallet(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
    ) -> Result<(), GameEconomyError> {
        let addr = derive_game_wallet(owner_wallet, game_id);
        let gw = self.game_wallets.get_mut(&addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.owner_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized { reason: "Nicht dein Wallet".into() });
        }

        gw.frozen = true;
        gw.consent = ConsentStatus::Revoked {
            at: Utc::now().timestamp(),
            reason: "Vom Nutzer eingefroren".into(),
        };
        self.audit(game_id, owner_wallet, "wallet_frozen", serde_json::json!({}), true);
        Ok(())
    }

    /// Nutzer gibt sein Game-Wallet wieder frei.
    pub fn unfreeze_wallet(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
    ) -> Result<(), GameEconomyError> {
        let addr = derive_game_wallet(owner_wallet, game_id);
        let gw = self.game_wallets.get_mut(&addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.owner_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized { reason: "Nicht dein Wallet".into() });
        }

        gw.frozen = false;
        gw.consent = ConsentStatus::Approved { at: Utc::now().timestamp() };
        self.audit(game_id, owner_wallet, "wallet_unfrozen", serde_json::json!({}), true);
        Ok(())
    }

    /// Nutzer passt sein tägliches Limit an.
    pub fn set_daily_limit(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
        new_limit: Decimal,
    ) -> Result<(), GameEconomyError> {
        if new_limit < Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount {
                reason: "Limit darf nicht negativ sein".into(),
            });
        }

        // Prüfe Game-Maximum
        if let Some(game) = self.registered_games.get(game_id) {
            if new_limit > game.max_wallet_limit {
                return Err(GameEconomyError::InvalidAmount {
                    reason: format!("Limit ({}) > Game-Maximum ({})", new_limit, game.max_wallet_limit),
                });
            }
        }

        let addr = derive_game_wallet(owner_wallet, game_id);
        let gw = self.game_wallets.get_mut(&addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.owner_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized { reason: "Nicht dein Wallet".into() });
        }

        let old = gw.daily_limit;
        gw.daily_limit = new_limit;
        self.audit(game_id, owner_wallet, "limit_changed", serde_json::json!({
            "old": old.to_string(), "new": new_limit.to_string(),
        }), true);

        Ok(())
    }

    /// Prüft ob eine Aktion für ein Game-Wallet erlaubt ist.
    /// Prüft: Spiel aktiv + Wallet nicht frozen + Consent approved + Permission vorhanden.
    pub fn check_wallet_action(
        &self,
        game_wallet_addr: &str,
        required_permission: GamePermission,
    ) -> Result<&GameWallet, GameEconomyError> {
        let gw = self.game_wallets.get(game_wallet_addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.frozen {
            return Err(GameEconomyError::WalletFrozen { game_id: gw.game_id.clone() });
        }

        if !matches!(gw.consent, ConsentStatus::Approved { .. }) {
            return Err(GameEconomyError::Unauthorized {
                reason: "Wallet hat keinen genehmigten Consent".into(),
            });
        }

        if !gw.has_permission(required_permission) {
            return Err(GameEconomyError::PermissionDenied {
                action: format!("'{}' nicht genehmigt für dieses Wallet", required_permission),
            });
        }

        // Spiel-Status prüfen
        if let Some(game) = self.registered_games.get(&gw.game_id) {
            if !matches!(game.status, GameStatus::Active) {
                return Err(GameEconomyError::GameSuspended {
                    game_id: gw.game_id.clone(),
                    reason: "Spiel nicht aktiv".into(),
                });
            }
        }

        Ok(gw)
    }

    /// Prüft Daily Limit und registriert Ausgabe.
    pub fn enforce_daily_limit(
        &mut self,
        game_wallet_addr: &str,
        amount: Decimal,
    ) -> Result<(), GameEconomyError> {
        let gw = self.game_wallets.get_mut(game_wallet_addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if !gw.can_spend(amount) {
            return Err(GameEconomyError::DailyLimitExceeded {
                limit: gw.daily_limit,
                spent: gw.spent_today,
                requested: amount,
            });
        }

        gw.record_spend(amount);
        Ok(())
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §4 NFT Items
    // ═════════════════════════════════════════════════════════════════════

    pub fn mint_item(
        &mut self,
        item_id: &str,
        name: &str,
        description: &str,
        category: &str,
        rarity: ItemRarity,
        owner: &str,
        game_id: &str,
        creator: &str,
        metadata: HashMap<String, serde_json::Value>,
        transferable: bool,
    ) -> Result<GameItem, GameEconomyError> {
        if self.items.contains_key(item_id) {
            return Err(GameEconomyError::AlreadyExists { what: format!("Item {item_id}") });
        }

        let item = GameItem {
            item_id: item_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category: category.to_string(),
            rarity,
            owner: owner.to_string(),
            game_id: game_id.to_string(),
            creator: creator.to_string(),
            metadata,
            created_at: Utc::now().timestamp(),
            transferable,
            burned: false,
        };

        self.items.insert(item_id.to_string(), item.clone());
        self.audit(game_id, creator, "mint_item", serde_json::json!({
            "item_id": item_id, "owner": owner,
        }), true);
        Ok(item)
    }

    pub fn items_of(&self, owner: &str) -> Vec<&GameItem> {
        self.items.values().filter(|i| i.owner == owner && !i.burned).collect()
    }

    pub fn transfer_item(
        &mut self,
        item_id: &str,
        from: &str,
        to: &str,
    ) -> Result<(), GameEconomyError> {
        let item = self.items.get_mut(item_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Item {item_id}") })?;

        if item.owner != from {
            return Err(GameEconomyError::NotOwner {
                item_id: item_id.to_string(),
                expected: from.to_string(),
                actual: item.owner.clone(),
            });
        }

        if !item.transferable {
            return Err(GameEconomyError::NotTransferable { item_id: item_id.to_string() });
        }

        if item.burned {
            return Err(GameEconomyError::ItemBurned { item_id: item_id.to_string() });
        }

        let game_id = item.game_id.clone();
        item.owner = to.to_string();
        self.audit(&game_id, from, "transfer_item", serde_json::json!({
            "item_id": item_id, "to": to,
        }), true);
        Ok(())
    }

    pub fn burn_item(&mut self, item_id: &str, owner: &str) -> Result<(), GameEconomyError> {
        let item = self.items.get_mut(item_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Item {item_id}") })?;

        if item.owner != owner {
            return Err(GameEconomyError::NotOwner {
                item_id: item_id.to_string(),
                expected: owner.to_string(),
                actual: item.owner.clone(),
            });
        }

        if item.burned {
            return Err(GameEconomyError::ItemBurned { item_id: item_id.to_string() });
        }

        item.burned = true;
        let game_id = item.game_id.clone();
        for listing in self.listings.values_mut() {
            if listing.item_id == item_id && listing.status == ListingStatus::Active {
                listing.status = ListingStatus::Cancelled;
            }
        }

        self.audit(&game_id, owner, "burn_item", serde_json::json!({
            "item_id": item_id,
        }), true);
        Ok(())
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §5 Marktplatz
    // ═════════════════════════════════════════════════════════════════════

    pub fn list_item(
        &mut self,
        seller: &str,
        item_id: &str,
        price: Decimal,
        expires_at: Option<i64>,
    ) -> Result<MarketListing, GameEconomyError> {
        let item = self.items.get(item_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Item {item_id}") })?;

        if item.owner != seller {
            return Err(GameEconomyError::NotOwner {
                item_id: item_id.to_string(),
                expected: seller.to_string(),
                actual: item.owner.clone(),
            });
        }

        if !item.transferable || item.burned {
            return Err(GameEconomyError::NotTransferable { item_id: item_id.to_string() });
        }

        if price <= Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount { reason: "Preis muss positiv sein".into() });
        }

        let already_listed = self.listings.values()
            .any(|l| l.item_id == item_id && l.status == ListingStatus::Active);
        if already_listed {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Aktives Listing für Item {item_id}"),
            });
        }

        let seller_count = self.listings.values()
            .filter(|l| l.seller == seller && l.status == ListingStatus::Active)
            .count();
        if seller_count >= MAX_LISTINGS_PER_WALLET {
            return Err(GameEconomyError::LimitReached { limit: MAX_LISTINGS_PER_WALLET });
        }

        let listing_id = generate_id("LST", item_id);
        let now = Utc::now().timestamp();

        let listing = MarketListing {
            listing_id: listing_id.clone(),
            item_id: item_id.to_string(),
            seller: seller.to_string(),
            price,
            status: ListingStatus::Active,
            created_at: now,
            expires_at,
        };

        self.listings.insert(listing_id, listing.clone());
        Ok(listing)
    }

    pub fn delist_item(&mut self, listing_id: &str, seller: &str) -> Result<(), GameEconomyError> {
        let listing = self.listings.get_mut(listing_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Listing {listing_id}") })?;

        if listing.seller != seller {
            return Err(GameEconomyError::NotOwner {
                item_id: listing.item_id.clone(),
                expected: seller.to_string(),
                actual: listing.seller.clone(),
            });
        }

        if listing.status != ListingStatus::Active {
            return Err(GameEconomyError::InvalidState {
                reason: "Listing ist nicht aktiv".into(),
            });
        }

        listing.status = ListingStatus::Cancelled;
        Ok(())
    }

    /// Item kaufen. Gibt (fee, seller_amount, seller_wallet) zurück.
    pub fn buy_item(
        &mut self,
        listing_id: &str,
        buyer: &str,
    ) -> Result<(Decimal, Decimal, String), GameEconomyError> {
        let listing = self.listings.get(listing_id).cloned()
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Listing {listing_id}") })?;

        if listing.status != ListingStatus::Active {
            return Err(GameEconomyError::InvalidState { reason: "Listing ist nicht aktiv".into() });
        }

        if listing.seller == buyer {
            return Err(GameEconomyError::InvalidState { reason: "Eigene Items können nicht gekauft werden".into() });
        }

        if let Some(exp) = listing.expires_at {
            if Utc::now().timestamp() > exp {
                let l = self.listings.get_mut(&listing.listing_id).unwrap();
                l.status = ListingStatus::Expired;
                return Err(GameEconomyError::InvalidState { reason: "Listing ist abgelaufen".into() });
            }
        }

        let fee = (listing.price * Decimal::from(MARKETPLACE_FEE_PCT) / Decimal::from(MARKETPLACE_FEE_BASE)).round_dp(8);
        let seller_amount = listing.price - fee;

        self.transfer_item(&listing.item_id, &listing.seller, buyer)?;

        let l = self.listings.get_mut(&listing.listing_id).unwrap();
        l.status = ListingStatus::Sold {
            buyer: buyer.to_string(),
            sold_at: Utc::now().timestamp(),
        };

        self.price_history.entry(listing.item_id.clone()).or_default().push(PriceHistoryEntry {
            item_id: listing.item_id.clone(),
            price: listing.price,
            seller: listing.seller.clone(),
            buyer: buyer.to_string(),
            timestamp: Utc::now().timestamp(),
        });

        Ok((fee, seller_amount, listing.seller.clone()))
    }

    pub fn place_offer(
        &mut self,
        listing_id: &str,
        bidder: &str,
        amount: Decimal,
    ) -> Result<MarketOffer, GameEconomyError> {
        let listing = self.listings.get(listing_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Listing {listing_id}") })?;

        if listing.status != ListingStatus::Active {
            return Err(GameEconomyError::InvalidState { reason: "Listing ist nicht aktiv".into() });
        }

        if amount <= Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount { reason: "Gebot muss positiv sein".into() });
        }

        let offer_id = generate_id("OFR", &format!("{listing_id}:{bidder}"));
        let offer = MarketOffer {
            offer_id: offer_id.clone(),
            listing_id: listing_id.to_string(),
            bidder: bidder.to_string(),
            amount,
            created_at: Utc::now().timestamp(),
            accepted: false,
        };

        self.offers.insert(offer_id, offer.clone());
        Ok(offer)
    }

    pub fn active_listings(&self, category: Option<&str>) -> Vec<ListingWithItem> {
        self.listings.values()
            .filter(|l| l.status == ListingStatus::Active)
            .filter_map(|l| {
                let item = self.items.get(&l.item_id)?;
                if let Some(cat) = category {
                    if item.category != cat { return None; }
                }
                Some(ListingWithItem { listing: l.clone(), item: item.clone() })
            })
            .collect()
    }

    pub fn floor_price(&self, category: &str) -> Option<(Decimal, String)> {
        self.listings.values()
            .filter(|l| l.status == ListingStatus::Active)
            .filter_map(|l| {
                let item = self.items.get(&l.item_id)?;
                if item.category == category { Some((l.price, l.listing_id.clone())) } else { None }
            })
            .min_by_key(|(p, _)| *p)
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §6 SDK Sessions
    // ═════════════════════════════════════════════════════════════════════

    pub fn create_session(
        &mut self,
        wallet: &str,
        game_id: &str,
        permissions: Vec<GamePermission>,
    ) -> SdkSession {
        let now = Utc::now().timestamp();
        let token = generate_id("SDK", &format!("{wallet}:{game_id}:{now}"));

        let session = SdkSession {
            token: token.clone(),
            wallet: wallet.to_string(),
            game_id: game_id.to_string(),
            permissions,
            created_at: now,
            expires_at: now + SESSION_TTL_SECS,
            active: true,
        };

        self.sessions.insert(token, session.clone());
        session
    }

    pub fn validate_session(&self, token: &str) -> Option<&SdkSession> {
        let session = self.sessions.get(token)?;
        if !session.active || Utc::now().timestamp() > session.expires_at { return None; }
        Some(session)
    }

    pub fn revoke_session(&mut self, token: &str) -> Result<(), GameEconomyError> {
        let session = self.sessions.get_mut(token)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Session".into() })?;
        session.active = false;
        Ok(())
    }

    pub fn cleanup_expired_sessions(&mut self) {
        let now = Utc::now().timestamp();
        self.sessions.retain(|_, s| s.active && s.expires_at > now);
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §7 Wallet Links
    // ═════════════════════════════════════════════════════════════════════

    pub fn link_wallet(&mut self, player_id: &str, game_id: &str, wallet: &str) -> WalletLink {
        let key = format!("{game_id}:{player_id}");
        let link = WalletLink {
            player_id: player_id.to_string(),
            game_id: game_id.to_string(),
            wallet: wallet.to_string(),
            linked_at: Utc::now().timestamp(),
        };
        self.wallet_links.insert(key, link.clone());
        link
    }

    pub fn find_wallet_link(&self, player_id: &str, game_id: &str) -> Option<&WalletLink> {
        let key = format!("{game_id}:{player_id}");
        self.wallet_links.get(&key)
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §8 Audit-Log
    // ═════════════════════════════════════════════════════════════════════

    /// Loggt eine SDK-Aktion.
    pub fn audit(
        &mut self,
        game_id: &str,
        wallet: &str,
        action: &str,
        details: serde_json::Value,
        success: bool,
    ) {
        let entry = AuditLogEntry {
            entry_id: generate_id("AUD", &format!("{game_id}:{wallet}:{action}")),
            timestamp: Utc::now().timestamp(),
            game_id: game_id.to_string(),
            wallet: wallet.to_string(),
            action: action.to_string(),
            details,
            success,
        };
        self.audit_log.push(entry);

        // Trim wenn zu groß
        if self.audit_log.len() > MAX_AUDIT_ENTRIES {
            let drain_count = self.audit_log.len() - MAX_AUDIT_ENTRIES;
            self.audit_log.drain(..drain_count);
        }
    }

    /// Audit-Log für einen Spieler (über alle Spiele hinweg).
    pub fn audit_log_for_player(&self, wallet: &str, limit: usize) -> Vec<&AuditLogEntry> {
        self.audit_log.iter()
            .rev()
            .filter(|e| e.wallet == wallet)
            .take(limit)
            .collect()
    }

    /// Audit-Log für ein bestimmtes Spiel.
    pub fn audit_log_for_game(&self, game_id: &str, limit: usize) -> Vec<&AuditLogEntry> {
        self.audit_log.iter()
            .rev()
            .filter(|e| e.game_id == game_id)
            .take(limit)
            .collect()
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §9 Leaderboard
    // ═════════════════════════════════════════════════════════════════════

    pub fn leaderboard(&self, game_id: &str, limit: usize) -> Vec<LeaderboardEntry> {
        let mut player_stats: HashMap<String, (usize, Decimal)> = HashMap::new();

        for item in self.items.values() {
            if item.game_id == game_id && !item.burned {
                let entry = player_stats.entry(item.owner.clone()).or_default();
                entry.0 += 1;
                if let Some(history) = self.price_history.get(&item.item_id) {
                    if let Some(last) = history.last() {
                        entry.1 += last.price;
                    }
                }
            }
        }

        let mut board: Vec<LeaderboardEntry> = player_stats.into_iter()
            .map(|(wallet, (items, value))| LeaderboardEntry {
                wallet, item_count: items, estimated_value: value,
            })
            .collect();

        board.sort_by(|a, b| b.estimated_value.cmp(&a.estimated_value));
        board.truncate(limit);
        board
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §10 Persistence
    // ═════════════════════════════════════════════════════════════════════

    const DB_KEY: &'static [u8] = b"game_economy_store_v2";

    pub fn persist(&self) -> Result<(), String> {
        let json = serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))?;

        // JSON-File-Backup (immer schreiben – kein Lock-Problem)
        let json_path = format!("{}/game_economy.json", crate::blockchain::data_dir());
        if let Err(e) = std::fs::write(&json_path, &json) {
            eprintln!("[game-economy] ⚠️  JSON-Backup fehlgeschlagen: {e}");
        }

        // RocksDB (kann bei Lock-Contention fehlschlagen)
        match super::open_token_db() {
            Ok(db) => db.put(Self::DB_KEY, &json).map_err(|e| format!("db put: {e}"))?,
            Err(e) => eprintln!("[game-economy] ⚠️  DB-Persist übersprungen (Lock): {e}"),
        }
        Ok(())
    }

    pub fn load() -> Self {
        // 1. Versuche RocksDB
        if let Ok(db) = super::open_token_db() {
            if let Ok(Some(bytes)) = db.get(Self::DB_KEY) {
                if let Ok(store) = serde_json::from_slice::<Self>(&bytes) {
                    return store;
                }
                eprintln!("[game-economy] ⚠️  DB-Deserialize fehlgeschlagen, versuche JSON-Fallback");
            }
        }

        // 2. Fallback: JSON-File
        let json_path = format!("{}/game_economy.json", crate::blockchain::data_dir());
        if let Ok(bytes) = std::fs::read(&json_path) {
            if let Ok(store) = serde_json::from_slice::<Self>(&bytes) {
                println!("[game-economy] 📂 Aus JSON-Backup geladen");
                return store;
            }
            eprintln!("[game-economy] ⚠️  JSON-Backup Deserialize fehlgeschlagen");
        }

        eprintln!("[game-economy] ⚠️  Kein Datenbestand gefunden – starte leer");
        Self::new()
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
