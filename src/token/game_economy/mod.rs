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

pub mod genres;
pub use genres::{validate_genres, parse_genre_list, GenreFilter};

pub const MAX_LISTINGS_PER_WALLET: usize = 50;
pub const MARKETPLACE_FEE_PCT: u64 = 25;
pub const MARKETPLACE_FEE_BASE: u64 = 1000;
pub const SESSION_TTL_SECS: i64 = 24 * 3600;
pub const MAX_BATCH_SIZE: usize = 20;
pub const MARKETPLACE_POOL: &str = "pool:marketplace";
pub const CONSENT_TTL_SECS: i64 = 7 * 24 * 3600;
pub const MAX_AUDIT_ENTRIES: usize = 50_000;
pub const GAME_DORMANT_SECS:    i64 = 30 * 24 * 3600;
pub const GAME_ABANDON_SECS:    i64 = 90 * 24 * 3600;
pub const FORK_CHALLENGE_SECS:  i64 = 14 * 24 * 3600;
pub const FORK_BOND_POOL:       &str = "pool:fork";
pub const FORK_MIN_BOND_STONE:  &str = "1000";
pub const FORK_BOND_VEST_SECS:  i64 = 30 * 24 * 3600;

/// Maximale Nachrichten pro Text-Channel (ältere werden geprunt).
pub const MAX_CHANNEL_MESSAGES: usize = 1000;

/// Eine Server-Rolle mit Berechtigungen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerRole {
    pub role_id: String,
    pub org_id: String,
    pub name: String,
    pub color: String,
    pub permissions: Vec<String>,
    pub position: i32,
    pub created_at: i64,
}

impl ServerRole {
    pub fn has_perm(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }
}

/// Eine Kategorie für Text-Channels (Discord-ähnlich).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCategory {
    pub category_id: String,
    pub org_id: String,
    pub name: String,
    pub position: i32,
    pub created_at: i64,
}

/// Ein Text-Channel in einem Server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextChannel {
    pub channel_id: String,
    pub org_id: String,
    pub name: String,
    pub topic: String,
    pub category_id: String,  // empty = no category (uncategorized)
    pub position: i32,
    pub created_at: i64,
    pub created_by: String,
}

/// Eine Nachricht in einem Text-Channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMessage {
    pub msg_id: String,
    pub channel_id: String,
    pub org_id: String,
    pub sender_wallet: String,
    pub sender_name: String,
    pub content: String,
    pub timestamp: i64,
    pub edited: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GamePermission {
    Basic,
    Marketplace,
    Assets,
    Tournament,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GameStatus {
    Active,
    Suspended { reason: String, until: Option<i64> },
    Blacklisted { reason: String },
    Dormant { since: i64 },
    Abandoned { since: i64 },
    Forked { successor: String, at: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerKey {
    pub pubkey: String,
    pub label: String,
    #[serde(default)]
    pub permissions: Vec<GamePermission>,
    pub added_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredGame {
    pub game_id: String,
    pub name: String,
    pub description: String,
    pub website: String,
    pub developer_wallet: String,
    pub api_key_hash: String,
    pub max_wallet_limit: Decimal,
    pub permissions: Vec<GamePermission>,
    #[serde(default)]
    pub authorized_servers: Vec<ServerKey>,
    pub status: GameStatus,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub last_owner_heartbeat: i64,
    #[serde(default)]
    pub inherited_game_ids: Vec<String>,
    #[serde(default)]
    pub successor_of: Option<String>,
    #[serde(default)]
    pub genres: Vec<GameGenre>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GameGenre {
    Shooter, BattleRoyale, MOBA,
    OpenWorld, RPG, StoryDriven,
    RealTimeStrategy, TurnBased,
    Crafting, Survival, Simulation, Minecraft,
    Sports, Racing, Puzzle, Music, Idle, Rougelike, BlockchainGaming, Custom,
}

impl std::fmt::Display for GameGenre {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shooter => write!(f, "shooter"),
            Self::BattleRoyale => write!(f, "battle_royale"),
            Self::MOBA => write!(f, "moba"),
            Self::OpenWorld => write!(f, "open_world"),
            Self::RPG => write!(f, "rpg"),
            Self::StoryDriven => write!(f, "story_driven"),
            Self::RealTimeStrategy => write!(f, "real_time_strategy"),
            Self::TurnBased => write!(f, "turn_based"),
            Self::Crafting => write!(f, "crafting"),
            Self::Minecraft => write!(f, "minecraft"),
            Self::Survival => write!(f, "survival"),
            Self::Simulation => write!(f, "simulation"),
            Self::Sports => write!(f, "sports"),
            Self::Racing => write!(f, "racing"),
            Self::Puzzle => write!(f, "puzzle"),
            Self::Music => write!(f, "music"),
            Self::Idle => write!(f, "idle"),
            Self::Rougelike => write!(f, "rougelike"),
            Self::BlockchainGaming => write!(f, "blockchain_gaming"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl GameGenre {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "shooter" => Some(Self::Shooter),
            "battle_royale" | "battle royale" | "battleroyale" | "battle-royale" => Some(Self::BattleRoyale),
            "moba" => Some(Self::MOBA),
            "open_world" | "open world" | "openworld" => Some(Self::OpenWorld),
            "rpg" => Some(Self::RPG),
            "story_driven" | "story driven" | "storydriven" => Some(Self::StoryDriven),
            "real_time_strategy" | "real time strategy" | "realtimestrategy" => Some(Self::RealTimeStrategy),
            "turn_based" | "turn based" | "turnbased" => Some(Self::TurnBased),
            "crafting" => Some(Self::Crafting),
            "survival" => Some(Self::Survival),
            "simulation" => Some(Self::Simulation),
            "minecraft" => Some(Self::Minecraft),
            "sports" => Some(Self::Sports),
            "racing" => Some(Self::Racing),
            "puzzle" => Some(Self::Puzzle),
            "music" => Some(Self::Music),
            "idle" => Some(Self::Idle),
            "rougelike" | "roguelike" | "rogue like" => Some(Self::Rougelike),
            "blockchain_gaming" | "blockchain gaming" | "blockchaingaming" => Some(Self::BlockchainGaming),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
    pub fn form_str(s: &str) -> Option<Self> { Self::from_str(s) }
    pub fn all_names() -> Vec<&'static str> {
        vec!["shooter","battle_royale","moba","open_world","rpg","story_driven","real_time_strategy","turn_based","crafting","survival","simulation","minecraft","sports","racing","puzzle","music","idle","rougelike","blockchain_gaming","custom"]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForkProposalStatus { Pending, Challenged, Finalized, Cancelled { reason: String } }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkProposal {
    pub proposal_id: String,
    pub predecessor_game_id: String,
    pub new_game_id: String,
    pub new_name: String,
    pub claimant_pubkey: String,
    pub stake_amount: Decimal,
    pub created_at: i64,
    pub challenge_until: i64,
    pub status: ForkProposalStatus,
    #[serde(default)] pub challengers: HashMap<String, Decimal>,
    #[serde(default)] pub bond_pool: String,
    #[serde(default)] pub bond_tx_ids: HashMap<String, String>,
    #[serde(default)] pub bonds_refunded: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus { Pending, Approved { at: i64 }, Rejected { at: i64 }, Revoked { at: i64, reason: String } }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentRequestStatus { Pending, Approved, Rejected, Expired }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequest {
    pub request_id: String, pub game_id: String, pub game_name: String,
    pub player_wallet: String, pub requested_limit: Decimal,
    pub requested_permissions: Vec<GamePermission>, pub status: ConsentRequestStatus,
    pub created_at: i64, pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameWallet {
    pub owner_wallet: String, pub game_wallet: String, pub game_id: String,
    pub display_name: String, pub daily_limit: Decimal, pub spent_today: Decimal,
    pub limit_reset_at: i64, pub consent: ConsentStatus,
    pub allowed_permissions: Vec<GamePermission>, pub frozen: bool,
    pub created_at: i64, pub last_active: i64,
}

impl GameWallet {
    pub fn has_permission(&self, perm: GamePermission) -> bool { self.allowed_permissions.contains(&perm) }
    pub fn check_and_reset_daily_limit(&mut self) {
        let now = Utc::now().timestamp();
        if now >= self.limit_reset_at { self.spent_today = Decimal::ZERO; self.limit_reset_at = next_midnight_utc(now); }
    }
    pub fn can_spend(&mut self, amount: Decimal) -> bool { self.check_and_reset_daily_limit(); self.spent_today + amount <= self.daily_limit }
    pub fn record_spend(&mut self, amount: Decimal) { self.check_and_reset_daily_limit(); self.spent_today += amount; self.last_active = Utc::now().timestamp(); }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ItemRarity { Common, Uncommon, Rare, Epic, Legendary }
impl std::fmt::Display for ItemRarity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Common => write!(f, "common"), Self::Uncommon => write!(f, "uncommon"), Self::Rare => write!(f, "rare"), Self::Epic => write!(f, "epic"), Self::Legendary => write!(f, "legendary") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameItem {
    pub item_id: String, pub name: String, pub description: String, pub category: String,
    pub rarity: ItemRarity, pub owner: String, pub game_id: String, pub creator: String,
    pub metadata: HashMap<String, serde_json::Value>, pub created_at: i64,
    pub transferable: bool, pub burned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListingStatus { Active, Sold { buyer: String, sold_at: i64 }, Cancelled, Expired }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PriceMode { Stone { amount: Decimal }, Usd { amount: Decimal } }
impl PriceMode { pub fn stone(amount: Decimal) -> Self { Self::Stone { amount } } pub fn usd(amount: Decimal) -> Self { Self::Usd { amount } } }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketListing {
    pub listing_id: String, pub item_id: String, pub seller: String,
    pub price: Decimal, pub status: ListingStatus, pub created_at: i64,
    pub expires_at: Option<i64>, #[serde(default)] pub price_mode: Option<PriceMode>,
    #[serde(default)] pub warnings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketOffer { pub offer_id: String, pub listing_id: String, pub bidder: String, pub amount: Decimal, pub created_at: i64, pub accepted: bool }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceHistoryEntry { pub item_id: String, pub price: Decimal, pub seller: String, pub buyer: String, pub timestamp: i64, #[serde(default)] pub price_usd_at_sale: Option<Decimal>, #[serde(default)] pub oracle_source: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkSession { pub token: String, pub game_id: String, pub wallet: String, pub permissions: Vec<GamePermission>, pub created_at: i64, pub expires_at: i64, pub active: bool }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletLink { pub player_id: String, pub game_id: String, pub wallet: String, pub linked_at: i64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry { pub entry_id: String, pub timestamp: i64, pub game_id: String, pub wallet: String, pub action: String, pub details: serde_json::Value, pub success: bool }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingWithItem { pub listing: MarketListing, pub item: GameItem }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry { pub wallet: String, pub item_count: usize, pub estimated_value: Decimal }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShopItem {
    pub shop_item_id: String, pub game_id: String, pub name: String, pub description: String,
    pub price: Decimal, pub stock: Option<u64>, pub sold: u64, pub category: String,
    pub rarity: ItemRarity, pub metadata: serde_json::Value, pub active: bool, pub created_at: i64,
    #[serde(default)] pub price_mode: Option<PriceMode>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameServerHeartbeat { pub game_id: String, pub ip: String, pub port: u16, pub player_count: u32, pub max_players: u32, pub motd: String, pub last_heartbeat: i64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameEconomyStore {
    pub registered_games: HashMap<String, RegisteredGame>,
    pub consent_requests: HashMap<String, ConsentRequest>,
    pub game_wallets: HashMap<String, GameWallet>,
    pub items: HashMap<String, GameItem>,
    pub listings: HashMap<String, MarketListing>,
    pub offers: HashMap<String, MarketOffer>,
    pub price_history: HashMap<String, Vec<PriceHistoryEntry>>,
    pub sessions: HashMap<String, SdkSession>,
    pub wallet_links: HashMap<String, WalletLink>,
    #[serde(default)] pub shop_items: HashMap<String, ShopItem>,
    pub audit_log: Vec<AuditLogEntry>,
    #[serde(default)] pub rarity_guard: RarityPriceGuard,
    #[serde(default)] pub fork_proposals: HashMap<String, ForkProposal>,
    #[serde(default)] pub owner_totp_secrets: HashMap<String, String>,
    #[serde(default)] pub server_heartbeats: HashMap<String, GameServerHeartbeat>,
    #[serde(default)] pub server_roles: HashMap<String, Vec<ServerRole>>,
    #[serde(default)] pub channel_categories: HashMap<String, Vec<ChannelCategory>>,
    #[serde(default)] pub text_channels: HashMap<String, Vec<TextChannel>>,
    #[serde(default)] pub channel_messages: HashMap<String, Vec<ChannelMessage>>,
}

pub mod registry;
pub mod wallet;
pub mod marketplace;
pub mod session;
pub mod persistence;
pub mod oracle;
pub mod rarity_guard;
pub mod fork;

pub use oracle::{PriceOracle, FixedOracle, MarketSimOracle, ResolvedPrice, resolve_price_stone};
pub use rarity_guard::RarityPriceGuard;

impl GameEconomyStore {
    pub fn new() -> Self {
        Self {
            registered_games: HashMap::new(), consent_requests: HashMap::new(),
            game_wallets: HashMap::new(), items: HashMap::new(),
            listings: HashMap::new(), offers: HashMap::new(),
            price_history: HashMap::new(), sessions: HashMap::new(),
            wallet_links: HashMap::new(), shop_items: HashMap::new(),
            audit_log: Vec::new(), rarity_guard: RarityPriceGuard::default(),
            fork_proposals: HashMap::new(), owner_totp_secrets: HashMap::new(),
            server_heartbeats: HashMap::new(),
            server_roles: HashMap::new(),
            channel_categories: HashMap::new(), text_channels: HashMap::new(),
            channel_messages: HashMap::new(),
        }
    }

    pub fn record_server_heartbeat(&mut self, game_id: &str, ip: &str, port: u16, player_count: u32, max_players: u32, motd: &str) {
        let now = chrono::Utc::now().timestamp();
        self.server_heartbeats.insert(game_id.to_string(), GameServerHeartbeat { game_id: game_id.to_string(), ip: ip.to_string(), port, player_count, max_players, motd: motd.to_string(), last_heartbeat: now });
    }

    pub fn get_server_heartbeat(&self, game_id: &str) -> Option<&GameServerHeartbeat> {
        let hb = self.server_heartbeats.get(game_id)?;
        if chrono::Utc::now().timestamp() - hb.last_heartbeat > 120 { None } else { Some(hb) }
    }

    pub fn create_category(&mut self, org_id: &str, name: &str) -> Result<ChannelCategory, GameEconomyError> {
        let categories = self.channel_categories.entry(org_id.to_string()).or_default();
        let cat_id = generate_event_id("cat", &format!("{org_id}:{name}"));
        let cat = ChannelCategory { category_id: cat_id.clone(), org_id: org_id.to_string(), name: name.to_string(), position: categories.len() as i32, created_at: Utc::now().timestamp() };
        categories.push(cat.clone());
        Ok(cat)
    }

    pub fn create_channel(&mut self, org_id: &str, name: &str, category_id: &str, created_by: &str) -> Result<TextChannel, GameEconomyError> {
        let channels = self.text_channels.entry(org_id.to_string()).or_default();
        let channel_id = generate_event_id("ch", &format!("{org_id}:{name}"));
        let ch = TextChannel { channel_id: channel_id.clone(), org_id: org_id.to_string(), name: name.to_string(), topic: String::new(), category_id: category_id.to_string(), position: channels.len() as i32, created_at: Utc::now().timestamp(), created_by: created_by.to_string() };
        channels.push(ch.clone());
        Ok(ch)
    }

    pub fn delete_channel(&mut self, org_id: &str, channel_id: &str) -> Result<(), GameEconomyError> {
        let channels = self.text_channels.get_mut(org_id).ok_or(GameEconomyError::NotFound { what: format!("Server '{org_id}'") })?;
        let pos = channels.iter().position(|c| c.channel_id == channel_id).ok_or(GameEconomyError::NotFound { what: format!("Channel '{channel_id}'") })?;
        channels.remove(pos);
        self.channel_messages.remove(channel_id);
        Ok(())
    }

    pub fn add_channel_message(&mut self, channel_id: &str, org_id: &str, sender_wallet: &str, sender_name: &str, content: &str) -> ChannelMessage {
        let msgs = self.channel_messages.entry(channel_id.to_string()).or_default();
        if msgs.len() >= MAX_CHANNEL_MESSAGES { msgs.remove(0); }
        let msg = ChannelMessage { msg_id: generate_event_id("cmsg", &format!("{channel_id}:{}", Utc::now().timestamp_nanos_opt().unwrap_or(0))), channel_id: channel_id.to_string(), org_id: org_id.to_string(), sender_wallet: sender_wallet.to_string(), sender_name: sender_name.to_string(), content: content.to_string(), timestamp: Utc::now().timestamp(), edited: false };
        msgs.push(msg.clone());
        msg
    }

    pub fn messages_for_channel(&self, channel_id: &str, limit: usize) -> Vec<ChannelMessage> {
        let msgs = self.channel_messages.get(channel_id).cloned().unwrap_or_default();
        let start = msgs.len().saturating_sub(limit.min(msgs.len()));
        msgs[start..].to_vec()
    }
}

impl Default for GameEconomyStore {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GameEconomyError {
    NotFound { what: String }, AlreadyExists { what: String },
    NotOwner { item_id: String, expected: String, actual: String },
    NotTransferable { item_id: String }, ItemBurned { item_id: String },
    InvalidAmount { reason: String }, InvalidInput { reason: String }, InvalidState { reason: String },
    LimitReached { limit: usize }, Unauthorized { reason: String },
    PermissionDenied { action: String }, WalletFrozen { game_id: String },
    DailyLimitExceeded { limit: Decimal, spent: Decimal, requested: Decimal },
    GameSuspended { game_id: String, reason: String },
    GameBlacklisted { game_id: String, reason: String },
    GameNotAbandoned { game_id: String }, GameAlreadyForked { game_id: String, successor: String },
    ForkChallengeOpen { proposal_id: String, until: i64 }, ForkProposalActive { proposal_id: String },
}

impl std::fmt::Display for GameEconomyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { what } => write!(f, "{what} nicht gefunden"),
            Self::AlreadyExists { what } => write!(f, "{what} existiert bereits"),
            Self::NotOwner { item_id, expected, actual } => write!(f, "Item {item_id}: erwartet Besitzer {expected}, ist {actual}"),
            Self::NotTransferable { item_id } => write!(f, "Item {item_id} nicht transferierbar"),
            Self::ItemBurned { item_id } => write!(f, "Item {item_id} wurde verbrannt"),
            Self::InvalidAmount { reason } => write!(f, "Ungültiger Betrag: {reason}"),
            Self::InvalidInput { reason } => write!(f, "Ungültige Eingabe: {reason}"),
            Self::InvalidState { reason } => write!(f, "Ungültiger Zustand: {reason}"),
            Self::LimitReached { limit } => write!(f, "Limit erreicht ({limit})"),
            Self::Unauthorized { reason } => write!(f, "Nicht autorisiert: {reason}"),
            Self::PermissionDenied { action } => write!(f, "Keine Berechtigung: {action}"),
            Self::WalletFrozen { game_id } => write!(f, "Game-Wallet für '{game_id}' ist eingefroren"),
            Self::DailyLimitExceeded { limit, spent, requested } => write!(f, "Tageslimit überschritten: {spent}+{requested} > {limit}"),
            Self::GameSuspended { game_id, reason } => write!(f, "Spiel '{game_id}' gesperrt: {reason}"),
            Self::GameBlacklisted { game_id, reason } => write!(f, "Spiel '{game_id}' blacklisted: {reason}"),
            Self::GameNotAbandoned { game_id } => write!(f, "Spiel '{game_id}' ist noch nicht als verlassen markiert"),
            Self::GameAlreadyForked { game_id, successor } => write!(f, "Spiel '{game_id}' wurde bereits an '{successor}' übergeben"),
            Self::ForkChallengeOpen { proposal_id, until } => write!(f, "Fork-Antrag '{proposal_id}' ist noch in Challenge-Period (bis {until})"),
            Self::ForkProposalActive { proposal_id } => write!(f, "Es läuft bereits ein Fork-Antrag '{proposal_id}'"),
        }
    }
}
impl std::error::Error for GameEconomyError {}

pub fn derive_game_wallet(owner: &str, game_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("stone:game-wallet:{owner}:{game_id}").as_bytes());
    let result = hasher.finalize();
    format!("game:{}", hex::encode(&result[..16]))
}

fn generate_api_key(game_id: &str, wallet: &str) -> (String, String) {
    let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(format!("stone:sdk-key:{game_id}:{wallet}:{now}").as_bytes());
    let key_bytes = hasher.finalize();
    let api_key = format!("sk_{}", hex::encode(key_bytes));
    (api_key.clone(), hash_api_key(&api_key))
}

pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_id(prefix: &str, seed: &str) -> String {
    let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(format!("{seed}:{now}").as_bytes());
    let hash = hasher.finalize();
    format!("{}-{}", prefix, hex::encode(&hash[..8]))
}

/// generate_id alias für Server-IDs (verwendet dasselbe Schema).
pub(crate) fn generate_event_id(prefix: &str, seed: &str) -> String {
    generate_id(prefix, seed)
}

fn next_midnight_utc(now: i64) -> i64 { (now / 86400 + 1) * 86400 }