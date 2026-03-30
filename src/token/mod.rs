//! StoneCoin Token-Modul
//!
//! Account-basierte Token-Economy für die Stone-Chain.
//!
//! ## Module
//!
//! - `transaction` – TokenTx-Struct, Signierung, Validierung
//! - `ledger`      – Balance-Map, Mint/Transfer/Burn, RocksDB-Persistierung
//! - `genesis`     – Initiale 50M-Allokation, Testnet/Mainnet-Modus
//! - `mempool`     – Thread-safe TX-Queue für Block-Integration
//! - `wallet`      – Ed25519 Wallet: Keypair-Gen, Mnemonic-Recovery, TX-Signierung

pub mod address;
pub mod bridge;
pub mod game_economy;
pub mod genesis;
pub mod governance;
pub mod htlc;
pub mod ledger;
pub mod market_sim;
pub mod mempool;
pub mod reputation;
pub mod staking;
pub mod transaction;
pub mod wallet;

// Re-exports für bequemen Zugriff
pub use genesis::{apply_genesis, GenesisConfig, NetworkMode, SupplyInfo};
pub use game_economy::{GameEconomyStore, GameEconomyError, GameItem, GameWallet, MarketListing, SdkSession, GamePermission, RegisteredGame, ConsentRequest, AuditLogEntry};
pub use governance::{GovernanceStore, GovernanceInfo, GovernanceError, Proposal, ProposalCategory, ProposalStatus, TrustedNode, TrustedNodeStatus, ModerationReward, VOTING_REWARD, MODERATION_REPORT_REWARD, MODERATION_VOTE_REWARD, UPGRADE_BONUS, MAX_GRANT_AMOUNT, GOVERNANCE_POOL};
pub use ledger::{AccountInfo, LedgerError, TokenLedger, TxReceipt, VestingSchedule};
pub use mempool::{Mempool, MempoolError, MempoolStats};
pub use reputation::{ReputationRegistry, ReputationSummary, NodeReputationInfo};
pub use staking::{StakingPool, StakingPoolInfo, StakerInfo, StakingError, StakeLevel, SnapshotAttestation, SnapshotTrust};
pub use transaction::{FeeTier, TokenTx, TxError, TxType, compute_tx_id, create_signed_tx, default_chain_id, validate_tx, verify_tx_signature};
pub use wallet::{Wallet, WalletError, WalletInfo};
pub use address::{encode as encode_address, decode as decode_address, normalize_to_hex as normalize_address, to_display as display_address, hex_to_bech32, is_valid as is_valid_address};
pub use market_sim::{TestnetMarket, TestnetMarketConfig, MarketInfo, TradeResult, MarketBalance, MARKET_RESERVE_POOL};
pub use htlc::{HtlcStore, HtlcContract, HtlcStatus, HtlcError, HTLC_ESCROW_POOL, HtlcCreateParams, HtlcClaimParams, HtlcRefundParams, TradePrice, PendingBuy, BuyStatus, SUPPORTED_CHAINS, SUPPORTED_ASSETS};
pub use bridge::{BridgeStore, BridgeDeposit, BridgeWithdrawal, BridgeError, BridgeSummary, WrappedAsset, DepositStatus, WithdrawalStatus, BRIDGE_RESERVE_POOL};

// ─── Shared Token-DB (Column Families) ───────────────────────────────────────

use std::sync::{Arc, OnceLock};

/// Globale Token-DB Instanz – wird einmal beim Start geöffnet und geteilt.
/// Kein Lock-Retry mehr nötig, da die DB über die gesamte Laufzeit offen bleibt.
static TOKEN_DB: OnceLock<Arc<rocksdb::DB>> = OnceLock::new();

/// Column Families für die Token-DB.
/// Phase 1: Definiert, aber Daten bleiben vorerst in "default".
/// Phase 2: Daten werden in die jeweilige CF migriert.
pub const TOKEN_CF_DEFAULT: &str = "default";
pub const TOKEN_CF_HTLC: &str = "htlc";
pub const TOKEN_CF_BRIDGE: &str = "bridge";
pub const TOKEN_CF_STAKING: &str = "staking";
pub const TOKEN_CF_GOVERNANCE: &str = "governance";
pub const TOKEN_CF_REPUTATION: &str = "reputation";
pub const TOKEN_CF_GAME_REGISTRY: &str = "game_registry";
pub const TOKEN_CF_GAME_WALLETS: &str = "game_wallets";
pub const TOKEN_CF_GAME_ITEMS: &str = "game_items";
pub const TOKEN_CF_GAME_MARKET: &str = "game_market";
pub const TOKEN_CF_GAME_SESSIONS: &str = "game_sessions";
pub const TOKEN_CF_GAME_AUDIT: &str = "game_audit";

/// Alle Column Families (ohne "default", wird automatisch erstellt).
const ALL_CFS: &[&str] = &[
    TOKEN_CF_HTLC,
    TOKEN_CF_BRIDGE,
    TOKEN_CF_STAKING,
    TOKEN_CF_GOVERNANCE,
    TOKEN_CF_REPUTATION,
    TOKEN_CF_GAME_REGISTRY,
    TOKEN_CF_GAME_WALLETS,
    TOKEN_CF_GAME_ITEMS,
    TOKEN_CF_GAME_MARKET,
    TOKEN_CF_GAME_SESSIONS,
    TOKEN_CF_GAME_AUDIT,
];

/// Initialisiert die Token-DB mit Column Families.
/// Muss einmal beim Start aufgerufen werden (vor allen load()-Aufrufen).
pub fn init_token_db() -> Result<(), String> {
    let db_path = format!("{}/token_db", crate::blockchain::data_dir());
    std::fs::create_dir_all(&db_path).map_err(|e| format!("create dir: {e}"))?;

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_compression_type(rocksdb::DBCompressionType::Snappy);

    let cf_descriptors: Vec<rocksdb::ColumnFamilyDescriptor> = std::iter::once("default")
        .chain(ALL_CFS.iter().copied())
        .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()))
        .collect();

    let db = rocksdb::DB::open_cf_descriptors(&opts, &db_path, cf_descriptors)
        .map_err(|e| format!("token_db open: {e}"))?;

    TOKEN_DB.set(Arc::new(db)).map_err(|_| "token_db already initialized".to_string())?;

    println!("[token-db] ✅ Token-DB geöffnet mit {} Column Families", ALL_CFS.len() + 1);
    Ok(())
}

/// Gibt eine Referenz auf die geteilte Token-DB zurück.
/// Panikt wenn `init_token_db()` nicht vorher aufgerufen wurde.
pub fn token_db() -> &'static rocksdb::DB {
    TOKEN_DB.get().expect("token_db nicht initialisiert – init_token_db() zuerst aufrufen")
}

/// Gibt ein Column-Family-Handle zurück.
/// Panikt wenn die CF nicht existiert (sollte nie passieren nach init_token_db).
pub fn token_cf(name: &str) -> &'static rocksdb::ColumnFamily {
    token_db().cf_handle(name)
        .unwrap_or_else(|| panic!("Column Family '{name}' nicht gefunden in token_db"))
}

/// Legacy-Wrapper: öffnet die DB oder gibt die geteilte Instanz zurück.
/// Wird schrittweise durch `token_db()` ersetzt.
pub fn open_token_db() -> Result<&'static rocksdb::DB, String> {
    match TOKEN_DB.get() {
        Some(db) => Ok(db.as_ref()),
        None => {
            // Fallback: initialisiere beim ersten Zugriff (z.B. in Tests)
            init_token_db()?;
            Ok(TOKEN_DB.get().unwrap().as_ref())
        }
    }
}
