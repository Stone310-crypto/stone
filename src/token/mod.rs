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

pub mod genesis;
pub mod ledger;
pub mod mempool;
pub mod reputation;
pub mod staking;
pub mod transaction;
pub mod wallet;

// Re-exports für bequemen Zugriff
pub use genesis::{apply_genesis, GenesisConfig, NetworkMode, SupplyInfo};
pub use ledger::{AccountInfo, LedgerError, TokenLedger, TxReceipt, VestingSchedule};
pub use mempool::{Mempool, MempoolError, MempoolStats};
pub use reputation::{ReputationRegistry, ReputationSummary, NodeReputationInfo};
pub use staking::{StakingPool, StakingPoolInfo, StakerInfo, StakingError};
pub use transaction::{FeeTier, TokenTx, TxError, TxType, compute_tx_id, create_signed_tx, default_chain_id, validate_tx, verify_tx_signature};
pub use wallet::{Wallet, WalletError, WalletInfo};

// ─── Shared Token-DB Helper ──────────────────────────────────────────────────

/// Öffnet die Token-DB (RocksDB) mit Retry bei LOCK-Konflikten.
///
/// Mehrere Threads/Subsysteme (Ledger, Staking, Reputation) teilen sich
/// `stone_data/token_db`. RocksDB erlaubt nur einen Opener gleichzeitig.
/// Diese Funktion versucht es bis zu 5× mit exponentiell steigendem Backoff.
pub fn open_token_db() -> Result<rocksdb::DB, String> {
    let db_path = format!("{}/token_db", crate::blockchain::data_dir());
    let max_retries = 5u32;
    let mut delay_ms = 50u64;

    for attempt in 0..=max_retries {
        match rocksdb::DB::open_default(&db_path) {
            Ok(db) => return Ok(db),
            Err(e) => {
                let msg = e.to_string();
                if attempt < max_retries && (msg.contains("LOCK") || msg.contains("lock file")) {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    delay_ms *= 2; // 50 → 100 → 200 → 400 → 800ms
                } else {
                    return Err(format!("DB open: {e}"));
                }
            }
        }
    }
    Err("DB open: LOCK timeout nach 5 Versuchen".into())
}
