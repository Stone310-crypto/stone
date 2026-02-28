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
pub mod transaction;
pub mod wallet;

// Re-exports für bequemen Zugriff
pub use genesis::{apply_genesis, GenesisConfig, NetworkMode, SupplyInfo};
pub use ledger::{AccountInfo, LedgerError, TokenLedger, TxReceipt};
pub use mempool::{Mempool, MempoolError, MempoolStats};
pub use transaction::{TokenTx, TxError, TxType, create_signed_tx, validate_tx, verify_tx_signature};
pub use wallet::{Wallet, WalletError, WalletInfo};
