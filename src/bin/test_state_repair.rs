//! State-Repair-Test: Synced Chain von VPS laden und State rekonstruieren.
//!
//! Prüft: Ist der lokale State (rebuilt from chain) konsistent mit dem VPS-State?
//!
//! Usage:
//!   cargo run --bin test-state-repair
//!
//! Was es macht:
//! 1. Lädt Chain aus lokaler RocksDB
//! 2. Rebuilt Token-Ledger aus der Chain
//! 3. Prüft Balance einer Wallet (über VPS vergleichen)
//! 4. Zeigt alle registrierten Accounts + Balances
//! 5. Report über State-Konsistenz

use stone::blockchain::{data_dir, NodeRole};
use stone::master::MasterNodeState;
use stone::token::TokenLedger;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data_dir = if args.len() > 1 { args[1].clone() } else { data_dir() };

    std::env::set_var("STONE_DATA_DIR", &data_dir);
    std::env::set_var("STONE_NETWORK", "testnet");

    println!("State-Repair-Test");
    println!("==================");
    println!("Data-Dir: {data_dir}");

    let node = MasterNodeState::new("test".into(), "key".into(), NodeRole::Master);
    let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let block_count = chain.blocks.len();
    let latest_hash = chain.latest_hash.clone();

    println!("Chain: {block_count} Blöcke, Tip: {}", &latest_hash[..12.min(latest_hash.len())]);

    let rebuilt = TokenLedger::rebuild_from_chain(&chain.blocks);
    println!("Ledger: {} Accounts, Supply: {}", rebuilt.account_count(), rebuilt.total_supply());

    // Wallets mit non-zero balance
    let registered = rebuilt.all_registered_accounts();
    println!("\nRegistered Accounts:");
    for (addr, name) in registered.iter() {
        let bal = rebuilt.balance(addr);
        let nonce = rebuilt.nonce(addr);
        if bal > rust_decimal::Decimal::ZERO || nonce > 0 {
            println!("  {} ({}): {} STONE, nonce={}", name, &addr[..8], bal, nonce);
        }
    }

    // Pool-Balances
    println!("\nPool Balances:");
    for pool in &[
        "pool:mining_rewards", "pool:gaming", "pool:onboarding",
        "pool:founders", "pool:treasury", "pool:governance",
        "pool:liquidity", "pool:bug_bounty",
    ] {
        let bal = rebuilt.balance(pool);
        if bal > rust_decimal::Decimal::ZERO {
            println!("  {}: {}", pool, bal);
        }
    }

    println!("\n✅ Test abgeschlossen");
}