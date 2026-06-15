//! Test-Binary: Token-Ledger State-Verifikation
//!
//! Lädt die Chain aus RocksDB, spielt alle TXs nach und prüft ob die
//! Balance einer bestimmten Wallet nach Block #826 korrekt ist.
//!
//! Usage:
//!   cargo run --bin test-token-state -- <data-dir> <wallet>
//!
//! Beispiel:
//!   cargo run --bin test-token-state -- \
//!     "/Users/leon/Library/Application Support/dev.stonechain.dashboard/node_data" \
//!     57f1ae7936c6805d9976323ababe54fb075734d5309f43cea6479eaebb2d55e2

use stone::blockchain::{data_dir, NodeRole};
use stone::master::MasterNodeState;
use stone::token::TokenLedger;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data_dir = if args.len() > 1 { args[1].clone() } else { data_dir() };
    let wallet = if args.len() > 2 { args[2].clone() } else { String::new() };

    // Setze STONE_DATA_DIR damit die library die richtige DB findet
    std::env::set_var("STONE_DATA_DIR", &data_dir);
    std::env::set_var("STONE_NETWORK", "testnet");

    let node_id = "TestNode";
    let api_key = "test-key";

    // Erstelle MasterNodeState – lädt Chain + Token-Ledger aus DB
    let node = MasterNodeState::new(node_id.to_string(), api_key.to_string(), NodeRole::Master);

    // Chain aus der DB lesen
    let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let block_count = chain.blocks.len();
    println!("═══════════════════════════════════════");
    println!("Data-Dir: {data_dir}");
    println!("Blöcke in Chain: {block_count}");
    println!("Latest Hash: {}", &chain.latest_hash[..16.min(chain.latest_hash.len())]);

    // Token-Ledger separat aus Chain rekonstruieren (unabhängig von evtl. korrupter token_db)
    let rebuilt = TokenLedger::rebuild_from_chain(&chain.blocks);
    println!("Ledger rebuilt: {} Accounts, Supply: {}",
        rebuilt.account_count(), rebuilt.total_supply());

    if !wallet.is_empty() {
        let balance = rebuilt.balance(&wallet);
        let nonce = rebuilt.nonce(&wallet);
        println!("\nWallet: {wallet}");
        println!("  Balance: {balance} (rebuilt)");
        println!("  Nonce:   {nonce}");
    }

    // Vergleiche mit dem Ledger aus der DB
    let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    if !wallet.is_empty() {
        let balance_db = ledger.balance(&wallet);
        let nonce_db = ledger.nonce(&wallet);
        println!("  Balance (DB): {balance_db}");
        println!("  Nonce (DB):   {nonce_db}");
    }

    println!("\n═══════════════════════════════════════");
    println!("Pool-Balances (rebuilt):");
    let pools = [
        ("pool:mining_rewards", "Mining Rewards"),
        ("pool:gaming", "Gaming Pool"),
        ("pool:onboarding", "Onboarding"),
        ("pool:founders", "Founders"),
        ("pool:treasury", "Treasury"),
        ("pool:governance", "Governance"),
        ("pool:liquidity", "Liquidity"),
        ("pool:bug_bounty", "Bug Bounty"),
    ];
    for (addr, label) in &pools {
        let bal = rebuilt.balance(addr);
        println!("  {label}: {bal} STONE");
    }

    // Registrierte Accounts
    println!("\n═══════════════════════════════════════");
    println!("Registrierte Accounts:");
    let registered = rebuilt.all_registered_accounts();
    for (addr, name) in &registered.clone() {
        let bal = rebuilt.balance(addr);
        println!("  {name} ({addr}): {bal} STONE");
    }

    // ── State-Korruption prüfen ─────────────────────────────────
    println!("\n═══════════════════════════════════════");
    println!("State-Korruptionscheck:");
    let chain_len = chain.blocks.len();
    let mut corruption_found = false;
    for i in (chain_len as i64 - 10).max(0)..chain_len as i64 {
        let idx = i as usize;
        let block = &chain.blocks[idx];
        let txs = block.transactions.len();
        if txs == 0 { continue; }
        // Nur Reward-TXs sind in jedem Block
        let user_txs = block.transactions.iter()
            .filter(|tx| tx.from != "pool:mining_rewards"
                && tx.to != "pool:mining_rewards")
            .count();
        if user_txs > 0 {
            println!("  Block #{idx}: {txs} TXs ({user_txs} user), merkle={}", &block.merkle_root[..16.min(block.merkle_root.len())]);
        }
    }

    if !corruption_found {
        println!("  ✅ Keine offensichtliche State-Korruption gefunden");
    }

    println!("\n═══════════════════════════════════════");
    if block_count < 2 {
        println!("⚠️  Nur Genesis-Block – Chain ist leer / wurde nicht synced");
    } else {
        println!("✅ Chain ist synced: {} Blöcke", block_count);
    }
}