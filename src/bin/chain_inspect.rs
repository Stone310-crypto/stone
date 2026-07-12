/// chain-inspect – Liest alle Blöcke aus der RocksDB und gibt sie als JSON aus.
///
/// Ausführung:
///   cargo run --bin chain-inspect [--data-dir <pfad>] [--compact]
///
/// Ohne --compact: volles JSON mit Block-Details + Message-Pool-Status
/// Mit --compact:   eine Zeile pro Block (index + hash + tx/docs/chat counts)
///
/// Exit-Codes:
///   0 = OK
///   1 = RocksDB konnte nicht geöffnet werden
///   2 = Lesefehler

use std::env;

fn main() {
    dotenvy::from_filename(".env").ok();

    let args: Vec<String> = env::args().collect();
    let compact = args.iter().any(|a| a == "--compact");
    if let Some(dir) = args.iter().position(|a| a == "--data-dir").and_then(|i| args.get(i + 1)) {
        env::set_var("STONE_DATA_DIR", dir);
    }

    let store = match stone::storage::ChainStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ RocksDB konnte nicht geöffnet werden: {e}");
            std::process::exit(1);
        }
    };

    let summary = store.summary();
    let blocks = match store.read_all_blocks() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ Fehler beim Lesen der Blöcke: {e}");
            std::process::exit(2);
        }
    };

    if blocks.is_empty() {
        println!("⚠️  Keine Blöcke in der Datenbank gefunden.");
        return;
    }

    if compact {
        for b in &blocks {
            let ts = if b.timestamp > 0 {
                chrono::DateTime::from_timestamp(b.timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "n/a".into())
            } else {
                "n/a".into()
            };
            println!(
                "  #{:<5}  {}  tx={:<4} docs={:<4} chat={:<3}  ts={}",
                b.index,
                &b.hash[..12.min(b.hash.len())],
                b.transactions.len(),
                b.documents.len(),
                b.chat_batches.len(),
                ts,
            );
        }
    } else {
        let blocks_json: Vec<serde_json::Value> = blocks.iter().map(|b| {
            serde_json::json!({
                "index": b.index,
                "hash": b.hash,
                "previous_hash": &b.previous_hash[..16.min(b.previous_hash.len())],
                "timestamp": b.timestamp,
                "signer": b.signer,
                "tx_count": b.transactions.len(),
                "doc_count": b.documents.len(),
                "chat_batches": b.chat_batches.iter().map(|cb| {
                    serde_json::json!({
                        "merkle_root": &cb.merkle_root[..16.min(cb.merkle_root.len())],
                        "batch_size": cb.batch_size,
                        "seq_range": format!("{}-{}", cb.seq_start, cb.seq_end),
                    })
                }).collect::<Vec<_>>(),
                "merkle_root": &b.merkle_root[..16.min(b.merkle_root.len())],
                "pow_nonce": b.pow_nonce,
                "pow_difficulty": b.pow_difficulty,
            })
        }).collect();

        let seq_path = format!("{}/message_pool/sequence.json", stone::blockchain::data_dir());
        let seq: Option<serde_json::Value> = std::fs::read_to_string(&seq_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());

        let output = serde_json::json!({
            "data_dir": stone::blockchain::data_dir(),
            "total_blocks": summary.block_count,
            "genesis_hash": summary.genesis_hash,
            "latest_hash": summary.latest_hash,
            "message_pool_sequence": seq,
            "blocks": blocks_json,
        });

        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    }
}
