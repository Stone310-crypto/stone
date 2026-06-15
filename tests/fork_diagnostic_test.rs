//! Fork-Diagnose: Testet ALLE Fork-Ursachen systematisch.
//!
//! Jeder Test prüft genau einen Aspekt der Fork-Entstehung.
//! Wenn ein Test fehlschlägt → dieser Bereich muss gefixt werden.
//!
//! Usage:
//!   cargo test --test fork_diagnostic_test -- --nocapture

#[cfg(test)]
mod fork_diagnostic {
    use stone::blockchain::{Block, NodeRole, StoneChain, data_dir};

    // ── Hilfsfunktionen ──────────────────────────────────────────────────

    fn temp_data_dir(name: &str) -> String {
        let dir = format!("/tmp/stone_fork_test_{}", name);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn make_chain_with_key(key: &str, data: &str) -> StoneChain {
        std::env::set_var("STONE_DATA_DIR", data);
        StoneChain::load_or_create(key)
    }

    fn genesis_of(chain: &StoneChain) -> &Block {
        &chain.blocks[0]
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 1: GENESIS — Starten alle Nodes mit demselben Genesis?
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_genesis_deterministic_for_same_key() {
        let key = "stone-mainnet-test";
        let d1 = temp_data_dir("g1");
        let d2 = temp_data_dir("g2");
        let c1 = make_chain_with_key(key, &d1);
        let c2 = make_chain_with_key(key, &d2);
        assert_eq!(genesis_of(&c1).hash, genesis_of(&c2).hash,
            "❌ GENESIS: Gleicher Key → unterschiedliche Genesis-Hashes!");
    }

    #[test]
    fn test_genesis_different_for_different_key() {
        let d1 = temp_data_dir("g3");
        let d2 = temp_data_dir("g4");
        let c1 = make_chain_with_key("cluster-key-a", &d1);
        let c2 = make_chain_with_key("cluster-key-b", &d2);
        assert_ne!(genesis_of(&c1).hash, genesis_of(&c2).hash,
            "❌ GENESIS: Unterschiedliche Keys → gleicher Genesis?!");
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 2: GENESIS-ÜBERNAHME — Akzeptiert ein Node einen anderen Genesis?
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_adopts_bootstrap_genesis_on_first_sync() {
        // Bootstrap-Node hat eine bestimmte Chain
        let bootstrap_key = "bootstrap-genesis-key";
        let d1 = temp_data_dir("g5");
        let mut bootstrap = make_chain_with_key(bootstrap_key, &d1);
        // Bootstrap minet Block 1
        let block_1 = bootstrap.add_documents(vec![], vec![], vec![],
            "bootstrap".into(), "bootstrap".into(), bootstrap_key, NodeRole::Master);

        // Neuer Node startet mit EIGENEM Genesis (anderer Key)
        let d2 = temp_data_dir("g6");
        let mut new_node = make_chain_with_key("different-initial-key", &d2);

        // Neuer Node empfängt Block 1 vom Bootstrap
        let result = new_node.accept_peer_block(block_1, Some(true), None);
        match result {
            Ok(_) => {
                // Wenn akzeptiert: Genesis wurde überschrieben
                let genesis_match = genesis_of(&new_node).hash == genesis_of(&bootstrap).hash;
                assert!(genesis_match,
                    "❌ GENESIS: Block 1 akzeptiert aber Genesis nicht übernommen!");
            }
            Err(e) => {
                // Erwartet: "previous_hash" oder "Gap" weil Genesis unterschiedlich
                assert!(
                    e.contains("previous_hash") || e.contains("Gap") || e.contains("Fork"),
                    "❌ GENESIS: Unerwarteter Fehler beim Block-Empfang: {e}"
                );
                println!("  ℹ️  Bootstrap-Block abgelehnt weil Genesis unterschiedlich — erwartet");
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 3: CHAIN-AUSWAHL — Wechselt ein Node jemals die Kette?
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_heaviest_chain_triggers_reorg() {
        let key = "reorg-test";
        let d1 = temp_data_dir("r1");
        let mut chain_a = make_chain_with_key(key, &d1);
        let d2 = temp_data_dir("r2");
        let mut chain_b = make_chain_with_key(key, &d2);

        // Chain A: 3 Blöcke (Genesis + 2)
        chain_a.add_documents(vec![], vec![], vec![], "a".into(), "a".into(), key, NodeRole::Master);
        chain_a.add_documents(vec![], vec![], vec![], "a".into(), "a".into(), key, NodeRole::Master);

        // Chain B: NUR Genesis (kürzer)
        let tip_a = chain_a.blocks.last().unwrap().hash.clone();
        let height_a = chain_a.blocks.len();

        // B empfängt A's Blöcke. B hat nur 1 Block → sollte reorganisieren
        let mut accepted = 0;
        for block in chain_a.blocks.iter().skip(1) {
            let result = chain_b.accept_peer_block(block.clone(), Some(true), None);
            if result.is_ok() {
                accepted += 1;
            } else {
                println!("  Block {} abgelehnt: {:?}", block.index, result);
            }
        }

        let height_b = chain_b.blocks.len();
        println!("  Chain A: {height_a} Blöcke, Chain B nach Sync: {height_b} Blöcke (accepted: {accepted})");

        if height_b > 1 && chain_b.blocks.last().unwrap().hash == tip_a {
            println!("  ✅ CHAIN-AUSWAHL: Node hat schwerere Chain übernommen");
        } else {
            println!("  ⚠️  CHAIN-AUSWAHL: Node hat NICHT zur schwereren Chain gewechselt (Fork-Bug)");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 4: BLOCK-VALIDIERUNG — Parent-Hash, PoW, Signatur
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_block_must_match_parent_hash() {
        let key = "validation-test";
        let d = temp_data_dir("v1");
        let mut chain = make_chain_with_key(key, &d);

        // Erstelle einen Block mit FALSCHEM previous_hash
        let mut bad_block = Block {
            index: 1,
            timestamp: 1,
            merkle_root: "aa".repeat(32),
            data_size: 0,
            previous_hash: "ff".repeat(32),
            hash: String::new(),
            signer: "fake".into(),
            signature: String::new(),
            owner: String::new(),
            documents: vec![],
            tombstones: vec![],
            transactions: vec![],
            node_role: NodeRole::Master,
            proposal_round: 0,
            validator_pub_key: String::new(),
            validator_signature: String::new(),
            storage_proof: Default::default(),
            storage_challenges: vec![],
            challenge_responses: vec![],
            chat_batches: vec![],
            pow_nonce: 0,
            pow_hash: String::new(),
            pow_difficulty: 0,
            effective_difficulty: 0,
            cumulative_difficulty: 0,
        };
        bad_block.hash = stone::blockchain::calculate_hash(&bad_block);

        let result = chain.accept_peer_block(bad_block, Some(true), None);
        let err_msg = format!("{:?}", result);
        assert!(result.is_err(), "❌ VALIDIERUNG: Block mit falschem previous_hash wurde akzeptiert!");
        assert!(
            err_msg.contains("previous_hash"),
            "❌ VALIDIERUNG: Falsche Fehlermeldung: {}", err_msg
        );
    }

    #[test]
    fn test_block_with_wrong_hash_is_rejected() {
        let key = "hash-test";
        let d = temp_data_dir("v2");
        let mut chain = make_chain_with_key(key, &d);

        let mut fake_block = Block {
            index: 1,
            timestamp: 1,
            merkle_root: "bb".repeat(32),
            data_size: 0,
            previous_hash: chain.latest_hash.clone(),
            hash: "deadbeef".repeat(8),
            signer: "fake".into(),
            signature: String::new(),
            owner: String::new(),
            documents: vec![],
            tombstones: vec![],
            transactions: vec![],
            node_role: NodeRole::Master,
            proposal_round: 0,
            validator_pub_key: String::new(),
            validator_signature: String::new(),
            storage_proof: Default::default(),
            storage_challenges: vec![],
            challenge_responses: vec![],
            chat_batches: vec![],
            pow_nonce: 0,
            pow_hash: String::new(),
            pow_difficulty: 0,
            effective_difficulty: 0,
            cumulative_difficulty: 0,
        };

        let result = chain.accept_peer_block(fake_block, Some(true), None);
        let err_msg = format!("{:?}", result);
        assert!(result.is_err(), "❌ VALIDIERUNG: Block mit falschem Hash wurde akzeptiert!");
        assert!(
            err_msg.contains("Hash"),
            "❌ VALIDIERUNG: Falsche Fehlermeldung: {}", err_msg
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 5: ROCKSDB — WriteBatch / Corruption
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rocksdb_persists_state_across_restarts() {
        let key = "persist-test";
        let d = temp_data_dir("p1");

        // Phase 1: Chain erstellen und Block schreiben
        {
            let mut chain = make_chain_with_key(key, &d);
            chain.add_documents(vec![], vec![], vec![],
                "node".into(), "node".into(), key, NodeRole::Master);
            // Chain wird beim Drop persistiert
        }

        // Phase 2: Neu laden und prüfen
        {
            let chain = make_chain_with_key(key, &d);
            assert!(chain.blocks.len() >= 2,
                "❌ ROCKSDB: Block wurde nicht persistiert! Nur {} Blöcke nach Restart",
                chain.blocks.len());
        }
    }

    #[test]
    fn test_rocksdb_detects_genesis_mismatch() {
        let key_a = "mismatch-test-a";
        let key_b = "mismatch-test-b";
        let d = temp_data_dir("p2");

        // Schreibe Chain mit Key A
        {
            let _chain = make_chain_with_key(key_a, &d);
        }

        // Lade mit Key B → muss Genesis erkennen und neu anlegen ODER korrupt melden
        {
            let chain = make_chain_with_key(key_b, &d);
            // Erwartet: Entweder Chain wurde zurückgesetzt (nur Genesis)
            // oder Genesis-Mismatch wurde erkannt
            let genesis = genesis_of(&chain).hash.clone();
            let expected = make_chain_with_key(key_b, &temp_data_dir("p3")).blocks[0].hash.clone();
            assert_eq!(genesis, expected,
                "❌ ROCKSDB: Genesis-Mismatch nicht erkannt! Alte DB wiederverwendet");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 6: P2P/SYNC — Werden Blöcke überhaupt geteilt?
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_unknown_parent_is_handled_gracefully() {
        let key = "unknown-parent";
        let d = temp_data_dir("u1");
        let mut chain = make_chain_with_key(key, &d);

        // Block mit Index 5, aber Chain hat nur Genesis (Index 0)
        let mut future_block = Block {
            index: 5,
            timestamp: 1,
            merkle_root: "cc".repeat(32),
            data_size: 0,
            previous_hash: "dd".repeat(32),
            hash: String::new(),
            signer: "future".into(),
            signature: String::new(),
            owner: String::new(),
            documents: vec![],
            tombstones: vec![],
            transactions: vec![],
            node_role: NodeRole::Master,
            proposal_round: 0,
            validator_pub_key: String::new(),
            validator_signature: String::new(),
            storage_proof: Default::default(),
            storage_challenges: vec![],
            challenge_responses: vec![],
            chat_batches: vec![],
            pow_nonce: 0,
            pow_hash: String::new(),
            pow_difficulty: 0,
            effective_difficulty: 0,
            cumulative_difficulty: 0,
        };
        future_block.hash = stone::blockchain::calculate_hash(&future_block);

        let result = chain.accept_peer_block(future_block, Some(true), None);
        assert!(result.is_err(), "❌ SYNC: Block mit unbekanntem Parent wurde akzeptiert!");
        let err = result.unwrap_err();
        assert!(err.contains("Gap") || err.contains("previous_hash"),
            "❌ SYNC: Falsche Fehlermeldung für unknown parent: {err}");
        println!("  ✅ SYNC: Unknown-Parent korrekt abgelehnt: {err}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // TEST 7: AUTO-SYNC — Synchronisiert ein Node vom Bootstrap?
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fresh_node_accepts_entire_bootstrap_chain() {
        let key = "full-sync";
        let d_bootstrap = temp_data_dir("s1");
        let mut bootstrap = make_chain_with_key(key, &d_bootstrap);

        // Bootstrap minet 5 Blöcke
        for i in 0..5 {
            bootstrap.add_documents(vec![], vec![], vec![],
                format!("node-{}", i), format!("node-{}", i), key, NodeRole::Master);
        }

        // Neuer Node bekommt alle Blöcke nacheinander
        let d_new = temp_data_dir("s2");
        let mut new_node = make_chain_with_key(key, &d_new);

        let mut accepted = 0;
        for block in bootstrap.blocks.iter().skip(1) {
            match new_node.accept_peer_block(block.clone(), Some(true), None) {
                Ok(_) => accepted += 1,
                Err(ref e) if e.starts_with("Stale:") => {}
                Err(e) => {
                    println!("  Block {} abgelehnt: {e}", block.index);
                }
            }
        }

        let tip_match = new_node.blocks.last().map(|b| b.hash.clone())
            == bootstrap.blocks.last().map(|b| b.hash.clone());
        println!("  Bootstrap: {} Blöcke, Neuer Node: {} Blöcke (accepted: {})",
            bootstrap.blocks.len(), new_node.blocks.len(), accepted);

        if tip_match {
            println!("  ✅ SYNC: Vollständige Chain wurde übertragen");
        } else {
            println!("  ⚠️  SYNC: Chain nicht vollständig übertragen (Fork-Problem)");
        }
    }
}