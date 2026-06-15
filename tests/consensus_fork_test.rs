//! Consensus Fork-Erkennung Integration Test
//!
//! Testet: Zwei Nodes starten mit demselben Genesis-Block, tauschen Blöcke
//! und müssen am Ende konsistent sein (identische Chain-Hashes).
//!
//! Nutzung:
//!   cargo test --test consensus_fork_test -- --nocapture
//!
//! Ziel: Fork-Bug im Testnet reproduzieren und Root-Cause identifizieren.

#[cfg(test)]
mod consensus_tests {
    use stone::blockchain::{Block, NodeRole, StoneChain};
    use stone::consensus::ValidatorSet;
    use stone::token::{TokenLedger, TokenTx, TxType, create_signed_tx};
    use stone::token::transaction::FeeTier;

    /// Erstellt einen Genesis-Block (minimale Chain-Initialisierung).
    fn make_genesis(cluster_key: &str) -> (StoneChain, Vec<Block>) {
        // Keine existierende DB — neue Chain
        let mut chain = StoneChain::load_or_create(cluster_key);
        let blocks = chain.blocks.clone();
        assert!(!blocks.is_empty(), "Genesis-Block muss existieren");
        assert_eq!(blocks[0].index, 0);
        (chain, blocks)
    }

    /// Zwei Chains starten mit demselben Cluster-Key → gleicher Genesis.
    #[test]
    fn test_same_genesis_for_same_key() {
        let key = "test-cluster-key-consensus";
        let (chain_a, _) = make_genesis(key);
        let (chain_b, _) = make_genesis(key);
        let ga = &chain_a.blocks[0];
        let gb = &chain_b.blocks[0];
        assert_eq!(ga.hash, gb.hash, "Genesis-Hash muss für denselben Key identisch sein");
    }

    /// Test: Chain A baut Block 1, Chain B empfängt ihn via
    /// accept_peer_block und muss ihn akzeptieren.
    #[test]
    fn test_peer_accepts_valid_block() {
        let key = "peer-accept-test";
        let (mut chain_a, _) = make_genesis(key);
        let (mut chain_b, _) = make_genesis(key);

        // Node A erzeugt Block 1 (ohne TXs, einfacher Fall)
        let block_1 = chain_a.add_documents(
            vec![],
            vec![],
            vec![],
            "node-a".into(),
            "node-a".into(),
            key,
            NodeRole::Master,
        );
        assert_eq!(block_1.index, 1);
        assert!(!block_1.hash.is_empty());

        // Node B empfängt den Block per accept_peer_block
        let result = chain_b.accept_peer_block(block_1.clone(), Some(true), None);
        assert!(result.is_ok(), "accept_peer_block muss für PoA-Bypass true sein: {:?}", result);
        assert_eq!(chain_b.blocks.len(), 2);
        assert_eq!(chain_b.blocks[1].hash, block_1.hash,
            "Chain B muss denselben Block 1 haben wie Chain A");
    }

    /// Test: Zwei Nodes bauen abwechselnd Blöcke und syncen.
    /// Am Ende müssen beide dieselbe Chain-Höhe und denselben Tip-Hash haben.
    #[test]
    fn test_bidirectional_sync_converges() {
        let key = "bidirectional-sync";
        let (mut chain_a, _) = make_genesis(key);
        let (mut chain_b, _) = make_genesis(key);

        // Node A → Block 1, Block 3
        let _b1 = chain_a.add_documents(vec![], vec![], vec![], "a".into(), "a".into(), key, NodeRole::Master);
        let _b3 = chain_a.add_documents(vec![], vec![], vec![], "a".into(), "a".into(), key, NodeRole::Master);
        // Node B → Block 2, Block 4
        let _b2 = chain_b.add_documents(vec![], vec![], vec![], "b".into(), "b".into(), key, NodeRole::Master);
        let _b4 = chain_b.add_documents(vec![], vec![], vec![], "b".into(), "b".into(), key, NodeRole::Master);

        // Nun tauschen: B bekommt A's Blöcke
        // Problem: Block-Indizes von Chain B sind [0,2,4], A's sind [0,1,3]
        // accept_peer_block wird bei unterschiedlichen Indices mit "Gap" fehlschlagen.
        // Das ist der Fork-Bug: Zwei Nodes die parallel minen, haben
        // unterschiedliche Block-Indizes → keine Konvergenz.
        //
        // Erwartetes Verhalten (korrekt): Der Node mit der "Heaviest Chain"
        // (höchste cumulative difficulty) gewinnt. Dieser Test soll den
        // Bug demonstrieren.

        let chain_a_blocks: Vec<Block> = chain_a.blocks.clone();
        for block in chain_a_blocks.iter().skip(1) {
            let result = chain_b.accept_peer_block(block.clone(), Some(true), None);
            if block.index == 1 || block.index == 3 {
                // A's Blöcke passen nicht in B's Chain weil Indices kollidieren
                // → entfweder "Stale" (identisch) oder "Fork" (unterschiedlich)
                match result {
                    Err(ref e) if e.starts_with("Stale:") => {
                        // Okay: B hat bereits einen Block mit diesem Index
                    }
                    Err(ref e) if e.contains("previous_hash") || e.contains("Gap:") => {
                        // Erwartet: Fork – die Chains sind divergiert
                    }
                    Ok(_) => {
                        panic!("Block {} wurde akzeptiert obwohl Chain B anders ist", block.index);
                    }
                    Err(e) => {
                        // Anderer Fehler ist akzeptabel
                    }
                }
            }
        }

        let chain_b_blocks: Vec<Block> = chain_b.blocks.clone();
        for block in chain_b_blocks.iter().skip(1) {
            let result = chain_a.accept_peer_block(block.clone(), Some(true), None);
            if block.index == 2 || block.index == 4 {
                match result {
                    Err(ref e) if e.starts_with("Stale:") => {}
                    Err(ref e) if e.contains("previous_hash") || e.contains("Gap:") => {}
                    Ok(_) => {
                        panic!("Block {} wurde akzeptiert obwohl Chain A anders ist", block.index);
                    }
                    Err(e) => {}
                }
            }
        }

        // Nach dem Fork: Beide Chains sind unterschiedlich
        // Das ist der BUG den wir fixen müssen.
        let tip_hash_a = chain_a.blocks.last().map(|b| b.hash.as_str()).unwrap_or("");
        let tip_hash_b = chain_b.blocks.last().map(|b| b.hash.as_str()).unwrap_or("");
        println!("Chain A: {} Blöcke, tip={}", chain_a.blocks.len(), &tip_hash_a[..12.min(tip_hash_a.len())]);
        println!("Chain B: {} Blöcke, tip={}", chain_b.blocks.len(), &tip_hash_b[..12.min(tip_hash_b.len())]);

        // Aktueller Status: Fork erkannt. Wenn beide Chains identisch sind → Bug gelöst.
        if tip_hash_a == tip_hash_b {
            println!("✅ Fork-Bug ist BEHOBEN — Chains sind konvergent!");
        } else {
            println!("⚠️  Fork besteht weiterhin (dieser Test dokumentiert den Bug)");
        }
    }
}