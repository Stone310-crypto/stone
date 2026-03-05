//! Blockchain Stability Tests
//!
//! Tests für:
//! - Chain-Integrität über viele Blöcke
//! - Challenge-Generierung und Response-Verifikation
//! - Fork-Resistance und Hash-Konsistenz
//! - Token-Ledger-Konsistenz
//! - Deterministische Challenge-Verteilung

use sha2::{Digest, Sha256};
use std::path::PathBuf;

use stone::blockchain::{calculate_hash, Block, ChunkRef};
use stone::storage::ChunkStore;
use stone::storage_proof::*;
use stone::token::transaction::{TokenTx, TxType, FeeTier};

fn empty_block() -> Block {
    Block {
        index: 0,
        timestamp: 0,
        merkle_root: String::new(),
        data_size: 0,
        previous_hash: String::new(),
        hash: String::new(),
        signer: String::new(),
        signature: String::new(),
        owner: String::new(),
        documents: Vec::new(),
        tombstones: Vec::new(),
        transactions: Vec::new(),
        node_role: stone::blockchain::NodeRole::default(),
        proposal_round: 0,
        validator_pub_key: String::new(),
        validator_signature: String::new(),
        storage_proof: StorageProof::empty(),
        storage_challenges: Vec::new(),
        challenge_responses: Vec::new(),
    }
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

fn make_chunk_refs(n: usize) -> Vec<ChunkRef> {
    (0..n)
        .map(|i| {
            let hash = format!("{:064x}", i + 1);
            ChunkRef {
                hash,
                size: 8192,
                shards: vec![],
                ec_k: 0,
                ec_m: 0,
            }
        })
        .collect()
}

fn make_wallets(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("{:064x}", 0xA000 + i))
        .collect()
}

fn make_test_chunk_store(chunks: &[Vec<u8>]) -> (PathBuf, ChunkStore, Vec<ChunkRef>) {
    let tmp = std::env::temp_dir().join(format!(
        "stone_stability_test_{}_{}", std::process::id(), 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let store = ChunkStore::with_dir(tmp.clone()).unwrap();
    let mut refs = Vec::new();

    for data in chunks {
        let hash = store.write_chunk(data).unwrap();
        refs.push(ChunkRef {
            hash,
            size: data.len() as u64,
            shards: vec![],
            ec_k: 0,
            ec_m: 0,
        });
    }

    (tmp, store, refs)
}

fn cleanup(tmp: &PathBuf) {
    let _ = std::fs::remove_dir_all(tmp);
}

// ─── Challenge-Generierung Stabilitätstests ──────────────────────────────────

#[test]
fn test_challenge_generation_over_1000_blocks() {
    let refs = make_chunk_refs(50);
    let wallets = make_wallets(20);

    let mut challenge_count = 0u64;
    let mut unique_ids = std::collections::HashSet::new();

    for block_idx in 0..1000u64 {
        let prev_hash = format!("{:064x}", block_idx.wrapping_mul(7919));
        let challenges = generate_network_challenges(&prev_hash, block_idx, &refs, &wallets, "own_wallet");

        for c in &challenges {
            challenge_count += 1;

            // Challenge-ID muss global eindeutig sein
            assert!(
                unique_ids.insert(c.challenge_id.clone()),
                "Doppelte Challenge-ID '{}' bei Block {}",
                &c.challenge_id[..16], block_idx
            );

            // Deadline korrekt
            assert_eq!(c.deadline_block, block_idx + CHALLENGE_DEADLINE_BLOCKS);

            // Offset muss im Chunk passen
            let chunk_size = refs.iter().find(|r| r.hash == c.chunk_hash).unwrap().size;
            let max_offset = (chunk_size as usize).saturating_sub(PROOF_WINDOW);
            assert!(
                c.offset <= max_offset,
                "Offset {} > max {} für Chunk-Size {} bei Block {}",
                c.offset, max_offset, chunk_size, block_idx
            );
        }
    }

    println!("✅ 1000 Blöcke: {} Challenges generiert, alle IDs eindeutig", challenge_count);
    assert!(challenge_count >= 1000, "Zu wenig Challenges generiert");
}

#[test]
fn test_challenge_wallet_fairness() {
    let refs = make_chunk_refs(30);
    let wallets = make_wallets(10);

    let mut wallet_hits: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    for block_idx in 0..2000u64 {
        let prev_hash = format!("{:064x}", block_idx.wrapping_mul(104729));
        let challenges = generate_network_challenges(&prev_hash, block_idx, &refs, &wallets, "own");

        for c in &challenges {
            *wallet_hits.entry(c.target_wallet.clone()).or_default() += 1;
        }
    }

    let total: u32 = wallet_hits.values().sum();
    let expected_pct = 100.0 / wallets.len() as f64;

    println!("Challenge-Distribution über 2000 Blöcke:");
    for (w, count) in &wallet_hits {
        let pct = (*count as f64 / total as f64) * 100.0;
        println!("  Wallet {}…: {} ({:.1}%, erwartet {:.1}%)", &w[..16], count, pct, expected_pct);

        // Kein Wallet sollte mehr als 3x den erwarteten Anteil bekommen
        assert!(
            pct < expected_pct * 3.0,
            "Wallet {}… hat {:.1}% statt ~{:.1}% – unfaire Distribution!",
            &w[..16], pct, expected_pct
        );
    }

    // Alle Wallets müssen mindestens einmal gechallenged worden sein
    for w in &wallets {
        assert!(
            wallet_hits.contains_key(w),
            "Wallet {}… wurde nie gechallenged!", &w[..16]
        );
    }

    println!("✅ Wallet-Distribution fair (alle getroffen, keine > {}%)", expected_pct * 3.0);
}

// ─── Challenge-Response End-to-End ───────────────────────────────────────────

#[test]
fn test_challenge_response_full_cycle() {
    // Erstelle Chunk-Daten und Store
    let chunk_data: Vec<Vec<u8>> = (0..5)
        .map(|i| vec![(i * 17 + 3) as u8; 8192])
        .collect();
    let (tmp, store, chunk_refs) = make_test_chunk_store(&chunk_data);

    // Signing-Keys für 3 Nodes
    let keys: Vec<ed25519_dalek::SigningKey> = (0..3)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            ed25519_dalek::SigningKey::from_bytes(&seed)
        })
        .collect();

    let wallets: Vec<String> = keys.iter()
        .map(|k| hex::encode(k.verifying_key().as_bytes()))
        .collect();

    // Generiere Challenges für Block #10 (vom Miner mit wallet[0])
    let challenges = generate_network_challenges(
        "previous_block_hash_value",
        10,
        &chunk_refs,
        &wallets,
        &wallets[0], // Miner's eigene Wallet
    );

    assert!(!challenges.is_empty(), "Es müssen Challenges generiert werden");

    // Jede Challenge sollte NICHT an wallet[0] gehen (eigene Wallet ausgeschlossen)
    for c in &challenges {
        assert_ne!(
            c.target_wallet, wallets[0],
            "Miner darf sich nicht selbst challengen"
        );
    }

    // Simuliere: Target-Nodes antworten auf ihre Challenges
    let mut responses = Vec::new();
    for challenge in &challenges {
        let target_idx = wallets.iter().position(|w| w == &challenge.target_wallet).unwrap();
        let response = create_challenge_response(
            challenge,
            &store,
            &wallets[target_idx],
            &keys[target_idx],
            11, // Response im nächsten Block
        );

        assert!(response.is_some(), "Target sollte antworten können (hat alle Chunks)");
        responses.push(response.unwrap());
    }

    // Verifiziere alle Responses
    for (challenge, response) in challenges.iter().zip(responses.iter()) {
        let result = verify_challenge_response(challenge, response, Some(&store), 11);
        assert!(
            result.is_ok(),
            "Gültige Response sollte verifiziert werden: {:?}", result
        );
    }

    println!("✅ Full-Cycle: {} Challenges → {} Responses → alle verifiziert",
        challenges.len(), responses.len());

    cleanup(&tmp);
}

#[test]
fn test_challenge_response_tampered_proof_rejected() {
    let chunk_data = vec![vec![0xFFu8; 8192]];
    let (tmp, store, chunk_refs) = make_test_chunk_store(&chunk_data);

    let mut seed = [0u8; 32];
    seed[0] = 1;
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    seed[0] = 2;
    let target_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let target_wallet = hex::encode(target_key.verifying_key().as_bytes());

    let wallets = vec![
        hex::encode(signer.verifying_key().as_bytes()),
        target_wallet.clone(),
    ];

    let challenges = generate_network_challenges(
        "hash", 1, &chunk_refs, &wallets,
        &wallets[0],
    );

    if challenges.is_empty() {
        cleanup(&tmp);
        return; // Kann passieren wenn nur 1 anderer Wallet → OK
    }

    let challenge = &challenges[0];
    let mut response = create_challenge_response(
        challenge, &store, &target_wallet, &target_key, 2,
    ).unwrap();

    // Manipuliere den Proof-Hash
    response.proof_hash = "0".repeat(64);

    // Lokale Verifikation mit Store sollte fehlschlagen
    let result = verify_challenge_response(challenge, &response, Some(&store), 2);
    assert!(result.is_err(), "Manipulierter Proof sollte abgelehnt werden");

    println!("✅ Tampered Proof korrekt abgelehnt");

    cleanup(&tmp);
}

// ─── Block-Hash Integrität ───────────────────────────────────────────────────

#[test]
fn test_block_hash_includes_challenges() {
    let mut block = empty_block();
    block.index = 1;
    block.previous_hash = "genesis".to_string();
    block.signer = "test_node".to_string();

    let hash_without = calculate_hash(&block);

    // Füge Challenge hinzu
    block.storage_challenges = vec![NetworkChallenge {
        challenge_id: "test_challenge".to_string(),
        block_index: 1,
        target_wallet: "target".to_string(),
        chunk_hash: "chunk".to_string(),
        chunk_size: 4096,
        offset: 0,
        deadline_block: 11,
    }];

    let hash_with = calculate_hash(&block);

    assert_ne!(
        hash_without, hash_with,
        "Block-Hash muss sich ändern wenn Challenges hinzugefügt werden"
    );

    // Deterministisch
    let hash_with_2 = calculate_hash(&block);
    assert_eq!(hash_with, hash_with_2, "Block-Hash muss deterministisch sein");

    println!("✅ Block-Hash enthält Challenge-Daten");
}

#[test]
fn test_block_hash_includes_storage_proof() {
    let mut block = empty_block();
    block.index = 5;
    block.previous_hash = "prevhash".to_string();
    block.signer = "node1".to_string();

    let hash_empty_proof = calculate_hash(&block);

    block.storage_proof = StorageProof {
        proofs: vec![ChunkProof {
            chunk_hash: "a".repeat(64),
            offset: 0,
            proof_hash: "b".repeat(64),
        }],
        available_chunks: 1,
        audited_bytes: 4096,
    };

    let hash_with_proof = calculate_hash(&block);
    assert_ne!(
        hash_empty_proof, hash_with_proof,
        "Storage-Proof muss den Block-Hash beeinflussen"
    );

    println!("✅ Block-Hash enthält Storage-Proof");
}

// ─── Chain-Link-Konsistenz ───────────────────────────────────────────────────

#[test]
fn test_chain_link_integrity_simulation() {
    let mut blocks = Vec::new();
    let mut previous_hash = "genesis_hash_000".to_string();

    for i in 0..100u64 {
        let mut block = empty_block();
        block.index = i;
        block.previous_hash = previous_hash.clone();
        block.signer = format!("node_{}", i % 3);
        block.hash = calculate_hash(&block);

        previous_hash = block.hash.clone();
        blocks.push(block);
    }

    // Verifiziere Chain-Integrität
    for window in blocks.windows(2) {
        assert_eq!(
            window[1].previous_hash, window[0].hash,
            "Block #{} zeigt nicht auf Block #{}'s Hash",
            window[1].index, window[0].index
        );
    }

    // Verifiziere Hash-Korrektheit
    for block in &blocks {
        let recomputed = calculate_hash(block);
        assert_eq!(
            block.hash, recomputed,
            "Block #{} Hash stimmt nicht mit Neuberechnung überein",
            block.index
        );
    }

    // Simuliere Manipulation: Ändere einen Block in der Mitte
    let tampered_idx = 50;
    let original_hash = blocks[tampered_idx].hash.clone();
    blocks[tampered_idx].signer = "attacker".to_string();
    let tampered_hash = calculate_hash(&blocks[tampered_idx]);

    assert_ne!(
        original_hash, tampered_hash,
        "Manipulation muss den Hash ändern"
    );
    assert_ne!(
        blocks[tampered_idx + 1].previous_hash, tampered_hash,
        "Chain-Link ist gebrochen nach Manipulation"
    );

    println!("✅ 100 Blöcke: Chain-Integrität verifiziert, Manipulation erkannt");
}

// ─── Determinismus über Node-Grenzen ─────────────────────────────────────────

#[test]
fn test_cross_node_challenge_determinism() {
    // Simuliere 3 verschiedene Nodes die dieselben Challenges berechnen
    let refs = make_chunk_refs(20);
    let wallets = make_wallets(5);
    let prev_hash = "shared_previous_hash";

    for block_idx in 0..50u64 {
        let node_a = generate_network_challenges(prev_hash, block_idx, &refs, &wallets, &wallets[0]);
        let node_b = generate_network_challenges(prev_hash, block_idx, &refs, &wallets, &wallets[0]);

        // Gleiche Inputs → gleiche Challenges
        assert_eq!(node_a.len(), node_b.len());
        for (a, b) in node_a.iter().zip(node_b.iter()) {
            assert_eq!(a.challenge_id, b.challenge_id);
            assert_eq!(a.target_wallet, b.target_wallet);
            assert_eq!(a.chunk_hash, b.chunk_hash);
            assert_eq!(a.offset, b.offset);
        }
    }

    println!("✅ Cross-Node Determinismus: 50 Blöcke identisch auf allen Nodes");
}

// ─── Performance-Test ────────────────────────────────────────────────────────

#[test]
fn test_challenge_generation_performance() {
    let refs = make_chunk_refs(500);
    let wallets = make_wallets(100);

    let start = std::time::Instant::now();
    let iterations = 10_000u64;

    for block_idx in 0..iterations {
        let prev_hash = format!("{:064x}", block_idx);
        let _ = generate_network_challenges(&prev_hash, block_idx, &refs, &wallets, "own");
    }

    let elapsed = start.elapsed();
    let per_block = elapsed / iterations as u32;

    println!(
        "⏱️  {} Challenge-Generierungen in {:.2}s ({:?} pro Block)",
        iterations,
        elapsed.as_secs_f64(),
        per_block
    );

    // Sollte unter 1ms pro Block liegen
    assert!(
        per_block.as_micros() < 1000,
        "Challenge-Generierung zu langsam: {:?} pro Block (max 1ms)",
        per_block
    );
}

// ─── Storage-Proof End-to-End ────────────────────────────────────────────────

#[test]
fn test_storage_proof_create_and_verify_cycle() {
    // Erstelle echte Chunks
    let chunk_data: Vec<Vec<u8>> = (0..10)
        .map(|i| {
            let mut data = vec![0u8; 16384]; // 16 KB pro Chunk
            for (j, byte) in data.iter_mut().enumerate() {
                *byte = ((i * 31 + j) % 256) as u8;
            }
            data
        })
        .collect();

    let (tmp, store, chunk_refs) = make_test_chunk_store(&chunk_data);

    // Block-Level Challenges generieren
    let prev_hash = "test_prev_hash";
    let block_index = 42u64;

    let challenges = generate_challenges(prev_hash, block_index, &chunk_refs);
    assert!(!challenges.is_empty(), "Es müssen Challenges generiert werden");
    assert!(challenges.len() <= CHALLENGES_PER_BLOCK);

    // Proofs erstellen (wie der Miner es tut)
    let mut proofs = Vec::new();
    for challenge in &challenges {
        let data = store.read_chunk(&challenge.chunk_hash).unwrap();
        let end = (challenge.offset + PROOF_WINDOW).min(data.len());
        let window = &data[challenge.offset.min(data.len())..end];
        let proof_hash = format!("{:x}", Sha256::digest(window));

        proofs.push(ChunkProof {
            chunk_hash: challenge.chunk_hash.clone(),
            offset: challenge.offset,
            proof_hash,
        });
    }

    let storage_proof = StorageProof {
        proofs,
        available_chunks: chunk_refs.len() as u64,
        audited_bytes: challenges.iter().map(|c| PROOF_WINDOW.min(c.chunk_size as usize) as u64).sum(),
    };

    assert!(!storage_proof.is_empty());
    assert_eq!(storage_proof.proofs.len(), challenges.len());

    // Hash muss deterministisch sein
    let h1 = storage_proof_hash(&storage_proof);
    let h2 = storage_proof_hash(&storage_proof);
    assert_eq!(h1, h2);

    println!(
        "✅ Storage-Proof: {} Challenges, {} Proofs, {} Bytes auditiert",
        challenges.len(), storage_proof.proofs.len(), storage_proof.audited_bytes
    );

    cleanup(&tmp);
}

// ─── Deadline-Tracking ───────────────────────────────────────────────────────

#[test]
fn test_challenge_deadline_tracking() {
    let refs = make_chunk_refs(10);
    let wallets = make_wallets(5);

    // Simuliere 100 Blöcke und tracke offene Challenges
    let mut open_challenges: Vec<NetworkChallenge> = Vec::new();
    let mut expired_count = 0u64;

    for block_idx in 0..100u64 {
        let prev_hash = format!("{:064x}", block_idx);
        let new_challenges = generate_network_challenges(&prev_hash, block_idx, &refs, &wallets, "own");

        // Abgelaufene entfernen
        let before = open_challenges.len();
        open_challenges.retain(|c| c.deadline_block > block_idx);
        expired_count += (before - open_challenges.len()) as u64;

        // Neue hinzufügen
        open_challenges.extend(new_challenges);

        // Sanity: keine offenen Challenges sollten eine Deadline < aktuellen Block haben
        for c in &open_challenges {
            assert!(
                c.deadline_block > block_idx,
                "Challenge mit abgelaufener Deadline noch offen: deadline={} current={}",
                c.deadline_block, block_idx
            );
        }
    }

    println!(
        "✅ Deadline-Tracking: {} offen, {} abgelaufen über 100 Blöcke",
        open_challenges.len(), expired_count
    );
    assert!(expired_count > 0, "Es müssen Challenges ablaufen");
}
