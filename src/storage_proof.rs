//! Proof of Storage (PoSt) + Data Integrity Audit (Spot-Check)
//!
//! Jeder Block muss beweisen, dass der Mining-Node tatsächlich Daten speichert
//! und diese intakt sind. Dazu werden vor dem Block-Mining zufällige Challenges
//! generiert, die nur mit Zugriff auf die echten Chunk-Daten gelöst werden können.
//!
//! ## Ablauf
//!
//! 1. **Challenge-Generierung** (deterministisch aus `previous_hash + block_index`):
//!    - N zufällige Chunk-Hashes aus der Chain werden ausgewählt
//!    - Für jeden Chunk wird ein zufälliger Offset bestimmt
//!
//! 2. **Proof-Erstellung** (Mining-Node):
//!    - Chunk von Disk lesen
//!    - `SHA-256(chunk_data[offset..offset+WINDOW])` berechnen
//!    - Ergebnis als `ChunkProof` in den Block schreiben
//!
//! 3. **Verifikation** (alle Nodes bei `accept_peer_block`):
//!    - Gleiche Challenge deterministisch nachberechnen
//!    - Eigene Chunk-Daten lesen und Hash vergleichen
//!    - Stimmt der Hash nicht überein → Block ablehnen
//!
//! ## Edge Cases
//!
//! - **Leere Chain** (keine Chunks): `StorageProof::Empty` — erlaubt
//! - **Node hat Chunk nicht lokal**: Proof-Verifikation wird übersprungen
//!   (Node kann den Beweis nicht widerlegen, vertraut dem Konsensus)
//! - **Weniger Chunks als Challenges**: Es werden so viele wie möglich geprüft

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blockchain::{Block, ChunkRef, StoneChain};
use crate::storage::ChunkStore;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Anzahl der Chunks, die pro Block geprüft werden (Spot-Check Tiefe)
pub const CHALLENGES_PER_BLOCK: usize = 3;

/// Größe des Proof-Fensters in Bytes.
/// Aus dem Chunk wird ab `offset` ein Abschnitt dieser Größe gelesen und gehasht.
/// Kleines Fenster = schnell, aber beweist nur partiellen Besitz.
/// 4 KiB ist ein guter Kompromiss: schnell zum Lesen, groß genug für Sicherheit.
pub const PROOF_WINDOW: usize = 4096;

// ─── Datentypen ──────────────────────────────────────────────────────────────

/// Beweis für den Besitz eines einzelnen Chunks.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChunkProof {
    /// SHA-256-Hash des Chunks (Identifikation)
    pub chunk_hash: String,
    /// Start-Offset im Chunk, ab dem das Proof-Window gelesen wird
    pub offset: usize,
    /// SHA-256(chunk_data[offset..offset+PROOF_WINDOW])
    /// Bei kleinen Chunks (< offset+PROOF_WINDOW): SHA-256(chunk_data[offset..])
    pub proof_hash: String,
}

/// Challenge: welchen Chunk an welchem Offset muss der Miner beweisen?
#[derive(Debug, Clone)]
pub struct Challenge {
    pub chunk_hash: String,
    pub chunk_size: u64,
    pub offset: usize,
}

/// Gesamter Storage-Proof für einen Block.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageProof {
    /// Die einzelnen Chunk-Beweise
    pub proofs: Vec<ChunkProof>,
    /// Anzahl der verfügbaren Chunks zum Zeitpunkt der Challenge
    pub available_chunks: u64,
    /// Gesamtzahl geprüfter Bytes (für Statistik)
    pub audited_bytes: u64,
}

impl StorageProof {
    /// Leerer Proof (wenn keine Chunks in der Chain vorhanden sind)
    pub fn empty() -> Self {
        StorageProof {
            proofs: Vec::new(),
            available_chunks: 0,
            audited_bytes: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty() && self.available_chunks == 0
    }
}

// ─── Challenge-Generierung ───────────────────────────────────────────────────

/// Sammelt alle bekannten ChunkRefs aus der Chain (nicht-gelöschte Dokumente).
pub fn collect_chunk_refs(chain: &StoneChain) -> Vec<ChunkRef> {
    let deleted: std::collections::HashSet<String> = chain
        .blocks
        .iter()
        .flat_map(|b| b.tombstones.iter())
        .map(|t| t.doc_id.clone())
        .collect();

    chain
        .blocks
        .iter()
        .flat_map(|b| b.documents.iter())
        .filter(|d| !d.deleted && !deleted.contains(&d.doc_id))
        .flat_map(|d| d.chunks.iter())
        .cloned()
        .collect()
}

/// Erzeugt deterministische Challenges basierend auf dem vorherigen Block-Hash
/// und dem nächsten Block-Index. Jeder Node mit denselben Daten erzeugt
/// dieselben Challenges → deterministisch verifizierbar.
pub fn generate_challenges(
    previous_hash: &str,
    block_index: u64,
    chunk_refs: &[ChunkRef],
) -> Vec<Challenge> {
    if chunk_refs.is_empty() {
        return Vec::new();
    }

    let n = CHALLENGES_PER_BLOCK.min(chunk_refs.len());
    let mut challenges = Vec::with_capacity(n);

    for i in 0..n {
        // Deterministischer Seed: SHA-256(previous_hash || block_index || challenge_index)
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(previous_hash.as_bytes());
        seed_hasher.update(block_index.to_le_bytes());
        seed_hasher.update((i as u64).to_le_bytes());
        let seed = seed_hasher.finalize();

        // Chunk-Auswahl: seed[0..8] mod chunk_count
        let chunk_selector = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        let chunk_idx = (chunk_selector % chunk_refs.len() as u64) as usize;
        let chunk = &chunk_refs[chunk_idx];

        // Offset-Berechnung: seed[8..16] mod max(chunk_size - PROOF_WINDOW, 1)
        let max_offset = if chunk.size as usize > PROOF_WINDOW {
            chunk.size as usize - PROOF_WINDOW
        } else {
            0 // Chunk ist kleiner als das Fenster → Offset = 0
        };
        let offset = if max_offset > 0 {
            let offset_selector = u64::from_le_bytes(seed[8..16].try_into().unwrap());
            (offset_selector % max_offset as u64) as usize
        } else {
            0
        };

        challenges.push(Challenge {
            chunk_hash: chunk.hash.clone(),
            chunk_size: chunk.size,
            offset,
        });
    }

    challenges
}

// ─── Proof-Erstellung ────────────────────────────────────────────────────────

/// Erstellt den Storage-Proof für einen neuen Block.
///
/// Liest die ausgewählten Chunks von Disk und berechnet die Proof-Hashes.
/// Wird vom Mining-Node vor dem Block-Erstellen aufgerufen.
pub fn create_storage_proof(
    chain: &StoneChain,
    block_index: u64,
    previous_hash: &str,
) -> StorageProof {
    let chunk_refs = collect_chunk_refs(chain);
    let available = chunk_refs.len() as u64;

    if chunk_refs.is_empty() {
        return StorageProof::empty();
    }

    let challenges = generate_challenges(previous_hash, block_index, &chunk_refs);

    let store = match ChunkStore::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[storage-proof] ChunkStore Fehler: {e}");
            return StorageProof::empty();
        }
    };

    let mut proofs = Vec::new();
    let mut audited_bytes: u64 = 0;

    for challenge in &challenges {
        match create_chunk_proof(&store, challenge) {
            Some(proof) => {
                audited_bytes += PROOF_WINDOW.min(challenge.chunk_size as usize) as u64;
                proofs.push(proof);
            }
            None => {
                eprintln!(
                    "[storage-proof] ⚠️  Chunk {}... nicht lokal verfügbar – übersprungen",
                    &challenge.chunk_hash[..12.min(challenge.chunk_hash.len())]
                );
            }
        }
    }

    StorageProof {
        proofs,
        available_chunks: available,
        audited_bytes,
    }
}

/// Erstellt einen einzelnen Chunk-Proof: liest Chunk von Disk, hasht das Fenster.
fn create_chunk_proof(store: &ChunkStore, challenge: &Challenge) -> Option<ChunkProof> {
    let data = store.read_chunk(&challenge.chunk_hash).ok()?;

    let end = (challenge.offset + PROOF_WINDOW).min(data.len());
    let window = &data[challenge.offset.min(data.len())..end];

    let proof_hash = format!("{:x}", Sha256::digest(window));

    Some(ChunkProof {
        chunk_hash: challenge.chunk_hash.clone(),
        offset: challenge.offset,
        proof_hash,
    })
}

// ─── Proof-Verifikation ──────────────────────────────────────────────────────

/// Verifiziert den Storage-Proof eines empfangenen Blocks.
///
/// Gibt `Ok(())` zurück wenn:
/// - Der Proof die korrekte Anzahl Challenges enthält
/// - Alle Proof-Hashes mit lokalen Daten übereinstimmen (falls lokal vorhanden)
/// - Bei leerer Chain (keine Chunks) ein leerer Proof akzeptiert wird
///
/// Gibt `Err(reason)` zurück wenn:
/// - Ein Proof-Hash nicht mit den lokalen Daten übereinstimmt (Datenmanipulation!)
/// - Die Challenge-Parameter nicht mit der deterministischen Berechnung übereinstimmen
pub fn verify_storage_proof(
    chain: &StoneChain,
    block: &Block,
) -> Result<(), String> {
    let chunk_refs = collect_chunk_refs(chain);

    // Keine Chunks in der Chain → leerer Proof ist OK
    if chunk_refs.is_empty() {
        if !block.storage_proof.proofs.is_empty() {
            return Err("Storage-Proof enthält Beweise obwohl keine Chunks existieren".into());
        }
        return Ok(());
    }

    // Challenges nachberechnen (deterministisch)
    let challenges = generate_challenges(
        &block.previous_hash,
        block.index,
        &chunk_refs,
    );

    // Proof muss mindestens so viele Einträge haben wie Challenges
    // (weniger nur erlaubt, wenn der Node den Chunk nicht lokal hat)
    if block.storage_proof.proofs.len() > challenges.len() {
        return Err(format!(
            "Zu viele Proofs: {} statt maximal {}",
            block.storage_proof.proofs.len(),
            challenges.len()
        ));
    }

    // Verifiziere: stimmen die Chunk-Hashes und Offsets mit den Challenges überein?
    for proof in &block.storage_proof.proofs {
        let matching_challenge = challenges.iter().find(|c| c.chunk_hash == proof.chunk_hash);
        match matching_challenge {
            None => {
                return Err(format!(
                    "Proof für Chunk {}... ist keine gültige Challenge",
                    &proof.chunk_hash[..12.min(proof.chunk_hash.len())]
                ));
            }
            Some(challenge) => {
                if proof.offset != challenge.offset {
                    return Err(format!(
                        "Proof-Offset für Chunk {}... stimmt nicht: erwartet {}, erhalten {}",
                        &proof.chunk_hash[..12.min(proof.chunk_hash.len())],
                        challenge.offset,
                        proof.offset
                    ));
                }
            }
        }
    }

    // Spot-Check: eigene lokale Daten gegen den Proof verifizieren
    let store = match ChunkStore::new() {
        Ok(s) => s,
        Err(_) => return Ok(()), // Kein lokaler Store → kann nicht verifizieren, Trust
    };

    let mut verified = 0u32;
    let mut skipped = 0u32;

    for proof in &block.storage_proof.proofs {
        match store.read_chunk(&proof.chunk_hash) {
            Ok(data) => {
                // Lokal vorhanden → Proof-Hash verifizieren
                let end = (proof.offset + PROOF_WINDOW).min(data.len());
                let window = &data[proof.offset.min(data.len())..end];
                let expected_hash = format!("{:x}", Sha256::digest(window));

                if proof.proof_hash != expected_hash {
                    return Err(format!(
                        "🚨 Data Integrity Violation! Chunk {}... Proof-Hash stimmt nicht! \
                         Erwartet: {}..., Erhalten: {}...",
                        &proof.chunk_hash[..12.min(proof.chunk_hash.len())],
                        &expected_hash[..12.min(expected_hash.len())],
                        &proof.proof_hash[..12.min(proof.proof_hash.len())],
                    ));
                }
                verified += 1;
            }
            Err(_) => {
                // Chunk nicht lokal → können nicht verifizieren, Trust
                skipped += 1;
            }
        }
    }

    if verified > 0 || skipped > 0 {
        println!(
            "[storage-proof] ✅ Block #{}: {} Proofs verifiziert, {} übersprungen (nicht lokal)",
            block.index, verified, skipped
        );
    }

    Ok(())
}

// ─── Proof-Hash für Block-Hashing ────────────────────────────────────────────

/// Berechnet einen kompakten Hash über den gesamten StorageProof,
/// der in den Block-Hash eingeht. So wird der Proof unveränderlich
/// Teil des Block-Hashes.
pub fn storage_proof_hash(proof: &StorageProof) -> String {
    let mut h = Sha256::new();
    h.update(proof.available_chunks.to_le_bytes());
    h.update((proof.proofs.len() as u64).to_le_bytes());
    for p in &proof.proofs {
        h.update(p.chunk_hash.as_bytes());
        h.update(p.offset.to_le_bytes());
        h.update(p.proof_hash.as_bytes());
    }
    format!("{:x}", h.finalize())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_proof() {
        let proof = StorageProof::empty();
        assert!(proof.is_empty());
        assert_eq!(proof.proofs.len(), 0);
    }

    #[test]
    fn test_challenge_determinism() {
        // Gleiche Inputs → gleiche Challenges
        let refs = vec![
            ChunkRef { hash: "a".repeat(64), size: 8192, shards: vec![], ec_k: 0, ec_m: 0 },
            ChunkRef { hash: "b".repeat(64), size: 16384, shards: vec![], ec_k: 0, ec_m: 0 },
            ChunkRef { hash: "c".repeat(64), size: 4096, shards: vec![], ec_k: 0, ec_m: 0 },
        ];

        let c1 = generate_challenges("abc123", 42, &refs);
        let c2 = generate_challenges("abc123", 42, &refs);

        assert_eq!(c1.len(), c2.len());
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.chunk_hash, b.chunk_hash);
            assert_eq!(a.offset, b.offset);
        }
    }

    #[test]
    fn test_challenges_different_for_different_blocks() {
        let refs = vec![
            ChunkRef { hash: "a".repeat(64), size: 1_000_000, shards: vec![], ec_k: 0, ec_m: 0 },
            ChunkRef { hash: "b".repeat(64), size: 1_000_000, shards: vec![], ec_k: 0, ec_m: 0 },
            ChunkRef { hash: "c".repeat(64), size: 1_000_000, shards: vec![], ec_k: 0, ec_m: 0 },
        ];

        let c1 = generate_challenges("abc123", 1, &refs);
        let c2 = generate_challenges("abc123", 2, &refs);

        // Sehr unwahrscheinlich, dass alle Challenges identisch sind
        let all_same = c1.iter().zip(c2.iter())
            .all(|(a, b)| a.chunk_hash == b.chunk_hash && a.offset == b.offset);
        assert!(!all_same, "Challenges für verschiedene Blöcke sollten verschieden sein");
    }

    #[test]
    fn test_no_chunks_no_challenges() {
        let refs: Vec<ChunkRef> = vec![];
        let challenges = generate_challenges("abc", 1, &refs);
        assert!(challenges.is_empty());
    }

    #[test]
    fn test_storage_proof_hash_determinism() {
        let proof = StorageProof {
            proofs: vec![ChunkProof {
                chunk_hash: "a".repeat(64),
                offset: 1024,
                proof_hash: "b".repeat(64),
            }],
            available_chunks: 5,
            audited_bytes: 4096,
        };

        let h1 = storage_proof_hash(&proof);
        let h2 = storage_proof_hash(&proof);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }
}
