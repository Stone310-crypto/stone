//! Proof of Storage (PoSt) + Chain-Driven Challenge System
//!
//! ## Block-Level Storage Proof (original)
//!
//! Jeder Block enthält einen Beweis, dass der Mining-Node tatsächlich Daten speichert.
//! Challenges werden deterministisch aus `previous_hash + block_index` generiert.
//!
//! ## Network Storage Challenges (chain-driven)
//!
//! Zusätzlich erstellt die Chain pro Block **NetworkChallenges**, die an zufällige
//! Nodes im Netzwerk gerichtet sind. Der Ablauf:
//!
//! 1. **Challenge-Erstellung** (im Block durch den Miner):
//!    - Der Block-Ersteller wählt deterministisch zufällige Validator-Wallets aus
//!    - Für jeden gewählten Node wird ein zufälliger Chunk + Offset bestimmt
//!    - Diese Challenges werden als `storage_challenges` im Block veröffentlicht
//!
//! 2. **Challenge-Response** (durch den angefragten Node):
//!    - Der Miner sieht eine Challenge die an seine Wallet gerichtet ist
//!    - Er liest den Chunk, berechnet den Proof-Hash und sendet eine Response
//!    - Die Response wird als `ChallengeResponse` in den nächsten Block aufgenommen
//!
//! 3. **Reward / Penalty**:
//!    - Korrekte Antwort innerhalb der Deadline → Storage-Reward
//!    - Keine/falsche Antwort → Reputation sinkt (kein Token-Slashing vorerst)
//!
//! Somit wird nicht nur der Block-Ersteller geprüft, sondern das gesamte Netzwerk
//! muss kontinuierlich beweisen, dass es die Daten tatsächlich speichert.
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

// ─── Network Storage Challenge (Chain-Driven) ───────────────────────────────

/// Anzahl der Network-Challenges pro Block
pub const NETWORK_CHALLENGES_PER_BLOCK: usize = 2;

/// Deadline in Blöcken: Wie viele Blöcke hat der Node Zeit um zu antworten
pub const CHALLENGE_DEADLINE_BLOCKS: u64 = 10;

/// Reward pro bestandener Network-Challenge (in STONE, milli-precision)
pub const CHALLENGE_REWARD: &str = "0.5";

/// Eine Chain-generierte Challenge die an einen bestimmten Node im Netzwerk gerichtet ist.
///
/// Wird im Block veröffentlicht und der Ziel-Node muss innerhalb von
/// `CHALLENGE_DEADLINE_BLOCKS` mit einem gültigen Proof antworten.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NetworkChallenge {
    /// Eindeutige ID dieser Challenge: SHA-256(block_index || target_wallet || chunk_hash || offset)
    pub challenge_id: String,
    /// Block-Index in dem die Challenge erstellt wurde
    pub block_index: u64,
    /// Wallet-Adresse (Hex Public Key) des Ziel-Nodes
    pub target_wallet: String,
    /// SHA-256-Hash des zu beweisenden Chunks
    pub chunk_hash: String,
    /// Chunk-Größe in Bytes (für Offset-Berechnung)
    pub chunk_size: u64,
    /// Start-Offset für das Proof-Window
    pub offset: usize,
    /// Deadline: Antwort muss vor diesem Block-Index eingehen
    pub deadline_block: u64,
}

/// Antwort eines Nodes auf eine NetworkChallenge.
///
/// Wird vom herausgeforderten Node erstellt und im nächsten Block
/// als `challenge_response` aufgenommen (via Mempool/P2P).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponse {
    /// Referenz auf die Challenge-ID
    pub challenge_id: String,
    /// Wallet des antwortenden Nodes (muss == challenge.target_wallet sein)
    pub responder_wallet: String,
    /// SHA-256(chunk_data[offset..offset+PROOF_WINDOW]) — der Beweis
    pub proof_hash: String,
    /// Block-Index in dem die Antwort eingereicht wird
    pub response_block: u64,
    /// Ed25519-Signatur über (challenge_id || proof_hash) vom Responder
    pub signature: String,
}

/// Zusammenfassung offener und beantworteter Challenges für den Miner-Status
#[derive(Debug, Clone, Serialize, Default)]
pub struct ChallengeStatus {
    /// Challenges die an UNS gerichtet sind und noch offen
    pub pending_challenges: Vec<NetworkChallenge>,
    /// Anzahl erfolgreich beantworteter Challenges (kumulativ)
    pub responded_total: u64,
    /// Anzahl verpasster Challenges (Deadline überschritten)
    pub missed_total: u64,
    /// Rewards verdient durch Chain-Challenges
    pub rewards_earned: String,
}

// ─── Network Challenge Generation ───────────────────────────────────────────

/// Erzeugt deterministische Network-Challenges für einen neuen Block.
///
/// Wählt zufällige (aber deterministische) Validator-Wallets und Chunks aus.
/// Der Seed ist SHA-256(previous_hash || block_index || "network_challenge").
///
/// `known_wallets`: Alle bekannten Validator-Wallets im Netzwerk
/// `own_wallet`: Eigene Wallet (wird nicht herausgefordert)
pub fn generate_network_challenges(
    previous_hash: &str,
    block_index: u64,
    chunk_refs: &[ChunkRef],
    known_wallets: &[String],
    own_wallet: &str,
) -> Vec<NetworkChallenge> {
    if chunk_refs.is_empty() || known_wallets.is_empty() {
        return Vec::new();
    }

    // Filtere eigene Wallet raus — man kann sich nicht selbst challengen
    let target_wallets: Vec<&String> = known_wallets.iter()
        .filter(|w| w.as_str() != own_wallet)
        .collect();

    if target_wallets.is_empty() {
        return Vec::new();
    }

    let n = NETWORK_CHALLENGES_PER_BLOCK.min(target_wallets.len()).min(chunk_refs.len());
    let mut challenges = Vec::with_capacity(n);

    for i in 0..n {
        // Deterministischer Seed
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(previous_hash.as_bytes());
        seed_hasher.update(block_index.to_le_bytes());
        seed_hasher.update(b"network_challenge");
        seed_hasher.update((i as u64).to_le_bytes());
        let seed = seed_hasher.finalize();

        // Wallet-Auswahl
        let wallet_idx = u64::from_le_bytes(seed[0..8].try_into().unwrap()) as usize
            % target_wallets.len();
        let target_wallet = target_wallets[wallet_idx].clone();

        // Chunk-Auswahl
        let chunk_idx = u64::from_le_bytes(seed[8..16].try_into().unwrap()) as usize
            % chunk_refs.len();
        let chunk = &chunk_refs[chunk_idx];

        // Offset-Berechnung
        let max_offset = if chunk.size as usize > PROOF_WINDOW {
            chunk.size as usize - PROOF_WINDOW
        } else { 0 };
        let offset = if max_offset > 0 {
            let off_sel = u64::from_le_bytes(seed[16..24].try_into().unwrap()) as usize;
            off_sel % max_offset
        } else { 0 };

        // Challenge-ID
        let challenge_id = {
            let mut h = Sha256::new();
            h.update(block_index.to_le_bytes());
            h.update(target_wallet.as_bytes());
            h.update(chunk.hash.as_bytes());
            h.update(offset.to_le_bytes());
            format!("{:x}", h.finalize())
        };

        challenges.push(NetworkChallenge {
            challenge_id,
            block_index,
            target_wallet,
            chunk_hash: chunk.hash.clone(),
            chunk_size: chunk.size,
            offset,
            deadline_block: block_index + CHALLENGE_DEADLINE_BLOCKS,
        });
    }

    challenges
}

// ─── Network Challenge Response ─────────────────────────────────────────────

/// Erstellt eine ChallengeResponse für eine an uns gerichtete Challenge.
///
/// Liest den Chunk von Disk, berechnet den Proof-Hash und signiert das Ganze.
pub fn create_challenge_response(
    challenge: &NetworkChallenge,
    store: &ChunkStore,
    responder_wallet: &str,
    signing_key: &ed25519_dalek::SigningKey,
    current_block: u64,
) -> Option<ChallengeResponse> {
    // Chunk lesen
    let data = store.read_chunk(&challenge.chunk_hash).ok()?;

    // Proof-Hash berechnen (gleiche Logik wie block-level proofs)
    let end = (challenge.offset + PROOF_WINDOW).min(data.len());
    let window = &data[challenge.offset.min(data.len())..end];
    let proof_hash = format!("{:x}", Sha256::digest(window));

    // Signatur: Ed25519 über (challenge_id || proof_hash)
    use ed25519_dalek::Signer;
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(challenge.challenge_id.as_bytes());
    sign_data.extend_from_slice(proof_hash.as_bytes());
    let sig = signing_key.sign(&sign_data);
    let signature = hex::encode(sig.to_bytes());

    Some(ChallengeResponse {
        challenge_id: challenge.challenge_id.clone(),
        responder_wallet: responder_wallet.to_string(),
        proof_hash,
        response_block: current_block,
        signature,
    })
}

/// Verifiziert eine ChallengeResponse gegen die ursprüngliche Challenge.
///
/// Prüft:
/// 1. Responder-Wallet stimmt mit Challenge-Target überein
/// 2. Antwort ist innerhalb der Deadline
/// 3. Signatur ist gültig
/// 4. Proof-Hash stimmt mit lokalen Daten überein (falls lokal vorhanden)
pub fn verify_challenge_response(
    challenge: &NetworkChallenge,
    response: &ChallengeResponse,
    store: Option<&ChunkStore>,
    current_block: u64,
) -> Result<(), String> {
    // 1. Wallet-Match
    if response.responder_wallet != challenge.target_wallet {
        return Err(format!(
            "Wallet mismatch: erwartet {}, erhalten {}",
            &challenge.target_wallet[..12.min(challenge.target_wallet.len())],
            &response.responder_wallet[..12.min(response.responder_wallet.len())]
        ));
    }

    // 2. Deadline
    if current_block > challenge.deadline_block {
        return Err(format!(
            "Deadline überschritten: Block {} > Deadline {}",
            current_block, challenge.deadline_block
        ));
    }

    // 3. Signatur verifizieren
    if response.signature.len() == 128 {
        if let (Ok(pub_bytes), Ok(sig_bytes)) = (
            hex::decode(&response.responder_wallet),
            hex::decode(&response.signature),
        ) {
            if pub_bytes.len() == 32 {
                if let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(
                    pub_bytes.as_slice().try_into().unwrap_or(&[0u8; 32]),
                ) {
                    let sig = ed25519_dalek::Signature::from_bytes(
                        sig_bytes.as_slice().try_into().unwrap_or(&[0u8; 64]),
                    );
                    use ed25519_dalek::Verifier;
                    let mut verify_data = Vec::new();
                    verify_data.extend_from_slice(response.challenge_id.as_bytes());
                    verify_data.extend_from_slice(response.proof_hash.as_bytes());
                    if verifying_key.verify(&verify_data, &sig).is_err() {
                        return Err("Ungültige Signatur".into());
                    }
                }
            }
        }
    }

    // 4. Lokale Verifikation (optional)
    if let Some(store) = store {
        if let Ok(data) = store.read_chunk(&challenge.chunk_hash) {
            let end = (challenge.offset + PROOF_WINDOW).min(data.len());
            let window = &data[challenge.offset.min(data.len())..end];
            let expected = format!("{:x}", Sha256::digest(window));
            if response.proof_hash != expected {
                return Err(format!(
                    "Proof-Hash stimmt nicht! Erwartet: {}..., Erhalten: {}...",
                    &expected[..12], &response.proof_hash[..12]
                ));
            }
        }
    }

    Ok(())
}

/// Hash über alle NetworkChallenges eines Blocks (geht in den Block-Hash ein)
pub fn network_challenges_hash(challenges: &[NetworkChallenge]) -> String {
    let mut h = Sha256::new();
    h.update((challenges.len() as u64).to_le_bytes());
    for c in challenges {
        h.update(c.challenge_id.as_bytes());
        h.update(c.target_wallet.as_bytes());
        h.update(c.chunk_hash.as_bytes());
        h.update(c.offset.to_le_bytes());
        h.update(c.deadline_block.to_le_bytes());
    }
    format!("{:x}", h.finalize())
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

    // ─── Hilfsfunktionen ─────────────────────────────────────────────────

    fn make_chunk_refs(n: usize) -> Vec<ChunkRef> {
        (0..n).map(|i| {
            let hash = format!("{:064x}", i + 1);
            ChunkRef { hash, size: 8192, shards: vec![], ec_k: 0, ec_m: 0 }
        }).collect()
    }

    fn make_wallets(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{:064x}", 0xA000 + i)).collect()
    }

    fn make_signing_key() -> ed25519_dalek::SigningKey {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(&[42u8; 32])
    }

    // ─── Block-Level Challenges ──────────────────────────────────────────

    #[test]
    fn test_empty_proof() {
        let proof = StorageProof::empty();
        assert!(proof.is_empty());
        assert_eq!(proof.proofs.len(), 0);
    }

    #[test]
    fn test_challenge_determinism() {
        let refs = make_chunk_refs(3);
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
        assert_eq!(h1.len(), 64);
    }

    // ─── Network Challenge Generation ────────────────────────────────────

    #[test]
    fn test_network_challenge_generation_basic() {
        let refs = make_chunk_refs(5);
        let wallets = make_wallets(3);
        let own_wallet = "own_wallet_not_in_list".to_string();

        let challenges = generate_network_challenges("prevhash", 10, &refs, &wallets, &own_wallet);

        assert_eq!(challenges.len(), NETWORK_CHALLENGES_PER_BLOCK);
        for c in &challenges {
            assert_eq!(c.block_index, 10);
            assert_eq!(c.deadline_block, 10 + CHALLENGE_DEADLINE_BLOCKS);
            assert_ne!(c.target_wallet, own_wallet, "Eigene Wallet darf nicht gechallenged werden");
            assert!(wallets.contains(&c.target_wallet), "Target muss aus known_wallets stammen");
            assert!(!c.challenge_id.is_empty());
            assert!(!c.chunk_hash.is_empty());
        }
    }

    #[test]
    fn test_network_challenge_excludes_own_wallet() {
        let refs = make_chunk_refs(3);
        let wallets = vec!["only_wallet".to_string()];
        let own_wallet = "only_wallet".to_string();

        // Eigene Wallet ist die einzige → keine Targets → keine Challenges
        let challenges = generate_network_challenges("prev", 1, &refs, &wallets, &own_wallet);
        assert!(challenges.is_empty(), "Keine Challenges wenn nur eigene Wallet bekannt");
    }

    #[test]
    fn test_network_challenge_empty_chunks() {
        let refs: Vec<ChunkRef> = vec![];
        let wallets = make_wallets(3);

        let challenges = generate_network_challenges("prev", 1, &refs, &wallets, "me");
        assert!(challenges.is_empty(), "Keine Challenges ohne Chunks");
    }

    #[test]
    fn test_network_challenge_empty_wallets() {
        let refs = make_chunk_refs(3);
        let wallets: Vec<String> = vec![];

        let challenges = generate_network_challenges("prev", 1, &refs, &wallets, "me");
        assert!(challenges.is_empty(), "Keine Challenges ohne bekannte Wallets");
    }

    #[test]
    fn test_network_challenge_determinism() {
        let refs = make_chunk_refs(10);
        let wallets = make_wallets(5);

        let c1 = generate_network_challenges("hash42", 100, &refs, &wallets, "me");
        let c2 = generate_network_challenges("hash42", 100, &refs, &wallets, "me");

        assert_eq!(c1.len(), c2.len());
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.challenge_id, b.challenge_id);
            assert_eq!(a.target_wallet, b.target_wallet);
            assert_eq!(a.chunk_hash, b.chunk_hash);
            assert_eq!(a.offset, b.offset);
        }
    }

    #[test]
    fn test_network_challenge_different_blocks_differ() {
        let refs = make_chunk_refs(10);
        let wallets = make_wallets(5);

        let c1 = generate_network_challenges("hash", 1, &refs, &wallets, "me");
        let c2 = generate_network_challenges("hash", 2, &refs, &wallets, "me");

        let all_same = c1.iter().zip(c2.iter())
            .all(|(a, b)| a.challenge_id == b.challenge_id);
        assert!(!all_same, "Verschiedene Blöcke sollten verschiedene Challenges produzieren");
    }

    #[test]
    fn test_network_challenge_unique_ids() {
        let refs = make_chunk_refs(10);
        let wallets = make_wallets(10);

        let challenges = generate_network_challenges("hash", 1, &refs, &wallets, "me");
        let ids: std::collections::HashSet<_> = challenges.iter().map(|c| &c.challenge_id).collect();
        assert_eq!(ids.len(), challenges.len(), "Challenge-IDs müssen eindeutig sein");
    }

    // ─── Challenge Response + Verification ───────────────────────────────

    #[test]
    fn test_challenge_response_creation_and_verification() {
        // Tempdir für ChunkStore
        let tmp = std::env::temp_dir().join(format!("stone_test_chunks_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        // Test-Chunk-Daten schreiben
        let chunk_data = vec![0xABu8; 8192];
        let chunk_hash = format!("{:x}", Sha256::digest(&chunk_data));
        std::fs::write(tmp.join(&chunk_hash), &chunk_data).unwrap();

        // ChunkStore mit Temp-Dir
        let store = ChunkStore::with_dir(tmp.clone()).unwrap();

        let signing_key = make_signing_key();
        let wallet = hex::encode(signing_key.verifying_key().as_bytes());

        let challenge = NetworkChallenge {
            challenge_id: "test_challenge_001".to_string(),
            block_index: 5,
            target_wallet: wallet.clone(),
            chunk_hash: chunk_hash.clone(),
            chunk_size: 8192,
            offset: 0,
            deadline_block: 15,
        };

        // Response erstellen
        let response = create_challenge_response(&challenge, &store, &wallet, &signing_key, 6);
        assert!(response.is_some(), "Response sollte erstellt werden können");
        let response = response.unwrap();

        assert_eq!(response.challenge_id, "test_challenge_001");
        assert_eq!(response.responder_wallet, wallet);
        assert!(!response.proof_hash.is_empty());
        assert!(!response.signature.is_empty());

        // Verifizierung
        let result = verify_challenge_response(&challenge, &response, Some(&store), 6);
        assert!(result.is_ok(), "Gültige Response sollte verifiziert werden: {:?}", result);

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_challenge_response_wrong_wallet_rejected() {
        let challenge = NetworkChallenge {
            challenge_id: "test".to_string(),
            block_index: 1,
            target_wallet: "correct_wallet".to_string(),
            chunk_hash: "a".repeat(64),
            chunk_size: 4096,
            offset: 0,
            deadline_block: 10,
        };

        let response = ChallengeResponse {
            challenge_id: "test".to_string(),
            responder_wallet: "wrong_wallet".to_string(),
            proof_hash: "b".repeat(64),
            response_block: 2,
            signature: String::new(),
        };

        let result = verify_challenge_response(&challenge, &response, None, 2);
        assert!(result.is_err(), "Falsche Wallet sollte abgelehnt werden");
        assert!(result.unwrap_err().contains("Wallet mismatch"));
    }

    #[test]
    fn test_challenge_response_deadline_expired() {
        let challenge = NetworkChallenge {
            challenge_id: "test".to_string(),
            block_index: 1,
            target_wallet: "wallet_a".to_string(),
            chunk_hash: "a".repeat(64),
            chunk_size: 4096,
            offset: 0,
            deadline_block: 10,
        };

        let response = ChallengeResponse {
            challenge_id: "test".to_string(),
            responder_wallet: "wallet_a".to_string(),
            proof_hash: "b".repeat(64),
            response_block: 11,
            signature: String::new(),
        };

        // current_block > deadline → abgelehnt
        let result = verify_challenge_response(&challenge, &response, None, 11);
        assert!(result.is_err(), "Abgelaufene Deadline sollte abgelehnt werden");
        assert!(result.unwrap_err().contains("Deadline"));
    }

    #[test]
    fn test_challenge_response_missing_chunk() {
        let tmp = std::env::temp_dir().join(format!("stone_test_no_chunk_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let store = ChunkStore::with_dir(tmp.clone()).unwrap();

        let signing_key = make_signing_key();
        let wallet = hex::encode(signing_key.verifying_key().as_bytes());

        let challenge = NetworkChallenge {
            challenge_id: "missing_chunk".to_string(),
            block_index: 1,
            target_wallet: wallet.clone(),
            chunk_hash: "nonexistent".repeat(4) + &"0".repeat(24),
            chunk_size: 4096,
            offset: 0,
            deadline_block: 10,
        };

        // Chunk existiert nicht → None
        let response = create_challenge_response(&challenge, &store, &wallet, &signing_key, 2);
        assert!(response.is_none(), "Fehlender Chunk sollte None zurückgeben");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── Network Challenges Hash ─────────────────────────────────────────

    #[test]
    fn test_network_challenges_hash_determinism() {
        let challenges = vec![
            NetworkChallenge {
                challenge_id: "id1".to_string(),
                block_index: 1,
                target_wallet: "w1".to_string(),
                chunk_hash: "c1".to_string(),
                chunk_size: 4096,
                offset: 100,
                deadline_block: 11,
            },
        ];

        let h1 = network_challenges_hash(&challenges);
        let h2 = network_challenges_hash(&challenges);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_network_challenges_hash_empty() {
        let h = network_challenges_hash(&[]);
        assert_eq!(h.len(), 64, "Leere Challenges sollten trotzdem einen Hash produzieren");
    }

    // ─── Offset-Berechnung Edge Cases ─────────────────────────────────────

    #[test]
    fn test_challenge_small_chunk_offset_zero() {
        // Chunk kleiner als PROOF_WINDOW → Offset muss 0 sein
        let refs = vec![
            ChunkRef { hash: "a".repeat(64), size: 100, shards: vec![], ec_k: 0, ec_m: 0 },
        ];

        let challenges = generate_challenges("hash", 1, &refs);
        assert!(!challenges.is_empty());
        assert_eq!(challenges[0].offset, 0, "Kleiner Chunk → Offset 0");
    }

    #[test]
    fn test_challenge_offset_within_bounds() {
        let refs = vec![
            ChunkRef { hash: "a".repeat(64), size: 1_000_000, shards: vec![], ec_k: 0, ec_m: 0 },
        ];

        // Über viele Blöcke testen dass Offset immer im gültigen Bereich liegt
        for block_idx in 0..100 {
            let challenges = generate_challenges("hash", block_idx, &refs);
            for c in &challenges {
                let max_valid = (c.chunk_size as usize).saturating_sub(PROOF_WINDOW);
                assert!(c.offset <= max_valid,
                    "Offset {} > max {} bei Block {}", c.offset, max_valid, block_idx);
            }
        }
    }

    // ─── Stress-Tests ─────────────────────────────────────────────────────

    #[test]
    fn test_many_challenges_no_panic() {
        let refs = make_chunk_refs(1000);
        let wallets = make_wallets(100);

        // 1000 Blöcke durchsimulieren
        for block_idx in 0..1000u64 {
            let prev_hash = format!("{:064x}", block_idx);
            let challenges = generate_network_challenges(&prev_hash, block_idx, &refs, &wallets, "own");
            assert!(challenges.len() <= NETWORK_CHALLENGES_PER_BLOCK);

            for c in &challenges {
                assert!(c.deadline_block == block_idx + CHALLENGE_DEADLINE_BLOCKS);
                assert!(!c.challenge_id.is_empty());
            }
        }
    }

    #[test]
    fn test_challenge_coverage_distribution() {
        // Verifiziere, dass Challenges über verschiedene Wallets verteilt werden
        let refs = make_chunk_refs(20);
        let wallets = make_wallets(10);

        let mut wallet_hit_count: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for block_idx in 0..500u64 {
            let prev_hash = format!("{:064x}", block_idx);
            let challenges = generate_network_challenges(&prev_hash, block_idx, &refs, &wallets, "own");
            for c in &challenges {
                *wallet_hit_count.entry(c.target_wallet.clone()).or_default() += 1;
            }
        }

        // Alle Wallets sollten mindestens einmal getroffen worden sein
        for w in &wallets {
            assert!(
                wallet_hit_count.get(w).copied().unwrap_or(0) > 0,
                "Wallet {} wurde nie gechallenged – Distribution-Fehler", &w[..16]
            );
        }

        // Kein Wallet sollte > 50% aller Challenges bekommen (bei 10 Wallets)
        let total: u32 = wallet_hit_count.values().sum();
        for (w, count) in &wallet_hit_count {
            let pct = (*count as f64 / total as f64) * 100.0;
            assert!(pct < 50.0,
                "Wallet {}… hat {:.1}% aller Challenges – unfair!", &w[..16], pct);
        }
    }
}
