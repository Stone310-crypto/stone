use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::token::transaction::{TokenTx, TxType, FeeTier, compute_tx_id};

type HmacSha256 = Hmac<Sha256>;

// ─── bincode-kompatibles serde_json::Value Wrapper ───────────────────────────
//
// bincode v2 unterstützt kein serde_json::Value direkt (AnyNotSupported-Fehler).
// Lösung: Value wird als JSON-String in RocksDB gespeichert und beim Lesen
// wieder deserialisiert. Für alle anderen Formate (JSON API) ist es transparent.

#[derive(Debug, Clone, Default)]
pub struct JsonValue(pub serde_json::Value);

impl Serialize for JsonValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            // JSON-API: Value direkt serialisieren
            self.0.serialize(s)
        } else {
            // bincode: als JSON-String serialisieren
            let json_str = serde_json::to_string(&self.0)
                .map_err(serde::ser::Error::custom)?;
            s.serialize_str(&json_str)
        }
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            // JSON-API: Value direkt deserialisieren
            Ok(JsonValue(serde_json::Value::deserialize(d)?))
        } else {
            // bincode: JSON-String → Value parsen
            let s = String::deserialize(d)?;
            let val = serde_json::from_str(&s)
                .unwrap_or(serde_json::Value::Null);
            Ok(JsonValue(val))
        }
    }
}

/// Datenverzeichnis – überschreibbar per `STONE_DATA_DIR` env var.
/// Verwendet von: token, RocksDB, chunks, users, peers.
pub fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string())
}

pub const MAX_BLOCK_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB
pub fn chunk_dir() -> String { format!("{}/chunks", data_dir()) }
pub const CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

// ─── Block-Hashing ───────────────────────────────────────────────────────────
//
// Jeder Block enthält:
//   index          – Position in der Chain (0 = Genesis)
//   timestamp      – Unix-Sekunden (i64)
//   previous_hash  – SHA-256-Hash des Vorgänger-Blocks (64 Hex-Zeichen)
//   merkle_root    – SHA-256 über alle Dokument- und Tombstone-Hashes (Merkle-ähnlich)
//   data_size      – Gesamtgröße der Dokument-Bytes in diesem Block
//   hash           – SHA-256 über (index || timestamp || previous_hash || merkle_root || data_size)
//   signer         – Node-ID des Erstellers
//   signature      – HMAC-SHA-256(cluster_key, hash)
//   node_role      – Master / Replica
//   documents      – Liste der Dokumente in diesem Block
//   tombstones     – Soft-Delete-Einträge
//
// Die Hash-Eingabe ist binär kodiert (Little-Endian für Zahlen), nie als
// String-Konkatenation, um Kollisionen wie (1,"23") == (12,"3") zu vermeiden.

// ─── Dokument-Modell ─────────────────────────────────────────────────────────

/// Ein Dokument ist eine atomare, versionierte Dateneinheit.
/// Kein Ordner-Konzept – Kategorisierung erfolgt über tags + metadata.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Document {
    pub doc_id: String,
    pub title: String,
    pub content_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: JsonValue,
    #[serde(default = "default_version")]
    pub version: u32,
    pub size: u64,
    #[serde(default)]
    pub chunks: Vec<ChunkRef>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub owner: String,

    // ─── Kryptographie-Felder ────────────────────────────────────────────────

    /// Ed25519-Signatur über (doc_id | version | size | content_type).
    /// 128 Hex-Zeichen (64 Byte). Leer = nicht signiert.
    #[serde(default)]
    pub doc_signature: String,

    /// Erste 16 Hex-Zeichen des signierende Public Keys – zur schnellen Zuordnung.
    /// Leer = nicht signiert.
    #[serde(default)]
    pub public_key_hint: String,

    /// Gibt an ob die Chunks AES-256-GCM verschlüsselt sind.
    /// Falls true, enthält `encryption_blob` die nötigen Entschlüsselungsmetadaten.
    #[serde(default)]
    pub encrypted: bool,

    /// JSON-serialisierter `EncryptedBlob` (ephemeral_pubkey, nonce, ciphertext leer –
    /// nur Metadaten; der eigentliche Ciphertext ist in den Chunks gespeichert).
    /// Leer = nicht verschlüsselt.
    #[serde(default)]
    pub encryption_meta: String,
}

fn default_version() -> u32 { 1 }

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ChunkRef {
    pub hash: String,
    pub size: u64,
    /// Erasure-coded Shard-Verteilung (leer = Legacy Full-Replication)
    #[serde(default)]
    pub shards: Vec<ShardRef>,
    /// Daten-Shards für Reed-Solomon (z.B. 4)
    #[serde(default)]
    pub ec_k: u8,
    /// Paritäts-Shards für Reed-Solomon (z.B. 2)
    #[serde(default)]
    pub ec_m: u8,
}

/// Ein Shard ist ein Fragment eines erasure-coded Chunks.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ShardRef {
    /// Original-Chunk-Hash (für Zuordnung)
    pub chunk_hash: String,
    /// Shard-Index: 0..k-1 = Daten, k..k+m-1 = Parität
    pub shard_index: u8,
    /// SHA-256 des Shard-Inhalts
    pub shard_hash: String,
    /// Größe des Shards in Bytes
    pub shard_size: u64,
    /// PeerId des Nodes der diesen Shard hält
    pub holder: String,
}

/// Soft-Delete: markiert ein Dokument als gelöscht
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DocumentTombstone {
    pub block_index: u64,
    pub doc_id: String,
    #[serde(default)]
    pub owner: String,
}

// ─── Node-Rolle ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub enum NodeRole {
    #[default]
    Master,
    Replica,
}

// ─── Block ───────────────────────────────────────────────────────────────────

/// Ein Block ist die atomare Einheit der Stone-Chain.
///
/// Hash-Input (binär, deterministisch):
///   SHA-256(
///     index.to_le_bytes()       [8 Byte]
///     timestamp.to_le_bytes()   [8 Byte]
///     previous_hash.as_bytes()  [64 Byte, Hex-ASCII]
///     merkle_root.as_bytes()    [64 Byte, Hex-ASCII]
///     data_size.to_le_bytes()   [8 Byte]
///     signer.as_bytes()         [variabel]
///   )
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    /// Position in der Chain (0 = Genesis)
    pub index: u64,
    /// Unix-Timestamp in Sekunden
    pub timestamp: i64,
    /// Merkle-ähnlicher Root-Hash über alle Dokument- und Tombstone-Hashes
    pub merkle_root: String,
    /// Gesamtgröße der Nutzdaten in Bytes
    pub data_size: u64,
    /// SHA-256 des Vorgänger-Blocks (64 Hex-Zeichen; "000...0" beim Genesis)
    pub previous_hash: String,
    /// SHA-256 dieses Blocks (über die o.g. Felder)
    pub hash: String,
    /// Node-ID des Signierers
    #[serde(default)]
    pub signer: String,
    /// HMAC-SHA-256(cluster_key, hash) – Cluster-Authentizität
    #[serde(default)]
    pub signature: String,
    /// Besitzer / Ersteller dieses Blocks
    #[serde(default)]
    pub owner: String,
    /// Dokumente in diesem Block
    #[serde(default)]
    pub documents: Vec<Document>,
    /// Soft-Delete-Einträge
    #[serde(default)]
    pub tombstones: Vec<DocumentTombstone>,
    /// Token-Transaktionen in diesem Block
    #[serde(default)]
    pub transactions: Vec<TokenTx>,
    /// Rolle der Node die diesen Block erstellt hat
    #[serde(default)]
    pub node_role: NodeRole,
    /// Konsensus-Runden-ID (0 = kein Konsensus nötig)
    #[serde(default)]
    pub proposal_round: u64,
    // ─── PoA-Felder ──────────────────────────────────────────────────────────
    /// Ed25519-Public-Key des Validators der diesen Block signiert hat (64 Hex-Zeichen)
    /// Leer = Block wurde vor PoA-Aktivierung erstellt (rückwärtskompatibel)
    #[serde(default)]
    pub validator_pub_key: String,
    /// Ed25519-Signatur über `block.hash` (128 Hex-Zeichen, 64 Byte)
    /// Gehört NICHT zum Hash-Input (calculate_hash), damit Signaturen ohne Re-Hash möglich sind
    #[serde(default)]
    pub validator_signature: String,

    // ─── Proof of Storage ────────────────────────────────────────────────
    /// Storage-Proof: Beweis, dass der Miner echte Daten speichert.
    /// Geht in den Block-Hash ein und wird bei accept_peer_block verifiziert.
    #[serde(default)]
    pub storage_proof: crate::storage_proof::StorageProof,

    // ─── Network Storage Challenges (Chain-Driven) ──────────────────────
    /// Vom Block-Ersteller generierte Challenges an andere Nodes im Netzwerk
    #[serde(default)]
    pub storage_challenges: Vec<crate::storage_proof::NetworkChallenge>,

    /// Antworten auf frühere Challenges (durch herausgeforderte Nodes eingereicht)
    #[serde(default)]
    pub challenge_responses: Vec<crate::storage_proof::ChallengeResponse>,
}

// ─── Chain ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct StoneChain {
    pub blocks: Vec<Block>,
    pub latest_hash: String,
}

impl StoneChain {
    /// Lädt die Chain aus RocksDB oder erstellt eine neue mit Genesis-Block.
    pub fn load_or_create(cluster_key: &str) -> Self {
        use crate::storage::ChainStore;

        std::fs::create_dir_all(data_dir()).unwrap_or(());
        std::fs::create_dir_all(chunk_dir()).unwrap_or(());

        // Erwarteter Genesis-Hash für diesen cluster_key (deterministisch)
        let expected_genesis = genesis_block(cluster_key);

        match ChainStore::open() {
            Ok(store) if !store.is_empty() => {
                match store.read_all_blocks() {
                    Ok(blocks) if !blocks.is_empty() => {
                        let stored_genesis_hash = blocks[0].hash.clone();

                        // Genesis-Hash Validierung: stimmt die DB mit dem aktuellen
                        // cluster_key überein?
                        if stored_genesis_hash != expected_genesis.hash {
                            eprintln!(
                                "[chain] ⚠️  Genesis-Mismatch in lokaler DB! \
                                 Gespeichert: {}... | Erwartet: {}...",
                                &stored_genesis_hash[..8],
                                &expected_genesis.hash[..8]
                            );
                            eprintln!(
                                "[chain] DB stammt von einem anderen Cluster-Key. \
                                 Starte mit frischer Chain."
                            );
                            // DB zurücksetzen und neue Chain anlegen
                            drop(store);
                            let db_path = format!("{}/chain_db", data_dir());
                            if let Err(e) = std::fs::remove_dir_all(&db_path) {
                                eprintln!("[chain] DB-Reset fehlgeschlagen: {e}");
                            }
                        } else {
                            let latest_hash = blocks.last().map(|b| b.hash.clone()).unwrap_or_default();
                            println!(
                                "[chain] RocksDB geladen: {} Blöcke, Latest: {}...",
                                blocks.len(),
                                &latest_hash[..8]
                            );
                            return StoneChain { blocks, latest_hash };
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        // Leere oder neue Datenbank → Genesis-Block erstellen
        let genesis = expected_genesis;
        let chain = StoneChain {
            blocks: vec![genesis.clone()],
            latest_hash: genesis.hash.clone(),
        };
        chain.persist_last_block();
        println!("[chain] Neue Stone-Chain erstellt – Genesis Block: {}...", &genesis.hash[..8]);
        chain
    }

    /// Persistiert den letzten Block in RocksDB (mit WAL-Sync).
    ///
    /// Wird nach `add_documents()` automatisch aufgerufen.
    pub fn persist_last_block(&self) {
        use crate::storage::ChainStore;
        if let Some(block) = self.blocks.last() {
            match ChainStore::open() {
                Ok(store) => {
                    if let Err(e) = store.write_block_sync(block) {
                        eprintln!("[chain] RocksDB-Schreibfehler: {e}");
                    }
                }
                Err(e) => eprintln!("[chain] RocksDB konnte nicht geöffnet werden: {e}"),
            }
        }
    }

    /// Persistiert alle Blöcke in RocksDB (für Migration / Rebuild).
    pub fn persist_all(&self) {
        use crate::storage::ChainStore;
        match ChainStore::open() {
            Ok(store) => {
                for block in &self.blocks {
                    if let Err(e) = store.write_block_sync(block) {
                        eprintln!("[chain] Fehler beim Schreiben von Block #{}: {e}", block.index);
                    }
                }
            }
            Err(e) => eprintln!("[chain] RocksDB konnte nicht geöffnet werden: {e}"),
        }
    }

    /// Kürzt die Chain auf `target_len` Blöcke (für Fork-Reorg).
    /// Entfernt alle Blöcke ab Index `target_len` und aktualisiert latest_hash.
    /// Die entfernten Blöcke werden auch aus RocksDB gelöscht.
    pub fn truncate_to(&mut self, target_len: u64) {
        let target = target_len as usize;
        if target >= self.blocks.len() {
            return; // Nichts zu tun
        }
        let removed = self.blocks.len() - target;
        self.blocks.truncate(target);
        self.latest_hash = self.blocks.last().map(|b| b.hash.clone()).unwrap_or_default();
        println!(
            "[chain] 🔄 Chain auf {} Blöcke gekürzt ({} entfernt), latest_hash={}...",
            target,
            removed,
            &self.latest_hash[..8.min(self.latest_hash.len())],
        );
        // RocksDB: entfernte Blöcke löschen
        use crate::storage::ChainStore;
        if let Ok(store) = ChainStore::open() {
            for idx in target..target + removed {
                if let Err(e) = store.delete_block(idx as u64) {
                    eprintln!("[chain] ⚠ Block {idx} löschen fehlgeschlagen: {e}");
                }
            }
        }
    }

    /// Neuen Block mit Dokumenten und Token-Transaktionen hinzufügen
    pub fn add_documents(
        &mut self,
        documents: Vec<Document>,
        tombstones: Vec<DocumentTombstone>,
        transactions: Vec<TokenTx>,
        owner: String,
        signer: String,
        cluster_key: &str,
        node_role: NodeRole,
    ) -> Block {
        let block = self.prepare_block(documents, tombstones, transactions, owner, signer, cluster_key, node_role);
        self.commit_block(block.clone());
        block
    }

    /// Erstellt einen neuen Block **ohne** ihn in die Chain zu schreiben.
    ///
    /// Der Block ist vollständig (Hash, Signatur) und kann an Peers zur Abstimmung
    /// gesendet werden. Erst `commit_block()` fügt ihn tatsächlich ein.
    pub fn prepare_block(
        &self,
        documents: Vec<Document>,
        tombstones: Vec<DocumentTombstone>,
        transactions: Vec<TokenTx>,
        owner: String,
        signer: String,
        cluster_key: &str,
        node_role: NodeRole,
    ) -> Block {
        // Memorial TX wird nur im Genesis-Block gespeichert – nicht in
        // jedem Block wiederholt (spart Platz, vermeidet doppelte TX-IDs).
        let transactions = transactions;

        let manifest = serde_json::to_vec(&documents).unwrap_or_default();
        let merkle_root = compute_merkle_root(&documents, &tombstones, &transactions);

        // ── Proof of Storage: Challenge lösen ─────────────────────────
        let next_index = self.blocks.len() as u64;
        let storage_proof = crate::storage_proof::create_storage_proof(
            self,
            next_index,
            &self.latest_hash,
        );
        if !storage_proof.is_empty() {
            println!(
                "[storage-proof] ⛏️  Block #{}: {} Chunks geprüft, {} Bytes auditiert",
                next_index, storage_proof.proofs.len(), storage_proof.audited_bytes
            );
        }

        let new_block = Block {
            index: next_index,
            timestamp: Utc::now().timestamp(),
            merkle_root,
            data_size: manifest.len() as u64,
            previous_hash: self.latest_hash.clone(),
            hash: String::new(),
            signer,
            signature: String::new(),
            owner,
            documents,
            tombstones,
            transactions,
            node_role,
            proposal_round: 0,
            validator_pub_key: String::new(),
            validator_signature: String::new(),
            storage_proof,
            storage_challenges: Vec::new(),
            challenge_responses: Vec::new(),
        };

        let hash = calculate_hash(&new_block);
        let final_block = Block {
            hash: hash.clone(),
            signature: sign_hash(cluster_key, &hash),
            ..new_block
        };

        println!(
            "[chain] Block #{} vorbereitet – {} Dok., {} TXs, {} Bytes",
            final_block.index,
            final_block.documents.len(),
            final_block.transactions.len(),
            final_block.data_size,
        );
        final_block
    }

    /// Fügt einen bereits vorbereiteten Block in die lokale Chain ein und persistiert ihn.
    ///
    /// Wird nach erfolgreicher Voting-Phase (oder im Single-Node-Modus) aufgerufen.
    pub fn commit_block(&mut self, block: Block) {
        let hash = block.hash.clone();
        let idx = block.index;
        let docs = block.documents.len();
        let txs = block.transactions.len();
        let bytes = block.data_size;

        self.blocks.push(block);
        self.latest_hash = hash;
        self.persist_last_block();

        println!(
            "[chain] Block #{} committed – {} Dok., {} TXs, {} Bytes",
            idx, docs, txs, bytes,
        );
    }

    /// Nimmt einen von einem Peer empfangenen fertigen Block in die lokale Chain auf.
    /// Prüft Verkettung (previous_hash) und Hash-Integrität. Gibt Err zurück wenn ungültig.
    ///
    /// `poa_ok` – Ergebnis der externen PoA-Signaturprüfung (durch ValidatorSet).
    ///   - `None`  → PoA-Prüfung wird übersprungen (kein Validator-Set geladen)
    ///   - `Some(true)`  → Prüfung bestanden
    ///   - `Some(false)` → Prüfung fehlgeschlagen → Block wird abgelehnt
    pub fn accept_peer_block(
        &mut self,
        block: Block,
        poa_ok: Option<bool>,
    ) -> Result<(), String> {
        let local_len = self.blocks.len() as u64;

        // ── Fork-Reorg: Block liegt hinter unserer Chain ──────────────────
        // Bei kurzen Chains (< 50 Blöcke) Reorg erlauben, falls der Block
        // von einer längeren Peer-Chain stammt.
        if block.index < local_len {
            // Prüfe ob der Block identisch mit unserem ist → Stale (ignorieren)
            if let Some(existing) = self.blocks.get(block.index as usize) {
                if existing.hash == block.hash {
                    return Err(format!(
                        "Stale: Block #{} bereits bekannt (identisch)",
                        block.index
                    ));
                }
                // Block hat gleichen Index aber anderen Hash → Fork!
                if local_len <= 50 {
                    // Prüfe ob der block.previous_hash zu unserem Vorgänger passt
                    let prev_ok = if block.index == 0 {
                        true // Genesis
                    } else {
                        self.blocks.get((block.index - 1) as usize)
                            .map(|b| b.hash == block.previous_hash)
                            .unwrap_or(false)
                    };
                    if prev_ok {
                        println!(
                            "[chain] 🔄 Fork-Reorg bei Block #{}: lokal={}… peer={}… – ersetze lokale Blöcke",
                            block.index,
                            &existing.hash[..8.min(existing.hash.len())],
                            &block.hash[..8.min(block.hash.len())],
                        );
                        self.truncate_to(block.index);
                        // Weiter mit normaler Block-Akzeptanz
                    } else {
                        return Err(format!(
                            "Stale: Block #{} bereits bekannt (Fork, previous_hash passt nicht)",
                            block.index
                        ));
                    }
                } else {
                    return Err(format!(
                        "Stale: Block #{} bereits bekannt (lokale Höhe: {local_len})",
                        block.index
                    ));
                }
            } else {
                return Err(format!(
                    "Stale: Block #{} Index out-of-range (lokale Höhe: {local_len})",
                    block.index
                ));
            }
        }

        // Aktuelle Länge nach potentiellem Reorg neu lesen
        let local_len = self.blocks.len() as u64;

        // Block für einen Index den wir noch nicht haben, aber nicht der nächste →
        // Lücke in der Chain → vollständiger Resync vom Peer nötig
        if block.index != local_len {
            return Err(format!(
                "Gap: erwarte Index {local_len}, empfangen {} – Resync erforderlich",
                block.index
            ));
        }

        if block.previous_hash != self.latest_hash {
            // ── Fork-Erkennung bei kurzer Chain ───────────────────────────
            // Wenn unsere Chain sehr kurz ist (< 50 Blöcke), ist es wahrscheinlich
            // ein lokaler Fork durch Mining vor Peer-Sync. In diesem Fall: Reorg
            // durchführen, also unsere divergierenden Blöcke entfernen und den
            // Peer-Block akzeptieren.
            if local_len <= 50 && block.index > 0 {
                // Suche den gemeinsamen Vorgänger (Fork-Punkt)
                if let Some(prev_block) = self.blocks.iter().find(|b| b.hash == block.previous_hash) {
                    let fork_point = prev_block.index + 1;
                    println!(
                        "[chain] 🔄 Fork-Reorg: Lokale Chain hat {} Blöcke, Fork bei #{} – entferne {} lokale Blöcke",
                        local_len, fork_point, local_len - fork_point
                    );
                    self.truncate_to(fork_point);
                    // Jetzt sollte latest_hash == block.previous_hash sein
                    if block.previous_hash != self.latest_hash {
                        return Err(format!(
                            "previous_hash nach Reorg immer noch falsch: erwartet {}, empfangen {}",
                            &self.latest_hash[..12.min(self.latest_hash.len())],
                            &block.previous_hash[..12.min(block.previous_hash.len())],
                        ));
                    }
                    // Block-Index muss jetzt auch passen
                    let new_len = self.blocks.len() as u64;
                    if block.index != new_len {
                        return Err(format!(
                            "Gap nach Reorg: erwarte Index {new_len}, empfangen {}",
                            block.index
                        ));
                    }
                } else {
                    return Err(format!(
                        "previous_hash passt nicht: erwartet {}, empfangen {} – möglicher Fork (kein gemeinsamer Vorgänger)",
                        &self.latest_hash[..12.min(self.latest_hash.len())],
                        &block.previous_hash[..12.min(block.previous_hash.len())],
                    ));
                }
            } else {
                return Err(format!(
                    "previous_hash passt nicht: erwartet {}, empfangen {} – möglicher Fork",
                    &self.latest_hash[..12.min(self.latest_hash.len())],
                    &block.previous_hash[..12.min(block.previous_hash.len())],
                ));
            }
        }

        // ── Hash-Integrität ───────────────────────────────────────────────
        let expected_hash = calculate_hash(&block);
        if block.hash != expected_hash {
            return Err(format!(
                "Hash ungültig: erwartet {}, empfangen {}",
                &expected_hash[..12.min(expected_hash.len())],
                &block.hash[..12.min(block.hash.len())],
            ));
        }

        // ── Merkle-Root-Verifikation ──────────────────────────────────────
        let expected_merkle = compute_merkle_root(&block.documents, &block.tombstones, &block.transactions);
        if expected_merkle != block.merkle_root {
            return Err(format!(
                "Merkle-Root ungültig: erwartet {}..., empfangen {}...",
                &expected_merkle[..12.min(expected_merkle.len())],
                &block.merkle_root[..12.min(block.merkle_root.len())],
            ));
        }

        // Memorial TX: Ab v0.7.7 nur noch im Genesis-Block.
        // Alte Blöcke die eine Memorial TX enthalten werden weiterhin akzeptiert
        // (die Merkle-Root-Prüfung oben validiert die tatsächlichen TXs im Block).

        // ── Proof of Storage Verifikation ─────────────────────────────────
        // Jeder Block (außer Genesis) muss einen gültigen Storage-Proof enthalten
        if block.index > 0 {
            if let Err(e) = crate::storage_proof::verify_storage_proof(self, &block) {
                return Err(format!("Storage-Proof ungültig: {e}"));
            }
        }

        // ── Timestamp-Plausibilität ───────────────────────────────────────
        if block.index > 0 {
            let now = Utc::now().timestamp();
            // Nicht mehr als 5 Minuten in der Zukunft
            if block.timestamp > now + 300 {
                return Err(format!(
                    "Timestamp zu weit in der Zukunft: {} Sekunden",
                    block.timestamp - now,
                ));
            }
            // Block-Timestamp muss >= Timestamp des vorherigen Blocks sein
            if let Some(prev_block) = self.blocks.last() {
                if block.timestamp < prev_block.timestamp {
                    return Err(format!(
                        "Timestamp-Regression: Block #{} ({}) < Vorgänger ({})",
                        block.index, block.timestamp, prev_block.timestamp,
                    ));
                }
            }
        }

        // ── Signer darf nicht leer sein (außer Genesis) ───────────────────
        if block.signer.is_empty() && block.index > 0 {
            return Err("Block hat keinen Signer".to_string());
        }

        // PoA: externer Signatur-Check
        if poa_ok == Some(false) {
            return Err(format!(
                "PoA-Signaturprüfung fehlgeschlagen für Signer '{}'",
                block.signer
            ));
        }

        self.latest_hash = block.hash.clone();
        self.blocks.push(block);
        self.persist_last_block();
        Ok(())
    }

    /// Aktives Dokument per doc_id finden
    pub fn find_document(&self, doc_id: &str) -> Option<(&Document, u64)> {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        if deleted.contains(doc_id) {
            return None;
        }

        for block in self.blocks.iter().rev() {
            if let Some(doc) = block.documents.iter().find(|d| d.doc_id == doc_id) {
                return Some((doc, block.index));
            }
        }
        None
    }

    /// Alle aktiven Dokumente eines Nutzers (neueste Version je doc_id)
    pub fn list_documents_for_user(&self, user_id: &str) -> Vec<(&Document, u64)> {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        let mut seen: std::collections::HashMap<String, (&Document, u64)> =
            std::collections::HashMap::new();
        for block in &self.blocks {
            for doc in &block.documents {
                if doc.owner == user_id && !deleted.contains(&doc.doc_id) {
                    seen.insert(doc.doc_id.clone(), (doc, block.index));
                }
            }
        }
        seen.into_values().collect()
    }

    /// Alle aktiven Dokumente (admin)
    pub fn list_all_documents(&self) -> Vec<(&Document, u64)> {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        let mut seen: std::collections::HashMap<String, (&Document, u64)> =
            std::collections::HashMap::new();
        for block in &self.blocks {
            for doc in &block.documents {
                if !deleted.contains(&doc.doc_id) {
                    seen.insert(doc.doc_id.clone(), (doc, block.index));
                }
            }
        }
        seen.into_values().collect()
    }

    /// Versionshistorie eines Dokuments
    pub fn document_history(&self, doc_id: &str) -> Vec<(&Document, u64)> {
        self.blocks
            .iter()
            .flat_map(|b| {
                b.documents
                    .iter()
                    .filter(|d| d.doc_id == doc_id)
                    .map(move |d| (d, b.index))
            })
            .collect()
    }

    /// Speicherverbrauch eines Nutzers (nur aktive Dokumente)
    pub fn user_usage_bytes(&self, user_id: &str) -> u64 {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        self.blocks
            .iter()
            .flat_map(|b| b.documents.iter())
            .filter(|d| d.owner == user_id && !deleted.contains(&d.doc_id))
            .map(|d| d.size)
            .sum()
    }

    pub fn verify(&self, cluster_key: &str) -> bool {
        for i in 1..self.blocks.len() {
            let block = &self.blocks[i];
            let prev = &self.blocks[i - 1];
            if block.previous_hash != prev.hash {
                return false;
            }
            if block.hash != calculate_hash(block) {
                return false;
            }
            // HMAC-Signatur nur prüfen wenn kein PoA-Validator-Signatur vorhanden.
            // Peer-synced Blocks haben ggf. einen anderen cluster_key – deren
            // Authentizität wird durch die Ed25519 validator_signature garantiert.
            if !block.signature.is_empty()
                && block.validator_signature.is_empty()
                && block.signature != sign_hash(cluster_key, &block.hash)
            {
                return false;
            }
        }
        true
    }
}

// ─── Hash & Signatur ─────────────────────────────────────────────────────────

/// Merkle-ähnlicher Root-Hash über alle Dokumente, Tombstones und Token-TXs.
///
/// Ablauf:
///   1. Für jedes Dokument: SHA-256(doc_id || version || size || content_type)
///   2. Für jeden Tombstone: SHA-256("del:" || doc_id)
///   3. Für jede Token-TX: SHA-256("tx:" || tx_id)
///   4. Alle Einzel-Hashes sortieren (kanonische Reihenfolge, unabhängig von Einfüge-Reihenfolge)
///   5. SHA-256 über die Konkatenation aller sortierten Hashes
///   → Leere Liste → SHA-256("empty")
pub fn compute_merkle_root(
    documents: &[Document],
    tombstones: &[DocumentTombstone],
    transactions: &[TokenTx],
) -> String {
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();

    for doc in documents {
        let mut h = Sha256::new();
        h.update(doc.doc_id.as_bytes());
        h.update(b"|");
        h.update(doc.version.to_le_bytes());
        h.update(b"|");
        h.update(doc.size.to_le_bytes());
        h.update(b"|");
        h.update(doc.content_type.as_bytes());
        leaf_hashes.push(h.finalize().into());
    }

    for t in tombstones {
        let mut h = Sha256::new();
        h.update(b"del:");
        h.update(t.doc_id.as_bytes());
        leaf_hashes.push(h.finalize().into());
    }

    for tx in transactions {
        let mut h = Sha256::new();
        h.update(b"tx:");
        h.update(tx.tx_id.as_bytes());
        leaf_hashes.push(h.finalize().into());
    }

    if leaf_hashes.is_empty() {
        return format!("{:x}", Sha256::digest(b"empty"));
    }

    // Kanonische Reihenfolge: nach Hex-Darstellung sortieren
    leaf_hashes.sort_unstable();

    let mut root = Sha256::new();
    for lh in &leaf_hashes {
        root.update(lh);
    }
    format!("{:x}", root.finalize())
}

/// Block-Hash: SHA-256 über binär kodierte Felder.
///
/// Kodierung (in dieser Reihenfolge, kein Trennzeichen):
///   index          8 Byte LE
///   timestamp      8 Byte LE
///   previous_hash  64 Byte (Hex-ASCII, immer 64 Zeichen)
///   merkle_root    64 Byte (Hex-ASCII, immer 64 Zeichen)
///   data_size      8 Byte LE
///   signer         variable (UTF-8)
///   storage_proof  64 Byte (SHA-256 über Proof-Daten)
///
/// Durch die feste Byte-Länge der Zahlen sind Kollisionen ausgeschlossen.
pub fn calculate_hash(block: &Block) -> String {
    let mut h = Sha256::new();
    h.update(block.index.to_le_bytes());
    h.update(block.timestamp.to_le_bytes());
    h.update(block.previous_hash.as_bytes());
    h.update(block.merkle_root.as_bytes());
    h.update(block.data_size.to_le_bytes());
    h.update(block.signer.as_bytes());
    // Storage-Proof geht in den Block-Hash ein → unveränderlich
    h.update(crate::storage_proof::storage_proof_hash(&block.storage_proof).as_bytes());
    // Network-Challenges gehen ebenfalls in den Block-Hash ein
    h.update(crate::storage_proof::network_challenges_hash(&block.storage_challenges).as_bytes());
    format!("{:x}", h.finalize())
}

/// HMAC-SHA-256(cluster_key, hash) – beweist Cluster-Zugehörigkeit
pub fn sign_hash(key: &str, hash: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC init");
    mac.update(hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Signatur eines einzelnen Blocks prüfen
pub fn verify_signature(block: &Block, key: &str) -> bool {
    if block.signature.is_empty() {
        return true;
    }
    sign_hash(key, &block.hash) == block.signature
}

// ─── Eternal Memorial Transaction ────────────────────────────────────────────
//
// Jeder Block enthält eine unveränderliche Memorial-Transaktion für Dennis.
// Timestamp: 1735430400 (29.12.2025) – der Tag an dem er von uns ging.
// Amount: 0 STONE – kein wirtschaftlicher Wert, nur ewige Erinnerung.

/// Erzeugt die Eternal Memorial Transaction, die in **jedem** Block enthalten ist.
pub fn memorial_tx() -> TokenTx {
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Memorial,
        from: "memorial".to_string(),
        to: "forever".to_string(),
        amount: rust_decimal::Decimal::ZERO,
        fee: rust_decimal::Decimal::ZERO,
        nonce: 0,
        timestamp: 1735430400, // 29.12.2025 – In loving memory of Dennis
        signature: String::new(),
        memo: "In loving memory of Dennis (22.07.1994 – 29.12.2025). \
               Forever in the Stonechain. #neverforgetdennis".to_string(),
        chain_id: "stone-memorial".to_string(),
        fee_tier: FeeTier::Standard,
    };
    tx.tx_id = compute_tx_id(&tx);
    tx
}

/// Prüft ob ein Block die korrekte Memorial-TX enthält.
pub fn has_valid_memorial(block: &Block) -> bool {
    let expected = memorial_tx();
    block.transactions.iter().any(|tx| {
        tx.tx_type == TxType::Memorial
            && tx.tx_id == expected.tx_id
            && tx.timestamp == 1735430400
    })
}

/// Genesis-Block: fester Startpunkt der Chain.
///
/// - index = 0
/// - timestamp = 0  (deterministisch, unabhängig vom Startzeitpunkt)
/// - previous_hash = "0000...0000" (64 Nullen)
/// - merkle_root = SHA-256("genesis")
/// - Enthält Memorial-Dokument + Memorial-TX
/// - Hash wird normal berechnet → ist deterministisch für denselben cluster_key
fn genesis_block(cluster_key: &str) -> Block {
    let merkle_root = format!("{:x}", Sha256::digest(b"genesis"));

    // ── Memorial-Dokument für Dennis ──────────────────────────────────
    let memorial_content = "\
in loving memory of my best friend Dennis

born 22.07.1994

Passed away 29.12.2025

This project is meant to keep your memory alive forever, \
and everyone should know that I miss you and will never forget you.
You will live on forever in the Stonechain.
Rest in peace, dear friend.

If this project becomes successful, I will donate 10% of my earnings to cancer research.
Because Dennis died of cancer and nobody could do anything.

#neverforgetdennis aka BauserHD"
        .to_string();

    let memorial_doc = Document {
        doc_id: "memorial-2025.12.29".to_string(),
        title: "In Memory of Dennis".to_string(),
        content_type: "text/plain".to_string(),
        tags: vec!["memorial".to_string(), "neverforgetdennis".to_string()],
        metadata: JsonValue(serde_json::json!({
            "born": "22.07.1994",
            "passed": "29.12.2025",
            "dedication": "Dennis"
        })),
        version: 1,
        size: memorial_content.len() as u64,
        chunks: Vec::new(),
        deleted: false,
        updated_at: 1735430400, // 29.12.2025 00:00 UTC
        owner: "stonechain-creator".to_string(),
        doc_signature: String::new(),
        public_key_hint: String::new(),
        encrypted: false,
        encryption_meta: String::new(),
    };

    // ── Genesis-Block mit Memorial ────────────────────────────────────
    let mut genesis = Block {
        index: 0,
        timestamp: 0,
        merkle_root,
        data_size: 0,
        previous_hash: "0".repeat(64),
        hash: String::new(),
        signer: "genesis".to_string(),
        signature: String::new(),
        owner: "system".to_string(),
        documents: vec![memorial_doc],
        tombstones: Vec::new(),
        transactions: vec![memorial_tx()],
        node_role: NodeRole::Master,
        storage_challenges: Vec::new(),
        challenge_responses: Vec::new(),
        proposal_round: 0,
        validator_pub_key: String::new(),
        validator_signature: String::new(),
        storage_proof: Default::default(),
    };
    let hash = calculate_hash(&genesis);
    genesis.hash = hash.clone();
    genesis.signature = sign_hash(cluster_key, &hash);
    genesis
}
