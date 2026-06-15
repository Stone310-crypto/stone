use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::token::transaction::{TokenTx, TxType, FeeTier, compute_tx_id};
use crate::consensus::CheckpointStore;

type HmacSha256 = Hmac<Sha256>;

/// Maximale Reorg-Tiefe in Blöcken.
///
/// Begrenzt wie viele Blöcke bei einem Fork zurückgerollt werden dürfen.
/// Verhindert Deep-Reorg-Angriffe, bei denen ein Angreifer eine lange
/// alternative Chain anbietet um bestätigte Transaktionen rückgängig zu machen.
pub const MAX_REORG_DEPTH: u64 = 10;

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
/// Mainnet: `stone_data_mainnet/`, Testnet: `stone_data/` (backward-kompatibel).
pub fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| {
        let mode = std::env::var("STONE_NETWORK")
            .unwrap_or_default()
            .to_lowercase();
        if mode == "mainnet" || mode == "main" {
            "stone_data_mainnet".to_string()
        } else {
            "stone_data".to_string()
        }
    })
}

/// Maximale Block-Größe (Summe aller `data_size`-Werte der enthaltenen Dokumente).
///
/// **Sicherheits-Limit gegen DoS:** Ein Validator könnte sonst einen
/// beliebig großen Block proposen, der das gesamte Netz für Minuten blockiert.
///
/// Große Game-Assets gehören NICHT direkt in den Block — sie liegen
/// content-addressed im `ChunkStore` und werden im Block nur per
/// `ChunkRef.hash` referenziert. 16 MiB reicht aus für viele
/// kleine Dokumente + Token-TXs pro Block.
pub const MAX_BLOCK_SIZE: u64 = 16 * 1024 * 1024; // 16 MiB
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

    // ─── Chat Batch Anchors ─────────────────────────────────────────────
    /// Merkle-Batch-Anker für Chat-Nachrichten.
    /// Nur der Merkle-Root-Hash geht in den Block-Hash ein;
    /// die einzelnen Nachrichten bleiben off-chain im MessagePool.
    #[serde(default)]
    pub chat_batches: Vec<crate::merkle_batch::ChatBatchAnchor>,

    // ─── Lite-PoW (Spam-Filter / Fallback-Mining) ───────────────────────
    /// Lite-PoW Nonce für Fallback-Mining (wenn Round-Robin-Validator ausfällt).
    /// 0 = normaler Round-Robin-Block (kein PoW nötig).
    /// >0 = Fallback-Block, gelöst mit `solve_lite_pow()`.
    #[serde(default)]
    pub pow_nonce: u64,

    // ─── Argon2id CPU-PoW ─────────────────────────────────────────────────
    /// Argon2id Proof-of-Work Hash.
    /// Jeder Block muss ein Argon2id-Puzzle lösen (memory-hard, CPU-fair).
    /// Leer = Block vor Argon2id-PoW-Aktivierung (rückwärtskompatibel).
    #[serde(default)]
    pub pow_hash: String,

    /// Argon2id PoW Difficulty-Target (Anzahl führender Null-Bits im Hash).
    /// Wird dynamisch angepasst (Ziel: ~15 Sekunden Mining-Zeit).
    /// 0 = Legacy-Block ohne Argon2id-PoW.
    #[serde(default)]
    pub pow_difficulty: u32,

    // ─── PoS/PoW Hybrid ─────────────────────────────────────────────────
    /// Effektive PoW-Difficulty nach Abzug des Stake-Bonus.
    /// Staker erhalten eine reduzierte Difficulty → finden Blöcke schneller.
    /// 0 = Legacy-Block oder kein Stake-Bonus (effektive == pow_difficulty).
    #[serde(default)]
    pub effective_difficulty: u32,

    // ─── Kumulative Difficulty (Fork-Choice) ────────────────────────────
    /// Kumulative Schwierigkeit der Chain bis einschließlich dieses Blocks.
    /// Summe von block_work(effective_difficulty) für alle Blöcke von Genesis bis hier.
    /// Dient der "Heaviest Chain"-Regel: bei Forks gewinnt die Chain mit der
    /// höchsten kumulativen Difficulty (meiste Gesamtarbeit).
    /// 0 = Legacy-Block (vor Einführung des Feldes).
    #[serde(default)]
    pub cumulative_difficulty: u64,
}

/// Berechnet die "Arbeit" eines einzelnen Blocks basierend auf seiner Difficulty.
/// Verwendet effective_difficulty wenn gesetzt (PoS/PoW Hybrid: tatsächlich geleistete Arbeit),
/// fällt zurück auf pow_difficulty für Legacy-Blöcke.
/// Blöcke mit höherer Difficulty repräsentieren exponentiell mehr Rechenarbeit.
pub fn block_work_effective(effective_difficulty: u32, pow_difficulty: u32) -> u64 {
    let d = if effective_difficulty > 0 { effective_difficulty } else { pow_difficulty };
    if d == 0 { return 1; }
    1u64.checked_shl(d).unwrap_or(u64::MAX)
}

/// Berechnet die "Arbeit" eines einzelnen Blocks basierend auf seiner PoW-Difficulty.
/// Legacy-Kompatibilität: Verwende `block_work_effective()` für PoS/PoW Hybrid.
pub fn block_work(pow_difficulty: u32) -> u64 {
    if pow_difficulty == 0 { return 1; }
    1u64.checked_shl(pow_difficulty).unwrap_or(u64::MAX)
}

// ─── Chain ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct StoneChain {
    pub blocks: Vec<Block>,
    pub latest_hash: String,
    /// Fork-Block-Cache: Blöcke die zu einer alternativen Chain gehören.
    /// Gespeichert nach Block-Hash, max. 50 Einträge.
    /// Wird genutzt um Forks aufzulösen wenn nachfolgende Blöcke eintreffen.
    pub fork_blocks: std::collections::HashMap<String, Block>,
    /// Temporärer Puffer für Blöcke die bei einem Reorg verwaist wurden.
    /// Der Aufrufer kann hieraus User-TXs zurück in den Mempool führen.
    /// Wird nach jedem `accept_peer_block` vom Aufrufer geleert.
    pub orphaned_blocks: Vec<Block>,
}

impl StoneChain {
    /// Lädt die Chain aus RocksDB oder erstellt eine neue mit Genesis-Block.
    pub fn load_or_create(cluster_key: &str) -> Self {
        use crate::storage::{ChainStore, chain_db_path};

        std::fs::create_dir_all(data_dir()).unwrap_or(());
        std::fs::create_dir_all(chunk_dir()).unwrap_or(());

        // Erwarteter Genesis-Hash für diesen cluster_key (deterministisch)
        let expected_genesis = genesis_block(cluster_key);

        // Versuche DB zu öffnen — bei LOCK-Fehler (z.B. nach Crash) einmal retrien
        let open_result = match ChainStore::open() {
            ok @ Ok(_) => ok,
            Err(e) => {
                let err_msg = format!("{e}");
                if err_msg.contains("lock") || err_msg.contains("LOCK") {
                    eprintln!(
                        "[chain] ⚠️  RocksDB LOCK-Fehler (vermutlich unsauberer Shutdown). \
                         Entferne stale LOCK und versuche erneut..."
                    );
                    let lock_path = format!("{}/LOCK", chain_db_path());
                    let _ = std::fs::remove_file(&lock_path);
                    ChainStore::open()
                } else {
                    Err(e)
                }
            }
        };

        match open_result {
            Ok(store) if !store.is_empty() => {
                let bc = store.block_count().unwrap_or(0);
                eprintln!("[chain] DB geöffnet: block_count={bc}");
                match store.read_all_blocks() {
                    Ok(mut blocks) if !blocks.is_empty() => {
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
                            // ── Integritäts-Check: blocks[i].index == i ──
                            // Erkennt Index-Lücken die durch fehlerhafte Reorgs entstehen können.
                            let mut truncate_at: Option<usize> = None;
                            for (pos, blk) in blocks.iter().enumerate() {
                                if blk.index != pos as u64 {
                                    eprintln!(
                                        "[chain] ⚠️  Index-Lücke erkannt: blocks[{pos}].index = {} (erwartet {pos}). \
                                         Kette wird bei Position {pos} abgeschnitten.",
                                        blk.index,
                                    );
                                    truncate_at = Some(pos);
                                    break;
                                }
                            }
                            if let Some(cut) = truncate_at {
                                blocks.truncate(cut);
                                // DB-Metadaten korrigieren (store ist noch offen)
                                let new_count = blocks.len() as u64;
                                let new_latest = blocks.last().map(|b| b.hash.as_str()).unwrap_or("genesis");
                                if let Err(e) = store.repair_meta(new_count, new_latest) {
                                    eprintln!("[chain] DB-Reparatur fehlgeschlagen: {e}");
                                } else {
                                    eprintln!(
                                        "[chain] ✅ Chain auf {} Blöcke repariert (block_count in DB korrigiert)",
                                        blocks.len()
                                    );
                                }
                            }

                            let latest_hash = blocks.last().map(|b| b.hash.clone()).unwrap_or_default();
                            println!(
                                "[chain] RocksDB geladen: {} Blöcke, Latest: {}...",
                                blocks.len(),
                                &latest_hash[..8]
                            );
                            return StoneChain { blocks, latest_hash, fork_blocks: std::collections::HashMap::new(), orphaned_blocks: Vec::new() };
                        }
                    }
                    Ok(blocks) => {
                        eprintln!("[chain] read_all_blocks returned {} blocks (empty)", blocks.len());
                    }
                    Err(e) => {
                        eprintln!("[chain] read_all_blocks fehlgeschlagen: {e}");
                    }
                }
            }
            Ok(_store) => {
                let bc = _store.block_count().unwrap_or(0);
                eprintln!("[chain] DB geöffnet aber leer (block_count={bc})");
            }
            Err(e) => {
                let err_msg = format!("{e}");
                if err_msg.contains("Corruption") || err_msg.contains("No such file or directory") {
                    eprintln!(
                        "[chain] ⚠️  RocksDB korrupt: {}",
                        &err_msg[..120.min(err_msg.len())]
                    );
                    eprintln!("[chain] 🗑️  Lösche beschädigte DB und starte mit frischer Chain...");
                    let db_path = format!("{}/chain_db", data_dir());
                    if let Err(e2) = std::fs::remove_dir_all(&db_path) {
                        eprintln!("[chain] DB-Löschung fehlgeschlagen: {e2}");
                    }
                } else {
                    eprintln!("[chain] RocksDB konnte nicht geöffnet werden: {e}");
                }
            }

        }

        // Leere oder neue Datenbank → Genesis-Block erstellen
        let genesis = expected_genesis;
        let chain = StoneChain {
            blocks: vec![genesis.clone()],
            latest_hash: genesis.hash.clone(),
            fork_blocks: std::collections::HashMap::new(),
            orphaned_blocks: Vec::new(),
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
            // Retry-Logik: RocksDB kann bei konkurrierendem Zugriff LOCK-Fehler werfen
            for attempt in 0..3 {
                match ChainStore::open() {
                    Ok(store) => {
                        if let Err(e) = store.write_block_sync(block) {
                            eprintln!("[chain] RocksDB-Schreibfehler: {e}");
                        }
                        return;
                    }
                    Err(e) => {
                        let msg = format!("{e}");
                        if (msg.contains("lock") || msg.contains("LOCK") || msg.contains("temporarily unavailable")) && attempt < 2 {
                            std::thread::sleep(std::time::Duration::from_millis(100 * (attempt as u64 + 1)));
                            continue;
                        }
                        eprintln!("[chain] RocksDB konnte nicht geöffnet werden: {e}");
                        return;
                    }
                }
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
    /// Gibt die entfernten Blöcke zurück, damit ihre TXs in den Mempool
    /// zurückgeführt werden können (Orphan-TX-Recovery).
    pub fn truncate_to(&mut self, target_len: u64) -> Vec<Block> {
        let target = target_len as usize;
        if target >= self.blocks.len() {
            return Vec::new();
        }
        let orphaned: Vec<Block> = self.blocks.split_off(target);
        self.latest_hash = self.blocks.last().map(|b| b.hash.clone()).unwrap_or_default();
        println!(
            "[chain] 🔄 Chain auf {} Blöcke gekürzt ({} entfernt), latest_hash={}...",
            target,
            orphaned.len(),
            &self.latest_hash[..8.min(self.latest_hash.len())],
        );
        // RocksDB: entfernte Blöcke löschen
        use crate::storage::ChainStore;
        if let Ok(store) = ChainStore::open() {
            for block in &orphaned {
                if let Err(e) = store.delete_block(block.index) {
                    eprintln!("[chain] ⚠ Block {} löschen fehlgeschlagen: {e}", block.index);
                }
            }
        }
        orphaned
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
        let block = self.prepare_block(documents, tombstones, transactions, owner, signer, cluster_key, node_role, Vec::new());
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
        chat_batches: Vec<crate::merkle_batch::ChatBatchAnchor>,
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
            chat_batches,
            pow_nonce: 0,
            pow_hash: String::new(),
            pow_difficulty: 0,
            effective_difficulty: 0,
            cumulative_difficulty: 0,
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
    /// Setzt `cumulative_difficulty` automatisch falls nicht gesetzt.
    pub fn commit_block(&mut self, mut block: Block) {
        let hash = block.hash.clone();
        let idx = block.index;
        let docs = block.documents.len();
        let txs = block.transactions.len();
        let bytes = block.data_size;

        // Kumulative Difficulty berechnen falls nicht gesetzt
        if block.cumulative_difficulty == 0 {
            let parent_cd = self.blocks.last()
                .map(|b| b.cumulative_difficulty)
                .unwrap_or(0);
            block.cumulative_difficulty = parent_cd
                + block_work_effective(block.effective_difficulty, block.pow_difficulty);
        }

        self.blocks.push(block);
        self.latest_hash = hash;

        println!(
            "[chain] Block #{} committed – {} Dok., {} TXs, {} Bytes, d={}/{}, cd={}",
            idx, docs, txs, bytes,
            self.blocks.last().map(|b| b.effective_difficulty).unwrap_or(0),
            self.blocks.last().map(|b| b.pow_difficulty).unwrap_or(0),
            self.blocks.last().map(|b| b.cumulative_difficulty).unwrap_or(0),
        );
    }

    /// Nimmt einen von einem Peer empfangenen fertigen Block in die lokale Chain auf.
    /// Prüft Verkettung (previous_hash) und Hash-Integrität. Gibt Err zurück wenn ungültig.
    ///
    /// `poa_ok` – Ergebnis der externen PoA-Signaturprüfung (durch ValidatorSet).
    ///   - `None`  → PoA-Prüfung wird übersprungen (kein Validator-Set geladen)
    ///   - `Some(true)`  → Prüfung bestanden
    ///   - `Some(false)` → Prüfung fehlgeschlagen → Block wird abgelehnt
    /// Akzeptiert einen Block von einem Peer und fügt ihn in die Chain ein.
    ///
    /// `checkpoints` (optional): Wenn `Some`, wird vor jedem Reorg geprüft, dass
    /// kein finalisierter Checkpoint verletzt würde (Long-Range-Attack-Schutz).
    /// Nodes ohne Checkpoint-Store (z.B. Sync-Only-Clients) können `None` übergeben
    /// — dann gilt nur der `MAX_REORG_DEPTH`-Schutz.
    pub fn accept_peer_block(
        &mut self,
        mut block: Block,
        poa_ok: Option<bool>,
        checkpoints: Option<&CheckpointStore>,
    ) -> Result<(), String> {
        // ── DoS-Schutz: Block-Größe begrenzen ────────────────────────────
        if block.data_size > MAX_BLOCK_SIZE {
            return Err(format!(
                "Block #{} zu groß: data_size={} > MAX_BLOCK_SIZE={}",
                block.index, block.data_size, MAX_BLOCK_SIZE
            ));
        }

        let local_len = self.blocks.len() as u64;

        // ── Fork-Reorg: Block liegt hinter unserer Chain ──────────────────
        if block.index < local_len {
            // Prüfe ob der Block identisch mit unserem ist → Stale (ignorieren)
            if let Some(existing) = self.blocks.get(block.index as usize) {
                if existing.hash == block.hash {
                    return Err(format!(
                        "Stale: Block #{} bereits bekannt (identisch)",
                        block.index
                    ));
                }

                // ── Equivocation-Erkennung: gleicher Validator, gleicher Index, anderer Hash ──
                if !existing.validator_pub_key.is_empty()
                    && !block.validator_pub_key.is_empty()
                    && existing.validator_pub_key == block.validator_pub_key
                    && existing.hash != block.hash
                {
                    eprintln!(
                        "[chain] ⚠️  EQUIVOCATION erkannt! Validator {} hat Block #{} doppelt signiert: \
                         lokal={}… peer={}…",
                        &existing.validator_pub_key[..16.min(existing.validator_pub_key.len())],
                        block.index,
                        &existing.hash[..12.min(existing.hash.len())],
                        &block.hash[..12.min(block.hash.len())],
                    );
                    return Err(format!(
                        "Equivocation: Validator {} hat zwei verschiedene Blöcke für Index #{} signiert",
                        &block.validator_pub_key[..16.min(block.validator_pub_key.len())],
                        block.index
                    ));
                }

                // Block hat gleichen Index aber anderen Hash → Fork!
                let reorg_depth = local_len - block.index;
                if reorg_depth > MAX_REORG_DEPTH {
                    return Err(format!(
                        "Reorg abgelehnt: Tiefe {} überschreitet MAX_REORG_DEPTH ({}) bei Block #{} (lokale Höhe: {local_len})",
                        reorg_depth, MAX_REORG_DEPTH, block.index
                    ));
                }

                // Prüfe ob der block.previous_hash zu unserem Vorgänger passt
                let prev_ok = if block.index == 0 {
                    true // Genesis
                } else {
                    self.blocks.get((block.index - 1) as usize)
                        .map(|b| b.hash == block.previous_hash)
                        .unwrap_or(false)
                };
                if prev_ok {
                    // ── Heaviest-Chain-Regel + Peak-Advance ────────────
                    let our_tip_cd = self.blocks.last()
                        .map(|b| b.cumulative_difficulty)
                        .unwrap_or(0);
                    let incoming_cd = if block.cumulative_difficulty > 0 {
                        block.cumulative_difficulty
                    } else {
                        let parent_cd = self.blocks.get((block.index - 1) as usize)
                            .map(|b| b.cumulative_difficulty)
                            .unwrap_or(0);
                        parent_cd + block_work_effective(block.effective_difficulty, block.pow_difficulty)
                    };

                    // Peak-Advance: Bei tiefen Reorgs (>10 Blöcke) und annähernd
                    // gleicher CD wie unser Tip, vertraue der Peer-Chain.
                    let cd_close = incoming_cd + 1000 >= our_tip_cd;
                    let deep_reorg = reorg_depth > 10;

                    if incoming_cd > our_tip_cd || (deep_reorg && cd_close) {
                        if let Some(cps) = checkpoints {
                            cps.check_reorg_allowed(block.index)
                                .map_err(|e| format!("Checkpoint-Schutz: {e}"))?;
                        }
                        let reason = if incoming_cd > our_tip_cd {
                            format!("cd: {} > {}", incoming_cd, our_tip_cd)
                        } else {
                            format!("Peak-Advance: depth={} cd_close=true", reorg_depth)
                        };
                        println!(
                            "[chain] 🔄 Fork-Reorg bei Block #{}: lokal={}… peer={}… ({})",
                            block.index,
                            &existing.hash[..8.min(existing.hash.len())],
                            &block.hash[..8.min(block.hash.len())],
                            reason,
                        );
                        let orphaned = self.truncate_to(block.index);
                        self.orphaned_blocks = orphaned;
                    } else if incoming_cd == our_tip_cd && reorg_depth == 1 {
                        let incoming_has_user_txs = block.transactions.iter()
                            .any(|tx| tx.tx_type != TxType::Reward && tx.tx_type != TxType::Mint);
                        let existing_has_user_txs = existing.transactions.iter()
                            .any(|tx| tx.tx_type != TxType::Reward && tx.tx_type != TxType::Mint);

                        let prefer_incoming = if incoming_has_user_txs && !existing_has_user_txs {
                            true
                        } else if !incoming_has_user_txs && existing_has_user_txs {
                            false
                        } else {
                            block.hash < existing.hash
                        };

                        if prefer_incoming {
                            if let Some(cps) = checkpoints {
                                cps.check_reorg_allowed(block.index)
                                    .map_err(|e| format!("Checkpoint-Schutz: {e}"))?;
                            }
                            println!(
                                "[chain] 🔄 Fork-Tiebreak bei Block #{}",
                                block.index
                            );
                            let orphaned = self.truncate_to(block.index);
                            self.orphaned_blocks = orphaned;
                        } else {
                            let bi = block.index;
                            self.store_fork_block(block);
                            return Err(format!(
                                "Fork bei Block #{}: Tiebreak verloren – gespeichert",
                                bi,
                            ));
                        }
                    } else {
                        let bi = block.index;
                        self.store_fork_block(block);
                        return Err(format!(
                            "Fork bei Block #{}: nicht schwerer (cd: {} ≤ {}) – gespeichert",
                            bi, incoming_cd, our_tip_cd,
                        ));
                    }
                } else {
                    return Err(format!(
                        "Stale: Block #{} bereits bekannt (Fork, previous_hash passt nicht)",
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
            // ── Fork-Erkennung: Suche gemeinsamen Vorgänger ──────────────
            if block.index > 0 {
                // Suche den gemeinsamen Vorgänger (Fork-Punkt)
                if let Some(prev_block) = self.blocks.iter().find(|b| b.hash == block.previous_hash) {
                    let fork_point = prev_block.index + 1;
                    let reorg_depth = local_len - fork_point;

                    // Reorg-Tiefe prüfen
                    if reorg_depth > MAX_REORG_DEPTH {
                        return Err(format!(
                            "Reorg abgelehnt: Tiefe {} überschreitet MAX_REORG_DEPTH ({}) – Fork bei #{}",
                            reorg_depth, MAX_REORG_DEPTH, fork_point
                        ));
                    }

                    // ── Heaviest-Chain-Regel ──────────────────────────────────
                    let our_tip_cd = self.blocks.last()
                        .map(|b| b.cumulative_difficulty)
                        .unwrap_or(0);
                    let incoming_cd = if block.cumulative_difficulty > 0 {
                        block.cumulative_difficulty
                    } else {
                        let parent_cd = prev_block.cumulative_difficulty;
                        parent_cd + block_work_effective(block.effective_difficulty, block.pow_difficulty)
                    };

                    if incoming_cd <= our_tip_cd {
                        // Fork ist nicht schwerer → speichern, nicht reorgen
                        self.store_fork_block(block);
                        return Err(format!(
                            "Fork bei #{}: nicht schwerer (cd: {} ≤ {}) – gespeichert für spätere Auflösung",
                            fork_point, incoming_cd, our_tip_cd,
                        ));
                    }

                    println!(
                        "[chain] 🔄 Fork-Reorg: Lokale Chain hat {} Blöcke, Fork bei #{} – ersetze {} Blöcke (cd: {} > {})",
                        local_len, fork_point, reorg_depth, incoming_cd, our_tip_cd,
                    );
                    // Reorg-Schutz: finalisierter Checkpoint darf nicht verletzt werden.
                    if let Some(cps) = checkpoints {
                        cps.check_reorg_allowed(fork_point)
                            .map_err(|e| format!("Checkpoint-Schutz: {e}"))?;
                    }
                    let orphaned = self.truncate_to(fork_point);
                    self.orphaned_blocks.extend(orphaned);
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
                    // Kein gemeinsamer Vorgänger in der Hauptchain → Fork-Cache prüfen
                    // Speichere den Block im Cache und versuche den Fork aufzulösen
                    self.store_fork_block(block.clone());
                    match self.try_resolve_fork(&block, checkpoints) {
                        Ok(true) => {
                            // Fork wurde aufgelöst, neuer Block kann normal angefügt werden
                            // (latest_hash sollte jetzt block.previous_hash sein)
                            if block.previous_hash != self.latest_hash {
                                return Err(format!(
                                    "Fork aufgelöst aber previous_hash passt nicht: {} ≠ {}",
                                    &block.previous_hash[..12.min(block.previous_hash.len())],
                                    &self.latest_hash[..12.min(self.latest_hash.len())],
                                ));
                            }
                            // Entferne den neuen Block aus dem Fork-Cache
                            self.fork_blocks.remove(&block.hash);
                        }
                        Ok(false) => {
                            return Err(format!(
                                "Fork-Block #{} gespeichert (cd nicht ausreichend für Reorg)",
                                block.index,
                            ));
                        }
                        Err(e) => {
                            return Err(format!("Fork-Auflösung fehlgeschlagen: {e}"));
                        }
                    }
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

        // ── Challenge-Response Verifikation ────────────────────────────────
        // Responses im Block müssen gegen offene Challenges in der Chain validiert werden
        if !block.challenge_responses.is_empty() && block.index > 0 {
            let lookback = crate::storage_proof::CHALLENGE_DEADLINE_BLOCKS as usize + 5;
            let start = self.blocks.len().saturating_sub(lookback);

            // Offene Challenges sammeln
            let open_challenges: Vec<&crate::storage_proof::NetworkChallenge> = self.blocks[start..]
                .iter()
                .flat_map(|b| b.storage_challenges.iter())
                .collect();

            // Schon beantwortete Challenge-IDs
            let answered: std::collections::HashSet<&str> = self.blocks[start..]
                .iter()
                .flat_map(|b| b.challenge_responses.iter())
                .map(|r| r.challenge_id.as_str())
                .collect();

            let store = crate::storage::ChunkStore::new().ok();

            for resp in &block.challenge_responses {
                // Response referenziert eine existierende Challenge?
                let challenge = open_challenges.iter()
                    .find(|c| c.challenge_id == resp.challenge_id);
                match challenge {
                    None => {
                        return Err(format!(
                            "Challenge-Response für unbekannte Challenge {}",
                            &resp.challenge_id[..12.min(resp.challenge_id.len())]
                        ));
                    }
                    Some(challenge) => {
                        // Nicht doppelt beantworten
                        if answered.contains(resp.challenge_id.as_str()) {
                            return Err(format!(
                                "Challenge {} wurde bereits beantwortet",
                                &resp.challenge_id[..12.min(resp.challenge_id.len())]
                            ));
                        }
                        // Kryptographische Verifikation (Signatur + Proof)
                        if let Err(e) = crate::storage_proof::verify_challenge_response(
                            challenge, resp, store.as_ref(), block.index,
                        ) {
                            return Err(format!("Challenge-Response ungültig: {e}"));
                        }
                    }
                }
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

        // ── Argon2id CPU-PoW Verifikation (nur wenn BLOCK_POW_ENABLED) ──
        if crate::consensus::BLOCK_POW_ENABLED {
            use crate::consensus::{
                get_current_pow_difficulty, verify_argon2_pow,
                ARGON2_POW_ACTIVATION_BLOCK, MIN_EFFECTIVE_POW_DIFFICULTY,
            };
            if block.index >= ARGON2_POW_ACTIVATION_BLOCK {
                let base_difficulty = get_current_pow_difficulty(&self.blocks, block.index);
                if base_difficulty > 0 {
                    if block.pow_hash.is_empty() || block.pow_difficulty == 0 {
                        return Err(format!(
                            "Argon2id-PoW fehlt (ab Block #{} erforderlich)",
                            ARGON2_POW_ACTIVATION_BLOCK,
                        ));
                    }
                    if block.pow_difficulty < base_difficulty {
                        return Err(format!(
                            "Argon2id-Difficulty zu niedrig: {} < {}",
                            block.pow_difficulty, base_difficulty,
                        ));
                    }
                    // PoS/PoW Hybrid: effektive Difficulty bestimmen
                    // effective_difficulty muss zwischen MIN_EFFECTIVE_POW_DIFFICULTY
                    // und pow_difficulty liegen (Stake-Bonus darf maximal MAX_STAKE_DIFFICULTY_BONUS reduzieren)
                    let verify_difficulty = if block.effective_difficulty > 0 {
                        if block.effective_difficulty > block.pow_difficulty {
                            return Err(format!(
                                "effective_difficulty ({}) > pow_difficulty ({}) – ungültig",
                                block.effective_difficulty, block.pow_difficulty,
                            ));
                        }
                        if block.effective_difficulty < MIN_EFFECTIVE_POW_DIFFICULTY {
                            return Err(format!(
                                "effective_difficulty ({}) < MIN ({}) – ungültig",
                                block.effective_difficulty, MIN_EFFECTIVE_POW_DIFFICULTY,
                            ));
                        }
                        block.effective_difficulty
                    } else {
                        block.pow_difficulty
                    };
                    if !verify_argon2_pow(
                        &block.previous_hash,
                        block.index,
                        &block.validator_pub_key,
                        block.pow_nonce,
                        &block.pow_hash,
                        verify_difficulty,
                    ) {
                        return Err("Ungültiger Argon2id-PoW (Hash-Verifikation fehlgeschlagen)".into());
                    }
                }
            }
        }

        // PoA: externer Signatur-Check
        if poa_ok == Some(false) {
            return Err(format!(
                "PoA-Signaturprüfung fehlgeschlagen für Signer '{}'",
                block.signer
            ));
        }

        // ── Kumulative Difficulty berechnen ───────────────────────────────
        if block.cumulative_difficulty == 0 {
            let parent_cd = self.blocks.last()
                .map(|b| b.cumulative_difficulty)
                .unwrap_or(0);
            block.cumulative_difficulty = parent_cd
                + block_work_effective(block.effective_difficulty, block.pow_difficulty);
        }

        self.latest_hash = block.hash.clone();
        self.blocks.push(block);
        // Chain-Persistierung erfolgt im Caller NACH Freigabe des chain-Locks.
        // persist_last_block() öffnet RocksDB frisch + sync-Write — das würde
        // den chain-Lock für 100+ ms blockieren und alle P2P-Block-Requests
        // (die chain_ref.lock() brauchen) zum Timeout bringen → HTTP 503.

        // Fork-Cache aufräumen: Blöcke die jetzt hinter der Chain liegen entfernen
        self.prune_fork_blocks();

        Ok(())
    }

    // ── Fork-Block-Cache ──────────────────────────────────────────────────────

    /// Speichert einen Fork-Block im Cache für spätere Auflösung.
    /// Begrenzt auf 50 Einträge (älteste werden entfernt).
    /// Blockiert leere/Fremd-Blöcke ohne Parent in Chain oder Fork-Cache.
    pub fn store_fork_block(&mut self, block: Block) -> bool {
        // Fork-Blöcke nur speichern wenn der Parent in der Hauptchain ODER
        // im Fork-Cache existiert. Ansonsten ist es ein Fremd-Block von
        // einer inkompatiblen Chain (= anderer Genesis).
        let parent_exists = self.blocks.iter().any(|b| b.hash == block.previous_hash)
            || self.fork_blocks.contains_key(&block.previous_hash);
        if !parent_exists {
            eprintln!(
                "[fork] ❌ Fremd-Block #{} verworfen – kein Parent in Chain oder Cache",
                block.index
            );
            return false;
        }

        const MAX_FORK_BLOCKS: usize = 50;
        println!(
            "[fork] 📦 Fork-Block #{} gespeichert (hash={}…, cd={})",
            block.index,
            &block.hash[..8.min(block.hash.len())],
            block.cumulative_difficulty,
        );
        self.fork_blocks.insert(block.hash.clone(), block);
        // Eviction: älteste (niedrigster Index) entfernen
        while self.fork_blocks.len() > MAX_FORK_BLOCKS {
            if let Some(oldest_hash) = self.fork_blocks.values()
                .min_by_key(|b| b.index)
                .map(|b| b.hash.clone())
            {
                self.fork_blocks.remove(&oldest_hash);
            } else {
                break;
            }
        }
        true
    }

    /// Entfernt Fork-Blöcke die weit hinter der Chain liegen.
    fn prune_fork_blocks(&mut self) {
        let chain_height = self.blocks.len() as u64;
        self.fork_blocks.retain(|_, b| {
            b.index + MAX_REORG_DEPTH >= chain_height
        });
    }

    /// Versucht eine Fork-Chain aufzubauen die bei `tip_hash` endet.
    /// Sucht rückwärts durch den Fork-Cache bis ein Vorgänger in der
    /// Hauptchain gefunden wird.
    /// Gibt die Fork-Blöcke in aufsteigender Reihenfolge zurück (ohne den Hauptchain-Block).
    pub fn build_fork_chain(&self, tip_hash: &str) -> Option<(u64, Vec<Block>)> {
        let mut chain = Vec::new();
        let mut current_hash = tip_hash.to_string();

        // Rückwärts durch Fork-Blöcke suchen
        for _ in 0..MAX_REORG_DEPTH {
            if let Some(block) = self.fork_blocks.get(&current_hash) {
                current_hash = block.previous_hash.clone();
                chain.push(block.clone());
            } else {
                break;
            }
        }

        if chain.is_empty() {
            return None;
        }

        chain.reverse(); // Aufsteigend sortieren

        // Prüfen ob der erste Fork-Block an die Hauptchain anknüpft
        let fork_start = &chain[0];
        let connects = self.blocks.iter().any(|b| b.hash == fork_start.previous_hash);
        if connects {
            let fork_point = fork_start.index;
            Some((fork_point, chain))
        } else {
            None
        }
    }

    /// Prüft ob ein Fork im Cache zusammen mit einem neuen Block schwerer ist
    /// als unsere aktuelle Chain. Wenn ja, führt die Reorg durch.
    /// Gibt Ok(true) zurück wenn reorgt wurde, Ok(false) wenn nicht.
    pub fn try_resolve_fork(
        &mut self,
        new_block: &Block,
        checkpoints: Option<&CheckpointStore>,
    ) -> Result<bool, String> {
        // Suche ob new_block.previous_hash auf einen Fork-Block zeigt
        if let Some((fork_point, fork_chain)) = self.build_fork_chain(&new_block.previous_hash) {
            // Kumulative Difficulty des Forks berechnen
            let fork_tip_cd = if new_block.cumulative_difficulty > 0 {
                new_block.cumulative_difficulty
            } else {
                // Berechne aus Fork-Chain
                let last_fork = fork_chain.last().unwrap();
                let last_cd = if last_fork.cumulative_difficulty > 0 {
                    last_fork.cumulative_difficulty
                } else {
                    // Berechne manuell entlang der Fork-Chain
                    let anchor_cd = self.blocks.get((fork_point - 1) as usize)
                        .map(|b| b.cumulative_difficulty)
                        .unwrap_or(0);
                    let mut cd = anchor_cd;
                    for fb in &fork_chain {
                        cd = cd.saturating_add(block_work_effective(
                            fb.effective_difficulty,
                            fb.pow_difficulty,
                        ));
                    }
                    cd
                };
                last_cd.saturating_add(block_work_effective(
                    new_block.effective_difficulty,
                    new_block.pow_difficulty,
                ))
            };

            let our_tip_cd = self.blocks.last()
                .map(|b| b.cumulative_difficulty)
                .unwrap_or(0);

            if fork_tip_cd > our_tip_cd {
                let reorg_depth = self.blocks.len() as u64 - fork_point;
                if reorg_depth > MAX_REORG_DEPTH {
                    return Err(format!(
                        "Fork-Reorg abgelehnt: Tiefe {} > MAX_REORG_DEPTH",
                        reorg_depth
                    ));
                }

                println!(
                    "[fork] 🔄 Fork-Reorg via Cache: {} Fork-Blöcke + neuer Block, cd: {} > {} (Tiefe: {})",
                    fork_chain.len(), fork_tip_cd, our_tip_cd, reorg_depth,
                );

                // Reorg-Schutz: finalisierter Checkpoint darf nicht verletzt werden.
                if let Some(cps) = checkpoints {
                    cps.check_reorg_allowed(fork_point)
                        .map_err(|e| format!("Checkpoint-Schutz: {e}"))?;
                }

                // Hauptchain kürzen
                let orphaned = self.truncate_to(fork_point);
                self.orphaned_blocks.extend(orphaned);

                // Fork-Blöcke einfügen
                for mut fb in fork_chain {
                    if fb.cumulative_difficulty == 0 {
                        let parent_cd = self.blocks.last()
                            .map(|b| b.cumulative_difficulty)
                            .unwrap_or(0);
                        fb.cumulative_difficulty = parent_cd + block_work_effective(
                            fb.effective_difficulty,
                            fb.pow_difficulty,
                        );
                    }
                    // Entferne aus Fork-Cache
                    self.fork_blocks.remove(&fb.hash);
                    self.latest_hash = fb.hash.clone();
                    self.blocks.push(fb);
                    // Kein persist_last_block() im hot-Pfad — siehe accept_peer_block
                }

                return Ok(true);
            }
        }
        Ok(false)
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
    // Challenge-Responses sind ebenfalls Teil des Block-Hashes → manipulationssicher
    h.update(crate::storage_proof::challenge_responses_hash(&block.challenge_responses).as_bytes());
    // Chat-Batch-Anchors: Merkle-Roots der Off-Chain-Nachrichten-Batches
    h.update(crate::merkle_batch::chat_batches_hash(&block.chat_batches).as_bytes());
    // Lite-PoW Nonce (nur relevant bei Fallback-Blöcken)
    h.update(block.pow_nonce.to_le_bytes());
    // Argon2id PoW: Hash + Difficulty in Block-Hash einbeziehen
    h.update(block.pow_hash.as_bytes());
    h.update(block.pow_difficulty.to_le_bytes());
    // PoS/PoW Hybrid: effective_difficulty in Block-Hash einbeziehen
    h.update(block.effective_difficulty.to_le_bytes());
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
        signed_by: None,
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

    // Genesis previous_hash hängt vom Netzwerk ab (testnet/mainnet),
    // NICHT vom cluster_key. So haben alle Nodes im selben Netzwerk
    // denselben Genesis-Hash, aber unterschiedliche Netzwerke sind isoliert.
    let network = std::env::var("STONE_NETWORK").unwrap_or_else(|_| "testnet".into());
    let genesis_prev = format!("{:x}", Sha256::digest(
        format!("stone-genesis-v2-{}", network).as_bytes()
    ));

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

#nRestinPeaceBauserHD i miss you every day and will never forget you"
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
        previous_hash: genesis_prev,
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
        chat_batches: Vec::new(),
        pow_nonce: 0,
        pow_hash: String::new(),
        pow_difficulty: 0,
        effective_difficulty: 0,
        cumulative_difficulty: 1, // Genesis = 1
    };
    let hash = calculate_hash(&genesis);
    genesis.hash = hash.clone();
    genesis.signature = sign_hash(cluster_key, &hash);
    genesis
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config::standard;

    #[test]
    fn test_block_bincode_roundtrip() {
        let block = genesis_block("test-key");
        eprintln!("Block hash: {}", block.hash);
        eprintln!("Block has {} docs, {} txs", block.documents.len(), block.transactions.len());

        // Encode
        let encoded = bincode::serde::encode_to_vec(&block, standard())
            .expect("encode failed");
        eprintln!("Encoded size: {} bytes", encoded.len());

        // Decode
        let (decoded, _): (Block, _) = bincode::serde::decode_from_slice(&encoded, standard())
            .expect("decode failed");

        assert_eq!(block.hash, decoded.hash);
        assert_eq!(block.index, decoded.index);
        assert_eq!(block.documents.len(), decoded.documents.len());
        assert_eq!(block.transactions.len(), decoded.transactions.len());
        eprintln!("Roundtrip OK!");
    }

    #[test]
    fn test_decimal_bincode_roundtrip() {
        use rust_decimal::Decimal;
        let val = Decimal::new(12345, 2); // 123.45
        let encoded = bincode::serde::encode_to_vec(&val, standard())
            .expect("encode Decimal failed");
        let (decoded, _): (Decimal, _) = bincode::serde::decode_from_slice(&encoded, standard())
            .expect("decode Decimal failed");
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_jsonvalue_bincode_roundtrip() {
        let jv = JsonValue(serde_json::json!({"key": "value", "num": 42}));
        let encoded = bincode::serde::encode_to_vec(&jv, standard())
            .expect("encode JsonValue failed");
        let (decoded, _): (JsonValue, _) = bincode::serde::decode_from_slice(&encoded, standard())
            .expect("decode JsonValue failed");
        assert_eq!(jv.0, decoded.0);
    }
}
