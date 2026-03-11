//! Off-Chain Message Pool mit Sequenznummern für StoneChain Chat.
//!
//! ## Konzept
//!
//! Chat-Nachrichten werden **nicht** mehr einzeln als `TokenTx` in Blocks geschrieben.
//! Stattdessen sammelt der MessagePool Nachrichten off-chain, vergibt sofort eine
//! fortlaufende Sequenznummer und macht sie per P2P-Gossip sofort lesbar.
//!
//! Periodisch (Batch-Trigger) werden gesammelte Nachrichten zu einem Merkle-Batch
//! zusammengefasst. Nur der Merkle-Root-Hash landet als `ChatBatchAnchor` im Block.
//! Jede einzelne Nachricht bleibt kryptografisch beweisbar über ihren Merkle-Proof.
//!
//! ## Ablauf
//!
//! 1. User sendet verschlüsselte Nachricht → `MessagePool::add_message()`
//! 2. Nachricht bekommt Sequenznummer, Status = `Pending`
//! 3. Sofortige Zustellung per P2P-Gossip (kein Warten auf Block)
//! 4. Batch-Trigger: `BATCH_MIN_MESSAGES` erreicht ODER `BATCH_MAX_WAIT_SECS` abgelaufen
//! 5. `drain_for_batch()` → Merkle-Tree wird in `merkle_batch.rs` gebaut
//! 6. Nur der Merkle-Root geht als `ChatBatchAnchor` in den nächsten Block
//!
//! ## Persistenz
//!
//! Pending Messages und Sequenzstand werden in `stone_data/message_pool/` gespeichert,
//! damit bei einem Crash keine Nachrichten verloren gehen.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::sync::RwLock;

use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey, ed25519::signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blockchain::data_dir;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Mindestanzahl an Nachrichten für einen Batch
pub const BATCH_MIN_MESSAGES: usize = 50;

/// Maximale Wartezeit in Sekunden bevor ein Batch erzwungen wird (auch mit weniger Nachrichten)
pub const BATCH_MAX_WAIT_SECS: i64 = 30;

/// Maximale Nachrichten im Pool bevor neue abgelehnt werden
pub const MAX_POOL_SIZE: usize = 50_000;

/// Nachrichten-TTL: Nachrichten älter als 24h werden verworfen
pub const MESSAGE_TTL_SECS: i64 = 86_400;

/// Maximale Zukunfts-Drift in Sekunden (5 Minuten)
const MAX_FUTURE_DRIFT_SECS: i64 = 300;

/// Maximale Größe des Known-IDs Cache bevor GC einsetzt
const MAX_KNOWN_IDS: usize = 100_000;

// ─── Nachrichten-Status ──────────────────────────────────────────────────────

/// Status einer Nachricht im Pool.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum MessageStatus {
    /// Im Pool, noch nicht gebatcht – sofort lesbar per P2P
    Pending,
    /// In einen Merkle-Batch aufgenommen, wartet auf Block-Commit
    Batched { batch_id: String },
    /// Block mit dem Merkle-Root wurde gemined – endgültig bestätigt
    Confirmed { block_index: u64 },
}

impl Default for MessageStatus {
    fn default() -> Self {
        MessageStatus::Pending
    }
}

// ─── Pool-Nachricht ──────────────────────────────────────────────────────────

/// Eine Chat-Nachricht im Off-Chain Message Pool.
///
/// Verschlüsselt mit AES-256-GCM (ECDH Shared Secret zwischen Sender und Empfänger).
/// Die Sequenznummer wird vom Pool vergeben und ist unabhängig von Block-Indizes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PooledMessage {
    /// Eindeutige Nachrichten-ID (SHA-256 über Inhalt + Sender + Timestamp)
    pub msg_id: String,
    /// Fortlaufende Sequenznummer (monoton steigend, Pool-weit)
    pub sequence: u64,
    /// Sender Wallet-Adresse (Ed25519 Public Key, 64 Hex-Zeichen)
    pub from_wallet: String,
    /// Empfänger Wallet-Adresse
    pub to_wallet: String,
    /// Sender User-ID (für Anzeige)
    #[serde(default)]
    pub from_user_id: String,
    /// Sender Display-Name
    #[serde(default)]
    pub from_name: String,
    /// AES-256-GCM verschlüsselter Nachrichteninhalt (base64)
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    pub nonce: String,
    /// Unix-Timestamp in Sekunden
    pub timestamp: i64,
    /// Ed25519-Signatur des Senders über `msg_id` (128 Hex-Zeichen)
    pub signature: String,
    /// Lite-PoW Nonce: SHA256(msg_id | pow_nonce) muss `MESSAGE_POW_DIFFICULTY` führende Null-Bits haben.
    /// Spam-Filter: ~2-5ms Rechenzeit für normale Nutzer, macht Massen-Spam unmöglich.
    #[serde(default)]
    pub pow_nonce: u64,
    /// Aktueller Status der Nachricht
    #[serde(default)]
    pub status: MessageStatus,
}

impl PooledMessage {
    /// Berechnet die deterministische Nachrichten-ID.
    ///
    /// `msg_id = SHA-256(from_wallet | to_wallet | encrypted_content | nonce | timestamp)`
    pub fn compute_msg_id(
        from_wallet: &str,
        to_wallet: &str,
        encrypted_content: &str,
        nonce: &str,
        timestamp: i64,
    ) -> String {
        let mut h = Sha256::new();
        h.update(from_wallet.as_bytes());
        h.update(b"|");
        h.update(to_wallet.as_bytes());
        h.update(b"|");
        h.update(encrypted_content.as_bytes());
        h.update(b"|");
        h.update(nonce.as_bytes());
        h.update(b"|");
        h.update(timestamp.to_le_bytes());
        format!("{:x}", h.finalize())
    }

    /// Berechnet den Leaf-Hash dieser Nachricht für den Merkle-Tree.
    ///
    /// `leaf = SHA-256("msg:" | msg_id | "|" | sequence.to_le_bytes())`
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"msg:");
        h.update(self.msg_id.as_bytes());
        h.update(b"|");
        h.update(self.sequence.to_le_bytes());
        h.finalize().into()
    }
}

// ─── Sequenzstand (persistiert) ──────────────────────────────────────────────

/// Persistierter Sequenzstand des Message Pools.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SequenceState {
    /// Nächste zu vergebende Sequenznummer
    pub next_sequence: u64,
    /// Höchste bestätigte Sequenznummer (Block-Commit)
    pub last_confirmed_seq: u64,
    /// Anzahl erstellter Batches
    pub batch_count: u64,
}

impl Default for SequenceState {
    fn default() -> Self {
        SequenceState {
            next_sequence: 1,
            last_confirmed_seq: 0,
            batch_count: 0,
        }
    }
}

// ─── Pool-Fehler ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PoolError {
    /// Nachricht ist bereits bekannt
    Duplicate(String),
    /// Pool ist voll
    Full,
    /// Nachrichten-ID stimmt nicht überein
    InvalidMsgId { expected: String, got: String },
    /// Ed25519-Signatur ungültig
    InvalidSignature(String),
    /// Nachricht ist abgelaufen
    Expired { age_secs: i64 },
    /// Timestamp liegt zu weit in der Zukunft
    FutureTimestamp { drift_secs: i64 },
    /// Pflichtfeld fehlt
    MissingField(String),
    /// Lite-PoW unzureichend (Spam-Filter nicht bestanden)
    InsufficientPoW,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Duplicate(id) => {
                write!(f, "Nachricht {} ist bereits bekannt", &id[..12.min(id.len())])
            }
            PoolError::Full => write!(f, "Message Pool ist voll ({MAX_POOL_SIZE} Nachrichten)"),
            PoolError::InvalidMsgId { expected, got } => {
                write!(
                    f,
                    "Ungültige msg_id: erwartet {}, empfangen {}",
                    &expected[..12],
                    &got[..12.min(got.len())]
                )
            }
            PoolError::InvalidSignature(s) => write!(f, "Ungültige Signatur: {s}"),
            PoolError::Expired { age_secs } => {
                write!(f, "Nachricht abgelaufen: {age_secs}s alt (max {MESSAGE_TTL_SECS}s)")
            }
            PoolError::FutureTimestamp { drift_secs } => {
                write!(f, "Timestamp liegt {drift_secs}s in der Zukunft (max {MAX_FUTURE_DRIFT_SECS}s)")
            }
            PoolError::MissingField(field) => write!(f, "Pflichtfeld fehlt: {field}"),
            PoolError::InsufficientPoW => write!(f, "Lite-PoW ungültig: SHA256(msg_id|pow_nonce) hat nicht genug führende Nullen"),
        }
    }
}

// ─── Message Pool ────────────────────────────────────────────────────────────

/// Thread-sicherer Off-Chain Message Pool.
///
/// Sammelt Chat-Nachrichten, vergibt Sequenznummern und triggert Batch-Erstellung.
/// Intern geschützt durch `RwLock`.
pub struct MessagePool {
    inner: RwLock<MessagePoolInner>,
}

struct MessagePoolInner {
    /// Pending Nachrichten in Eingangs-Reihenfolge (FIFO)
    queue: VecDeque<PooledMessage>,
    /// Bekannte Nachrichten-IDs (Duplikat-Schutz)
    known_ids: HashSet<String>,
    /// Nachrichten nach msg_id für schnellen Lookup
    by_id: HashMap<String, PooledMessage>,
    /// Sequenzstand
    seq_state: SequenceState,
    /// Timestamp des letzten Batch-Drains (für Timer-Trigger)
    last_batch_time: i64,
}

impl MessagePool {
    /// Neuen leeren Message Pool erstellen.
    pub fn new() -> Self {
        let now = Utc::now().timestamp();
        MessagePool {
            inner: RwLock::new(MessagePoolInner {
                queue: VecDeque::new(),
                known_ids: HashSet::new(),
                by_id: HashMap::new(),
                seq_state: SequenceState::default(),
                last_batch_time: now,
            }),
        }
    }

    /// Pool aus persistiertem Zustand wiederherstellen.
    pub fn load() -> Self {
        let pool = Self::new();

        // Sequenzstand laden
        if let Ok(data) = fs::read_to_string(seq_state_file()) {
            if let Ok(state) = serde_json::from_str::<SequenceState>(&data) {
                let mut inner = pool.inner.write().unwrap();
                inner.seq_state = state;
            }
        }

        // Pending Messages laden
        if let Ok(data) = fs::read_to_string(pending_file()) {
            if let Ok(messages) = serde_json::from_str::<Vec<PooledMessage>>(&data) {
                let mut inner = pool.inner.write().unwrap();
                for msg in messages {
                    inner.known_ids.insert(msg.msg_id.clone());
                    inner.by_id.insert(msg.msg_id.clone(), msg.clone());
                    inner.queue.push_back(msg);
                }
                println!(
                    "[message_pool] 📂 {} Nachrichten aus Disk geladen, Sequenz bei {}",
                    inner.queue.len(),
                    inner.seq_state.next_sequence
                );
            }
        }

        pool
    }

    // ─── Nachricht aufnehmen ─────────────────────────────────────────────

    /// Neue Nachricht in den Pool aufnehmen.
    ///
    /// Prüft:
    /// 1. Pflichtfelder
    /// 2. TTL-Check (nicht zu alt, nicht zu weit in der Zukunft)
    /// 3. msg_id Integrität
    /// 4. Ed25519 Signatur des Senders
    /// 5. Duplikat-Check
    /// 6. Kapazitäts-Limit
    ///
    /// Bei Erfolg wird eine Sequenznummer vergeben und die Nachricht ist sofort lesbar.
    pub fn add_message(&self, mut msg: PooledMessage) -> Result<u64, PoolError> {
        // 1. Pflichtfelder
        if msg.from_wallet.is_empty() {
            return Err(PoolError::MissingField("from_wallet".into()));
        }
        if msg.to_wallet.is_empty() {
            return Err(PoolError::MissingField("to_wallet".into()));
        }
        if msg.encrypted_content.is_empty() {
            return Err(PoolError::MissingField("encrypted_content".into()));
        }
        if msg.nonce.is_empty() {
            return Err(PoolError::MissingField("nonce".into()));
        }
        if msg.signature.is_empty() {
            return Err(PoolError::MissingField("signature".into()));
        }

        // 2. TTL-Check
        let now = Utc::now().timestamp();
        if msg.timestamp < now - MESSAGE_TTL_SECS {
            return Err(PoolError::Expired {
                age_secs: now - msg.timestamp,
            });
        }
        if msg.timestamp > now + MAX_FUTURE_DRIFT_SECS {
            return Err(PoolError::FutureTimestamp {
                drift_secs: msg.timestamp - now,
            });
        }

        // 3. msg_id Integrität
        let expected_id = PooledMessage::compute_msg_id(
            &msg.from_wallet,
            &msg.to_wallet,
            &msg.encrypted_content,
            &msg.nonce,
            msg.timestamp,
        );
        if msg.msg_id != expected_id {
            return Err(PoolError::InvalidMsgId {
                expected: expected_id,
                got: msg.msg_id,
            });
        }

        // 4. Ed25519 Signatur prüfen
        verify_message_signature(&msg)?;

        // 5. Lite-PoW prüfen (Spam-Filter)
        if !crate::consensus::verify_message_pow(&msg.msg_id, msg.pow_nonce, crate::consensus::MESSAGE_POW_DIFFICULTY) {
            return Err(PoolError::InsufficientPoW);
        }

        // 6 + 7: Lock nehmen für Duplikat + Kapazität
        let mut inner = self.inner.write().unwrap();

        if inner.known_ids.contains(&msg.msg_id) {
            return Err(PoolError::Duplicate(msg.msg_id));
        }

        if inner.queue.len() >= MAX_POOL_SIZE {
            return Err(PoolError::Full);
        }

        // GC: known_ids Cache bereinigen wenn zu groß
        if inner.known_ids.len() > MAX_KNOWN_IDS {
            let active: HashSet<String> = inner.queue.iter().map(|m| m.msg_id.clone()).collect();
            inner.known_ids = active;
        }

        // Sequenznummer vergeben
        let seq = inner.seq_state.next_sequence;
        inner.seq_state.next_sequence += 1;
        msg.sequence = seq;
        msg.status = MessageStatus::Pending;

        // Einfügen
        inner.known_ids.insert(msg.msg_id.clone());
        inner.by_id.insert(msg.msg_id.clone(), msg.clone());
        inner.queue.push_back(msg.clone());

        println!(
            "[message_pool] ✅ Nachricht {} aufgenommen (seq: {}, {} → {})",
            &msg.msg_id[..12],
            seq,
            &msg.from_wallet[..8.min(msg.from_wallet.len())],
            &msg.to_wallet[..8.min(msg.to_wallet.len())],
        );

        // Asynchron persistieren (best-effort)
        drop(inner);
        self.persist();

        Ok(seq)
    }

    // ─── Batch-Drain ─────────────────────────────────────────────────────

    /// Prüft ob ein Batch fällig ist.
    ///
    /// Gibt `true` zurück wenn:
    /// - Mindestens `BATCH_MIN_MESSAGES` pending sind, ODER
    /// - Mindestens 1 pending Message UND `BATCH_MAX_WAIT_SECS` seit letztem Batch vergangen
    pub fn batch_ready(&self) -> bool {
        let inner = self.inner.read().unwrap();
        let pending = inner.queue.len();
        if pending == 0 {
            return false;
        }
        if pending >= BATCH_MIN_MESSAGES {
            return true;
        }
        let now = Utc::now().timestamp();
        now - inner.last_batch_time >= BATCH_MAX_WAIT_SECS
    }

    /// Entnimmt alle pending Nachrichten für einen neuen Batch.
    ///
    /// Aktualisiert den `last_batch_time` Timer und persistiert den Zustand.
    /// Gibt einen leeren Vec zurück wenn keine Nachrichten pending sind.
    pub fn drain_for_batch(&self) -> Vec<PooledMessage> {
        let mut inner = self.inner.write().unwrap();

        if inner.queue.is_empty() {
            return Vec::new();
        }

        let drained: Vec<PooledMessage> = inner.queue.drain(..).collect();
        inner.last_batch_time = Utc::now().timestamp();

        if !drained.is_empty() {
            println!(
                "[message_pool] 📦 {} Nachrichten für Batch entnommen (seq {}-{})",
                drained.len(),
                drained.first().map(|m| m.sequence).unwrap_or(0),
                drained.last().map(|m| m.sequence).unwrap_or(0),
            );
        }

        drop(inner);
        self.persist();

        drained
    }

    // ─── Batch-Bestätigung ───────────────────────────────────────────────

    /// Markiert Nachrichten als gebatcht (Merkle-Batch erstellt, wartet auf Block).
    pub fn mark_batched(&self, msg_ids: &[String], batch_id: &str) {
        let mut inner = self.inner.write().unwrap();
        for id in msg_ids {
            if let Some(msg) = inner.by_id.get_mut(id) {
                msg.status = MessageStatus::Batched {
                    batch_id: batch_id.to_string(),
                };
            }
        }
    }

    /// Gibt alle Nachrichten-IDs zurück die zu einem bestimmten Batch gehören.
    pub fn msg_ids_for_batch(&self, batch_id: &str) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner.by_id.iter()
            .filter(|(_, msg)| matches!(
                &msg.status,
                MessageStatus::Batched { batch_id: bid } if bid == batch_id
            ))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Setzt gebatchte Nachrichten zurück auf Pending (Rollback bei Block-Commit-Fehler).
    pub fn unbatch(&self, batch_id: &str) {
        let mut inner = self.inner.write().unwrap();
        let to_restore: Vec<PooledMessage> = inner.by_id.values()
            .filter(|msg| matches!(&msg.status, MessageStatus::Batched { batch_id: bid } if bid == batch_id))
            .cloned()
            .collect();
        for mut msg in to_restore {
            msg.status = MessageStatus::Pending;
            if let Some(stored) = inner.by_id.get_mut(&msg.msg_id) {
                stored.status = MessageStatus::Pending;
            }
            inner.queue.push_back(msg);
        }
    }

    /// Markiert Nachrichten als bestätigt (Block mit Merkle-Root gemined).
    pub fn mark_confirmed(&self, msg_ids: &[String], block_index: u64) {
        let mut inner = self.inner.write().unwrap();
        for id in msg_ids {
            if let Some(msg) = inner.by_id.get_mut(id) {
                msg.status = MessageStatus::Confirmed { block_index };
            }
        }
        // Bestätigte Sequenz aktualisieren
        let max_seq = msg_ids
            .iter()
            .filter_map(|id| inner.by_id.get(id))
            .map(|m| m.sequence)
            .max();
        if let Some(seq) = max_seq {
            if seq > inner.seq_state.last_confirmed_seq {
                inner.seq_state.last_confirmed_seq = seq;
            }
        }
        inner.seq_state.batch_count += 1;

        drop(inner);
        self.persist();
    }

    // ─── Lese-Operationen (für Chat-Anzeige & P2P) ──────────────────────

    /// Alle Nachrichten für eine Konversation (wallet_a ↔ wallet_b) aus dem Pool.
    /// Enthält Pending + Batched Nachrichten (noch nicht bestätigt).
    pub fn messages_for_conversation(&self, wallet_a: &str, wallet_b: &str) -> Vec<PooledMessage> {
        let inner = self.inner.read().unwrap();
        inner
            .by_id
            .values()
            .filter(|m| {
                (m.from_wallet == wallet_a && m.to_wallet == wallet_b)
                    || (m.from_wallet == wallet_b && m.to_wallet == wallet_a)
            })
            .cloned()
            .collect()
    }

    /// Nachricht nach msg_id abrufen.
    pub fn get_message(&self, msg_id: &str) -> Option<PooledMessage> {
        let inner = self.inner.read().unwrap();
        inner.by_id.get(msg_id).cloned()
    }

    /// Alle Nachrichten ab einer bestimmten Sequenznummer (für P2P-Sync).
    pub fn messages_since(&self, since_seq: u64) -> Vec<PooledMessage> {
        let inner = self.inner.read().unwrap();
        inner
            .by_id
            .values()
            .filter(|m| m.sequence >= since_seq)
            .cloned()
            .collect()
    }

    /// Anzahl der pending Nachrichten im Pool.
    pub fn pending_count(&self) -> usize {
        self.inner.read().unwrap().queue.len()
    }

    /// Alle Nachrichten (pending + batched) für eine Wallet-Adresse.
    /// Enthält sowohl gesendete als auch empfangene Nachrichten.
    pub fn pending_for_wallet(&self, wallet: &str) -> Vec<PooledMessage> {
        let inner = self.inner.read().unwrap();
        inner.by_id.values()
            .filter(|m| {
                (m.from_wallet == wallet || m.to_wallet == wallet)
                    && !matches!(m.status, MessageStatus::Confirmed { .. })
            })
            .cloned()
            .collect()
    }

    /// Gesamtzahl bekannter Nachrichten (pending + batched + confirmed im Cache).
    pub fn total_count(&self) -> usize {
        self.inner.read().unwrap().by_id.len()
    }

    /// Aktueller Sequenzstand.
    pub fn sequence_state(&self) -> SequenceState {
        self.inner.read().unwrap().seq_state.clone()
    }

    // ─── Eviction ────────────────────────────────────────────────────────

    /// Entfernt abgelaufene Nachrichten aus dem Pool.
    /// Bestätigte Nachrichten die älter als TTL sind werden ebenfalls entfernt
    /// (sie existieren ja kryptografisch beweisbar in der Chain).
    pub fn evict_expired(&self) -> usize {
        let now = Utc::now().timestamp();
        let cutoff = now - MESSAGE_TTL_SECS;

        let mut inner = self.inner.write().unwrap();
        let before = inner.by_id.len();

        // Queue: nur noch nicht-abgelaufene behalten
        inner.queue.retain(|m| m.timestamp >= cutoff);

        // by_id: bestätigte + abgelaufene entfernen
        inner.by_id.retain(|_, m| {
            if m.timestamp < cutoff {
                if let MessageStatus::Confirmed { .. } = m.status {
                    return false; // bestätigt + alt → raus
                }
                // Pending/Batched + alt: auch raus (sollte nicht vorkommen, aber sicher ist sicher)
                return false;
            }
            true
        });

        let evicted = before - inner.by_id.len();
        if evicted > 0 {
            println!(
                "[message_pool] 🗑️  {evicted} abgelaufene Nachrichten entfernt, {} verbleibend",
                inner.by_id.len()
            );
        }
        evicted
    }

    // ─── Batch Records (für Proof-Generierung) ─────────────────────────

    /// Speichert ein Batch-Record auf Disk für spätere Merkle-Proof-Generierung.
    ///
    /// Enthält die geordnete Liste der Nachrichten-IDs und Leaf-Hashes,
    /// damit der MerkleTree jederzeit rekonstruiert werden kann.
    pub fn store_batch_record(&self, merkle_root: &str, messages: &[PooledMessage], block_index: u64) {
        let entries: Vec<BatchLeafEntry> = messages.iter().map(|m| BatchLeafEntry {
            msg_id: m.msg_id.clone(),
            sequence: m.sequence,
            leaf_hash: hex::encode(m.leaf_hash()),
        }).collect();
        let record = BatchRecord {
            merkle_root: merkle_root.to_string(),
            block_index,
            entries,
            messages: messages.to_vec(),
        };
        let dir = batches_dir();
        let _ = fs::create_dir_all(&dir);
        if let Ok(json) = serde_json::to_string(&record) {
            let _ = fs::write(format!("{}/{}.json", dir, merkle_root), json);
        }
    }

    /// Lädt ein Batch-Record von Disk.
    pub fn load_batch_record(&self, merkle_root: &str) -> Option<BatchRecord> {
        let path = format!("{}/{}.json", batches_dir(), merkle_root);
        let data = fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Lädt die vollen Nachrichten aus einem persistierten Batch-Record.
    /// Fallback für ChatIndex-Rebuild wenn Pool leer ist.
    pub fn load_batch_messages(&self, merkle_root: &str) -> Vec<PooledMessage> {
        self.load_batch_record(merkle_root)
            .map(|r| r.messages)
            .unwrap_or_default()
    }

    /// Alle Nachrichten in einem Sequenzbereich (inkl. start und end).
    pub fn messages_in_seq_range(&self, seq_start: u64, seq_end: u64) -> Vec<PooledMessage> {
        let inner = self.inner.read().unwrap();
        let mut msgs: Vec<PooledMessage> = inner.by_id.values()
            .filter(|m| m.sequence >= seq_start && m.sequence <= seq_end)
            .cloned()
            .collect();
        msgs.sort_by_key(|m| m.sequence);
        msgs
    }

    // ─── Persistenz ──────────────────────────────────────────────────────

    /// Speichert den aktuellen Zustand auf Disk.
    fn persist(&self) {
        let inner = self.inner.read().unwrap();
        let dir = pool_dir();
        let _ = fs::create_dir_all(&dir);

        // Sequenzstand
        if let Ok(json) = serde_json::to_string(&inner.seq_state) {
            let _ = fs::write(seq_state_file(), json);
        }

        // Pending Queue
        let pending: Vec<&PooledMessage> = inner.queue.iter().collect();
        if let Ok(json) = serde_json::to_string(&pending) {
            let _ = fs::write(pending_file(), json);
        }
    }
}

// ─── Batch-Record (persistiert für Proof-Generierung) ────────────────────────

/// Ein persistiertes Batch-Record für spätere Merkle-Proof-Generierung.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchRecord {
    pub merkle_root: String,
    pub block_index: u64,
    pub entries: Vec<BatchLeafEntry>,
    /// Volle Nachrichteninhalte (für ChatIndex-Rebuild nach Restart).
    /// Optional für Rückwärtskompatibilität mit alten Batch-Records.
    #[serde(default)]
    pub messages: Vec<PooledMessage>,
}

/// Ein einzelner Leaf-Eintrag im Batch-Record.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchLeafEntry {
    pub msg_id: String,
    pub sequence: u64,
    pub leaf_hash: String,
}

// ─── Signatur-Verifizierung ──────────────────────────────────────────────────

/// Verifiziert die Ed25519-Signatur einer Pool-Nachricht.
///
/// Der Sender signiert `SHA-256(msg_id)` mit seinem Wallet-Key.
fn verify_message_signature(msg: &PooledMessage) -> Result<(), PoolError> {
    // Public Key aus Hex
    let pub_bytes = hex::decode(&msg.from_wallet).map_err(|e| {
        PoolError::InvalidSignature(format!("from_wallet kein gültiges Hex: {e}"))
    })?;
    if pub_bytes.len() != 32 {
        return Err(PoolError::InvalidSignature(format!(
            "Public Key muss 32 Byte sein, ist aber {} Byte",
            pub_bytes.len()
        )));
    }
    let verifying_key = VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap())
        .map_err(|e| PoolError::InvalidSignature(format!("Ungültiger Ed25519-Key: {e}")))?;

    // Signatur aus Hex
    let sig_bytes = hex::decode(&msg.signature).map_err(|e| {
        PoolError::InvalidSignature(format!("Signatur kein gültiges Hex: {e}"))
    })?;
    if sig_bytes.len() != 64 {
        return Err(PoolError::InvalidSignature(format!(
            "Signatur muss 64 Byte sein, ist aber {} Byte",
            sig_bytes.len()
        )));
    }
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    // Verifiziere: sign(SHA-256(msg_id))
    let hash = Sha256::digest(msg.msg_id.as_bytes());
    verifying_key
        .verify(&hash, &signature)
        .map_err(|_| PoolError::InvalidSignature("Ed25519-Verifikation fehlgeschlagen".into()))
}

// ─── Dateipfade ──────────────────────────────────────────────────────────────

fn pool_dir() -> String {
    format!("{}/message_pool", data_dir())
}

fn seq_state_file() -> String {
    format!("{}/sequence.json", pool_dir())
}

fn pending_file() -> String {
    format!("{}/pending.json", pool_dir())
}

fn batches_dir() -> String {
    format!("{}/batches", pool_dir())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::ed25519::signature::Signer;
    use rand::rngs::OsRng;

    /// Erstellt eine gültige Test-Nachricht mit echtem Ed25519-Schlüssel.
    /// Jeder Aufruf erzeugt eine eindeutige Nachricht (zufälliger Nonce).
    fn make_test_message(signing_key: &SigningKey, to_wallet: &str) -> PooledMessage {
        let from_wallet = hex::encode(signing_key.verifying_key().to_bytes());
        let encrypted_content = "dGVzdA==".to_string(); // base64("test")
        // Zufälliger Nonce für Eindeutigkeit (rand::random nutzt thread_rng)
        let nonce = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let timestamp = Utc::now().timestamp();

        let msg_id = PooledMessage::compute_msg_id(
            &from_wallet,
            to_wallet,
            &encrypted_content,
            &nonce,
            timestamp,
        );

        // Signiere SHA-256(msg_id) mit dem Sender-Key
        let hash = Sha256::digest(msg_id.as_bytes());
        let signature = signing_key.sign(&hash);

        // Lite-PoW lösen (Spam-Filter)
        let pow_nonce = crate::consensus::solve_message_pow(&msg_id, crate::consensus::MESSAGE_POW_DIFFICULTY);

        PooledMessage {
            msg_id,
            sequence: 0,
            from_wallet,
            to_wallet: to_wallet.to_string(),
            from_user_id: "test-user".into(),
            from_name: "Test User".into(),
            encrypted_content,
            nonce,
            timestamp,
            signature: hex::encode(signature.to_bytes()),
            pow_nonce,
            status: MessageStatus::Pending,
        }
    }

    #[test]
    fn test_add_message_and_sequence() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]); // dummy wallet

        let msg = make_test_message(&key, &to);
        let seq = pool.add_message(msg).unwrap();
        assert_eq!(seq, 1);

        let msg2 = make_test_message(&key, &to);
        let seq2 = pool.add_message(msg2).unwrap();
        assert_eq!(seq2, 2);

        assert_eq!(pool.pending_count(), 2);
    }

    #[test]
    fn test_duplicate_rejected() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        let msg = make_test_message(&key, &to);
        let msg_clone = msg.clone();
        pool.add_message(msg).unwrap();

        let err = pool.add_message(msg_clone);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), PoolError::Duplicate(_)));
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        let mut msg = make_test_message(&key, &to);
        // Signatur manipulieren
        msg.signature = hex::encode([0u8; 64]);

        let err = pool.add_message(msg);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), PoolError::InvalidSignature(_)));
    }

    #[test]
    fn test_invalid_msg_id_rejected() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        let mut msg = make_test_message(&key, &to);
        msg.msg_id = "fake_id_1234567890abcdef".to_string();

        let err = pool.add_message(msg);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), PoolError::InvalidMsgId { .. }));
    }

    #[test]
    fn test_drain_for_batch() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        for _ in 0..5 {
            let msg = make_test_message(&key, &to);
            pool.add_message(msg).unwrap();
        }

        assert_eq!(pool.pending_count(), 5);
        let batch = pool.drain_for_batch();
        assert_eq!(batch.len(), 5);
        assert_eq!(pool.pending_count(), 0);
    }

    #[test]
    fn test_batch_ready_by_count() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        assert!(!pool.batch_ready());

        for _ in 0..BATCH_MIN_MESSAGES {
            let msg = make_test_message(&key, &to);
            pool.add_message(msg).unwrap();
        }

        assert!(pool.batch_ready());
    }

    #[test]
    fn test_mark_confirmed() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        let msg = make_test_message(&key, &to);
        let msg_id = msg.msg_id.clone();
        pool.add_message(msg).unwrap();

        pool.drain_for_batch();
        pool.mark_batched(&[msg_id.clone()], "batch_001");

        let fetched = pool.get_message(&msg_id).unwrap();
        assert!(matches!(fetched.status, MessageStatus::Batched { .. }));

        pool.mark_confirmed(&[msg_id.clone()], 42);
        let fetched = pool.get_message(&msg_id).unwrap();
        assert!(matches!(
            fetched.status,
            MessageStatus::Confirmed { block_index: 42 }
        ));

        let state = pool.sequence_state();
        assert_eq!(state.last_confirmed_seq, 1);
        assert_eq!(state.batch_count, 1);
    }

    #[test]
    fn test_messages_for_conversation() {
        let pool = MessagePool::new();
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let wallet_a = hex::encode(key_a.verifying_key().to_bytes());
        let wallet_b = hex::encode(key_b.verifying_key().to_bytes());

        // A → B
        let msg1 = make_test_message(&key_a, &wallet_b);
        pool.add_message(msg1).unwrap();

        // B → A
        let msg2 = make_test_message(&key_b, &wallet_a);
        pool.add_message(msg2).unwrap();

        let conv = pool.messages_for_conversation(&wallet_a, &wallet_b);
        assert_eq!(conv.len(), 2);
    }

    #[test]
    fn test_messages_since_sequence() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        for _ in 0..5 {
            let msg = make_test_message(&key, &to);
            pool.add_message(msg).unwrap();
        }

        let since = pool.messages_since(3);
        assert_eq!(since.len(), 3); // seq 3, 4, 5
    }

    #[test]
    fn test_leaf_hash_deterministic() {
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);
        let msg = make_test_message(&key, &to);

        let h1 = msg.leaf_hash();
        let h2 = msg.leaf_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_expired_message_rejected() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let from_wallet = hex::encode(key.verifying_key().to_bytes());
        let to = hex::encode([0u8; 32]);
        let encrypted = "dGVzdA==".to_string();
        let nonce = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let old_timestamp = Utc::now().timestamp() - MESSAGE_TTL_SECS - 100;

        let msg_id =
            PooledMessage::compute_msg_id(&from_wallet, &to, &encrypted, &nonce, old_timestamp);
        let hash = Sha256::digest(msg_id.as_bytes());
        let signature = key.sign(&hash);

        let msg = PooledMessage {
            msg_id,
            sequence: 0,
            from_wallet,
            to_wallet: to,
            from_user_id: String::new(),
            from_name: String::new(),
            encrypted_content: encrypted,
            nonce,
            timestamp: old_timestamp,
            signature: hex::encode(signature.to_bytes()),
            pow_nonce: 0, // TTL check fires before PoW check, so no valid PoW needed
            status: MessageStatus::Pending,
        };

        let err = pool.add_message(msg);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), PoolError::Expired { .. }));
    }

    #[test]
    fn test_messages_in_seq_range() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        // 3 Nachrichten hinzufügen (seq 1, 2, 3)
        for _ in 0..3 {
            let msg = make_test_message(&key, &to);
            pool.add_message(msg).unwrap();
        }

        let range = pool.messages_in_seq_range(1, 2);
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].sequence, 1);
        assert_eq!(range[1].sequence, 2);

        let all = pool.messages_in_seq_range(1, 3);
        assert_eq!(all.len(), 3);

        let empty = pool.messages_in_seq_range(10, 20);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_batch_record_roundtrip() {
        let pool = MessagePool::new();
        let key = SigningKey::generate(&mut OsRng);
        let to = hex::encode([0u8; 32]);

        let msg = make_test_message(&key, &to);
        let msg_id = msg.msg_id.clone();
        pool.add_message(msg).unwrap();

        let msgs = pool.messages_in_seq_range(1, 1);
        assert_eq!(msgs.len(), 1);

        let root = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        pool.store_batch_record(root, &msgs, 42);

        let record = pool.load_batch_record(root);
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.merkle_root, root);
        assert_eq!(record.block_index, 42);
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.entries[0].msg_id, msg_id);
        assert_eq!(record.entries[0].sequence, 1);
    }
}
