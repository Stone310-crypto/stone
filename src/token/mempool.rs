//! StoneCoin Mempool
//!
//! Thread-sichere Warteschlange für eingehende Token-Transaktionen.
//!
//! ## Ablauf
//!
//! 1. Nutzer reicht signierte TX über `/api/v1/token/transfer` ein
//! 2. TX wird strukturell validiert (Signatur, TX-ID, Nonce-Prüfung gegen Ledger)
//! 3. TX landet im Mempool (pending)
//! 4. Beim nächsten Block-Commit (`commit_documents`) werden alle pending TXs
//!    aus dem Mempool geholt und in den neuen Block eingefügt
//! 5. Erst dann wird der Ledger aktualisiert
//!
//! ## Duplikat-Schutz
//!
//! Jede TX-ID wird in einem HashSet nachgehalten. Doppelte TXs werden abgelehnt.
//!
//! ## Kapazitäts-Limit
//!
//! Maximal `MAX_MEMPOOL_SIZE` TXs gleichzeitig im Mempool. Darüber wird
//! die Aufnahme verweigert.
//!
//! ## TTL & Eviction
//!
//! TXs die älter als `TX_TTL_SECS` (1 Stunde) sind werden bei `evict_expired()`
//! automatisch entfernt. Der bekannte TX-ID-Cache (`known_ids`) wird ebenfalls
//! periodisch bereinigt wenn er zu groß wird.

use std::collections::{HashSet, VecDeque};
use std::sync::RwLock;

use super::transaction::{TokenTx, TxError, validate_tx};
use super::ledger::TokenLedger;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Maximale Anzahl von TXs im Mempool
pub const MAX_MEMPOOL_SIZE: usize = 10_000;

/// Maximale TXs pro Block
pub const MAX_TXS_PER_BLOCK: usize = 500;

/// TX Time-To-Live: TXs die älter als 1 Stunde sind werden verworfen
pub const TX_TTL_SECS: i64 = 3600;

/// Maximale Größe des known_ids Cache bevor GC einsetzt
const MAX_KNOWN_IDS: usize = 50_000;

// ─── Mempool-Fehler ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum MempoolError {
    /// TX ist strukturell ungültig
    Validation(TxError),
    /// TX-ID ist bereits im Mempool oder in der Chain
    Duplicate(String),
    /// Mempool ist voll
    Full,
    /// Sender hat nicht genug Balance (Pre-Check)
    InsufficientBalance(String),
    /// Nonce passt nicht (Pre-Check gegen Ledger)
    InvalidNonce { expected: u64, got: u64 },
    /// TX ist abgelaufen (älter als TX_TTL_SECS)
    Expired { age_secs: i64, max_secs: i64 },
    /// TX-Timestamp liegt zu weit in der Zukunft
    FutureTimestamp { drift_secs: i64 },
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::Validation(e) => write!(f, "TX-Validierung: {e}"),
            MempoolError::Duplicate(id) => write!(f, "TX {} ist bereits bekannt", &id[..12.min(id.len())]),
            MempoolError::Full => write!(f, "Mempool ist voll ({MAX_MEMPOOL_SIZE} TXs)"),
            MempoolError::InsufficientBalance(s) => write!(f, "Ungenügendes Guthaben: {s}"),
            MempoolError::InvalidNonce { expected, got } => {
                write!(f, "Ungültige Nonce: erwartet {expected}, empfangen {got}")
            }
            MempoolError::Expired { age_secs, max_secs } => {
                write!(f, "TX abgelaufen: {age_secs}s alt (max {max_secs}s)")
            }
            MempoolError::FutureTimestamp { drift_secs } => {
                write!(f, "TX-Timestamp liegt {drift_secs}s in der Zukunft (max 300s)")
            }
        }
    }
}

impl From<TxError> for MempoolError {
    fn from(e: TxError) -> Self {
        MempoolError::Validation(e)
    }
}

// ─── Mempool ─────────────────────────────────────────────────────────────────

/// Thread-sichere TX-Warteschlange.
///
/// Intern geschützt durch `RwLock` – lesen (pending count) ist billig,
/// schreiben (add/drain) ist exklusiv.
pub struct Mempool {
    inner: RwLock<MempoolInner>,
}

struct MempoolInner {
    /// Pending TXs in Eingangs-Reihenfolge (FIFO)
    queue: VecDeque<TokenTx>,
    /// Bekannte TX-IDs (Duplikat-Schutz)
    known_ids: HashSet<String>,
}

impl Mempool {
    /// Neuen leeren Mempool erstellen.
    pub fn new() -> Self {
        Mempool {
            inner: RwLock::new(MempoolInner {
                queue: VecDeque::new(),
                known_ids: HashSet::new(),
            }),
        }
    }

    /// TX in den Mempool aufnehmen.
    ///
    /// Prüft:
    /// 1. Strukturelle Validierung (TX-ID, Signatur)
    /// 2. TTL-Check (TX darf nicht älter als TX_TTL_SECS sein)
    /// 3. Duplikat-Check
    /// 4. Kapazitäts-Limit
    /// 5. Pre-Check gegen Ledger (Balance, Nonce) – optional, bei Aufruf mit Ledger
    pub fn add_tx(&self, tx: TokenTx, ledger: Option<&TokenLedger>) -> Result<(), MempoolError> {
        // 1. Strukturelle Validierung
        validate_tx(&tx)?;

        // 2. TTL-Check: TX darf nicht zu alt sein
        let now = chrono::Utc::now().timestamp();
        if tx.timestamp < now - TX_TTL_SECS {
            return Err(MempoolError::Expired {
                age_secs: now - tx.timestamp,
                max_secs: TX_TTL_SECS,
            });
        }
        // TX darf auch nicht zu weit in der Zukunft liegen (5 Min Toleranz)
        if tx.timestamp > now + 300 {
            return Err(MempoolError::FutureTimestamp {
                drift_secs: tx.timestamp - now,
            });
        }

        let mut inner = self.inner.write().unwrap();

        // 2. Duplikat-Check
        if inner.known_ids.contains(&tx.tx_id) {
            return Err(MempoolError::Duplicate(tx.tx_id.clone()));
        }

        // 3. Kapazitäts-Limit
        if inner.queue.len() >= MAX_MEMPOOL_SIZE {
            return Err(MempoolError::Full);
        }

        // 4. Ledger Pre-Check (optional aber empfohlen)
        if let Some(ledger) = ledger {
            // Nonce prüfen – berücksichtige bereits im Mempool befindliche TXs vom selben Sender
            let base_nonce = ledger.nonce(&tx.from);
            let pending_from_sender = inner.queue.iter()
                .filter(|ptx| ptx.from == tx.from)
                .count() as u64;
            let expected_nonce = base_nonce + pending_from_sender;

            if tx.nonce != expected_nonce {
                return Err(MempoolError::InvalidNonce {
                    expected: expected_nonce,
                    got: tx.nonce,
                });
            }

            // Balance prüfen (grob – berücksichtigt pending TXs)
            let pending_debit: rust_decimal::Decimal = inner.queue.iter()
                .filter(|ptx| ptx.from == tx.from)
                .map(|ptx| ptx.amount + ptx.fee)
                .sum();
            let available = ledger.balance(&tx.from) - pending_debit;
            let required = tx.amount + tx.fee;

            if available < required {
                return Err(MempoolError::InsufficientBalance(format!(
                    "{} hat {} verfügbar (nach pending TXs), benötigt {}",
                    &tx.from[..12.min(tx.from.len())],
                    available,
                    required
                )));
            }
        }

        println!(
            "[mempool] ✅ TX {} aufgenommen ({} → {}, {} STONE)",
            &tx.tx_id[..12],
            &tx.from[..8.min(tx.from.len())],
            &tx.to[..8.min(tx.to.len())],
            tx.amount,
        );

        inner.known_ids.insert(tx.tx_id.clone());
        inner.queue.push_back(tx);

        Ok(())
    }

    /// Alle pending TXs für den nächsten Block abrufen und aus dem Mempool entfernen.
    ///
    /// Gibt maximal `MAX_TXS_PER_BLOCK` TXs zurück.
    pub fn drain_for_block(&self) -> Vec<TokenTx> {
        let mut inner = self.inner.write().unwrap();
        let count = inner.queue.len().min(MAX_TXS_PER_BLOCK);
        let txs: Vec<TokenTx> = inner.queue.drain(..count).collect();

        // known_ids NICHT entfernen – verhindert Replay innerhalb der Session
        // (Die Chain hat eigenen Duplikat-Check über den Ledger)

        if !txs.is_empty() {
            println!("[mempool] 📦 {} TXs für Block entnommen, {} verbleibend",
                txs.len(), inner.queue.len());
        }
        txs
    }

    /// TX aus dem Mempool entfernen (z.B. nach Block-Commit durch Peer).
    pub fn remove_tx(&self, tx_id: &str) {
        let mut inner = self.inner.write().unwrap();
        inner.queue.retain(|tx| tx.tx_id != tx_id);
        // known_ids behalten für Duplikat-Schutz
    }

    /// Alle TXs eines bestimmten Senders entfernen (z.B. nach Nonce-Reset).
    pub fn remove_sender_txs(&self, sender: &str) {
        let mut inner = self.inner.write().unwrap();
        inner.queue.retain(|tx| tx.from != sender);
    }

    /// Anzahl der pending TXs.
    pub fn pending_count(&self) -> usize {
        self.inner.read().unwrap().queue.len()
    }

    /// Alle pending TXs als Snapshot (für API).
    pub fn pending_txs(&self) -> Vec<TokenTx> {
        self.inner.read().unwrap().queue.iter().cloned().collect()
    }

    /// Bekannte TX-ID prüfen (Duplikat-Check von außen).
    pub fn is_known(&self, tx_id: &str) -> bool {
        self.inner.read().unwrap().known_ids.contains(tx_id)
    }

    /// TX-ID als bekannt markieren (z.B. wenn sie aus einem Peer-Block kommt).
    pub fn mark_known(&self, tx_id: &str) {
        self.inner.write().unwrap().known_ids.insert(tx_id.to_string());
    }

    // ── TTL & Eviction ────────────────────────────────────────────────────

    /// Entfernt alle TXs aus dem Mempool deren Timestamp älter als `TX_TTL_SECS` ist.
    ///
    /// Gibt die Anzahl der entfernten TXs zurück.
    /// Sollte periodisch aufgerufen werden (z.B. alle 60 Sekunden via Tokio-Intervall).
    pub fn evict_expired(&self) -> usize {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - TX_TTL_SECS;

        let mut inner = self.inner.write().unwrap();
        let before = inner.queue.len();
        inner.queue.retain(|tx| tx.timestamp >= cutoff);
        let evicted = before - inner.queue.len();

        if evicted > 0 {
            println!("[mempool] 🗑️  {evicted} abgelaufene TXs entfernt, {} verbleibend", inner.queue.len());
        }

        evicted
    }

    /// Bereinigt den `known_ids` Cache wenn er zu groß wird.
    ///
    /// Behält nur TX-IDs die noch in der Queue sind + die neuesten Einträge.
    /// Sollte periodisch aufgerufen werden (z.B. alle 5 Minuten).
    pub fn gc_known_ids(&self) -> usize {
        let mut inner = self.inner.write().unwrap();
        if inner.known_ids.len() <= MAX_KNOWN_IDS {
            return 0;
        }

        // Alle TX-IDs die noch in der Queue sind behalten
        let active_ids: HashSet<String> = inner.queue.iter().map(|tx| tx.tx_id.clone()).collect();
        let before = inner.known_ids.len();
        inner.known_ids = active_ids;
        let removed = before - inner.known_ids.len();

        if removed > 0 {
            println!("[mempool] 🧹 known_ids GC: {removed} alte Einträge entfernt, {} verbleibend", inner.known_ids.len());
        }

        removed
    }

    /// Statistiken für Monitoring/API.
    pub fn stats(&self) -> MempoolStats {
        let inner = self.inner.read().unwrap();
        let now = chrono::Utc::now().timestamp();

        let oldest_age = inner.queue.front().map(|tx| now - tx.timestamp).unwrap_or(0);
        let newest_age = inner.queue.back().map(|tx| now - tx.timestamp).unwrap_or(0);

        MempoolStats {
            pending_count: inner.queue.len(),
            known_ids_count: inner.known_ids.len(),
            oldest_tx_age_secs: oldest_age,
            newest_tx_age_secs: newest_age,
            max_size: MAX_MEMPOOL_SIZE,
            max_per_block: MAX_TXS_PER_BLOCK,
            ttl_secs: TX_TTL_SECS,
        }
    }
}

// ─── Mempool-Statistiken ─────────────────────────────────────────────────────

/// Mempool-Status für Monitoring und API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MempoolStats {
    pub pending_count: usize,
    pub known_ids_count: usize,
    pub oldest_tx_age_secs: i64,
    pub newest_tx_age_secs: i64,
    pub max_size: usize,
    pub max_per_block: usize,
    pub ttl_secs: i64,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}
