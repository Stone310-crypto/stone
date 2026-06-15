//! Hash Time-Locked Contracts (HTLC) für Atomic Swaps.
//!
//! Ein HTLC sperrt STONE-Coins in einem Escrow, die nur mit einem Geheimnis
//! (preimage) vor Ablauf des Timelocks eingelöst werden können.
//!
//! ## Flow (Atomic Swap STONE ↔ TC$)
//!
//! 1. Alice generiert `secret`, berechnet `hash = SHA-256(secret)`
//! 2. Alice erstellt HTLC: sperrt TC$ mit `hash_lock` + `time_lock = 24h`
//! 3. Bob sieht Hash, erstellt HTLC: sperrt STONE mit gleichem `hash_lock` + `time_lock = 12h`
//! 4. Alice claimed Bobs STONE mit `secret` → Bob sieht `secret` on-chain
//! 5. Bob claimed Alices TC$ mit `secret`
//!
//! ## Sicherheit
//!
//! - Ohne korrektes Preimage kein Claim möglich (SHA-256 Collision-Resistant)
//! - Time-Lock-Asymmetrie: Initiator (Alice) hat längeren Lock → kann nicht betrügen
//! - Automatischer Refund nach Timeout → kein Coin-Verlust
//! - Status-Prüfung verhindert Double-Claim
//!
//! ## Entfernbarkeit
//!
//! Um HTLC zu entfernen: Diese Datei löschen + TxType-Varianten entfernen
//! + Ledger apply_tx()-Arms entfernen + API-Handler entfernen + mod.rs bereinigen.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Escrow-Pool-Adresse für HTLC-gesperrte STONE-Coins.
pub const HTLC_ESCROW_POOL: &str = "pool:htlc_escrow";

/// Minimale Time-Lock-Dauer in Sekunden (10 Minuten).
pub const MIN_TIMELOCK_SECS: i64 = 600;

/// Maximale Time-Lock-Dauer in Sekunden (7 Tage).
pub const MAX_TIMELOCK_SECS: i64 = 7 * 24 * 3600;

/// Maximale Anzahl aktiver HTLCs pro Adresse.
pub const MAX_ACTIVE_PER_ADDRESS: usize = 20;

/// Unterstützte Payment-Chains für P2P-Trades.
pub const SUPPORTED_CHAINS: &[&str] = &["ethereum", "polygon", "bsc", "arbitrum", "base"];

/// Unterstützte Payment-Assets.
pub const SUPPORTED_ASSETS: &[&str] = &["USDT", "USDC", "ETH", "BTC", "BNB", "MATIC", "DAI"];

// ─── Typen ───────────────────────────────────────────────────────────────────

/// Status eines HTLC-Vertrags.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HtlcStatus {
    /// Coins sind gesperrt, warten auf Preimage oder Timeout.
    Locked,
    /// Preimage wurde enthüllt, Coins an Empfänger übertragen.
    Claimed,
    /// Timeout erreicht, Coins zurück an Sender.
    Refunded,
}

/// Ein Hash Time-Locked Contract.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HtlcContract {
    /// Eindeutige ID (= TX-ID der HtlcCreate-Transaktion).
    pub id: String,
    /// Sender (Ersteller) – bekommt Coins zurück bei Timeout.
    pub sender: String,
    /// Empfänger – bekommt Coins bei korrektem Preimage.
    pub receiver: String,
    /// Gesperrter Betrag in STONE.
    pub amount: Decimal,
    /// SHA-256 Hash des Geheimnisses (32 Byte, hex-kodiert).
    pub hash_lock: String,
    /// Unix-Timestamp: Ab diesem Zeitpunkt ist Refund möglich.
    pub time_lock: i64,
    /// Aktueller Status.
    pub status: HtlcStatus,
    /// Block-Index bei Erstellung.
    pub created_at_block: u64,
    /// TX-ID der Claim- oder Refund-Transaktion (falls abgeschlossen).
    pub settlement_tx: Option<String>,
    /// Preimage (nur nach Claim gesetzt, für On-Chain-Transparenz).
    pub preimage: Option<String>,
    /// Preisinformation für P2P-Trades (optional).
    #[serde(default)]
    pub price: Option<TradePrice>,
}

/// Preisinformation für einen P2P-Trade.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TradePrice {
    /// Gefordeter Betrag in externer Währung (z.B. "10.00").
    pub amount: String,
    /// Asset/Token-Name (z.B. "USDT", "USDC", "ETH").
    pub asset: String,
    /// Blockchain-Netzwerk (z.B. "polygon", "ethereum", "bsc").
    pub chain: String,
}

/// Status eines laufenden Kaufvorgangs mit Zahlungsverifizierung.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BuyStatus {
    /// Käufer hat Kauf initiiert, wartet auf Zahlung.
    WaitingForPayment,
    /// Zahlung erkannt, wird bestätigt.
    PaymentDetected,
    /// Zahlung bestätigt, HTLC wird geclaimed.
    PaymentConfirmed,
    /// STONE wurden übertragen.
    Completed,
    /// Zahlung nicht rechtzeitig eingegangen.
    Expired,
    /// Fehler bei der Abwicklung.
    Failed(String),
}

/// Ein laufender Kaufvorgang (Pending Buy).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingBuy {
    /// Eindeutige Buy-ID.
    pub buy_id: String,
    /// Zugehörige HTLC-ID.
    pub htlc_id: String,
    /// Wallet-Adresse des Käufers (Stone-Adresse).
    pub buyer: String,
    /// Erwarteter Zahlungsbetrag.
    pub expected_amount: String,
    /// Erwartetes Asset (z.B. "USDT").
    pub expected_asset: String,
    /// Erwartete Chain (z.B. "polygon").
    pub expected_chain: String,
    /// Gnosis Safe Adresse, an die gezahlt werden soll.
    pub safe_address: String,
    /// Aktueller Status.
    pub status: BuyStatus,
    /// Zeitstempel der Erstellung.
    pub created_at: i64,
    /// Ablaufzeit (nach der der Buy verfällt).
    pub expires_at: i64,
    /// TX-Hash der externen Zahlung (wenn erkannt).
    pub payment_tx_hash: Option<String>,
    /// TX-ID der STONE-Übertragung (wenn abgeschlossen).
    pub claim_tx_id: Option<String>,
}

// ─── Fehler ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum HtlcError {
    /// HTLC-ID nicht gefunden.
    NotFound(String),
    /// HTLC ist nicht im Status Locked.
    InvalidStatus(String),
    /// Preimage passt nicht zum Hash-Lock.
    InvalidPreimage,
    /// Time-Lock ist noch nicht abgelaufen (für Refund).
    TimeLockNotExpired { expires_at: i64, now: i64 },
    /// Time-Lock ist bereits abgelaufen (für Claim).
    TimeLockExpired { expired_at: i64, now: i64 },
    /// Time-Lock-Dauer ungültig.
    InvalidTimeLock(String),
    /// Hash-Lock ungültig (nicht 64 Hex-Zeichen = 32 Byte).
    InvalidHashLock(String),
    /// Zu viele aktive HTLCs für diese Adresse.
    TooManyActive { address: String, limit: usize },
    /// Betrag ungültig.
    InvalidAmount(String),
    /// Nur der Sender darf refunden.
    UnauthorizedRefund,
    /// Nur der Empfänger darf claimen.
    UnauthorizedClaim,
    /// Persistierungsfehler.
    Persistence(String),
}

impl std::fmt::Display for HtlcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HtlcError::NotFound(id) => write!(f, "HTLC nicht gefunden: {}", id),
            HtlcError::InvalidStatus(s) => write!(f, "HTLC Status ungültig: {}", s),
            HtlcError::InvalidPreimage => write!(f, "Preimage passt nicht zum Hash-Lock"),
            HtlcError::TimeLockNotExpired { expires_at, now } =>
                write!(f, "Time-Lock läuft erst in {}s ab", expires_at - now),
            HtlcError::TimeLockExpired { expired_at, now } =>
                write!(f, "Time-Lock ist seit {}s abgelaufen", now - expired_at),
            HtlcError::InvalidTimeLock(msg) => write!(f, "Ungültiger Time-Lock: {}", msg),
            HtlcError::InvalidHashLock(msg) => write!(f, "Ungültiger Hash-Lock: {}", msg),
            HtlcError::TooManyActive { address, limit } =>
                write!(f, "Adresse {} hat bereits {} aktive HTLCs", &address[..12.min(address.len())], limit),
            HtlcError::InvalidAmount(msg) => write!(f, "Ungültiger Betrag: {}", msg),
            HtlcError::UnauthorizedRefund => write!(f, "Nur der Sender darf einen Refund auslösen"),
            HtlcError::UnauthorizedClaim => write!(f, "Nur der Empfänger darf einen Claim auslösen"),
            HtlcError::Persistence(msg) => write!(f, "HTLC Persistierungsfehler: {}", msg),
        }
    }
}

impl std::error::Error for HtlcError {}

// ─── HTLC Store ──────────────────────────────────────────────────────────────

/// Verwaltet alle HTLC-Verträge (In-Memory + RocksDB-Persistierung).
///
/// Folgt dem gleichen Pattern wie `TokenLedger`:
/// - In-Memory HashMap für schnellen Zugriff
/// - `persist()` schreibt in RocksDB (`htlc/{id}`)
/// - `load()` lädt beim Startup aus RocksDB
pub struct HtlcStore {
    /// Aktive und abgeschlossene HTLCs: ID → Contract
    contracts: HashMap<String, HtlcContract>,
    /// Gespeicherte Preimages für offene Trades (Server-seitig für Auto-Buy)
    escrowed_preimages: HashMap<String, String>,
    /// Laufende Kaufvorgänge mit Zahlungsverifizierung: buy_id → PendingBuy
    pending_buys: HashMap<String, PendingBuy>,
}

impl HtlcStore {
    /// Neuen leeren Store erstellen.
    pub fn new() -> Self {
        HtlcStore {
            contracts: HashMap::new(),
            escrowed_preimages: HashMap::new(),
            pending_buys: HashMap::new(),
        }
    }

    /// Lädt alle HTLCs aus RocksDB (CF: htlc, Fallback: default).
    pub fn load() -> Self {
        let mut store = HtlcStore::new();

        let db = match super::open_token_db() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("[htlc] ⚠️  DB laden fehlgeschlagen: {e}");
                return store;
            }
        };

        let cf = db.cf_handle(super::TOKEN_CF_HTLC);

        // Contracts: erst CF, dann Fallback default
        let _loaded_from_cf = Self::load_prefix_iter(
            db, cf, b"htlc/", |_key_str, value| {
                if let Ok(contract) = serde_json::from_slice::<HtlcContract>(value) {
                    Some((contract.id.clone(), contract))
                } else { None }
            },
            &mut store.contracts,
        );

        let active = store.contracts.values().filter(|c| c.status == HtlcStatus::Locked).count();
        if !store.contracts.is_empty() {
            println!("[htlc] 📦 {} HTLCs geladen ({} aktiv)", store.contracts.len(), active);
        }

        // Escrowed Preimages
        Self::load_prefix_iter(
            db, cf, b"htlc_preimage/", |key_str, value| {
                let htlc_id = key_str.trim_start_matches("htlc_preimage/").to_string();
                String::from_utf8(value.to_vec()).ok().map(|p| (htlc_id, p))
            },
            &mut store.escrowed_preimages,
        );
        if !store.escrowed_preimages.is_empty() {
            println!("[htlc] 🔑 {} Preimages für Auto-Buy geladen", store.escrowed_preimages.len());
        }

        // Pending Buys
        Self::load_prefix_iter(
            db, cf, b"htlc_pending_buy/", |_key_str, value| {
                serde_json::from_slice::<PendingBuy>(value).ok().map(|b| (b.buy_id.clone(), b))
            },
            &mut store.pending_buys,
        );
        if !store.pending_buys.is_empty() {
            println!("[htlc] 🛒 {} Pending Buys geladen", store.pending_buys.len());
        }

        store
    }

    /// Hilfsfunktion: Lädt Einträge per Prefix-Iterator, erst aus CF, dann Fallback default.
    fn load_prefix_iter<V, F>(
        db: &rocksdb::DB,
        cf: Option<&rocksdb::ColumnFamily>,
        prefix: &[u8],
        parse: F,
        target: &mut std::collections::HashMap<String, V>,
    ) -> bool
    where
        F: Fn(&str, &[u8]) -> Option<(String, V)>,
    {
        let prefix_str = String::from_utf8_lossy(prefix);

        // Erst CF versuchen
        if let Some(cf) = cf {
            let iter = db.prefix_iterator_cf(cf, prefix);
            for item in iter {
                match item {
                    Ok((key, value)) => {
                        let key_str = String::from_utf8_lossy(&key);
                        if !key_str.starts_with(prefix_str.as_ref()) { break; }
                        if let Some((k, v)) = parse(&key_str, &value) {
                            target.insert(k, v);
                        }
                    }
                    Err(_) => break,
                }
            }
            if !target.is_empty() {
                return true; // Daten aus CF geladen
            }
        }

        // Fallback: default CF
        let iter = db.prefix_iterator(prefix);
        for item in iter {
            match item {
                Ok((key, value)) => {
                    let key_str = String::from_utf8_lossy(&key);
                    if !key_str.starts_with(prefix_str.as_ref()) { break; }
                    if let Some((k, v)) = parse(&key_str, &value) {
                        target.insert(k, v);
                    }
                }
                Err(_) => break,
            }
        }
        false
    }

    /// Persistiert alle HTLCs in RocksDB (CF: htlc).
    pub fn persist(&self) -> Result<(), HtlcError> {
        let db = super::open_token_db()
            .map_err(|e| HtlcError::Persistence(e))?;
        let cf = db.cf_handle(super::TOKEN_CF_HTLC)
            .ok_or_else(|| HtlcError::Persistence("CF htlc nicht gefunden".into()))?;

        for (id, contract) in &self.contracts {
            let key = format!("htlc/{}", id);
            let value = serde_json::to_vec(contract)
                .map_err(|e| HtlcError::Persistence(format!("serialize: {e}")))?;
            db.put_cf(cf, key.as_bytes(), &value)
                .map_err(|e| HtlcError::Persistence(format!("put: {e}")))?;
        }

        // Escrowed Preimages persistieren
        for (htlc_id, preimage) in &self.escrowed_preimages {
            let key = format!("htlc_preimage/{}", htlc_id);
            db.put_cf(cf, key.as_bytes(), preimage.as_bytes())
                .map_err(|e| HtlcError::Persistence(format!("put preimage: {e}")))?;
        }

        // Pending Buys persistieren
        for (buy_id, buy) in &self.pending_buys {
            let key = format!("htlc_pending_buy/{}", buy_id);
            let value = serde_json::to_vec(buy)
                .map_err(|e| HtlcError::Persistence(format!("serialize pending_buy: {e}")))?;
            db.put_cf(cf, key.as_bytes(), &value)
                .map_err(|e| HtlcError::Persistence(format!("put pending_buy: {e}")))?;
        }

        Ok(())
    }

    // ── Abfragen ──────────────────────────────────────────────────────────

    /// HTLC nach ID abfragen.
    pub fn get(&self, id: &str) -> Option<&HtlcContract> {
        self.contracts.get(id)
    }

    // ── Escrowed Preimages (für Auto-Buy) ─────────────────────────────────

    /// Speichert ein Preimage für Auto-Buy (offene Trades).
    pub fn store_preimage(&mut self, htlc_id: &str, preimage: String) {
        self.escrowed_preimages.insert(htlc_id.to_string(), preimage);
    }

    /// Gibt das gespeicherte Preimage für Auto-Buy zurück.
    pub fn get_escrowed_preimage(&self, htlc_id: &str) -> Option<&String> {
        self.escrowed_preimages.get(htlc_id)
    }

    /// Entfernt das gespeicherte Preimage (nach Claim oder Refund).
    pub fn remove_escrowed_preimage(&mut self, htlc_id: &str) {
        self.escrowed_preimages.remove(htlc_id);
        // Auch aus DB löschen
        if let Ok(db) = super::open_token_db() {
            let key = format!("htlc_preimage/{}", htlc_id);
            if let Some(cf) = db.cf_handle(super::TOKEN_CF_HTLC) {
                let _ = db.delete_cf(cf, key.as_bytes());
            }
            let _ = db.delete(key.as_bytes());
        }
    }

    /// Alle HTLCs für eine Adresse (als Sender oder Empfänger).
    pub fn list_for_address(&self, address: &str) -> Vec<&HtlcContract> {
        self.contracts.values()
            .filter(|c| c.sender == address || c.receiver == address)
            .collect()
    }

    /// Alle HTLCs (für Admin/API).
    pub fn list_all(&self) -> Vec<&HtlcContract> {
        self.contracts.values().collect()
    }

    /// Alle aktiven (Locked) HTLCs.
    pub fn active_contracts(&self) -> Vec<&HtlcContract> {
        self.contracts.values()
            .filter(|c| c.status == HtlcStatus::Locked)
            .collect()
    }

    /// Anzahl aktiver HTLCs für eine Adresse (als Sender).
    fn active_count_for(&self, address: &str) -> usize {
        self.contracts.values()
            .filter(|c| c.sender == address && c.status == HtlcStatus::Locked)
            .count()
    }

    /// Alle abgelaufenen, noch nicht refundeten HTLCs finden.
    pub fn find_expired(&self, now: i64) -> Vec<&HtlcContract> {
        self.contracts.values()
            .filter(|c| c.status == HtlcStatus::Locked && now >= c.time_lock)
            .collect()
    }

    // ── Validierung ───────────────────────────────────────────────────────

    /// Validiert die Parameter für ein neues HTLC.
    pub fn validate_create(
        &self,
        sender: &str,
        receiver: &str,
        amount: Decimal,
        hash_lock: &str,
        time_lock: i64,
        now: i64,
    ) -> Result<(), HtlcError> {
        // Betrag > 0
        if amount <= Decimal::ZERO {
            return Err(HtlcError::InvalidAmount("Betrag muss positiv sein".into()));
        }

        // Sender ≠ Empfänger (nur prüfen wenn Empfänger angegeben)
        if !receiver.is_empty() && sender == receiver {
            return Err(HtlcError::InvalidAmount("Sender und Empfänger dürfen nicht gleich sein".into()));
        }

        // Hash-Lock: 64 Hex-Zeichen (32 Byte SHA-256)
        if hash_lock.len() != 64 || hex::decode(hash_lock).is_err() {
            return Err(HtlcError::InvalidHashLock(
                format!("Hash-Lock muss 64 Hex-Zeichen sein, hat {}", hash_lock.len())
            ));
        }

        // Time-Lock: muss in der Zukunft liegen
        let duration = time_lock - now;
        if duration < MIN_TIMELOCK_SECS {
            return Err(HtlcError::InvalidTimeLock(
                format!("Mindestens {} Sekunden, angegeben: {}s", MIN_TIMELOCK_SECS, duration)
            ));
        }
        if duration > MAX_TIMELOCK_SECS {
            return Err(HtlcError::InvalidTimeLock(
                format!("Maximal {} Sekunden, angegeben: {}s", MAX_TIMELOCK_SECS, duration)
            ));
        }

        // Rate-Limit: max aktive HTLCs pro Sender
        if self.active_count_for(sender) >= MAX_ACTIVE_PER_ADDRESS {
            return Err(HtlcError::TooManyActive {
                address: sender.to_string(),
                limit: MAX_ACTIVE_PER_ADDRESS,
            });
        }

        Ok(())
    }

    /// Validiert ein Preimage gegen den Hash-Lock eines HTLCs.
    pub fn verify_preimage(hash_lock: &str, preimage: &str) -> bool {
        let preimage_bytes = match hex::decode(preimage) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let hash = Sha256::digest(&preimage_bytes);
        let computed_hash = hex::encode(hash);
        computed_hash == hash_lock
    }

    // ── Zustandsänderungen (werden vom Ledger aufgerufen) ─────────────────

    /// Erstellt einen neuen HTLC-Vertrag.
    ///
    /// Wird vom Ledger bei `HtlcCreate`-TX aufgerufen, NACHDEM die Balance
    /// bereits auf `pool:htlc_escrow` übertragen wurde.
    pub fn create(
        &mut self,
        htlc_id: String,
        sender: String,
        receiver: String,
        amount: Decimal,
        hash_lock: String,
        time_lock: i64,
        block_index: u64,
        price: Option<TradePrice>,
    ) -> HtlcContract {
        let contract = HtlcContract {
            id: htlc_id.clone(),
            sender,
            receiver,
            amount,
            hash_lock,
            time_lock,
            status: HtlcStatus::Locked,
            created_at_block: block_index,
            settlement_tx: None,
            preimage: None,
            price,
        };

        self.contracts.insert(htlc_id, contract.clone());
        contract
    }

    /// Claimed ein HTLC mit dem Preimage.
    ///
    /// Prüft:
    /// 1. HTLC existiert und Status == Locked
    /// 2. Preimage passt zum Hash-Lock
    /// 3. Time-Lock ist noch nicht abgelaufen
    ///
    /// Gibt den Contract zurück (für Balance-Transfer im Ledger).
    pub fn claim(
        &mut self,
        htlc_id: &str,
        preimage: &str,
        claim_tx_id: &str,
        now: i64,
    ) -> Result<HtlcContract, HtlcError> {
        let contract = self.contracts.get(htlc_id)
            .ok_or_else(|| HtlcError::NotFound(htlc_id.to_string()))?;

        // Status prüfen
        if contract.status != HtlcStatus::Locked {
            return Err(HtlcError::InvalidStatus(
                format!("HTLC {} ist {:?}, erwartet Locked", htlc_id, contract.status)
            ));
        }

        // Preimage validieren
        if !Self::verify_preimage(&contract.hash_lock, preimage) {
            return Err(HtlcError::InvalidPreimage);
        }

        // Time-Lock prüfen (Claim nur vor Ablauf)
        if now >= contract.time_lock {
            return Err(HtlcError::TimeLockExpired {
                expired_at: contract.time_lock,
                now,
            });
        }

        // Contract aktualisieren
        let contract = self.contracts.get_mut(htlc_id).unwrap();
        contract.status = HtlcStatus::Claimed;
        contract.settlement_tx = Some(claim_tx_id.to_string());
        contract.preimage = Some(preimage.to_string());

        Ok(contract.clone())
    }

    /// Refunded ein HTLC nach Ablauf des Time-Locks.
    ///
    /// Prüft:
    /// 1. HTLC existiert und Status == Locked
    /// 2. Time-Lock ist abgelaufen
    ///
    /// Gibt den Contract zurück (für Balance-Transfer im Ledger).
    pub fn refund(
        &mut self,
        htlc_id: &str,
        refund_tx_id: &str,
        now: i64,
    ) -> Result<HtlcContract, HtlcError> {
        let contract = self.contracts.get(htlc_id)
            .ok_or_else(|| HtlcError::NotFound(htlc_id.to_string()))?;

        // Status prüfen
        if contract.status != HtlcStatus::Locked {
            return Err(HtlcError::InvalidStatus(
                format!("HTLC {} ist {:?}, erwartet Locked", htlc_id, contract.status)
            ));
        }

        // Time-Lock prüfen (Refund nur nach Ablauf)
        if now < contract.time_lock {
            return Err(HtlcError::TimeLockNotExpired {
                expires_at: contract.time_lock,
                now,
            });
        }

        // Contract aktualisieren
        let contract = self.contracts.get_mut(htlc_id).unwrap();
        contract.status = HtlcStatus::Refunded;
        contract.settlement_tx = Some(refund_tx_id.to_string());

        Ok(contract.clone())
    }

    /// Bereinigt alte abgeschlossene Contracts (Claimed/Refunded) um Speicher zu sparen.
    /// Behält die letzten `keep` abgeschlossenen Contracts.
    pub fn cleanup_settled(&mut self, keep: usize) {
        let mut settled: Vec<(String, i64)> = self.contracts.iter()
            .filter(|(_, c)| c.status != HtlcStatus::Locked)
            .map(|(id, c)| (id.clone(), c.time_lock))
            .collect();

        if settled.len() <= keep {
            return;
        }

        // Älteste zuerst entfernen
        settled.sort_by_key(|(_, ts)| *ts);
        let to_remove = settled.len() - keep;
        for (id, _) in settled.into_iter().take(to_remove) {
            self.contracts.remove(&id);
            // RocksDB-Eintrag wird beim nächsten persist() nicht mehr geschrieben,
            // aber auch nicht gelöscht. Explizites Löschen bei Bedarf:
            if let Ok(db) = super::open_token_db() {
                let key = format!("htlc/{}", id);
                if let Some(cf) = db.cf_handle(super::TOKEN_CF_HTLC) {
                    let _ = db.delete_cf(cf, key.as_bytes());
                }
                let _ = db.delete(key.as_bytes());
            }
        }
    }

    // ── Pending Buys (Kaufvorgänge mit Zahlungsverifizierung) ─────────────

    /// Erstellt einen neuen Pending Buy.
    pub fn create_pending_buy(&mut self, buy: PendingBuy) {
        self.pending_buys.insert(buy.buy_id.clone(), buy);
    }

    /// Gibt einen Pending Buy nach ID zurück.
    pub fn get_pending_buy(&self, buy_id: &str) -> Option<&PendingBuy> {
        self.pending_buys.get(buy_id)
    }

    /// Prüft, ob für einen HTLC bereits ein aktiver Pending Buy existiert.
    pub fn has_active_buy_for_htlc(&self, htlc_id: &str) -> bool {
        self.pending_buys.values().any(|b| {
            b.htlc_id == htlc_id
                && matches!(b.status, BuyStatus::WaitingForPayment | BuyStatus::PaymentDetected)
        })
    }

    /// Gibt alle aktiven Pending Buys zurück (WaitingForPayment / PaymentDetected).
    pub fn active_pending_buys(&self) -> Vec<&PendingBuy> {
        self.pending_buys.values()
            .filter(|b| matches!(b.status, BuyStatus::WaitingForPayment | BuyStatus::PaymentDetected))
            .collect()
    }

    /// Aktualisiert den Status eines Pending Buys.
    pub fn update_pending_buy_status(&mut self, buy_id: &str, status: BuyStatus) {
        if let Some(buy) = self.pending_buys.get_mut(buy_id) {
            buy.status = status;
        }
    }

    /// Setzt den Payment TX Hash eines Pending Buys.
    pub fn set_pending_buy_payment_tx(&mut self, buy_id: &str, tx_hash: String) {
        if let Some(buy) = self.pending_buys.get_mut(buy_id) {
            buy.payment_tx_hash = Some(tx_hash);
        }
    }

    /// Setzt die Claim TX ID eines Pending Buys.
    pub fn set_pending_buy_claim_tx(&mut self, buy_id: &str, claim_tx_id: String) {
        if let Some(buy) = self.pending_buys.get_mut(buy_id) {
            buy.claim_tx_id = Some(claim_tx_id);
        }
    }

    /// Bereinigt abgelaufene Pending Buys (markiert sie als Expired).
    pub fn expire_pending_buys(&mut self, now: i64) -> Vec<String> {
        let expired_ids: Vec<String> = self.pending_buys.values()
            .filter(|b| {
                b.expires_at <= now
                    && matches!(b.status, BuyStatus::WaitingForPayment | BuyStatus::PaymentDetected)
            })
            .map(|b| b.buy_id.clone())
            .collect();
        for id in &expired_ids {
            if let Some(buy) = self.pending_buys.get_mut(id) {
                buy.status = BuyStatus::Expired;
            }
        }
        expired_ids
    }

    /// Entfernt alte abgeschlossene/fehlgeschlagene Pending Buys.
    pub fn cleanup_pending_buys(&mut self, max_age_secs: i64, now: i64) {
        let to_remove: Vec<String> = self.pending_buys.values()
            .filter(|b| {
                matches!(b.status, BuyStatus::Completed | BuyStatus::Expired | BuyStatus::Failed(..))
                    && (now - b.created_at) > max_age_secs
            })
            .map(|b| b.buy_id.clone())
            .collect();
        for id in &to_remove {
            self.pending_buys.remove(id);
            if let Ok(db) = super::open_token_db() {
                let key = format!("htlc_pending_buy/{}", id);
                if let Some(cf) = db.cf_handle(super::TOKEN_CF_HTLC) {
                    let _ = db.delete_cf(cf, key.as_bytes());
                }
                let _ = db.delete(key.as_bytes());
            }
        }
    }
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/// Generiert ein kryptografisch sicheres Preimage (32 Byte).
pub fn generate_preimage() -> (String, String) {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let preimage = hex::encode(secret);
    let hash = hex::encode(Sha256::digest(&secret));
    (preimage, hash)
}

/// Parst HTLC-Parameter aus der TX-Memo (JSON).
///
/// Erwartetes Format:
/// ```json
/// {
///   "htlc_id": "...",
///   "hash_lock": "...",
///   "time_lock": 1234567890,
///   "receiver": "..."
/// }
/// ```
pub fn parse_htlc_create_memo(memo: &str) -> Result<HtlcCreateParams, HtlcError> {
    serde_json::from_str(memo)
        .map_err(|e| HtlcError::InvalidAmount(format!("Memo-JSON ungültig: {e}")))
}

/// Parst Claim-Parameter aus der TX-Memo.
///
/// Format: `{"htlc_id": "...", "preimage": "..."}`
pub fn parse_htlc_claim_memo(memo: &str) -> Result<HtlcClaimParams, HtlcError> {
    serde_json::from_str(memo)
        .map_err(|e| HtlcError::InvalidAmount(format!("Memo-JSON ungültig: {e}")))
}

/// Parst Refund-Parameter aus der TX-Memo.
///
/// Format: `{"htlc_id": "..."}`
pub fn parse_htlc_refund_memo(memo: &str) -> Result<HtlcRefundParams, HtlcError> {
    serde_json::from_str(memo)
        .map_err(|e| HtlcError::InvalidAmount(format!("Memo-JSON ungültig: {e}")))
}

// ─── Memo-Parameter ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HtlcCreateParams {
    pub hash_lock: String,
    pub time_lock: i64,
    pub receiver: String,
    #[serde(default)]
    pub price: Option<TradePrice>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HtlcClaimParams {
    pub htlc_id: String,
    pub preimage: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HtlcRefundParams {
    pub htlc_id: String,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preimage_verification() {
        let (preimage, hash) = generate_preimage();
        assert!(HtlcStore::verify_preimage(&hash, &preimage));
        assert!(!HtlcStore::verify_preimage(&hash, "0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_create_and_claim() {
        let mut store = HtlcStore::new();
        let (preimage, hash) = generate_preimage();
        let now = 1000i64;
        let time_lock = now + 3600;

        // Validierung
        assert!(store.validate_create(
            "sender_addr", "receiver_addr",
            Decimal::new(100, 0), &hash, time_lock, now,
        ).is_ok());

        // Erstellen
        store.create(
            "htlc_001".into(), "sender_addr".into(), "receiver_addr".into(),
            Decimal::new(100, 0), hash.clone(), time_lock, 42, None,
        );

        assert_eq!(store.get("htlc_001").unwrap().status, HtlcStatus::Locked);

        // Claim mit korrektem Preimage
        let result = store.claim("htlc_001", &preimage, "claim_tx_001", now + 1800);
        assert!(result.is_ok());
        assert_eq!(store.get("htlc_001").unwrap().status, HtlcStatus::Claimed);
        assert_eq!(store.get("htlc_001").unwrap().preimage.as_deref(), Some(preimage.as_str()));

        // Double-Claim verhindern
        let result = store.claim("htlc_001", &preimage, "claim_tx_002", now + 1801);
        assert!(result.is_err());
    }

    #[test]
    fn test_claim_with_wrong_preimage() {
        let mut store = HtlcStore::new();
        let (_preimage, hash) = generate_preimage();

        store.create(
            "htlc_002".into(), "sender".into(), "receiver".into(),
            Decimal::new(50, 0), hash, 2000, 42, None,
        );

        let result = store.claim(
            "htlc_002",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "tx_bad", 1500,
        );
        assert!(matches!(result, Err(HtlcError::InvalidPreimage)));
    }

    #[test]
    fn test_claim_after_expiry() {
        let mut store = HtlcStore::new();
        let (preimage, hash) = generate_preimage();
        let time_lock = 2000i64;

        store.create(
            "htlc_003".into(), "sender".into(), "receiver".into(),
            Decimal::new(50, 0), hash, time_lock, 42, None,
        );

        // Claim nach Ablauf → Fehler
        let result = store.claim("htlc_003", &preimage, "tx_late", 2001);
        assert!(matches!(result, Err(HtlcError::TimeLockExpired { .. })));
    }

    #[test]
    fn test_refund_before_expiry() {
        let mut store = HtlcStore::new();
        let (_preimage, hash) = generate_preimage();
        let time_lock = 2000i64;

        store.create(
            "htlc_004".into(), "sender".into(), "receiver".into(),
            Decimal::new(50, 0), hash, time_lock, 42, None,
        );

        // Refund vor Ablauf → Fehler
        let result = store.refund("htlc_004", "tx_early", 1999);
        assert!(matches!(result, Err(HtlcError::TimeLockNotExpired { .. })));

        // Refund nach Ablauf → OK
        let result = store.refund("htlc_004", "tx_refund", 2001);
        assert!(result.is_ok());
        assert_eq!(store.get("htlc_004").unwrap().status, HtlcStatus::Refunded);
    }

    #[test]
    fn test_validate_limits() {
        let store = HtlcStore::new();
        let now = 1000i64;

        // Sender == Receiver → Fehler
        assert!(store.validate_create(
            "same", "same", Decimal::new(100, 0),
            "a".repeat(64).as_str(), now + 3600, now,
        ).is_err());

        // Betrag <= 0 → Fehler
        assert!(store.validate_create(
            "a", "b", Decimal::ZERO,
            "a".repeat(64).as_str(), now + 3600, now,
        ).is_err());

        // Time-Lock zu kurz → Fehler
        assert!(store.validate_create(
            "a", "b", Decimal::new(100, 0),
            "a".repeat(64).as_str(), now + 60, now,
        ).is_err());
    }

    #[test]
    fn test_find_expired() {
        let mut store = HtlcStore::new();
        let hash = "a".repeat(64);

        store.create("h1".into(), "s".into(), "r".into(), Decimal::new(10, 0), hash.clone(), 1000, 1, None);
        store.create("h2".into(), "s".into(), "r".into(), Decimal::new(20, 0), hash.clone(), 2000, 1, None);
        store.create("h3".into(), "s".into(), "r".into(), Decimal::new(30, 0), hash, 3000, 1, None);

        let expired = store.find_expired(1500);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "h1");

        let expired = store.find_expired(2500);
        assert_eq!(expired.len(), 2);
    }
}
