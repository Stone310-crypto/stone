//! StoneCoin Token-Ledger
//!
//! Account-basiertes Modell (wie Ethereum, nicht UTXO).
//!
//! ## Zustand
//!
//! Für jeden Account (Public-Key-Hex) speichert der Ledger:
//! - `balance`  – aktuelles Guthaben (Decimal, max. 8 Nachkommastellen)
//! - `nonce`    – nächste erwartete Transaktionsnonce (Replay-Schutz)
//!
//! ## Persistierung
//!
//! Der Ledger-Zustand wird in RocksDB unter dem Prefix `token/` gespeichert:
//! - `token/bal/<pubkey_hex>`   → Decimal als String
//! - `token/nonce/<pubkey_hex>` → u64 als LE-Bytes
//! - `token/supply`             → Decimal als String (aktuelles Gesamtangebot)
//!
//! ## Thread-Safety
//!
//! Der Ledger ist in `Arc<RwLock<TokenLedger>>` verpackt und wird
//! zwischen HTTP-Handlern und Block-Verarbeitung geteilt.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::transaction::{TokenTx, TxError, TxType, validate_tx};

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Maximales Token-Supply: 50.000.000 STONE
pub const MAX_SUPPLY: &str = "50000000";

/// Minimale Transaktionsgebühr (0.001 STONE)
pub const MIN_FEE: &str = "0.001";

// ─── Ledger-Fehler ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum LedgerError {
    InsufficientBalance { account: String, available: Decimal, required: Decimal },
    SupplyExceeded { current: Decimal, mint_amount: Decimal, max: Decimal },
    InvalidNonce { expected: u64, got: u64 },
    TxValidation(TxError),
    Persistence(String),
    /// Key wurde bereits rotiert – Operation am alten Key nicht mehr erlaubt
    KeyAlreadyRotated { old_key: String, successor: String },
    /// Neuer Key existiert bereits im Ledger (Balance > 0 oder Nonce > 0)
    KeyRotationConflict { new_key: String },
    /// Versuch eine TX mit einem rotierten Key zu senden
    KeyRevoked { address: String, active_key: String },
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::InsufficientBalance { account, available, required } =>
                write!(f, "Ungenügendes Guthaben: {account} hat {available}, benötigt {required}"),
            LedgerError::SupplyExceeded { current, mint_amount, max } =>
                write!(f, "Supply-Limit überschritten: aktuell {current} + {mint_amount} > {max}"),
            LedgerError::InvalidNonce { expected, got } =>
                write!(f, "Ungültige Nonce: erwartet {expected}, empfangen {got}"),
            LedgerError::TxValidation(e) =>
                write!(f, "TX-Validierung: {e}"),
            LedgerError::Persistence(e) =>
                write!(f, "Persistierungsfehler: {e}"),
            LedgerError::KeyAlreadyRotated { old_key, successor } =>
                write!(f, "Key {old_key}... bereits rotiert → {successor}..."),
            LedgerError::KeyRotationConflict { new_key } =>
                write!(f, "Neuer Key {new_key}... hat bereits Ledger-Einträge"),
            LedgerError::KeyRevoked { address, active_key } =>
                write!(f, "Key {address}... wurde rotiert – aktiver Key: {active_key}..."),
        }
    }
}

impl From<TxError> for LedgerError {
    fn from(e: TxError) -> Self {
        LedgerError::TxValidation(e)
    }
}

// ─── Account-Info ────────────────────────────────────────────────────────────

/// Kontoinformationen für einen Account.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountInfo {
    pub address: String,
    pub balance: Decimal,
    pub nonce: u64,
}

// ─── TX-Receipt ──────────────────────────────────────────────────────────────

/// Ergebnis einer erfolgreich verarbeiteten Transaktion.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxReceipt {
    pub tx_id: String,
    pub block_index: u64,
    pub status: String,
    pub from_balance: Decimal,
    pub to_balance: Decimal,
}

// ─── Token-Ledger ────────────────────────────────────────────────────────────

/// Der Token-Ledger verwaltet alle Account-Balancen und Nonces.
///
/// # Invarianten
/// - `total_supply <= MAX_SUPPLY`
/// - Alle Balancen sind >= 0
/// - Nonces sind monoton steigend pro Account
pub struct TokenLedger {
    /// Account → Balance
    balances: HashMap<String, Decimal>,
    /// Account → nächste erwartete Nonce
    nonces: HashMap<String, u64>,
    /// Aktuell umlaufendes Supply
    total_supply: Decimal,
    /// Maximales Supply (50M)
    max_supply: Decimal,
    /// Alle verarbeiteten TX-IDs (Duplikat-Schutz innerhalb der Session)
    processed_txs: std::collections::HashSet<String>,
    /// Key-Rotation Registry: alter Key → neuer Key (Forward-Pointer)
    ///
    /// Wenn ein Nutzer seinen Key rotiert, wird die alte Adresse invalidiert
    /// und alle Operationen laufen über die neue Adresse.
    /// `key_rotations["old_key"] = "new_key"` bedeutet:
    ///   - `old_key` ist nicht mehr aktiv
    ///   - `new_key` ist der aktive Nachfolger
    key_rotations: HashMap<String, String>,
    /// Reverse-Lookup: neuer Key → alter Key (für History-Traversal)
    key_rotation_history: HashMap<String, Vec<String>>,
}

impl TokenLedger {
    /// Neuen leeren Ledger erstellen.
    pub fn new() -> Self {
        TokenLedger {
            balances: HashMap::new(),
            nonces: HashMap::new(),
            total_supply: Decimal::ZERO,
            max_supply: MAX_SUPPLY.parse().expect("MAX_SUPPLY parse"),
            processed_txs: std::collections::HashSet::new(),
            key_rotations: HashMap::new(),
            key_rotation_history: HashMap::new(),
        }
    }

    // ── Abfragen ──────────────────────────────────────────────────────────

    /// Balance eines Accounts abfragen.
    pub fn balance(&self, address: &str) -> Decimal {
        self.balances.get(address).copied().unwrap_or(Decimal::ZERO)
    }

    /// Nonce eines Accounts abfragen.
    pub fn nonce(&self, address: &str) -> u64 {
        self.nonces.get(address).copied().unwrap_or(0)
    }

    /// Aktuelles Gesamtangebot.
    pub fn total_supply(&self) -> Decimal {
        self.total_supply
    }

    /// Maximales Supply.
    pub fn max_supply(&self) -> Decimal {
        self.max_supply
    }

    /// Alle Accounts mit positivem Guthaben.
    pub fn all_accounts(&self) -> Vec<AccountInfo> {
        self.balances
            .iter()
            .filter(|(_, bal)| **bal > Decimal::ZERO)
            .map(|(addr, bal)| AccountInfo {
                address: addr.clone(),
                balance: *bal,
                nonce: self.nonce(addr),
            })
            .collect()
    }

    /// Anzahl der Accounts mit positivem Guthaben.
    pub fn account_count(&self) -> usize {
        self.balances.values().filter(|b| **b > Decimal::ZERO).count()
    }

    // ── Schreiboperationen ────────────────────────────────────────────────

    /// Neue Token minten (nur für System: Genesis, Rewards).
    ///
    /// Prüft ob das MAX_SUPPLY nicht überschritten wird.
    pub fn mint(&mut self, to: &str, amount: Decimal) -> Result<(), LedgerError> {
        if amount <= Decimal::ZERO {
            return Err(LedgerError::TxValidation(TxError::InvalidAmount(
                "Mint-Betrag muss positiv sein".into()
            )));
        }

        let new_supply = self.total_supply + amount;
        if new_supply > self.max_supply {
            return Err(LedgerError::SupplyExceeded {
                current: self.total_supply,
                mint_amount: amount,
                max: self.max_supply,
            });
        }

        *self.balances.entry(to.to_string()).or_insert(Decimal::ZERO) += amount;
        self.total_supply = new_supply;

        println!(
            "[token] 🪙 Mint: {} STONE → {} (Supply: {}/{})",
            amount, &to[..12.min(to.len())], self.total_supply, self.max_supply
        );
        Ok(())
    }

    /// Token von einem Account auf einen anderen übertragen.
    ///
    /// Prüft: Balance, Nonce, Signatur.
    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        amount: Decimal,
        fee: Decimal,
    ) -> Result<(), LedgerError> {
        let total_debit = amount + fee;
        let current_balance = self.balance(from);

        if current_balance < total_debit {
            return Err(LedgerError::InsufficientBalance {
                account: from.to_string(),
                available: current_balance,
                required: total_debit,
            });
        }

        // Abbuchen
        *self.balances.entry(from.to_string()).or_insert(Decimal::ZERO) -= total_debit;
        // Gutschreiben
        *self.balances.entry(to.to_string()).or_insert(Decimal::ZERO) += amount;
        // Fee wird verbrannt (reduziert total_supply)
        if fee > Decimal::ZERO {
            self.total_supply -= fee;
        }

        Ok(())
    }

    /// Token verbrennen (Burn).
    pub fn burn(&mut self, from: &str, amount: Decimal) -> Result<(), LedgerError> {
        let current_balance = self.balance(from);
        if current_balance < amount {
            return Err(LedgerError::InsufficientBalance {
                account: from.to_string(),
                available: current_balance,
                required: amount,
            });
        }

        *self.balances.entry(from.to_string()).or_insert(Decimal::ZERO) -= amount;
        self.total_supply -= amount;

        println!(
            "[token] 🔥 Burn: {} STONE von {} (Supply: {})",
            amount, &from[..12.min(from.len())], self.total_supply
        );
        Ok(())
    }

    // ── Key-Rotation ──────────────────────────────────────────────────────

    /// Rotiert den Key eines Accounts.
    ///
    /// Verschiebt Balance und Nonce vom alten Key zum neuen Key.
    /// Der alte Key wird invalidiert (Balance = 0, in key_rotations registriert).
    ///
    /// # Bedingungen
    /// - `old_key` muss existieren (positive Balance ODER Nonce > 0)
    /// - `new_key` darf noch keinen Ledger-Eintrag haben (frische Adresse)
    /// - `old_key` darf nicht bereits rotiert worden sein
    pub fn rotate_key(&mut self, old_key: &str, new_key: &str) -> Result<(), LedgerError> {
        // Prüfen ob der alte Key bereits rotiert wurde
        if self.key_rotations.contains_key(old_key) {
            let successor = &self.key_rotations[old_key];
            return Err(LedgerError::KeyAlreadyRotated {
                old_key: old_key[..12.min(old_key.len())].to_string(),
                successor: successor[..12.min(successor.len())].to_string(),
            });
        }

        // Prüfen ob der neue Key schon verwendet wird
        let new_balance = self.balance(new_key);
        let new_nonce = self.nonce(new_key);
        if new_balance > Decimal::ZERO || new_nonce > 0 {
            return Err(LedgerError::KeyRotationConflict {
                new_key: new_key[..12.min(new_key.len())].to_string(),
            });
        }

        // Balance und Nonce übertragen
        let old_balance = self.balance(old_key);
        let old_nonce = self.nonce(old_key);

        // Neuen Account anlegen
        if old_balance > Decimal::ZERO {
            self.balances.insert(new_key.to_string(), old_balance);
        }
        // Nonce wird NICHT übertragen – neuer Key startet bei 0
        // (verhindert Replay mit alten Nonces am neuen Key)

        // Alten Account nullen
        self.balances.remove(old_key);
        self.nonces.remove(old_key);

        // Key-Rotation registrieren
        self.key_rotations.insert(old_key.to_string(), new_key.to_string());
        self.key_rotation_history
            .entry(new_key.to_string())
            .or_default()
            .push(old_key.to_string());

        println!(
            "[token] 🔑 Key-Rotation: {}... → {}... (Balance: {} STONE, alte Nonce: {})",
            &old_key[..12.min(old_key.len())],
            &new_key[..12.min(new_key.len())],
            old_balance,
            old_nonce,
        );

        Ok(())
    }

    /// Gibt den aktuell aktiven Key für einen Account zurück.
    ///
    /// Folgt der Rotationskette bis zum letzten aktiven Key.
    /// Gibt `None` zurück wenn der Key unbekannt ist.
    pub fn resolve_active_key(&self, key: &str) -> Option<String> {
        let mut current = key.to_string();
        let mut depth = 0;
        while let Some(next) = self.key_rotations.get(&current) {
            current = next.clone();
            depth += 1;
            if depth > 100 {
                // Sicherheit gegen zirkuläre Referenzen
                eprintln!("[token] ⚠️  Key-Rotation-Kette zu tief für {}", &key[..12.min(key.len())]);
                return None;
            }
        }
        if current == key {
            // Kein Rotation-Eintrag → Key ist aktiv (oder unbekannt)
            None
        } else {
            Some(current)
        }
    }

    /// Prüft ob ein Key durch Rotation invalidiert wurde.
    pub fn is_key_rotated(&self, key: &str) -> bool {
        self.key_rotations.contains_key(key)
    }

    /// Gibt die komplette Rotations-Historie eines Keys zurück.
    ///
    /// Alle vorherigen Keys die auf diesen Key rotiert wurden.
    pub fn key_predecessors(&self, key: &str) -> Vec<String> {
        self.key_rotation_history.get(key).cloned().unwrap_or_default()
    }

    // ── Transaktionsverarbeitung ──────────────────────────────────────────

    /// Verarbeitet eine vollständig validierte Transaktion.
    ///
    /// Prüft:
    /// 1. Strukturelle Validierung (TX-ID, Signatur)
    /// 2. Duplikat-Prüfung
    /// 3. Nonce-Prüfung (nur für Transfer/Burn)
    /// 4. Balance-Prüfung
    /// 5. Supply-Limit (nur für Mint/Reward)
    ///
    /// Gibt ein `TxReceipt` mit den neuen Balancen zurück.
    pub fn apply_tx(&mut self, tx: &TokenTx, block_index: u64) -> Result<TxReceipt, LedgerError> {
        // 1. Strukturelle Validierung
        validate_tx(tx)?;

        // 2. Duplikat-Prüfung
        if self.processed_txs.contains(&tx.tx_id) {
            return Err(LedgerError::TxValidation(TxError::Replay(
                format!("TX {} bereits verarbeitet", &tx.tx_id[..12])
            )));
        }

        // 3. Nonce-Prüfung (nur für Nutzer-Transaktionen)
        if tx.tx_type == TxType::Transfer || tx.tx_type == TxType::Burn || tx.tx_type == TxType::RotateKey {
            // Prüfen ob der Key durch Rotation invalidiert wurde
            if let Some(active) = self.resolve_active_key(&tx.from) {
                return Err(LedgerError::KeyRevoked {
                    address: tx.from[..12.min(tx.from.len())].to_string(),
                    active_key: active[..12.min(active.len())].to_string(),
                });
            }

            let expected_nonce = self.nonce(&tx.from);
            if tx.nonce != expected_nonce {
                return Err(LedgerError::InvalidNonce {
                    expected: expected_nonce,
                    got: tx.nonce,
                });
            }
        }

        // 4+5. Ausführen
        match tx.tx_type {
            TxType::Mint | TxType::Reward => {
                self.mint(&tx.to, tx.amount)?;
            }
            TxType::Transfer => {
                self.transfer(&tx.from, &tx.to, tx.amount, tx.fee)?;
                // Nonce erhöhen
                *self.nonces.entry(tx.from.clone()).or_insert(0) += 1;
            }
            TxType::Burn => {
                self.burn(&tx.from, tx.amount)?;
                // Nonce erhöhen
                *self.nonces.entry(tx.from.clone()).or_insert(0) += 1;
            }
            TxType::RotateKey => {
                // from = alter Key, to = neuer Key
                self.rotate_key(&tx.from, &tx.to)?;
                // Nonce wird am alten Key NICHT mehr erhöht – Account ist ab jetzt inaktiv
            }
        }

        // TX als verarbeitet markieren
        self.processed_txs.insert(tx.tx_id.clone());

        let receipt = TxReceipt {
            tx_id: tx.tx_id.clone(),
            block_index,
            status: "confirmed".to_string(),
            from_balance: self.balance(&tx.from),
            to_balance: self.balance(&tx.to),
        };

        Ok(receipt)
    }

    /// Verarbeitet alle Transaktionen eines Blocks.
    ///
    /// Gibt Receipts für alle erfolgreichen TXs zurück.
    /// Bei einem Fehler wird die fehlerhafte TX übersprungen (Log) und die
    /// restlichen TXs werden trotzdem verarbeitet.
    pub fn apply_block_txs(
        &mut self,
        txs: &[TokenTx],
        block_index: u64,
    ) -> Vec<TxReceipt> {
        let mut receipts = Vec::new();
        for tx in txs {
            match self.apply_tx(tx, block_index) {
                Ok(receipt) => receipts.push(receipt),
                Err(e) => {
                    eprintln!(
                        "[token] ⚠️  TX {} in Block #{} fehlgeschlagen: {e}",
                        &tx.tx_id[..12.min(tx.tx_id.len())],
                        block_index
                    );
                }
            }
        }
        if !receipts.is_empty() {
            println!(
                "[token] Block #{}: {}/{} TXs verarbeitet, Supply: {}",
                block_index, receipts.len(), txs.len(), self.total_supply
            );
        }
        receipts
    }

    // ── Persistierung (RocksDB) ───────────────────────────────────────────

    /// Speichert den kompletten Ledger-Zustand in RocksDB.
    pub fn persist(&self) -> Result<(), LedgerError> {
        let db_path = format!("{}/token_db", crate::blockchain::data_dir());
        let db = rocksdb::DB::open_default(&db_path)
            .map_err(|e| LedgerError::Persistence(format!("DB open: {e}")))?;

        // Balancen
        for (addr, bal) in &self.balances {
            let key = format!("bal/{}", addr);
            db.put(key.as_bytes(), bal.to_string().as_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put balance: {e}")))?;
        }

        // Nonces
        for (addr, nonce) in &self.nonces {
            let key = format!("nonce/{}", addr);
            db.put(key.as_bytes(), nonce.to_le_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put nonce: {e}")))?;
        }

        // Supply
        db.put(b"supply", self.total_supply.to_string().as_bytes())
            .map_err(|e| LedgerError::Persistence(format!("put supply: {e}")))?;

        // Key-Rotations (forward: old → new)
        for (old_key, new_key) in &self.key_rotations {
            let key = format!("keyrot/{}", old_key);
            db.put(key.as_bytes(), new_key.as_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put keyrot: {e}")))?;
        }

        println!("[token] 💾 Ledger persistiert: {} Accounts, {} Key-Rotations, Supply: {}",
            self.account_count(), self.key_rotations.len(), self.total_supply);
        Ok(())
    }

    /// Lädt den Ledger-Zustand aus RocksDB.
    ///
    /// Gibt einen leeren Ledger zurück wenn die DB nicht existiert.
    pub fn load() -> Self {
        let db_path = format!("{}/token_db", crate::blockchain::data_dir());
        let db = match rocksdb::DB::open_default(&db_path) {
            Ok(db) => db,
            Err(_) => return TokenLedger::new(),
        };

        let mut ledger = TokenLedger::new();

        // Balancen laden
        let iter = db.prefix_iterator(b"bal/");
        for item in iter {
            if let Ok((key, value)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if !key_str.starts_with("bal/") {
                    break;
                }
                let addr = key_str.strip_prefix("bal/").unwrap_or("").to_string();
                if let Ok(bal) = String::from_utf8_lossy(&value).parse::<Decimal>() {
                    if bal > Decimal::ZERO {
                        ledger.balances.insert(addr, bal);
                    }
                }
            }
        }

        // Nonces laden
        let iter = db.prefix_iterator(b"nonce/");
        for item in iter {
            if let Ok((key, value)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if !key_str.starts_with("nonce/") {
                    break;
                }
                let addr = key_str.strip_prefix("nonce/").unwrap_or("").to_string();
                if value.len() == 8 {
                    let nonce = u64::from_le_bytes(value[..8].try_into().unwrap());
                    if nonce > 0 {
                        ledger.nonces.insert(addr, nonce);
                    }
                }
            }
        }

        // Supply laden
        if let Ok(Some(supply_bytes)) = db.get(b"supply") {
            if let Ok(supply) = String::from_utf8_lossy(&supply_bytes).parse::<Decimal>() {
                ledger.total_supply = supply;
            }
        }

        // Key-Rotations laden
        let iter = db.prefix_iterator(b"keyrot/");
        for item in iter {
            if let Ok((key, value)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if !key_str.starts_with("keyrot/") {
                    break;
                }
                let old_key = key_str.strip_prefix("keyrot/").unwrap_or("").to_string();
                let new_key = String::from_utf8_lossy(&value).to_string();
                if !old_key.is_empty() && !new_key.is_empty() {
                    ledger.key_rotation_history
                        .entry(new_key.clone())
                        .or_default()
                        .push(old_key.clone());
                    ledger.key_rotations.insert(old_key, new_key);
                }
            }
        }

        println!(
            "[token] 📂 Ledger geladen: {} Accounts, {} Key-Rotations, Supply: {}",
            ledger.account_count(),
            ledger.key_rotations.len(),
            ledger.total_supply
        );
        ledger
    }

    /// Rekonstruiert den Ledger-Zustand aus der kompletten Chain.
    ///
    /// Wird beim Start verwendet wenn keine RocksDB existiert aber eine
    /// Chain mit Token-TXs vorhanden ist.
    pub fn rebuild_from_chain(blocks: &[crate::blockchain::Block]) -> Self {
        let mut ledger = TokenLedger::new();
        for block in blocks {
            if !block.transactions.is_empty() {
                ledger.apply_block_txs(&block.transactions, block.index);
            }
        }
        if ledger.total_supply > Decimal::ZERO {
            println!(
                "[token] 🔄 Ledger aus Chain rekonstruiert: {} Accounts, Supply: {}",
                ledger.account_count(),
                ledger.total_supply
            );
            if let Err(e) = ledger.persist() {
                eprintln!("[token] Persistierung nach Rebuild fehlgeschlagen: {e}");
            }
        }
        ledger
    }
}

impl Default for TokenLedger {
    fn default() -> Self {
        Self::new()
    }
}
