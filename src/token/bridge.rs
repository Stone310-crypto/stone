//! Wrapped Token Bridge — Cross-Chain Token-Brücke
//!
//! Ermöglicht das Einzahlen externer Tokens (USDT, BTC, ETH) und erstellt
//! korrespondierende Wrapped Tokens (wUSDT, wBTC, wETH) auf der Stone-Chain.
//!
//! ## Flow
//!
//! 1. Nutzer generiert eine Bridge-Deposit-Adresse
//! 2. Nutzer sendet externe Tokens an diese Adresse
//! 3. Bridge-Operator bestätigt den Deposit → Mint von Wrapped Tokens
//! 4. Wrapped Tokens können via HTLC gehandelt werden
//! 5. Zum Auszahlen: Wrapped Tokens werden verbrannt → Auszahlung auf externer Chain
//!
//! ## Persistierung
//!
//! Alle Daten werden in RocksDB (`token_db`) unter dem Prefix `bridge/` gespeichert.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ─── Wrapped Asset Types ─────────────────────────────────────────────────────

/// Unterstützte Wrapped-Token-Typen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrappedAsset {
    /// Wrapped Tether USD (von Ethereum/Tron)
    #[serde(rename = "wUSDT")]
    WUSDT,
    /// Wrapped USD Coin (von Ethereum)
    #[serde(rename = "wUSDC")]
    WUSDC,
    /// Wrapped Bitcoin
    #[serde(rename = "wBTC")]
    WBTC,
    /// Wrapped Ethereum
    #[serde(rename = "wETH")]
    WETH,
}

impl std::fmt::Display for WrappedAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrappedAsset::WUSDT => write!(f, "wUSDT"),
            WrappedAsset::WUSDC => write!(f, "wUSDC"),
            WrappedAsset::WBTC => write!(f, "wBTC"),
            WrappedAsset::WETH => write!(f, "wETH"),
        }
    }
}

impl WrappedAsset {
    /// Alle unterstützten Assets.
    pub fn all() -> &'static [WrappedAsset] {
        &[
            WrappedAsset::WUSDT,
            WrappedAsset::WUSDC,
            WrappedAsset::WBTC,
            WrappedAsset::WETH,
        ]
    }

    /// Externe Chain für dieses Asset.
    pub fn external_chain(&self) -> &'static str {
        match self {
            WrappedAsset::WUSDT => "ethereum",
            WrappedAsset::WUSDC => "ethereum",
            WrappedAsset::WBTC => "bitcoin",
            WrappedAsset::WETH => "ethereum",
        }
    }

    /// Dezimalstellen des externen Assets.
    pub fn decimals(&self) -> u8 {
        match self {
            WrappedAsset::WUSDT => 6,
            WrappedAsset::WUSDC => 6,
            WrappedAsset::WBTC => 8,
            WrappedAsset::WETH => 18,
        }
    }

    /// Parse aus String (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "wusdt" => Some(WrappedAsset::WUSDT),
            "wusdc" => Some(WrappedAsset::WUSDC),
            "wbtc" => Some(WrappedAsset::WBTC),
            "weth" => Some(WrappedAsset::WETH),
            _ => None,
        }
    }
}

// ─── Bridge Deposit ──────────────────────────────────────────────────────────

/// Status eines Bridge-Deposits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    /// Warten auf Bestätigung der externen TX.
    Pending,
    /// Deposit bestätigt, Wrapped Tokens geminted.
    Confirmed,
    /// Deposit fehlgeschlagen (z.B. falsche Adresse).
    Failed,
}

/// Ein Deposit-Record: Einzahlung von externer Chain → Stone-Chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDeposit {
    /// Eindeutige Deposit-ID.
    pub id: String,
    /// Stone-Chain Wallet-Adresse des Empfängers.
    pub stone_address: String,
    /// Art des geminteten Wrapped Tokens.
    pub asset: WrappedAsset,
    /// Menge der geminteten Wrapped Tokens.
    pub amount: Decimal,
    /// Externe Chain (z.B. "ethereum").
    pub external_chain: String,
    /// TX-Hash auf der externen Chain.
    pub external_tx_hash: String,
    /// Aktueller Status.
    pub status: DepositStatus,
    /// Unix-Timestamp der Erstellung.
    pub created_at: i64,
    /// Unix-Timestamp der Bestätigung (falls bestätigt).
    pub confirmed_at: Option<i64>,
}

// ─── Bridge Withdrawal ──────────────────────────────────────────────────────

/// Status einer Bridge-Auszahlung.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Warten auf Verarbeitung.
    Pending,
    /// Wird verarbeitet (TX auf externer Chain gesendet).
    Processing,
    /// Auszahlung abgeschlossen.
    Completed,
    /// Auszahlung fehlgeschlagen.
    Failed,
}

/// Ein Withdrawal-Record: Auszahlung von Stone-Chain → externe Chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeWithdrawal {
    /// Eindeutige Withdrawal-ID.
    pub id: String,
    /// Stone-Chain Wallet-Adresse des Senders.
    pub stone_address: String,
    /// Art des verbrannten Wrapped Tokens.
    pub asset: WrappedAsset,
    /// Menge der verbrannten Wrapped Tokens.
    pub amount: Decimal,
    /// Externe Chain (z.B. "ethereum").
    pub external_chain: String,
    /// Ziel-Adresse auf der externen Chain.
    pub external_address: String,
    /// Aktueller Status.
    pub status: WithdrawalStatus,
    /// Unix-Timestamp der Erstellung.
    pub created_at: i64,
    /// Unix-Timestamp der Fertigstellung.
    pub completed_at: Option<i64>,
    /// TX-Hash auf der externen Chain (wenn abgeschlossen).
    pub external_tx_hash: Option<String>,
}

// ─── Bridge Store ────────────────────────────────────────────────────────────

/// Bridge Reserve Pool — hält gesperrte Wrapped Tokens.
pub const BRIDGE_RESERVE_POOL: &str = "pool:bridge_reserve";

/// Verwaltet Wrapped-Token-Balances, Deposits und Withdrawals.
pub struct BridgeStore {
    /// address → asset → balance
    balances: HashMap<String, HashMap<WrappedAsset, Decimal>>,
    /// Alle Deposits (chronologisch).
    deposits: Vec<BridgeDeposit>,
    /// Alle Withdrawals (chronologisch).
    withdrawals: Vec<BridgeWithdrawal>,
}

impl BridgeStore {
    /// Erstellt einen leeren Store.
    pub fn new() -> Self {
        BridgeStore {
            balances: HashMap::new(),
            deposits: Vec::new(),
            withdrawals: Vec::new(),
        }
    }

    /// Lädt den Store aus RocksDB (CF: bridge, Fallback: default).
    pub fn load() -> Self {
        let mut store = Self::new();

        let db = match super::open_token_db() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("[bridge] ⚠️  DB laden fehlgeschlagen: {e}");
                return store;
            }
        };

        let cf = db.cf_handle(super::TOKEN_CF_BRIDGE);

        // Balances laden (CF → default fallback)
        Self::load_bridge_prefix(db, cf, b"bridge/balance/", |value| {
            serde_json::from_slice::<BalanceEntry>(value).ok().map(|entry| {
                (format!("{}:{}", entry.address, entry.asset), entry)
            })
        }).into_iter().for_each(|(_, entry)| {
            store.balances.entry(entry.address.clone()).or_default()
                .insert(entry.asset, entry.amount);
        });

        // Deposits laden
        Self::load_bridge_prefix(db, cf, b"bridge/deposit/", |value| {
            serde_json::from_slice::<BridgeDeposit>(value).ok().map(|d| (d.id.clone(), d))
        }).into_iter().for_each(|(_, deposit)| {
            store.deposits.push(deposit);
        });

        // Withdrawals laden
        Self::load_bridge_prefix(db, cf, b"bridge/withdrawal/", |value| {
            serde_json::from_slice::<BridgeWithdrawal>(value).ok().map(|w| (w.id.clone(), w))
        }).into_iter().for_each(|(_, withdrawal)| {
            store.withdrawals.push(withdrawal);
        });

        let total_bal: usize = store.balances.values().map(|m| m.len()).sum();
        if total_bal > 0 || !store.deposits.is_empty() {
            println!(
                "[bridge] 📦 {} Balances, {} Deposits, {} Withdrawals geladen",
                total_bal,
                store.deposits.len(),
                store.withdrawals.len(),
            );
        }

        store
    }

    /// Hilfsfunktion: Lädt Einträge per Prefix, erst CF dann default.
    fn load_bridge_prefix<V, F>(
        db: &rocksdb::DB,
        cf: Option<&rocksdb::ColumnFamily>,
        prefix: &[u8],
        parse: F,
    ) -> Vec<(String, V)>
    where
        F: Fn(&[u8]) -> Option<(String, V)>,
    {
        let prefix_str = String::from_utf8_lossy(prefix);
        let mut results = Vec::new();

        // Erst CF versuchen
        if let Some(cf) = cf {
            for item in db.prefix_iterator_cf(cf, prefix) {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with(prefix_str.as_ref()) { break; }
                        if let Some(entry) = parse(&value) { results.push(entry); }
                    }
                    Err(_) => break,
                }
            }
            if !results.is_empty() { return results; }
        }

        // Fallback: default CF
        for item in db.prefix_iterator(prefix) {
            match item {
                Ok((key, value)) => {
                    if !String::from_utf8_lossy(&key).starts_with(prefix_str.as_ref()) { break; }
                    if let Some(entry) = parse(&value) { results.push(entry); }
                }
                Err(_) => break,
            }
        }
        results
    }

    /// Persistiert alle Daten in RocksDB (CF: bridge).
    pub fn persist(&self) -> Result<(), String> {
        let db = super::open_token_db().map_err(|e| e.to_string())?;
        let cf = db.cf_handle(super::TOKEN_CF_BRIDGE)
            .ok_or("CF bridge nicht gefunden")?;

        // Balances
        for (address, assets) in &self.balances {
            for (asset, amount) in assets {
                let key = format!("bridge/balance/{}/{}", address, asset);
                let entry = BalanceEntry {
                    address: address.clone(),
                    asset: asset.clone(),
                    amount: *amount,
                };
                let val = serde_json::to_vec(&entry).map_err(|e| format!("serialize: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put: {e}"))?;
            }
        }

        // Deposits
        for deposit in &self.deposits {
            let key = format!("bridge/deposit/{}", deposit.id);
            let val = serde_json::to_vec(deposit).map_err(|e| format!("serialize: {e}"))?;
            db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put: {e}"))?;
        }

        // Withdrawals
        for withdrawal in &self.withdrawals {
            let key = format!("bridge/withdrawal/{}", withdrawal.id);
            let val = serde_json::to_vec(withdrawal).map_err(|e| format!("serialize: {e}"))?;
            db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put: {e}"))?;
        }

        Ok(())
    }

    // ─── Balance Operations ─────────────────────────────────────────────────

    /// Gibt die Balance eines Wrapped Assets für eine Adresse zurück.
    pub fn balance(&self, address: &str, asset: &WrappedAsset) -> Decimal {
        self.balances
            .get(address)
            .and_then(|m| m.get(asset))
            .copied()
            .unwrap_or(Decimal::ZERO)
    }

    /// Gibt alle Wrapped-Token-Balances für eine Adresse zurück.
    pub fn balances_for(&self, address: &str) -> HashMap<WrappedAsset, Decimal> {
        self.balances.get(address).cloned().unwrap_or_default()
    }

    /// Alle Adressen mit Wrapped-Token-Balances.
    pub fn all_balances(&self) -> &HashMap<String, HashMap<WrappedAsset, Decimal>> {
        &self.balances
    }

    /// Minted Wrapped Tokens an eine Adresse (intern, nach Deposit-Bestätigung).
    fn credit(&mut self, address: &str, asset: &WrappedAsset, amount: Decimal) {
        let entry = self.balances
            .entry(address.to_string())
            .or_default()
            .entry(asset.clone())
            .or_insert(Decimal::ZERO);
        *entry += amount;
    }

    /// Verbrennt Wrapped Tokens von einer Adresse (intern, bei Withdrawal).
    fn debit(&mut self, address: &str, asset: &WrappedAsset, amount: Decimal) -> Result<(), BridgeError> {
        let bal = self.balance(address, asset);
        if bal < amount {
            return Err(BridgeError::InsufficientBalance {
                have: bal,
                need: amount,
                asset: asset.to_string(),
            });
        }
        let entry = self.balances
            .entry(address.to_string())
            .or_default()
            .entry(asset.clone())
            .or_insert(Decimal::ZERO);
        *entry -= amount;
        if *entry == Decimal::ZERO {
            // Null-Balances aufräumen
            self.balances.get_mut(address).unwrap().remove(asset);
            if self.balances.get(address).map_or(true, |m| m.is_empty()) {
                self.balances.remove(address);
            }
        }
        Ok(())
    }

    /// Transfer von Wrapped Tokens zwischen Adressen (für HTLC etc.).
    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        asset: &WrappedAsset,
        amount: Decimal,
    ) -> Result<(), BridgeError> {
        if amount <= Decimal::ZERO {
            return Err(BridgeError::InvalidAmount("Betrag muss positiv sein".into()));
        }
        self.debit(from, asset, amount)?;
        self.credit(to, asset, amount);
        Ok(())
    }

    // ─── Deposit Operations ─────────────────────────────────────────────────

    /// Erstellt einen neuen Deposit-Request.
    pub fn create_deposit(
        &mut self,
        stone_address: String,
        asset: WrappedAsset,
        amount: Decimal,
        external_chain: String,
        external_tx_hash: String,
    ) -> BridgeDeposit {
        let now = chrono::Utc::now().timestamp();
        let raw = format!("dep|{}|{}|{}|{}|{}", stone_address, asset, amount, now, self.deposits.len());
        let hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let id = format!("dep-{}", &hash[..16]);

        let deposit = BridgeDeposit {
            id: id.clone(),
            stone_address,
            asset,
            amount,
            external_chain,
            external_tx_hash,
            status: DepositStatus::Pending,
            created_at: chrono::Utc::now().timestamp(),
            confirmed_at: None,
        };

        self.deposits.push(deposit.clone());
        deposit
    }

    /// Bestätigt einen Deposit und minted die Wrapped Tokens.
    pub fn confirm_deposit(&mut self, deposit_id: &str) -> Result<BridgeDeposit, BridgeError> {
        let deposit = self.deposits.iter_mut()
            .find(|d| d.id == deposit_id)
            .ok_or_else(|| BridgeError::NotFound(deposit_id.to_string()))?;

        if deposit.status != DepositStatus::Pending {
            return Err(BridgeError::InvalidStatus(format!(
                "Deposit {} ist {:?}, erwartet Pending",
                deposit_id, deposit.status,
            )));
        }

        deposit.status = DepositStatus::Confirmed;
        deposit.confirmed_at = Some(chrono::Utc::now().timestamp());

        let addr = deposit.stone_address.clone();
        let asset = deposit.asset.clone();
        let amount = deposit.amount;

        self.credit(&addr, &asset, amount);

        let _ = self.persist();

        println!(
            "[bridge] ✅ Deposit {} bestätigt: {} {} → {}",
            &deposit_id[..12.min(deposit_id.len())],
            amount,
            asset,
            &addr[..12.min(addr.len())],
        );

        Ok(self.deposits.iter().find(|d| d.id == deposit_id).unwrap().clone())
    }

    /// Gibt alle Deposits für eine Adresse zurück.
    pub fn deposits_for(&self, address: &str) -> Vec<&BridgeDeposit> {
        self.deposits.iter().filter(|d| d.stone_address == address).collect()
    }

    /// Gibt alle Deposits zurück.
    pub fn all_deposits(&self) -> &[BridgeDeposit] {
        &self.deposits
    }

    // ─── Withdrawal Operations ──────────────────────────────────────────────

    /// Erstellt einen Withdrawal-Request (Wrapped Tokens verbrennen).
    pub fn create_withdrawal(
        &mut self,
        stone_address: String,
        asset: WrappedAsset,
        amount: Decimal,
        external_address: String,
    ) -> Result<BridgeWithdrawal, BridgeError> {
        if amount <= Decimal::ZERO {
            return Err(BridgeError::InvalidAmount("Betrag muss positiv sein".into()));
        }

        // Balance prüfen und Tokens verbrennen
        self.debit(&stone_address, &asset, amount)?;

        let external_chain = asset.external_chain().to_string();
        let now = chrono::Utc::now().timestamp();
        let raw = format!("wd|{}|{}|{}|{}|{}", stone_address, asset, amount, now, self.withdrawals.len());
        let hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let id = format!("wd-{}", &hash[..16]);

        let withdrawal = BridgeWithdrawal {
            id: id.clone(),
            stone_address,
            asset: asset.clone(),
            amount,
            external_chain,
            external_address,
            status: WithdrawalStatus::Pending,
            created_at: chrono::Utc::now().timestamp(),
            completed_at: None,
            external_tx_hash: None,
        };

        self.withdrawals.push(withdrawal.clone());
        let _ = self.persist();

        println!(
            "[bridge] 🔥 Withdrawal {} erstellt: {} {} burn",
            &id[..12.min(id.len())],
            amount,
            asset,
        );

        Ok(withdrawal)
    }

    /// Markiert einen Withdrawal als abgeschlossen.
    pub fn complete_withdrawal(
        &mut self,
        withdrawal_id: &str,
        external_tx_hash: String,
    ) -> Result<BridgeWithdrawal, BridgeError> {
        let withdrawal = self.withdrawals.iter_mut()
            .find(|w| w.id == withdrawal_id)
            .ok_or_else(|| BridgeError::NotFound(withdrawal_id.to_string()))?;

        if withdrawal.status != WithdrawalStatus::Pending
            && withdrawal.status != WithdrawalStatus::Processing
        {
            return Err(BridgeError::InvalidStatus(format!(
                "Withdrawal {} ist {:?}",
                withdrawal_id, withdrawal.status,
            )));
        }

        withdrawal.status = WithdrawalStatus::Completed;
        withdrawal.completed_at = Some(chrono::Utc::now().timestamp());
        withdrawal.external_tx_hash = Some(external_tx_hash);

        let _ = self.persist();

        Ok(self.withdrawals.iter().find(|w| w.id == withdrawal_id).unwrap().clone())
    }

    /// Gibt alle Withdrawals für eine Adresse zurück.
    pub fn withdrawals_for(&self, address: &str) -> Vec<&BridgeWithdrawal> {
        self.withdrawals.iter().filter(|w| w.stone_address == address).collect()
    }

    /// Gibt alle Withdrawals zurück.
    pub fn all_withdrawals(&self) -> &[BridgeWithdrawal] {
        &self.withdrawals
    }

    // ─── Summary ────────────────────────────────────────────────────────────

    /// Gesamte Supply pro Wrapped Asset (alle Adressen summiert).
    pub fn total_supply(&self) -> HashMap<WrappedAsset, Decimal> {
        let mut totals: HashMap<WrappedAsset, Decimal> = HashMap::new();
        for assets in self.balances.values() {
            for (asset, amount) in assets {
                *totals.entry(asset.clone()).or_insert(Decimal::ZERO) += amount;
            }
        }
        totals
    }

    /// Zusammenfassung der Bridge-Aktivität.
    pub fn summary(&self) -> BridgeSummary {
        let total_supply = self.total_supply();
        let holder_count = self.balances.len();
        let total_deposits = self.deposits.len();
        let pending_deposits = self.deposits.iter()
            .filter(|d| d.status == DepositStatus::Pending)
            .count();
        let total_withdrawals = self.withdrawals.len();
        let pending_withdrawals = self.withdrawals.iter()
            .filter(|w| w.status == WithdrawalStatus::Pending || w.status == WithdrawalStatus::Processing)
            .count();

        BridgeSummary {
            total_supply,
            holder_count,
            total_deposits,
            pending_deposits,
            total_withdrawals,
            pending_withdrawals,
        }
    }
}

// ─── Summary Struct ──────────────────────────────────────────────────────────

/// Zusammenfassung der Bridge-Aktivität.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeSummary {
    pub total_supply: HashMap<WrappedAsset, Decimal>,
    pub holder_count: usize,
    pub total_deposits: usize,
    pub pending_deposits: usize,
    pub total_withdrawals: usize,
    pub pending_withdrawals: usize,
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct BalanceEntry {
    address: String,
    asset: WrappedAsset,
    amount: Decimal,
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Bridge-Fehlertypen.
#[derive(Debug)]
pub enum BridgeError {
    InsufficientBalance {
        have: Decimal,
        need: Decimal,
        asset: String,
    },
    InvalidAmount(String),
    NotFound(String),
    InvalidStatus(String),
    InvalidAsset(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::InsufficientBalance { have, need, asset } => {
                write!(f, "Ungenügend {asset}: {have} vorhanden, {need} benötigt")
            }
            BridgeError::InvalidAmount(msg) => write!(f, "Ungültiger Betrag: {msg}"),
            BridgeError::NotFound(id) => write!(f, "Nicht gefunden: {id}"),
            BridgeError::InvalidStatus(msg) => write!(f, "Ungültiger Status: {msg}"),
            BridgeError::InvalidAsset(msg) => write!(f, "Ungültiges Asset: {msg}"),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_debit() {
        let mut store = BridgeStore::new();
        store.credit("alice", &WrappedAsset::WUSDT, Decimal::new(100, 0));
        assert_eq!(store.balance("alice", &WrappedAsset::WUSDT), Decimal::new(100, 0));

        store.debit("alice", &WrappedAsset::WUSDT, Decimal::new(30, 0)).unwrap();
        assert_eq!(store.balance("alice", &WrappedAsset::WUSDT), Decimal::new(70, 0));

        // Insufficient balance
        assert!(store.debit("alice", &WrappedAsset::WUSDT, Decimal::new(100, 0)).is_err());
    }

    #[test]
    fn test_transfer() {
        let mut store = BridgeStore::new();
        store.credit("alice", &WrappedAsset::WBTC, Decimal::new(5, 0));
        store.transfer("alice", "bob", &WrappedAsset::WBTC, Decimal::new(2, 0)).unwrap();

        assert_eq!(store.balance("alice", &WrappedAsset::WBTC), Decimal::new(3, 0));
        assert_eq!(store.balance("bob", &WrappedAsset::WBTC), Decimal::new(2, 0));
    }

    #[test]
    fn test_deposit_confirm() {
        let mut store = BridgeStore::new();
        let dep = store.create_deposit(
            "alice".into(),
            WrappedAsset::WUSDT,
            Decimal::new(1000, 0),
            "ethereum".into(),
            "0xabc123".into(),
        );
        assert_eq!(dep.status, DepositStatus::Pending);
        assert_eq!(store.balance("alice", &WrappedAsset::WUSDT), Decimal::ZERO);

        store.confirm_deposit(&dep.id).unwrap();
        assert_eq!(store.balance("alice", &WrappedAsset::WUSDT), Decimal::new(1000, 0));
    }

    #[test]
    fn test_withdrawal() {
        let mut store = BridgeStore::new();
        store.credit("alice", &WrappedAsset::WETH, Decimal::new(10, 0));

        let wd = store.create_withdrawal(
            "alice".into(),
            WrappedAsset::WETH,
            Decimal::new(3, 0),
            "0xRecipient".into(),
        ).unwrap();

        assert_eq!(store.balance("alice", &WrappedAsset::WETH), Decimal::new(7, 0));
        assert_eq!(wd.status, WithdrawalStatus::Pending);
    }

    #[test]
    fn test_total_supply() {
        let mut store = BridgeStore::new();
        store.credit("alice", &WrappedAsset::WUSDT, Decimal::new(100, 0));
        store.credit("bob", &WrappedAsset::WUSDT, Decimal::new(200, 0));
        store.credit("alice", &WrappedAsset::WBTC, Decimal::new(5, 0));

        let supply = store.total_supply();
        assert_eq!(supply[&WrappedAsset::WUSDT], Decimal::new(300, 0));
        assert_eq!(supply[&WrappedAsset::WBTC], Decimal::new(5, 0));
    }
}
