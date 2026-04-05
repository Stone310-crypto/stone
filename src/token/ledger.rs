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
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::transaction::{TokenTx, TxError, TxType, validate_tx};

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Maximales Token-Supply: 55.000.000 STONE (Mainnet)
pub const MAX_SUPPLY: &str = "55000000";
/// Testnet Max-Supply: 550.000.000 STONE (10x Mainnet, damit Faucet nicht blockiert)
pub const MAX_SUPPLY_TESTNET: &str = "550000000";

/// Minimale Transaktionsgebühr (0.0001 STONE — Basis-Fee, wird geburnt)
pub const MIN_FEE: &str = "0.0001";

// ─── Vesting ─────────────────────────────────────────────────────────────────

/// Vesting-Schedule für einen Pool-Account.
///
/// Erzwingt lineare Token-Freigabe über `duration_months` Monate ab
/// `start_timestamp`. Nur der freigegebene Anteil kann transferiert werden.
///
/// `released(now) = total_amount × min(elapsed_months / duration_months, 1)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Pool/Account-Adresse
    pub address: String,
    /// Gesamtbetrag unter Vesting
    pub total_amount: Decimal,
    /// Unix-Timestamp des Genesis/Start
    pub start_timestamp: i64,
    /// Vesting-Dauer in Monaten
    pub duration_months: u32,
    /// Bisher abgehobener/freigegebener Betrag
    pub withdrawn: Decimal,
}

impl VestingSchedule {
    /// Berechnet den bis jetzt insgesamt freigegebenen Betrag (linear).
    pub fn released_at(&self, now: i64) -> Decimal {
        if self.duration_months == 0 {
            return self.total_amount; // Kein Vesting → alles sofort
        }
        let elapsed_secs = (now - self.start_timestamp).max(0) as u64;
        let elapsed_months = elapsed_secs / (30 * 24 * 3600); // ~30 Tage pro Monat
        if elapsed_months >= self.duration_months as u64 {
            return self.total_amount; // Vesting vollständig
        }
        let ratio = Decimal::new(elapsed_months as i64, 0)
            / Decimal::new(self.duration_months as i64, 0);
        (self.total_amount * ratio).round_dp(8)
    }

    /// Berechnet den aktuell verfügbaren (noch nicht abgehobenen) Betrag.
    pub fn available_at(&self, now: i64) -> Decimal {
        (self.released_at(now) - self.withdrawn).max(Decimal::ZERO)
    }

    /// Versucht `amount` als Withdrawal zu buchen. Gibt Fehler zurück wenn
    /// der Betrag die Vesting-Freigabe überschreitet.
    pub fn withdraw(&mut self, amount: Decimal, now: i64) -> Result<(), String> {
        let available = self.available_at(now);
        if amount > available {
            return Err(format!(
                "Vesting-Sperre: {} STONE verfügbar, {} angefordert (freigesetzt: {}, abgehoben: {})",
                available, amount, self.released_at(now), self.withdrawn,
            ));
        }
        self.withdrawn += amount;
        Ok(())
    }
}

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
    /// Transfer-Betrag übersteigt den freigesetzten Vesting-Anteil
    VestingLocked { account: String, message: String },
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
            LedgerError::VestingLocked { account, message } =>
                write!(f, "Vesting-Sperre für {account}: {message}"),
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

    // ── On-Chain Account Registry ─────────────────────────────────────────
    /// Wallet-Adresse → registrierter Account-Name.
    /// Wird aus AccountRegister-TXs aufgebaut und ist die einzige
    /// autoritative Quelle für Account-Zuordnungen.
    account_names: HashMap<String, String>,
    /// Wallet-Adresse → API-Key-Hash (SHA-256 der Phrase).
    /// Dient als Authentifizierungsbeweis, wird aus AccountRegister-TX memo gelesen.
    account_api_keys: HashMap<String, String>,
    /// Vesting-Schedules: pool-Adresse → VestingSchedule
    /// Verhindert Auszahlungen über den freigegebenen Betrag hinaus.
    vesting_schedules: HashMap<String, VestingSchedule>,
    /// Kumulative Fee-Burns seit Genesis
    total_fees_burned: Decimal,
    /// Aktueller Block-Validator (für Fee-Split, wird vor apply_block_txs gesetzt)
    current_block_validator: Option<String>,
    /// Letzter Block-Index, der vom Ledger verarbeitet wurde.
    /// Dient zur Erkennung von Chain/Ledger-Desync beim Startup.
    last_synced_block: Option<u64>,
    /// Replay-Modus: überspringt Nonce-/Signatur-Prüfung für vertrauenswürdige Chain-Replays.
    pub replay_mode: bool,
}

impl TokenLedger {
    /// Neuen leeren Ledger erstellen.
    pub fn new() -> Self {
        let network = crate::token::NetworkMode::from_env();
        let supply_str = if network.is_testnet() { MAX_SUPPLY_TESTNET } else { MAX_SUPPLY };
        TokenLedger {
            balances: HashMap::new(),
            nonces: HashMap::new(),
            total_supply: Decimal::ZERO,
            max_supply: supply_str.parse().expect("MAX_SUPPLY parse"),
            processed_txs: std::collections::HashSet::new(),
            key_rotations: HashMap::new(),
            key_rotation_history: HashMap::new(),
            account_names: HashMap::new(),
            account_api_keys: HashMap::new(),
            vesting_schedules: HashMap::new(),
            total_fees_burned: Decimal::ZERO,
            current_block_validator: None,
            last_synced_block: None,
            replay_mode: false,
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

    /// Prüft ob eine TX-ID bereits verarbeitet wurde (Duplikat-Schutz).
    pub fn is_processed_tx(&self, tx_id: &str) -> bool {
        self.processed_txs.contains(tx_id)
    }

    /// Nonce nach einer verarbeiteten TX aktualisieren.
    /// Im Replay-Modus wird die Nonce auf das Maximum gesetzt,
    /// da Blöcke aus dem Netzwerk ggf. Lücken aufweisen.
    fn advance_nonce(&mut self, from: &str, tx_nonce: u64) {
        let entry = self.nonces.entry(from.to_string()).or_insert(0);
        if self.replay_mode {
            *entry = (*entry).max(tx_nonce + 1);
        } else {
            *entry += 1;
        }
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

    /// Deterministischer State-Root-Hash über den gesamten Ledger-Zustand.
    ///
    /// SHA-256 über sortierte (Adresse, Balance, Nonce)-Tripel + Supply + Fees.
    /// Identischer Ledger-Zustand → identischer state_root auf allen Nodes.
    pub fn state_root(&self) -> String {
        let mut hasher = Sha256::new();
        // Sortierte Adressen für Determinismus
        let mut addrs: Vec<&String> = self.balances.keys().collect();
        addrs.sort();
        for addr in &addrs {
            let bal = self.balances.get(*addr).copied().unwrap_or(Decimal::ZERO);
            let nonce = self.nonces.get(*addr).copied().unwrap_or(0);
            // SECURITY: Length-Prefix vor jedem Feld verhindert Hash-Kollisionen
            // zwischen verschiedenen Ledger-Zuständen (z.B. addr="ab",bal="1"
            // vs addr="a",bal="b1").
            let addr_bytes = addr.as_bytes();
            hasher.update((addr_bytes.len() as u32).to_le_bytes());
            hasher.update(addr_bytes);
            let bal_str = bal.to_string();
            hasher.update((bal_str.len() as u32).to_le_bytes());
            hasher.update(bal_str.as_bytes());
            hasher.update(nonce.to_le_bytes());
        }
        let supply_str = self.total_supply.to_string();
        hasher.update((supply_str.len() as u32).to_le_bytes());
        hasher.update(supply_str.as_bytes());
        let fees_str = self.total_fees_burned.to_string();
        hasher.update((fees_str.len() as u32).to_le_bytes());
        hasher.update(fees_str.as_bytes());
        hex::encode(hasher.finalize())
    }

    // ── On-Chain Account-Registry Abfragen ────────────────────────────────

    /// Gibt den registrierten Account-Namen für eine Wallet-Adresse zurück.
    pub fn account_name(&self, wallet_address: &str) -> Option<&str> {
        self.account_names.get(wallet_address).map(|s| s.as_str())
    }

    /// Gibt den API-Key-Hash für eine Wallet-Adresse zurück.
    pub fn account_api_key_hash(&self, wallet_address: &str) -> Option<&str> {
        self.account_api_keys.get(wallet_address).map(|s| s.as_str())
    }

    /// Alle registrierten Accounts (Wallet → Name).
    pub fn all_registered_accounts(&self) -> &HashMap<String, String> {
        &self.account_names
    }

    /// Sucht einen Account nach API-Key-Hash.
    /// Gibt (wallet_address, name) zurück.
    pub fn find_account_by_api_key(&self, api_key_hash: &str) -> Option<(String, String)> {
        for (wallet, hash) in &self.account_api_keys {
            if hash == api_key_hash {
                let name = self.account_names.get(wallet).cloned().unwrap_or_default();
                return Some((wallet.clone(), name));
            }
        }
        None
    }

    /// Anzahl der in der Chain registrierten Accounts.
    pub fn registered_account_count(&self) -> usize {
        self.account_names.len()
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
    /// Prüft: Balance, Vesting-Sperre, Nonce, Signatur.
    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        amount: Decimal,
        fee: Decimal,
    ) -> Result<(), LedgerError> {
        let total_debit = amount + fee;

        // Balance-Check immer durchführen — auch im Replay-Modus.
        // Ungültige TXs in der Chain (z.B. Transfer ohne ausreichende Balance)
        // werden so konsistent über alle Nodes hinweg übersprungen.
        let current_balance = self.balance(from);
        if current_balance < total_debit {
            return Err(LedgerError::InsufficientBalance {
                account: from.to_string(),
                available: current_balance,
                required: total_debit,
            });
        }

        // Vesting-Check: im Replay-Modus überspringen (Chain war validiert)
        if !self.replay_mode {
            if let Some(schedule) = self.vesting_schedules.get_mut(from) {
                let now = chrono::Utc::now().timestamp();
                if let Err(e) = schedule.withdraw(total_debit, now) {
                    return Err(LedgerError::VestingLocked {
                        account: from.to_string(),
                        message: e,
                    });
                }
            }
        }

        // Abbuchen
        *self.balances.entry(from.to_string()).or_insert(Decimal::ZERO) -= total_debit;
        // Gutschreiben
        *self.balances.entry(to.to_string()).or_insert(Decimal::ZERO) += amount;

        // Fee-Split: 50% burn, 30% Validator, 20% Node-Operator-Pool
        if fee > Decimal::ZERO {
            self.apply_fee_split(fee);
        }

        Ok(())
    }

    /// Setzt den aktuellen Block-Validator (für Fee-Split).
    ///
    /// Muss vor `apply_block_txs()` aufgerufen werden.
    pub fn set_current_validator(&mut self, wallet: Option<String>) {
        self.current_block_validator = wallet;
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

        // SECURITY: Vesting-Check — gevestete Token dürfen nicht verbrannt werden
        if !self.replay_mode {
            if let Some(schedule) = self.vesting_schedules.get_mut(from) {
                let now = chrono::Utc::now().timestamp();
                if let Err(e) = schedule.withdraw(amount, now) {
                    return Err(LedgerError::VestingLocked {
                        account: from.to_string(),
                        message: e,
                    });
                }
            }
        }

        *self.balances.entry(from.to_string()).or_insert(Decimal::ZERO) -= amount;
        self.total_supply -= amount;

        println!(
            "[token] 🔥 Burn: {} STONE von {} (Supply: {})",
            amount, &from[..12.min(from.len())], self.total_supply
        );
        Ok(())
    }

    // ── Vesting ───────────────────────────────────────────────────────────

    /// Registriert einen Vesting-Schedule für eine Pool-Adresse.
    ///
    /// Wird einmalig bei Genesis aufgerufen für Pools mit `vesting_months > 0`.
    pub fn add_vesting_schedule(&mut self, schedule: VestingSchedule) {
        println!(
            "[token] 🔒 Vesting: {} – {} STONE über {} Monate",
            schedule.address, schedule.total_amount, schedule.duration_months,
        );
        self.vesting_schedules.insert(schedule.address.clone(), schedule);
    }

    /// Gibt den Vesting-Schedule für eine Adresse zurück (falls vorhanden).
    pub fn vesting_schedule(&self, address: &str) -> Option<&VestingSchedule> {
        self.vesting_schedules.get(address)
    }

    /// Gibt alle aktiven Vesting-Schedules zurück.
    pub fn all_vesting_schedules(&self) -> &HashMap<String, VestingSchedule> {
        &self.vesting_schedules
    }

    /// Kumulative verbrannte Fees seit Genesis.
    pub fn total_fees_burned(&self) -> Decimal {
        self.total_fees_burned
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

    /// Filtert eine Liste von TXs und gibt nur die zurück, die gegen den
    /// aktuellen Ledger-Stand gültig sind. Ungültige TXs werden geloggt
    /// und verworfen. Berücksichtigt kumulative Balance-Änderungen
    /// (mehrere TXs desselben Senders in einem Block).
    pub fn filter_valid_txs(&self, txs: &[TokenTx]) -> Vec<TokenTx> {
        use std::collections::HashMap;
        let mut valid = Vec::with_capacity(txs.len());
        // Temporäre Balance-Tracker: Reale Balance minus bereits für diesen
        // Block eingerechnete Abzüge.
        let mut pending_debits: HashMap<String, Decimal> = HashMap::new();
        // Temporäre Nonce-Tracker
        let mut pending_nonces: HashMap<String, u64> = HashMap::new();

        for tx in txs {
            // System-TXs (Reward, Mint, Memorial) immer durchlassen
            match tx.tx_type {
                TxType::Reward | TxType::Mint | TxType::Memorial => {
                    valid.push(tx.clone());
                    continue;
                }
                _ => {}
            }

            // Duplikat-Check
            if self.processed_txs.contains(&tx.tx_id) {
                eprintln!(
                    "[token] 🚫 TX {} verworfen: Duplikat",
                    &tx.tx_id[..12.min(tx.tx_id.len())]
                );
                continue;
            }

            // Nonce-Check (kumulativ: berücksichtigt vorherige TXs im selben Block)
            // ChatMessage TXs (amount=0, fee=0) überspringen den Nonce-Check —
            // kein Double-Spend-Risiko, Replay-Schutz via tx_id Uniqueness.
            // Das erlaubt Chat-TXs von Nodes mit veraltetem Ledger-Stand.
            let needs_nonce = matches!(
                tx.tx_type,
                TxType::Transfer | TxType::Burn | TxType::RotateKey
                | TxType::AccountRegister | TxType::AccountUpdate
                | TxType::Stake | TxType::Unstake
                | TxType::HtlcCreate
            );
            if needs_nonce {
                let expected = pending_nonces
                    .get(&tx.from)
                    .copied()
                    .unwrap_or_else(|| self.nonce(&tx.from));
                if tx.nonce != expected {
                    eprintln!(
                        "[token] 🚫 TX {} verworfen: Nonce {} erwartet {expected}",
                        &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce
                    );
                    continue;
                }
            }

            // Balance-Check (kumulativ: berücksichtigt vorherige TXs im selben Block)
            let needs_balance = matches!(
                tx.tx_type,
                TxType::Transfer | TxType::Burn | TxType::Stake
                | TxType::HtlcCreate
            );
            if needs_balance {
                let total_debit = tx.amount + tx.fee;
                let already_debited = pending_debits.get(&tx.from).copied().unwrap_or(Decimal::ZERO);
                let available = self.balance(&tx.from) - already_debited;
                if available < total_debit {
                    eprintln!(
                        "[token] 🚫 TX {} verworfen: {} hat {} verfügbar, benötigt {}",
                        &tx.tx_id[..12.min(tx.tx_id.len())],
                        &tx.from[..12.min(tx.from.len())],
                        available, total_debit
                    );
                    continue;
                }
                *pending_debits.entry(tx.from.clone()).or_insert(Decimal::ZERO) += total_debit;
            }

            // Nonce-Fortschritt tracken
            if needs_nonce {
                let next = pending_nonces
                    .get(&tx.from)
                    .copied()
                    .unwrap_or_else(|| self.nonce(&tx.from));
                pending_nonces.insert(tx.from.clone(), next + 1);
            }

            valid.push(tx.clone());
        }

        let rejected = txs.len() - valid.len();
        if rejected > 0 {
            println!(
                "[token] 🛡️  Pre-Block-Filter: {rejected} von {} TXs verworfen",
                txs.len()
            );
        }
        valid
    }

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
        // 1. Strukturelle Validierung (im Replay-Modus nur TX-ID prüfen, keine Signatur)
        if !self.replay_mode {
            validate_tx(tx)?;
        }

        // 2. Duplikat-Prüfung (Memorial-TXs sind in jedem Block identisch → überspringen)
        if tx.tx_type != TxType::Memorial && self.processed_txs.contains(&tx.tx_id) {
            return Err(LedgerError::TxValidation(TxError::Replay(
                format!("TX {} bereits verarbeitet", &tx.tx_id[..12])
            )));
        }

        // 3. Nonce-Prüfung (für alle Nutzer-Transaktionen inkl. Stake/Unstake)
        //    Im Replay-Modus überspringen: Blöcke wurden bereits vom Netzwerk validiert.
        if !self.replay_mode
            && (tx.tx_type == TxType::Transfer || tx.tx_type == TxType::Burn || tx.tx_type == TxType::RotateKey
            || tx.tx_type == TxType::AccountRegister || tx.tx_type == TxType::AccountUpdate
            || tx.tx_type == TxType::Stake || tx.tx_type == TxType::Unstake
            || tx.tx_type == TxType::Delegate || tx.tx_type == TxType::Undelegate
            || tx.tx_type == TxType::HtlcCreate)
        {
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
            TxType::Mint => {
                self.mint(&tx.to, tx.amount)?;
            }
            TxType::Reward => {
                // Block-Rewards werden aus pool:mining_rewards transferiert (nicht neu geminted)
                let pool_addr = "pool:mining_rewards";
                let pool_balance = self.balance(pool_addr);
                if pool_balance < tx.amount {
                    return Err(LedgerError::InsufficientBalance {
                        account: pool_addr.to_string(),
                        available: pool_balance,
                        required: tx.amount,
                    });
                }
                *self.balances.entry(pool_addr.to_string()).or_insert(Decimal::ZERO) -= tx.amount;
                *self.balances.entry(tx.to.clone()).or_insert(Decimal::ZERO) += tx.amount;
                // total_supply bleibt gleich – es werden keine neuen Token erzeugt
                println!(
                    "[token] ⛏️  Reward: {} STONE pool:mining_rewards → {}",
                    tx.amount, &tx.to[..16.min(tx.to.len())]
                );
            }
            TxType::Transfer => {
                self.transfer(&tx.from, &tx.to, tx.amount, tx.fee)?;
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::Burn => {
                self.burn(&tx.from, tx.amount)?;
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::RotateKey => {
                // from = alter Key, to = neuer Key
                self.rotate_key(&tx.from, &tx.to)?;
                // Nonce wird am alten Key NICHT mehr erhöht – Account ist ab jetzt inaktiv
            }
            TxType::AccountRegister => {
                // from == to == wallet_address, memo = JSON mit name + api_key_hash
                if self.account_names.contains_key(&tx.from) {
                    return Err(LedgerError::TxValidation(TxError::Replay(
                        format!("Account {} bereits registriert", &tx.from[..12.min(tx.from.len())])
                    )));
                }
                // Memo parsen: {"name":"…","api_key_hash":"…"}
                if let Ok(memo) = serde_json::from_str::<serde_json::Value>(&tx.memo) {
                    let name = memo.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let api_key_hash = memo.get("api_key_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if !name.is_empty() {
                        self.account_names.insert(tx.from.clone(), name);
                    }
                    if !api_key_hash.is_empty() {
                        self.account_api_keys.insert(tx.from.clone(), api_key_hash);
                    }
                }
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::AccountUpdate => {
                // Account muss existieren
                if !self.account_names.contains_key(&tx.from) {
                    return Err(LedgerError::TxValidation(TxError::MissingField(
                        format!("Account {} nicht registriert", &tx.from[..12.min(tx.from.len())])
                    )));
                }
                // Memo parsen und Felder aktualisieren
                if let Ok(memo) = serde_json::from_str::<serde_json::Value>(&tx.memo) {
                    if let Some(name) = memo.get("name").and_then(|v| v.as_str()) {
                        if !name.is_empty() {
                            self.account_names.insert(tx.from.clone(), name.to_string());
                        }
                    }
                }
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::Stake => {
                // from = Staker-Wallet, to = "pool:staking", amount = Stake-Betrag
                // Balance vom Staker abziehen und auf pool:staking gutschreiben
                let total_debit = tx.amount + tx.fee;
                let balance = self.balance(&tx.from);
                if balance < total_debit {
                    return Err(LedgerError::InsufficientBalance {
                        account: tx.from.clone(),
                        available: balance,
                        required: total_debit,
                    });
                }
                *self.balances.entry(tx.from.clone()).or_insert(Decimal::ZERO) -= total_debit;
                *self.balances.entry(super::staking::STAKING_POOL_ADDRESS.to_string()).or_insert(Decimal::ZERO) += tx.amount;
                // Fee-Split: 50% burn, 30% Validator, 20% Node-Operator-Pool
                if tx.fee > Decimal::ZERO {
                    self.apply_fee_split(tx.fee);
                }
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::Unstake => {
                // from = Staker-Wallet, to = "pool:staking", amount = Unstake-Betrag
                // Balance vom pool:staking abziehen (wird nach Lock-Periode an Wallet gutgeschrieben)
                let pool_balance = self.balance(super::staking::STAKING_POOL_ADDRESS);
                if pool_balance < tx.amount {
                    return Err(LedgerError::InsufficientBalance {
                        account: super::staking::STAKING_POOL_ADDRESS.to_string(),
                        available: pool_balance,
                        required: tx.amount,
                    });
                }
                *self.balances.entry(super::staking::STAKING_POOL_ADDRESS.to_string()).or_insert(Decimal::ZERO) -= tx.amount;
                // Fee-Split: 50% burn, 30% Validator, 20% Node-Operator-Pool
                if tx.fee > Decimal::ZERO {
                    let balance = self.balance(&tx.from);
                    if balance >= tx.fee {
                        *self.balances.entry(tx.from.clone()).or_insert(Decimal::ZERO) -= tx.fee;
                        self.apply_fee_split(tx.fee);
                    }
                }
                // Betrag geht zunächst auf ein Escrow (in der Lock-Queue) –
                // der StakingPool verwaltet die Lock-Periode und gibt frei.
                // Hier buchen wir den Betrag temporär auf eine Escrow-Adresse.
                *self.balances.entry(format!("escrow:unstake:{}", tx.from)).or_insert(Decimal::ZERO) += tx.amount;
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::Memorial => {
                // Eternal Memorial TX – keine Balance-Änderung, nur Präsenz im Block
            }
            TxType::ChatMessage => {
                // Chat-Nachricht: Gebühr von 0.0001 STONE wird vom Sender abgezogen.
                // Die Gebühr geht an die verarbeitende Node (über den Fee-Split).
                // Onboarding-Wallets (gesperrt) dürfen Chat-Fees bezahlen.
                let msg_fee = Decimal::new(1, 4); // 0.0001 STONE
                let sender_balance = self.balance(&tx.from);
                let locked_addr = format!("locked:{}", tx.from);
                let locked_balance = self.balance(&locked_addr);

                if sender_balance >= msg_fee {
                    // Freie Balance zuerst belasten
                    *self.balances.entry(tx.from.clone()).or_insert(Decimal::ZERO) -= msg_fee;
                    self.apply_fee_split(msg_fee);
                } else if locked_balance >= msg_fee {
                    // Onboarding-Guthaben verwenden (gesperrte Coins nur für Msg-Fees)
                    *self.balances.entry(locked_addr).or_insert(Decimal::ZERO) -= msg_fee;
                    self.apply_fee_split(msg_fee);
                }
                // Kein Nonce-Inkrement: ChatMessages überspringen die Nonce-Validierung
                // damit Nodes mit veraltetem Ledger-Stand chatten können.
            }
            TxType::Onboard => {
                // Onboarding: 0.5 STONE aus pool:onboarding → neue Wallet (gesperrt).
                // Gesperrte Coins können NUR für Message-Fees verwendet werden.
                let pool_addr = "pool:onboarding";
                let pool_balance = self.balance(pool_addr);
                if pool_balance < tx.amount {
                    return Err(LedgerError::InsufficientBalance {
                        account: pool_addr.to_string(),
                        available: pool_balance,
                        required: tx.amount,
                    });
                }
                *self.balances.entry(pool_addr.to_string()).or_insert(Decimal::ZERO) -= tx.amount;
                // Auf eine gesperrte Adresse gutschreiben (locked:{wallet})
                let locked_addr = format!("locked:{}", tx.to);
                *self.balances.entry(locked_addr).or_insert(Decimal::ZERO) += tx.amount;
                println!(
                    "[token] 🎁 Onboard: {} STONE → {} (gesperrt, nur für Message-Fees)",
                    tx.amount, &tx.to[..16.min(tx.to.len())]
                );
            }
            TxType::Delegate => {
                // Delegation: Coins von Delegator an eine Validator-Node delegieren.
                // Coins gehen auf pool:staking, werden aber dem Validator zugeordnet.
                let total_debit = tx.amount + tx.fee;
                let balance = self.balance(&tx.from);
                if balance < total_debit {
                    return Err(LedgerError::InsufficientBalance {
                        account: tx.from.clone(),
                        available: balance,
                        required: total_debit,
                    });
                }
                *self.balances.entry(tx.from.clone()).or_insert(Decimal::ZERO) -= total_debit;
                *self.balances.entry(super::staking::STAKING_POOL_ADDRESS.to_string())
                    .or_insert(Decimal::ZERO) += tx.amount;
                if tx.fee > Decimal::ZERO {
                    self.apply_fee_split(tx.fee);
                }
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::Undelegate => {
                // Undelegation: Delegation zurückziehen → 7-Tage Escrow.
                let pool_balance = self.balance(super::staking::STAKING_POOL_ADDRESS);
                if pool_balance < tx.amount {
                    return Err(LedgerError::InsufficientBalance {
                        account: super::staking::STAKING_POOL_ADDRESS.to_string(),
                        available: pool_balance,
                        required: tx.amount,
                    });
                }
                *self.balances.entry(super::staking::STAKING_POOL_ADDRESS.to_string())
                    .or_insert(Decimal::ZERO) -= tx.amount;
                if tx.fee > Decimal::ZERO {
                    let balance = self.balance(&tx.from);
                    if balance >= tx.fee {
                        *self.balances.entry(tx.from.clone()).or_insert(Decimal::ZERO) -= tx.fee;
                        self.apply_fee_split(tx.fee);
                    }
                }
                *self.balances.entry(format!("escrow:unstake:{}", tx.from))
                    .or_insert(Decimal::ZERO) += tx.amount;
                self.advance_nonce(&tx.from, tx.nonce);
            }
            TxType::HtlcCreate => {
                // from = Sender-Wallet, to = pool:htlc_escrow, amount = Sperrbetrag
                // Balance vom Sender abziehen und auf Escrow-Pool gutschreiben
                let total_debit = tx.amount + tx.fee;
                let balance = self.balance(&tx.from);
                if balance < total_debit {
                    return Err(LedgerError::InsufficientBalance {
                        account: tx.from.clone(),
                        available: balance,
                        required: total_debit,
                    });
                }
                *self.balances.entry(tx.from.clone()).or_insert(Decimal::ZERO) -= total_debit;
                *self.balances.entry(super::htlc::HTLC_ESCROW_POOL.to_string())
                    .or_insert(Decimal::ZERO) += tx.amount;
                if tx.fee > Decimal::ZERO {
                    self.apply_fee_split(tx.fee);
                }
                self.advance_nonce(&tx.from, tx.nonce);
                println!(
                    "[token] 🔒 HTLC Create: {} STONE {} → escrow (TX: {})",
                    tx.amount, &tx.from[..12.min(tx.from.len())], &tx.tx_id[..12]
                );
            }
            TxType::HtlcClaim => {
                // from = pool:htlc_escrow, to = Empfänger-Wallet, amount = HTLC-Betrag
                // Balance vom Escrow-Pool abziehen und an Empfänger gutschreiben
                let pool_balance = self.balance(super::htlc::HTLC_ESCROW_POOL);
                if pool_balance < tx.amount {
                    return Err(LedgerError::InsufficientBalance {
                        account: super::htlc::HTLC_ESCROW_POOL.to_string(),
                        available: pool_balance,
                        required: tx.amount,
                    });
                }
                *self.balances.entry(super::htlc::HTLC_ESCROW_POOL.to_string())
                    .or_insert(Decimal::ZERO) -= tx.amount;
                *self.balances.entry(tx.to.clone()).or_insert(Decimal::ZERO) += tx.amount;
                println!(
                    "[token] 🔓 HTLC Claim: {} STONE escrow → {} (TX: {})",
                    tx.amount, &tx.to[..12.min(tx.to.len())], &tx.tx_id[..12]
                );
            }
            TxType::HtlcRefund => {
                // from = pool:htlc_escrow, to = Sender-Wallet (Original-Ersteller), amount = HTLC-Betrag
                // Balance vom Escrow-Pool zurück an den Sender
                let pool_balance = self.balance(super::htlc::HTLC_ESCROW_POOL);
                if pool_balance < tx.amount {
                    return Err(LedgerError::InsufficientBalance {
                        account: super::htlc::HTLC_ESCROW_POOL.to_string(),
                        available: pool_balance,
                        required: tx.amount,
                    });
                }
                *self.balances.entry(super::htlc::HTLC_ESCROW_POOL.to_string())
                    .or_insert(Decimal::ZERO) -= tx.amount;
                *self.balances.entry(tx.to.clone()).or_insert(Decimal::ZERO) += tx.amount;
                println!(
                    "[token] ↩️  HTLC Refund: {} STONE escrow → {} (TX: {})",
                    tx.amount, &tx.to[..12.min(tx.to.len())], &tx.tx_id[..12]
                );
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
            self.last_synced_block = Some(block_index);
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
        let db = super::open_token_db()
            .map_err(|e| LedgerError::Persistence(format!("Persistierungsfehler: {e}")))?;

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

        // Account-Registry: name
        for (wallet, name) in &self.account_names {
            let key = format!("acct_name/{}", wallet);
            db.put(key.as_bytes(), name.as_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put acct_name: {e}")))?;
        }

        // Account-Registry: api_key_hash
        for (wallet, hash) in &self.account_api_keys {
            let key = format!("acct_key/{}", wallet);
            db.put(key.as_bytes(), hash.as_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put acct_key: {e}")))?;
        }

        // Vesting-Schedules
        for (addr, schedule) in &self.vesting_schedules {
            let key = format!("vesting/{}", addr);
            let json = serde_json::to_string(schedule).unwrap_or_default();
            db.put(key.as_bytes(), json.as_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put vesting: {e}")))?;
        }

        // Kumulative Fee-Burns
        db.put(b"fees_burned", self.total_fees_burned.to_string().as_bytes())
            .map_err(|e| LedgerError::Persistence(format!("put fees_burned: {e}")))?;

        // Letzter verarbeiteter Block-Index
        if let Some(last_block) = self.last_synced_block {
            db.put(b"last_synced_block", last_block.to_le_bytes())
                .map_err(|e| LedgerError::Persistence(format!("put last_synced_block: {e}")))?;
        } else {
            let _ = db.delete(b"last_synced_block");
        }

        // Processed TX-IDs (Duplikat-Schutz über Restarts hinweg)
        // Nur die neuesten TX-IDs persistieren (letzte 100k), ältere sind
        // ohnehin durch die Chain abgedeckt.
        {
            // Alte ptx/ Einträge löschen
            let mut to_delete = Vec::new();
            let iter = db.prefix_iterator(b"ptx/");
            for item in iter {
                if let Ok((key, _)) = item {
                    let key_str = String::from_utf8_lossy(&key);
                    if !key_str.starts_with("ptx/") { break; }
                    to_delete.push(key.to_vec());
                }
            }
            for key in &to_delete {
                let _ = db.delete(key);
            }
            // Nur die letzten MAX_PERSIST_TX_IDS speichern
            const MAX_PERSIST_TX_IDS: usize = 100_000;
            let tx_ids: Vec<&String> = self.processed_txs.iter().collect();
            let start = tx_ids.len().saturating_sub(MAX_PERSIST_TX_IDS);
            for tx_id in &tx_ids[start..] {
                let key = format!("ptx/{}", tx_id);
                db.put(key.as_bytes(), b"1")
                    .map_err(|e| LedgerError::Persistence(format!("put ptx: {e}")))?;
            }
        }

        println!("[token] 💾 Ledger persistiert: {} Accounts, {} Registrierte, {} Key-Rotations, {} Vesting, {} TX-IDs, Supply: {}",
            self.account_count(), self.registered_account_count(), self.key_rotations.len(),
            self.vesting_schedules.len(), self.processed_txs.len(), self.total_supply);
        Ok(())
    }

    /// Lädt den Ledger-Zustand aus RocksDB.
    ///
    /// Gibt einen leeren Ledger zurück wenn die DB nicht existiert.
    pub fn load() -> Self {
        let db = match super::open_token_db() {
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

        // Account-Registry: Namen laden
        let iter = db.prefix_iterator(b"acct_name/");
        for item in iter {
            if let Ok((key, value)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if !key_str.starts_with("acct_name/") {
                    break;
                }
                let wallet = key_str.strip_prefix("acct_name/").unwrap_or("").to_string();
                let name = String::from_utf8_lossy(&value).to_string();
                if !wallet.is_empty() && !name.is_empty() {
                    ledger.account_names.insert(wallet, name);
                }
            }
        }

        // Account-Registry: API-Key-Hashes laden
        let iter = db.prefix_iterator(b"acct_key/");
        for item in iter {
            if let Ok((key, value)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if !key_str.starts_with("acct_key/") {
                    break;
                }
                let wallet = key_str.strip_prefix("acct_key/").unwrap_or("").to_string();
                let hash = String::from_utf8_lossy(&value).to_string();
                if !wallet.is_empty() && !hash.is_empty() {
                    ledger.account_api_keys.insert(wallet, hash);
                }
            }
        }

        // Vesting-Schedules laden
        let iter = db.prefix_iterator(b"vesting/");
        for item in iter {
            if let Ok((key, value)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if !key_str.starts_with("vesting/") {
                    break;
                }
                let addr = key_str.strip_prefix("vesting/").unwrap_or("").to_string();
                if let Ok(schedule) = serde_json::from_slice::<VestingSchedule>(&value) {
                    ledger.vesting_schedules.insert(addr, schedule);
                }
            }
        }

        // Kumulative Fee-Burns laden
        if let Ok(Some(val)) = db.get(b"fees_burned") {
            if let Ok(burned) = String::from_utf8_lossy(&val).parse::<Decimal>() {
                ledger.total_fees_burned = burned;
            }
        }

        // Letzter verarbeiteter Block-Index
        if let Ok(Some(val)) = db.get(b"last_synced_block") {
            if val.len() == 8 {
                ledger.last_synced_block = Some(u64::from_le_bytes(val[..8].try_into().unwrap()));
            }
        }

        // Processed TX-IDs laden (Duplikat-Schutz über Restarts hinweg)
        {
            let iter = db.prefix_iterator(b"ptx/");
            for item in iter {
                if let Ok((key, _)) = item {
                    let key_str = String::from_utf8_lossy(&key);
                    if !key_str.starts_with("ptx/") { break; }
                    if let Some(tx_id) = key_str.strip_prefix("ptx/") {
                        ledger.processed_txs.insert(tx_id.to_string());
                    }
                }
            }
        }

        println!(
            "[token] 📂 Ledger geladen: {} Accounts, {} Registrierte, {} Key-Rotations, {} Vesting, {} TX-IDs, Supply: {}",
            ledger.account_count(),
            ledger.registered_account_count(),
            ledger.key_rotations.len(),
            ledger.vesting_schedules.len(),
            ledger.processed_txs.len(),
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
        // Replay-Modus: Blöcke aus der Chain waren bereits validiert,
        // daher Nonce-/Signatur-Prüfung überspringen
        ledger.replay_mode = true;

        // Genesis-Allokation anwenden (Mint-TXs sind nicht im Genesis-Block
        // gespeichert, sondern werden beim ersten Start separat erstellt)
        if let Err(e) = crate::token::apply_genesis(&mut ledger) {
            eprintln!("[token] ⚠️  Genesis-Fehler beim Rebuild: {e}");
        }

        for block in blocks {
            if !block.transactions.is_empty() {
                ledger.apply_block_txs(&block.transactions, block.index);
            }
            ledger.last_synced_block = Some(block.index);
        }

        ledger.replay_mode = false;
        if ledger.total_supply > Decimal::ZERO || ledger.registered_account_count() > 0 {
            println!(
                "[token] 🔄 Ledger aus Chain rekonstruiert: {} Accounts, {} Registrierte, Supply: {}",
                ledger.account_count(),
                ledger.registered_account_count(),
                ledger.total_supply
            );
            if let Err(e) = ledger.persist() {
                eprintln!("[token] Persistierung nach Rebuild fehlgeschlagen: {e}");
            }
        }
        ledger
    }

    /// Rekonstruiert das `processed_txs`-Set aus der Chain.
    ///
    /// Wird nach `load()` aufgerufen, damit der Duplikat-Schutz auch nach
    /// einem Neustart greift (processed_txs wird nicht in RocksDB persistiert).
    pub fn rebuild_processed_txs(&mut self, blocks: &[crate::blockchain::Block]) {
        let before = self.processed_txs.len();
        for block in blocks {
            for tx in &block.transactions {
                self.processed_txs.insert(tx.tx_id.clone());
            }
        }
        let added = self.processed_txs.len() - before;
        if added > 0 {
            println!(
                "[token] 🛡️  Replay-Schutz: {} TX-IDs aus Chain geladen",
                self.processed_txs.len()
            );
        }
    }

    /// Synchronisiert den Ledger mit der tatsächlichen Chain.
    ///
    /// Erkennt vier Fälle:
    /// 0. **Kein Sync-Marker** (alte DB ohne last_synced_block) → Integritätsprüfung
    /// 1. **Chain hat mehr Blöcke** als `last_synced_block` → fehlende Blöcke nachspielen
    /// 2. **Chain hat weniger Blöcke** (Reset/Prune) → kompletter Rebuild
    /// 3. **Chain und Ledger konsistent** → nur processed_txs laden
    ///
    /// Gibt `true` zurück wenn ein Rebuild/Replay stattgefunden hat.
    pub fn sync_with_chain(&mut self, blocks: &[crate::blockchain::Block]) -> bool {
        let chain_height = if blocks.is_empty() { 0 } else { blocks.last().unwrap().index + 1 };

        // Fall 0: Kein Sync-Marker vorhanden (alte DB) → immer Integritätsprüfung
        if self.last_synced_block.is_none() && chain_height > 0 {
            println!(
                "[token] ℹ️  Kein Sync-Marker in DB — Integritätsprüfung gegen Chain ({} Blöcke)",
                blocks.len()
            );
            return self.verify_and_repair(blocks);
        }

        let synced_to = self.last_synced_block.unwrap_or(0);

        // Fall 2: Chain wurde zurückgesetzt oder hat weniger Blöcke → kompletter Rebuild
        if chain_height > 0 && synced_to > 0 && chain_height <= synced_to {
            println!(
                "[token] ⚠️  Chain-Höhe ({}) < Ledger-Stand ({}) – Chain wurde zurückgesetzt, Rebuild nötig",
                chain_height, synced_to + 1
            );
            let rebuilt = Self::rebuild_from_chain(blocks);
            *self = rebuilt;
            return true;
        }

        // Fall 1: Fehlende Blöcke nachspielen (nur wenn Sync-Marker bekannt!)
        if chain_height > synced_to + 1 {
            let start_block = synced_to + 1;
            let mut replayed = 0u64;
            self.replay_mode = true;
            for block in blocks {
                if block.index < start_block {
                    // Nur processed_txs auffüllen für bereits verarbeitete Blöcke
                    for tx in &block.transactions {
                        self.processed_txs.insert(tx.tx_id.clone());
                    }
                    continue;
                }
                if !block.transactions.is_empty() {
                    self.apply_block_txs(&block.transactions, block.index);
                }
                self.last_synced_block = Some(block.index);
                replayed += 1;
            }
            self.replay_mode = false;
            if replayed > 0 {
                println!(
                    "[token] 🔄 {} fehlende Blöcke nachgespielt (#{} → #{}), Supply: {}",
                    replayed, start_block, chain_height - 1, self.total_supply
                );
                if let Err(e) = self.persist() {
                    eprintln!("[token] Persistierung nach Replay fehlgeschlagen: {e}");
                }
            } else {
                self.rebuild_processed_txs(blocks);
            }
            return replayed > 0;
        }

        // Fall 3: Konsistent — nur Replay-Schutz laden
        self.rebuild_processed_txs(blocks);
        false
    }

    /// Vergleicht den geladenen Ledger mit einem Chain-Rebuild und repariert bei Abweichung.
    fn verify_and_repair(&mut self, blocks: &[crate::blockchain::Block]) -> bool {
        let rebuilt = Self::rebuild_from_chain(blocks);
        let mut mismatches = Vec::new();
        for (addr, rebuilt_bal) in &rebuilt.balances {
            let current_bal = self.balance(addr);
            if current_bal != *rebuilt_bal {
                mismatches.push((addr.clone(), format!("Balance DB: {}, Chain: {}", current_bal, rebuilt_bal)));
            }
        }
        // Auch Accounts prüfen die nur im geladenen Ledger existieren
        for (addr, current_bal) in &self.balances {
            if !rebuilt.balances.contains_key(addr) && *current_bal != Decimal::ZERO {
                mismatches.push((addr.clone(), format!("Balance DB: {}, Chain: 0", current_bal)));
            }
        }
        // Nonces vergleichen — falsche Nonces führen dazu dass TXs
        // mit dem falschen Nonce erstellt werden und nie bestätigt werden.
        for (addr, rebuilt_nonce) in &rebuilt.nonces {
            let current_nonce = self.nonce(addr);
            if current_nonce != *rebuilt_nonce {
                mismatches.push((addr.clone(), format!("Nonce DB: {}, Chain: {}", current_nonce, rebuilt_nonce)));
            }
        }

        if !mismatches.is_empty() {
            eprintln!(
                "[token] ⚠️  LEDGER-DESYNC ERKANNT: {} Abweichungen!",
                mismatches.len()
            );
            for (addr, detail) in &mismatches {
                let label = if addr.len() > 20 { &addr[..16] } else { addr };
                eprintln!(
                    "[token]   {} — {}",
                    label, detail
                );
            }
            eprintln!("[token] → Ledger wird aus Chain neu aufgebaut");
            *self = rebuilt;
            return true;
        }

        // Alles konsistent — Sync-Marker setzen und processed_txs laden
        println!("[token] ✅ Ledger-Integritätscheck bestanden — Sync-Marker gesetzt");
        self.last_synced_block = rebuilt.last_synced_block;
        self.rebuild_processed_txs(blocks);
        if let Err(e) = self.persist() {
            eprintln!("[token] Persistierung des Sync-Markers fehlgeschlagen: {e}");
        }
        false
    }

    /// Getter für last_synced_block.
    pub fn last_synced_block(&self) -> Option<u64> {
        self.last_synced_block
    }

    /// Setter für last_synced_block (wird nach genesis-apply gebraucht).
    pub fn set_last_synced_block(&mut self, block: u64) {
        self.last_synced_block = Some(block);
    }

    /// Setzt den Sync-Marker zurück (für Migration/Repair).
    pub fn reset_sync_marker(&mut self) {
        self.last_synced_block = None;
    }
}

impl Default for TokenLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenLedger {
    /// Gibt freigegebene Unstake-Beträge aus dem Escrow an die Wallets zurück.
    ///
    /// Wird vom Mining-Loop aufgerufen nachdem der StakingPool matured Unstakes
    /// zurückgibt.
    pub fn release_unstake_escrow(&mut self, address: &str, amount: Decimal) {
        let escrow_key = format!("escrow:unstake:{}", address);
        let escrow_balance = self.balance(&escrow_key);
        let release = amount.min(escrow_balance);

        if release > Decimal::ZERO {
            *self.balances.entry(escrow_key).or_insert(Decimal::ZERO) -= release;
            *self.balances.entry(address.to_string()).or_insert(Decimal::ZERO) += release;
            println!(
                "[token] 🔓 Unstake-Escrow: {} STONE → {}",
                release, &address[..12.min(address.len())]
            );
        }
    }

    /// Gutschreibung von Staking-Rewards aus pool:mining_rewards.
    ///
    /// Transferiert `amount` von pool:mining_rewards auf die Ziel-Wallet.
    pub fn credit_staking_reward(&mut self, address: &str, amount: Decimal) -> Result<(), LedgerError> {
        let pool_balance = self.balance("pool:mining_rewards");
        if pool_balance < amount {
            return Err(LedgerError::InsufficientBalance {
                account: "pool:mining_rewards".to_string(),
                available: pool_balance,
                required: amount,
            });
        }
        *self.balances.entry("pool:mining_rewards".to_string()).or_insert(Decimal::ZERO) -= amount;
        *self.balances.entry(address.to_string()).or_insert(Decimal::ZERO) += amount;
        Ok(())
    }

    /// Auszahlung aus pool:governance (Voting-Rewards, Grants, Moderation-Rewards).
    ///
    /// Transferiert `amount` von pool:governance auf die Ziel-Wallet.
    pub fn credit_governance_payout(&mut self, address: &str, amount: Decimal, memo: &str) -> Result<(), LedgerError> {
        let pool = "pool:governance";
        let pool_balance = self.balance(pool);
        if pool_balance < amount {
            return Err(LedgerError::InsufficientBalance {
                account: pool.to_string(),
                available: pool_balance,
                required: amount,
            });
        }
        *self.balances.entry(pool.to_string()).or_insert(Decimal::ZERO) -= amount;
        *self.balances.entry(address.to_string()).or_insert(Decimal::ZERO) += amount;
        println!(
            "[governance] 💰 {} STONE → {} ({})",
            amount, &address[..12.min(address.len())], memo
        );
        Ok(())
    }

    /// Gutschreibung eines Node-Operator-Rewards aus pool:node_operators.
    pub fn credit_operator_reward(&mut self, address: &str, amount: Decimal) -> Result<(), LedgerError> {
        let pool = super::reputation::NODE_OPERATOR_POOL;
        let pool_balance = self.balance(pool);
        if pool_balance < amount {
            return Err(LedgerError::InsufficientBalance {
                account: pool.to_string(),
                available: pool_balance,
                required: amount,
            });
        }
        *self.balances.entry(pool.to_string()).or_insert(Decimal::ZERO) -= amount;
        *self.balances.entry(address.to_string()).or_insert(Decimal::ZERO) += amount;
        Ok(())
    }

    /// Slash-Betrag dem Node-Operator-Pool gutschreiben (z.B. aus Report-Slashing).
    pub fn credit_to_operator_pool(&mut self, amount: Decimal) {
        if amount > Decimal::ZERO {
            let pool = super::reputation::NODE_OPERATOR_POOL;
            *self.balances.entry(pool.to_string()).or_insert(Decimal::ZERO) += amount;
        }
    }

    /// Gutschreibung eines Fee-Rewards aus pool:staker_fees.
    ///
    /// Transferiert `amount` von pool:staker_fees → Staker-Wallet.
    pub fn credit_fee_reward(&mut self, address: &str, amount: Decimal) -> Result<(), LedgerError> {
        let pool = super::reputation::STAKER_FEE_POOL;
        let pool_balance = self.balance(pool);
        if pool_balance < amount {
            return Err(LedgerError::InsufficientBalance {
                account: pool.to_string(),
                available: pool_balance,
                required: amount,
            });
        }
        *self.balances.entry(pool.to_string()).or_insert(Decimal::ZERO) -= amount;
        *self.balances.entry(address.to_string()).or_insert(Decimal::ZERO) += amount;
        Ok(())
    }

    /// Interne Fee-Split-Logik: 37% Miner, 28% Staker-Pool, 20% burn, 10% Node-Ops, 5% Governance.
    fn apply_fee_split(&mut self, fee: Decimal) {
        let (burn, miner_share, staker_share, pool_share, gov_share) = super::reputation::split_fee(fee);

        // 20% verbrennen (Deflation)
        if burn > Decimal::ZERO {
            self.total_supply -= burn;
            self.total_fees_burned += burn;
        }

        // 37% → Block-Miner (aktueller Validator)
        if miner_share > Decimal::ZERO {
            if let Some(ref vw) = self.current_block_validator {
                *self.balances.entry(vw.clone()).or_insert(Decimal::ZERO) += miner_share;
            } else {
                // Kein Validator bekannt → verbrennen
                self.total_supply -= miner_share;
                self.total_fees_burned += miner_share;
            }
        }

        // 28% → Staker-Fee-Pool (wird proportional nach Stake verteilt)
        if staker_share > Decimal::ZERO {
            *self.balances.entry(super::reputation::STAKER_FEE_POOL.to_string())
                .or_insert(Decimal::ZERO) += staker_share;
        }

        // 10% → Node-Operator-Pool (Reputation-gewichtet verteilt)
        if pool_share > Decimal::ZERO {
            *self.balances.entry(super::reputation::NODE_OPERATOR_POOL.to_string())
                .or_insert(Decimal::ZERO) += pool_share;
        }

        // 5% → Governance-Pool (Nachfüllung aus Netzwerkaktivität)
        if gov_share > Decimal::ZERO {
            *self.balances.entry(super::governance::GOVERNANCE_POOL.to_string())
                .or_insert(Decimal::ZERO) += gov_share;
        }
    }
}
