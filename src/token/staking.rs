//! StoneCoin Staking-Pool
//!
//! Proof-of-Stake Light: Nutzer können STONE in den Pool einzahlen
//! und erhalten proportionale Rewards aus dem Storage-Rewards-Pool.
//!
//! ## Konzept
//!
//! | Parameter           | Wert                        |
//! |---------------------|-----------------------------|
//! | Min. Stake          | 100 STONE                   |
//! | Lock-Periode        | 7 Tage (Unstake-Wartezeit)  |
//! | Reward-Quelle       | pool:storage_rewards (60%)  |
//! | Epoch-Länge         | 720 Blöcke (~6h bei 30s)    |
//! | Staking-APY         | 2%-9% (dynamisch, Pool-abhängig) |
//! | Rewards pro Epoch   | total_staked × dynamic_APY / epochs_per_year |
//!
//! ## Flow
//!
//! 1. **Stake**: Nutzer sendet TX (Stake, amount) → Balance wird in StakingPool verbucht
//! 2. **Epoch-Tick**: Alle 720 Blöcke werden 9% APY anteilig verteilt
//! 3. **Unstake**: Nutzer sendet TX (Unstake, amount) → 7-Tage-Lock startet
//! 4. **Withdraw**: Nach Lock-Periode wird der Betrag in die Wallet zurückgebucht

use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Minimaler Stake-Betrag: 100 STONE
pub const MIN_STAKE: &str = "100";

/// Lock-Periode für Unstake: 7 Tage in Sekunden
pub const UNSTAKE_LOCK_SECS: i64 = 7 * 24 * 3600;

/// Epoch-Länge in Blöcken (bei 30s Mining-Intervall ≈ 6 Stunden)
pub const EPOCH_LENGTH: u64 = 720;

/// Maximale jährliche Staking-Rendite (APY-Obergrenze bei vollem Reward-Pool)
pub const STAKING_APY_MAX: &str = "0.09";

/// Minimale jährliche Staking-Rendite (APY-Untergrenze wenn Pool fast leer)
pub const STAKING_APY_FLOOR: &str = "0.02";

/// Initiale Größe des Storage-Reward-Pools (60% von 50M = 30M)
pub const INITIAL_REWARD_POOL: &str = "30000000";

/// Anzahl Epochen pro Jahr: 365.25 * 24 * 3600 / (EPOCH_LENGTH * 30s) ≈ 1461
pub const EPOCHS_PER_YEAR: u64 = 1461;

/// Staking-Pool-Adresse (virtueller Account)
pub const STAKING_POOL_ADDRESS: &str = "pool:staking";

/// Berechnet die aktuelle dynamische APY basierend auf dem Reward-Pool-Füllstand.
///
/// Formel: APY = FLOOR + (MAX - FLOOR) × (pool_balance / initial_pool)
///
/// | Pool-Füllstand | APY     |
/// |----------------|---------|
/// | 100% (30M)     | 9.0%    |
/// | 50% (15M)      | 5.5%    |
/// | 10% (3M)       | 2.7%    |
/// | 0%             | 2.0%    |
pub fn dynamic_apy(reward_pool_balance: Decimal) -> Decimal {
    let max_apy: Decimal = STAKING_APY_MAX.parse().unwrap();
    let floor_apy: Decimal = STAKING_APY_FLOOR.parse().unwrap();
    let initial_pool: Decimal = INITIAL_REWARD_POOL.parse().unwrap();

    if initial_pool <= Decimal::ZERO {
        return floor_apy;
    }

    let ratio = (reward_pool_balance / initial_pool).min(Decimal::ONE).max(Decimal::ZERO);
    let apy = floor_apy + (max_apy - floor_apy) * ratio;
    apy.round_dp(6)
}

// ─── Staker-Eintrag ──────────────────────────────────────────────────────────

/// Ein einzelner Staker im Pool.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StakerEntry {
    /// Wallet-Adresse des Stakers
    pub address: String,
    /// Aktuell gestaketer Betrag
    pub staked_amount: Decimal,
    /// Gesamte bisher verdiente Rewards
    pub total_rewards: Decimal,
    /// Unverdiente (pending) Rewards seit letztem Claim
    pub pending_rewards: Decimal,
    /// Zeitpunkt des ersten Stakes (Unix-Timestamp)
    pub staked_since: i64,
    /// Zeitpunkt des letzten Reward-Ticks
    pub last_reward_epoch: u64,
}

// ─── Unstake-Request ─────────────────────────────────────────────────────────

/// Ein ausstehender Unstake-Request (Lock-Periode).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnstakeRequest {
    /// Wallet-Adresse des Stakers
    pub address: String,
    /// Betrag der freigegeben wird
    pub amount: Decimal,
    /// Zeitpunkt des Unstake-Requests (Unix-Timestamp)
    pub requested_at: i64,
    /// Zeitpunkt ab dem die Auszahlung möglich ist
    pub available_at: i64,
}

// ─── Staking-Pool ────────────────────────────────────────────────────────────

/// Der Staking-Pool verwaltet alle Stakes, Rewards und Unstake-Requests.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StakingPool {
    /// Alle aktiven Staker: wallet_address → StakerEntry
    pub stakers: HashMap<String, StakerEntry>,
    /// Ausstehende Unstake-Requests
    pub unstake_queue: Vec<UnstakeRequest>,
    /// Gesamter Pool-Betrag (Summe aller Stakes)
    pub total_staked: Decimal,
    /// Gesamte bisher ausgeschüttete Rewards
    pub total_rewards_distributed: Decimal,
    /// Aktuelle Epoch-Nummer
    pub current_epoch: u64,
    /// Letzter Block in dem eine Epoch verarbeitet wurde
    pub last_epoch_block: u64,
}

// ─── Fehler ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StakingError {
    BelowMinimum { amount: Decimal, min: Decimal },
    InsufficientStake { address: String, staked: Decimal, requested: Decimal },
    NotStaked { address: String },
    LockPeriodActive { available_at: i64 },
    PoolExhausted,
}

impl std::fmt::Display for StakingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StakingError::BelowMinimum { amount, min } =>
                write!(f, "Stake-Betrag {} unter Minimum {}", amount, min),
            StakingError::InsufficientStake { address, staked, requested } =>
                write!(f, "Ungenügender Stake: {} hat {}, angefragt {}", &address[..12.min(address.len())], staked, requested),
            StakingError::NotStaked { address } =>
                write!(f, "Adresse {} hat keinen aktiven Stake", &address[..12.min(address.len())]),
            StakingError::LockPeriodActive { available_at } =>
                write!(f, "Unstake-Lock aktiv bis {}", available_at),
            StakingError::PoolExhausted =>
                write!(f, "Reward-Pool erschöpft"),
        }
    }
}

// ─── Pool-Info (API-Response) ────────────────────────────────────────────────

/// Öffentliche Staking-Pool-Informationen für die API.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StakingPoolInfo {
    pub total_staked: Decimal,
    pub total_rewards_distributed: Decimal,
    pub staker_count: usize,
    pub current_epoch: u64,
    pub epoch_length: u64,
    pub min_stake: Decimal,
    pub lock_period_days: u64,
    pub estimated_apy: Decimal,
    pub reward_pool_balance: Decimal,
}

/// Staker-spezifische Info für die API.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StakerInfo {
    pub address: String,
    pub staked_amount: Decimal,
    pub pending_rewards: Decimal,
    pub total_rewards: Decimal,
    pub staked_since: i64,
    pub unstake_requests: Vec<UnstakeRequest>,
    pub share_percent: Decimal,
}

// ─── Implementierung ─────────────────────────────────────────────────────────

impl StakingPool {
    /// Neuen leeren Staking-Pool erstellen.
    pub fn new() -> Self {
        StakingPool {
            stakers: HashMap::new(),
            unstake_queue: Vec::new(),
            total_staked: Decimal::ZERO,
            total_rewards_distributed: Decimal::ZERO,
            current_epoch: 0,
            last_epoch_block: 0,
        }
    }

    // ── Stake ─────────────────────────────────────────────────────────────

    /// Fügt einen Stake zum Pool hinzu.
    ///
    /// Prüft Min-Stake und aktualisiert den Pool-Zustand.
    /// Die Balance-Verschiebung (wallet → pool) muss vom Ledger gemacht werden!
    pub fn stake(&mut self, address: &str, amount: Decimal) -> Result<(), StakingError> {
        let min: Decimal = MIN_STAKE.parse().unwrap();

        // Prüfe ob der neue Gesamtstake des Stakers >= MIN ist
        let current_stake = self.stakers.get(address)
            .map(|s| s.staked_amount)
            .unwrap_or(Decimal::ZERO);

        if current_stake + amount < min {
            return Err(StakingError::BelowMinimum { amount: current_stake + amount, min });
        }

        let entry = self.stakers.entry(address.to_string()).or_insert_with(|| StakerEntry {
            address: address.to_string(),
            staked_amount: Decimal::ZERO,
            total_rewards: Decimal::ZERO,
            pending_rewards: Decimal::ZERO,
            staked_since: Utc::now().timestamp(),
            last_reward_epoch: self.current_epoch,
        });

        entry.staked_amount += amount;
        self.total_staked += amount;

        println!(
            "[staking] 📥 Stake: {} STONE von {} (Pool: {} STONE, {} Staker)",
            amount, &address[..12.min(address.len())],
            self.total_staked, self.stakers.len(),
        );

        Ok(())
    }

    // ── Unstake ───────────────────────────────────────────────────────────

    /// Initiiert einen Unstake-Request mit Lock-Periode.
    ///
    /// Der Betrag wird sofort vom Stake abgezogen, aber erst nach
    /// UNSTAKE_LOCK_SECS an die Wallet zurückgezahlt.
    pub fn request_unstake(&mut self, address: &str, amount: Decimal) -> Result<UnstakeRequest, StakingError> {
        let entry = self.stakers.get_mut(address)
            .ok_or_else(|| StakingError::NotStaked { address: address.to_string() })?;

        if entry.staked_amount < amount {
            return Err(StakingError::InsufficientStake {
                address: address.to_string(),
                staked: entry.staked_amount,
                requested: amount,
            });
        }

        // Stake reduzieren
        entry.staked_amount -= amount;
        self.total_staked -= amount;

        // Wenn Stake auf 0 fällt, Staker entfernen (aber erst pending rewards claimen)
        if entry.staked_amount == Decimal::ZERO && entry.pending_rewards == Decimal::ZERO {
            self.stakers.remove(address);
        }

        let now = Utc::now().timestamp();
        let request = UnstakeRequest {
            address: address.to_string(),
            amount,
            requested_at: now,
            available_at: now + UNSTAKE_LOCK_SECS,
        };

        self.unstake_queue.push(request.clone());

        println!(
            "[staking] 📤 Unstake-Request: {} STONE von {} (verfügbar in {} Tagen)",
            amount, &address[..12.min(address.len())],
            UNSTAKE_LOCK_SECS / 86400,
        );

        Ok(request)
    }

    // ── Epoch-Verarbeitung ────────────────────────────────────────────────

    /// Prüft ob eine neue Epoch fällig ist und verteilt ggf. Rewards.
    ///
    /// Wird vom Mining-Loop aufgerufen. Gibt die Menge der verteilten
    /// Rewards zurück (0 wenn keine Epoch fällig).
    ///
    /// `reward_pool_balance` = Balance von pool:storage_rewards im Ledger.
    pub fn process_epoch(
        &mut self,
        current_block: u64,
        reward_pool_balance: Decimal,
    ) -> Decimal {
        // Prüfen ob eine neue Epoch fällig ist
        if current_block < self.last_epoch_block + EPOCH_LENGTH {
            return Decimal::ZERO;
        }
        if self.total_staked == Decimal::ZERO || self.stakers.is_empty() {
            self.last_epoch_block = current_block;
            self.current_epoch += 1;
            return Decimal::ZERO;
        }

        // Dynamische APY basierend auf Reward-Pool-Füllstand
        let apy = dynamic_apy(reward_pool_balance);
        let epochs_year = Decimal::new(EPOCHS_PER_YEAR as i64, 0);
        let epoch_reward = (self.total_staked * apy / epochs_year).round_dp(8);

        if epoch_reward <= Decimal::ZERO {
            self.last_epoch_block = current_block;
            self.current_epoch += 1;
            return Decimal::ZERO;
        }

        // Sicherstellen dass nicht mehr verteilt wird als im Reward-Pool vorhanden
        let capped_reward = if epoch_reward > reward_pool_balance {
            reward_pool_balance
        } else {
            epoch_reward
        };

        if capped_reward <= Decimal::ZERO {
            self.last_epoch_block = current_block;
            self.current_epoch += 1;
            println!("[staking] ⚠️  Epoch #{}: Reward-Pool erschöpft", self.current_epoch);
            return Decimal::ZERO;
        }

        // Rewards proportional verteilen
        let mut total_distributed = Decimal::ZERO;
        let stakers: Vec<String> = self.stakers.keys().cloned().collect();

        for addr in &stakers {
            if let Some(entry) = self.stakers.get_mut(addr) {
                // Anteil = staked_amount / total_staked
                let share = entry.staked_amount / self.total_staked;
                let reward = (capped_reward * share).round_dp(8);

                if reward > Decimal::ZERO {
                    entry.pending_rewards += reward;
                    entry.total_rewards += reward;
                    entry.last_reward_epoch = self.current_epoch + 1;
                    total_distributed += reward;
                }
            }
        }

        self.total_rewards_distributed += total_distributed;
        self.current_epoch += 1;
        self.last_epoch_block = current_block;

        let current_apy_pct = (dynamic_apy(reward_pool_balance) * Decimal::new(100, 0)).round_dp(2);
        println!(
            "[staking] 💰 Epoch #{}: {} STONE Rewards an {} Staker ({}% APY, Pool: {})",
            self.current_epoch, total_distributed, stakers.len(), current_apy_pct, reward_pool_balance,
        );

        total_distributed
    }

    // ── Fällige Unstakes verarbeiten ──────────────────────────────────────

    /// Gibt alle Unstake-Requests zurück die die Lock-Periode überschritten haben.
    /// Entfernt diese aus der Queue. Die tatsächliche Balance-Gutschrift
    /// muss vom Ledger vorgenommen werden!
    pub fn drain_matured_unstakes(&mut self) -> Vec<UnstakeRequest> {
        let now = Utc::now().timestamp();
        let (matured, pending): (Vec<_>, Vec<_>) = self.unstake_queue
            .drain(..)
            .partition(|r| now >= r.available_at);

        self.unstake_queue = pending;

        if !matured.is_empty() {
            println!(
                "[staking] 🔓 {} Unstake-Requests fällig ({} STONE gesamt)",
                matured.len(),
                matured.iter().map(|r| r.amount).sum::<Decimal>(),
            );
        }

        matured
    }

    // ── Abfragen ──────────────────────────────────────────────────────────

    /// Pool-Info für die API.
    pub fn pool_info(&self, reward_pool_balance: Decimal) -> StakingPoolInfo {
        // Dynamische APY basierend auf Pool-Füllstand
        let apy = dynamic_apy(reward_pool_balance) * Decimal::new(100, 0);

        StakingPoolInfo {
            total_staked: self.total_staked,
            total_rewards_distributed: self.total_rewards_distributed,
            staker_count: self.stakers.len(),
            current_epoch: self.current_epoch,
            epoch_length: EPOCH_LENGTH,
            min_stake: MIN_STAKE.parse().unwrap(),
            lock_period_days: (UNSTAKE_LOCK_SECS / 86400) as u64,
            estimated_apy: apy,
            reward_pool_balance,
        }
    }

    /// Info für einen einzelnen Staker.
    pub fn staker_info(&self, address: &str) -> Option<StakerInfo> {
        self.stakers.get(address).map(|entry| {
            let share = if self.total_staked > Decimal::ZERO {
                (entry.staked_amount / self.total_staked * Decimal::new(100, 0)).round_dp(4)
            } else {
                Decimal::ZERO
            };

            let unstake_requests: Vec<UnstakeRequest> = self.unstake_queue
                .iter()
                .filter(|r| r.address == address)
                .cloned()
                .collect();

            StakerInfo {
                address: address.to_string(),
                staked_amount: entry.staked_amount,
                pending_rewards: entry.pending_rewards,
                total_rewards: entry.total_rewards,
                staked_since: entry.staked_since,
                unstake_requests,
                share_percent: share,
            }
        })
    }

    /// Alle Staker sortiert nach Stake-Betrag (absteigend).
    pub fn top_stakers(&self, limit: usize) -> Vec<StakerInfo> {
        let mut stakers: Vec<_> = self.stakers.keys()
            .filter_map(|addr| self.staker_info(addr))
            .collect();
        stakers.sort_by(|a, b| b.staked_amount.cmp(&a.staked_amount));
        stakers.truncate(limit);
        stakers
    }

    /// Claimed pending rewards für einen Staker.
    /// Gibt den geclaimten Betrag zurück.
    /// Die Gutschrift im Ledger muss extern passieren!
    pub fn claim_rewards(&mut self, address: &str) -> Result<Decimal, StakingError> {
        let entry = self.stakers.get_mut(address)
            .ok_or_else(|| StakingError::NotStaked { address: address.to_string() })?;

        let amount = entry.pending_rewards;
        entry.pending_rewards = Decimal::ZERO;

        if amount > Decimal::ZERO {
            println!(
                "[staking] 🎁 Reward-Claim: {} STONE → {}",
                amount, &address[..12.min(address.len())],
            );
        }

        Ok(amount)
    }

    // ── Slashing ──────────────────────────────────────────────────────────

    /// Slash: Reduziert den Stake eines Validators um den angegebenen Betrag.
    ///
    /// Der geslashte Betrag wird verbrannt (aus dem Pool entfernt, nicht umverteilt).
    /// Gibt den tatsächlich geslashten Betrag zurück (kann kleiner sein wenn Stake < amount).
    pub fn slash(&mut self, address: &str, amount: Decimal) -> Decimal {
        let entry = match self.stakers.get_mut(address) {
            Some(e) => e,
            None => return Decimal::ZERO,  // Kein Stake vorhanden
        };

        let actual = amount.min(entry.staked_amount);
        if actual <= Decimal::ZERO {
            return Decimal::ZERO;
        }

        entry.staked_amount -= actual;
        self.total_staked -= actual;

        println!(
            "[slashing] 🔥 {} STONE von {} geslasht (verbleibend: {} STONE)",
            actual, &address[..12.min(address.len())], entry.staked_amount,
        );

        // Staker entfernen wenn komplett leer
        if entry.staked_amount == Decimal::ZERO && entry.pending_rewards == Decimal::ZERO {
            self.stakers.remove(address);
        }

        actual
    }

    // ── Persistierung ─────────────────────────────────────────────────────

    /// Speichert den StakingPool in RocksDB.
    pub fn persist(&self) -> Result<(), String> {
        let db_path = format!("{}/token_db", crate::blockchain::data_dir());
        let db = rocksdb::DB::open_default(&db_path)
            .map_err(|e| format!("Staking DB open: {e}"))?;

        let json = serde_json::to_string(self)
            .map_err(|e| format!("Staking serialize: {e}"))?;

        db.put(b"staking_pool", json.as_bytes())
            .map_err(|e| format!("Staking put: {e}"))?;

        Ok(())
    }

    /// Lädt den StakingPool aus RocksDB.
    pub fn load() -> Self {
        let db_path = format!("{}/token_db", crate::blockchain::data_dir());
        let db = match rocksdb::DB::open_default(&db_path) {
            Ok(db) => db,
            Err(_) => return StakingPool::new(),
        };

        match db.get(b"staking_pool") {
            Ok(Some(bytes)) => {
                match serde_json::from_slice::<StakingPool>(&bytes) {
                    Ok(pool) => {
                        println!(
                            "[staking] 📂 Pool geladen: {} Staker, {} STONE gestaked, Epoch #{}",
                            pool.stakers.len(), pool.total_staked, pool.current_epoch,
                        );
                        pool
                    }
                    Err(e) => {
                        eprintln!("[staking] ⚠️  Pool-Deserialisierung fehlgeschlagen: {e}");
                        StakingPool::new()
                    }
                }
            }
            _ => StakingPool::new(),
        }
    }
}

impl Default for StakingPool {
    fn default() -> Self {
        Self::new()
    }
}
