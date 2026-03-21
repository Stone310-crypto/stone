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

/// Mindest-Stake um als Validator aktiviert zu werden: 500 STONE
/// Anti-Sybil: Fake-Nodes wären wirtschaftlich unattraktiv.
pub const VALIDATOR_MIN_STAKE: &str = "500";

/// Mindest-Stake für Snapshot-Signierung: 250 STONE
pub const SNAPSHOT_SIGNER_MIN_STAKE: &str = "250";

/// Mindest-Stake für Governance-Voting: 100 STONE
pub const GOVERNANCE_MIN_STAKE: &str = "100";

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

/// Gebühren-Bonus-Multiplikator für aktive Node-Betreiber.
///
/// Node-Betreiber erhalten diesen Faktor auf ihren gewichteten Gebühren-Anteil.
/// Bei 1.5 bekommt ein Node-Betreiber 50% mehr Gebühren-Rewards pro STONE
/// als ein reiner Staker ohne eigene Node.
///
/// | Rolle          | Gewichtung pro STONE | Effekt                |
/// |----------------|----------------------|-----------------------|
/// | Staker         | 1.0×                 | Basis-Gebührenanteil  |
/// | Node-Betreiber | 1.5×                 | +50% Gebührenbonus    |
pub const NODE_OPERATOR_FEE_MULTIPLIER: &str = "1.5";

// ─── Stake-Level ─────────────────────────────────────────────────────────────

/// Stufe basierend auf Stake-Betrag. Bestimmt Berechtigungen im Netzwerk.
///
/// | Level       | Min. Stake | Rechte                                    |
/// |-------------|------------|-------------------------------------------|
/// | Observer    | 0 STONE    | Lesen, keine Governance                   |
/// | Participant | 100 STONE  | Governance-Voting, Chat                   |
/// | Guardian    | 250 STONE  | + Snapshot-Signierung                     |
/// | Validator   | 500 STONE  | + Block-Produktion, Report-Voting         |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeLevel {
    Observer,
    Participant,
    Guardian,
    Validator,
}

impl StakeLevel {
    /// Berechnet das Stake-Level anhand des gestaketen Betrags.
    pub fn from_stake(amount: Decimal) -> Self {
        let validator_min: Decimal = VALIDATOR_MIN_STAKE.parse().unwrap();
        let guardian_min: Decimal = SNAPSHOT_SIGNER_MIN_STAKE.parse().unwrap();
        let participant_min: Decimal = GOVERNANCE_MIN_STAKE.parse().unwrap();

        if amount >= validator_min {
            StakeLevel::Validator
        } else if amount >= guardian_min {
            StakeLevel::Guardian
        } else if amount >= participant_min {
            StakeLevel::Participant
        } else {
            StakeLevel::Observer
        }
    }

    /// Ob dieses Level Validator-Rechte hat (Block-Produktion, Report-Voting).
    pub fn can_validate(&self) -> bool {
        *self >= StakeLevel::Validator
    }

    /// Ob dieses Level Snapshots signieren darf.
    pub fn can_sign_snapshots(&self) -> bool {
        *self >= StakeLevel::Guardian
    }

    /// Ob dieses Level an Governance-Abstimmungen teilnehmen darf.
    pub fn can_vote_governance(&self) -> bool {
        *self >= StakeLevel::Participant
    }

    /// Mindest-Stake für dieses Level (als u32 für Netzwerk-Handshake).
    pub fn min_stake(&self) -> u32 {
        match self {
            StakeLevel::Observer => 0,
            StakeLevel::Participant => 100,
            StakeLevel::Guardian => 250,
            StakeLevel::Validator => 500,
        }
    }
}

impl std::fmt::Display for StakeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StakeLevel::Observer => write!(f, "observer"),
            StakeLevel::Participant => write!(f, "participant"),
            StakeLevel::Guardian => write!(f, "guardian"),
            StakeLevel::Validator => write!(f, "validator"),
        }
    }
}

// ─── Snapshot-Attestation ────────────────────────────────────────────────────

/// Eine Signatur eines Stakers über einen Snapshot.
/// Neue Nodes prüfen: Haben ≥2/3 der eligiblen Staker den Snapshot signiert?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAttestation {
    /// Block-Höhe des Snapshots
    pub block_height: u64,
    /// SHA-256 des Snapshot-Archivs
    pub archive_hash: String,
    /// State-Root zum Zeitpunkt des Snapshots
    pub state_root: String,
    /// Wallet-Adresse des Signers
    pub signer_wallet: String,
    /// Ed25519-Signatur über "snapshot:{block_height}:{archive_hash}:{state_root}"
    pub signature_hex: String,
    /// Stake des Signers zum Zeitpunkt der Signatur
    pub signer_stake: Decimal,
    /// Unix-Timestamp
    pub signed_at: i64,
}

/// Verifizierungsergebnis einer Snapshot-Attestation.
#[derive(Debug, Clone)]
pub struct SnapshotTrust {
    /// Anzahl gültiger Attestations
    pub valid_signatures: usize,
    /// Gesamter Stake der Signer
    pub attested_stake: Decimal,
    /// Gesamter Stake aller eligiblen Signer (Guardian+)
    pub total_eligible_stake: Decimal,
    /// Ob das Quorum erreicht ist (≥2/3 des eligiblen Stakes)
    pub quorum_reached: bool,
}

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

/// Der Staking-Pool verwaltet alle Stakes, Rewards, Delegations und Unstake-Requests.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StakingPool {
    /// Alle aktiven Staker: wallet_address → StakerEntry
    pub stakers: HashMap<String, StakerEntry>,
    /// Ausstehende Unstake-Requests
    pub unstake_queue: Vec<UnstakeRequest>,
    /// Gesamter Pool-Betrag (Summe aller Stakes + Delegations)
    pub total_staked: Decimal,
    /// Gesamte bisher ausgeschüttete Rewards
    pub total_rewards_distributed: Decimal,
    /// Aktuelle Epoch-Nummer
    pub current_epoch: u64,
    /// Letzter Block in dem eine Epoch verarbeitet wurde
    pub last_epoch_block: u64,
    /// Delegationen: delegator_wallet → DelegationEntry
    #[serde(default)]
    pub delegations: HashMap<String, DelegationEntry>,
    /// Gesamtes delegiertes Volumen
    #[serde(default)]
    pub total_delegated: Decimal,
}

// ─── Delegation (Split Validator) ────────────────────────────────────────────

/// Eine Delegation: Ein Coin-Halter delegiert Kapital an eine Validator-Node.
///
/// Split-Modell:
/// - Node-Betreiber stellt Infrastruktur
/// - Delegator stellt Kapital
/// - Rewards werden nach `split_pct` aufgeteilt:
///   `split_pct`% gehen an den Delegator, Rest an den Validator
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegationEntry {
    /// Wallet des Delegators
    pub delegator: String,
    /// Wallet des Validators (Node-Betreiber)
    pub validator: String,
    /// Delegierter Betrag
    pub amount: Decimal,
    /// Anteil des Delegators an den Rewards (0-100%)
    pub split_pct: u8,
    /// Zeitpunkt der Delegation (Unix-Timestamp)
    pub delegated_since: i64,
    /// Bisher verdiente Rewards (Delegator-Anteil)
    pub pending_rewards: Decimal,
    /// Gesamte bisherige Rewards
    pub total_rewards: Decimal,
}

// ─── Fehler ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StakingError {
    BelowMinimum { amount: Decimal, min: Decimal },
    InsufficientStake { address: String, staked: Decimal, requested: Decimal },
    NotStaked { address: String },
    LockPeriodActive { available_at: i64 },
    PoolExhausted,
    InsufficientStakeLevel { address: String, required: StakeLevel, actual: StakeLevel },
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
            StakingError::InsufficientStakeLevel { address, required, actual } =>
                write!(f, "Adresse {} hat Level '{}', benötigt '{}'", &address[..12.min(address.len())], actual, required),
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
    pub validator_min_stake: Decimal,
    pub lock_period_days: u64,
    pub estimated_apy: Decimal,
    pub reward_pool_balance: Decimal,
    pub validator_eligible_count: usize,
    pub guardian_eligible_count: usize,
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
    pub stake_level: StakeLevel,
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
            delegations: HashMap::new(),
            total_delegated: Decimal::ZERO,
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

        // Sicherstellen dass nicht mehr verteilt wird als im Reward-Pool vorhanden.
        // Staking darf pro Epoch maximal 20% des verbleibenden Pools nutzen,
        // damit der Mining-Reward (Halving-Schema) nicht ausgehungert wird.
        let max_staking_draw = (reward_pool_balance * Decimal::new(20, 2)).round_dp(8); // 20%
        let capped_reward = epoch_reward
            .min(reward_pool_balance)
            .min(max_staking_draw);

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

        // Delegation-Rewards: Split zwischen Delegator und Validator
        self.distribute_delegation_rewards(capped_reward);

        self.total_rewards_distributed += total_distributed;
        self.current_epoch += 1;
        self.last_epoch_block = current_block;

        let current_apy_pct = (dynamic_apy(reward_pool_balance) * Decimal::new(100, 0)).round_dp(2);
        println!(
            "[staking] 💰 Epoch #{}: {} STONE Rewards an {} Staker + {} Delegatoren ({}% APY, Pool: {})",
            self.current_epoch, total_distributed, stakers.len(), self.delegations.len(), current_apy_pct, reward_pool_balance,
        );

        total_distributed
    }

    // ── Gebühren-Verteilung (Fee Revenue Sharing) ─────────────────────────

    /// Verteilt akkumulierte TX-Gebühren aus `pool:staker_fees` an alle Staker.
    ///
    /// Node-Betreiber erhalten einen Bonus-Multiplikator ([`NODE_OPERATOR_FEE_MULTIPLIER`])
    /// auf ihren gewichteten Anteil, sodass sie pro STONE mehr Gebühren bekommen.
    ///
    /// Gibt eine Liste von `(wallet_address, amount)` zurück.
    /// Die Ledger-Gutschrift (pool:staker_fees → wallet) muss extern passieren!
    pub fn distribute_fee_income(
        &mut self,
        fee_pool_balance: Decimal,
        node_operator_wallets: &std::collections::HashSet<String>,
    ) -> Vec<(String, Decimal)> {
        if fee_pool_balance <= Decimal::ZERO || self.stakers.is_empty() {
            return Vec::new();
        }

        let multiplier: Decimal = NODE_OPERATOR_FEE_MULTIPLIER.parse().unwrap();
        let staker_addrs: Vec<String> = self.stakers.keys().cloned().collect();

        // 1. Gewichteten Gesamtstake berechnen
        let mut weighted_total = Decimal::ZERO;
        for addr in &staker_addrs {
            if let Some(entry) = self.stakers.get(addr) {
                if entry.staked_amount <= Decimal::ZERO {
                    continue;
                }
                let weight = if node_operator_wallets.contains(addr) {
                    entry.staked_amount * multiplier
                } else {
                    entry.staked_amount
                };
                weighted_total += weight;
            }
        }

        if weighted_total <= Decimal::ZERO {
            return Vec::new();
        }

        // 2. Proportional nach gewichtetem Stake verteilen
        let mut distributions: Vec<(String, Decimal)> = Vec::new();
        let mut distributed = Decimal::ZERO;
        let mut node_op_count = 0usize;

        for addr in &staker_addrs {
            if let Some(entry) = self.stakers.get_mut(addr) {
                if entry.staked_amount <= Decimal::ZERO {
                    continue;
                }
                let is_operator = node_operator_wallets.contains(addr);
                let weight = if is_operator {
                    entry.staked_amount * multiplier
                } else {
                    entry.staked_amount
                };
                let share = weight / weighted_total;
                let reward = (fee_pool_balance * share).round_dp(8);

                if reward > Decimal::ZERO {
                    entry.total_rewards += reward;
                    distributions.push((addr.clone(), reward));
                    distributed += reward;
                    if is_operator {
                        node_op_count += 1;
                    }
                }
            }
        }

        if distributed > Decimal::ZERO {
            println!(
                "[staking] 💸 Gebühren-Verteilung: {} STONE an {} Staker ({} Node-Ops mit {}x Bonus)",
                distributed, distributions.len(), node_op_count, multiplier,
            );
        }

        distributions
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

        let validator_eligible = self.stakers.values()
            .filter(|s| StakeLevel::from_stake(s.staked_amount).can_validate())
            .count();
        let guardian_eligible = self.stakers.values()
            .filter(|s| StakeLevel::from_stake(s.staked_amount).can_sign_snapshots())
            .count();

        StakingPoolInfo {
            total_staked: self.total_staked,
            total_rewards_distributed: self.total_rewards_distributed,
            staker_count: self.stakers.len(),
            current_epoch: self.current_epoch,
            epoch_length: EPOCH_LENGTH,
            min_stake: MIN_STAKE.parse().unwrap(),
            validator_min_stake: VALIDATOR_MIN_STAKE.parse().unwrap(),
            lock_period_days: (UNSTAKE_LOCK_SECS / 86400) as u64,
            estimated_apy: apy,
            reward_pool_balance,
            validator_eligible_count: validator_eligible,
            guardian_eligible_count: guardian_eligible,
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
                stake_level: StakeLevel::from_stake(entry.staked_amount),
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

    // ── Delegation (Split Validator Node) ─────────────────────────────────

    /// Delegiert Coins von einem Delegator an eine Validator-Node.
    ///
    /// Split-Modell: Der Delegator bekommt `split_pct`% der Rewards,
    /// der Validator-Betreiber den Rest. Default: 70% Delegator / 30% Validator.
    ///
    /// Die Balance-Verschiebung (wallet → pool) wird vom Ledger erledigt!
    pub fn delegate(
        &mut self,
        delegator: &str,
        validator: &str,
        amount: Decimal,
        split_pct: u8,
    ) -> Result<(), StakingError> {
        let min: Decimal = MIN_STAKE.parse().unwrap();

        // Delegation-Key: delegator → validator
        let key = format!("{}→{}", delegator, validator);

        let current = self.delegations.get(&key)
            .map(|d| d.amount)
            .unwrap_or(Decimal::ZERO);

        if current + amount < min {
            return Err(StakingError::BelowMinimum { amount: current + amount, min });
        }

        let split = split_pct.min(100);

        let entry = self.delegations.entry(key).or_insert_with(|| DelegationEntry {
            delegator: delegator.to_string(),
            validator: validator.to_string(),
            amount: Decimal::ZERO,
            split_pct: split,
            delegated_since: Utc::now().timestamp(),
            pending_rewards: Decimal::ZERO,
            total_rewards: Decimal::ZERO,
        });

        entry.amount += amount;
        entry.split_pct = split; // Aktualisiere Split bei nachträglicher Delegation
        self.total_delegated += amount;
        self.total_staked += amount;

        // Validator bekommt den delegierten Betrag zu seinem effektiven Stake
        let validator_entry = self.stakers.entry(validator.to_string()).or_insert_with(|| StakerEntry {
            address: validator.to_string(),
            staked_amount: Decimal::ZERO,
            total_rewards: Decimal::ZERO,
            pending_rewards: Decimal::ZERO,
            staked_since: Utc::now().timestamp(),
            last_reward_epoch: self.current_epoch,
        });
        validator_entry.staked_amount += amount;

        println!(
            "[staking] 🤝 Delegation: {} STONE von {} → {} (Split: {}% Delegator)",
            amount,
            &delegator[..12.min(delegator.len())],
            &validator[..12.min(validator.len())],
            split
        );

        Ok(())
    }

    /// Undelegation: Delegation zurückziehen → 7-Tage Escrow.
    pub fn request_undelegate(
        &mut self,
        delegator: &str,
        validator: &str,
        amount: Decimal,
    ) -> Result<UnstakeRequest, StakingError> {
        let key = format!("{}→{}", delegator, validator);

        let entry = self.delegations.get_mut(&key)
            .ok_or_else(|| StakingError::NotStaked { address: delegator.to_string() })?;

        if entry.amount < amount {
            return Err(StakingError::InsufficientStake {
                address: delegator.to_string(),
                staked: entry.amount,
                requested: amount,
            });
        }

        entry.amount -= amount;
        self.total_delegated -= amount;
        self.total_staked -= amount;

        // Vom Validator-Stake abziehen
        if let Some(vs) = self.stakers.get_mut(validator) {
            vs.staked_amount -= amount.min(vs.staked_amount);
            if vs.staked_amount == Decimal::ZERO && vs.pending_rewards == Decimal::ZERO {
                self.stakers.remove(validator);
            }
        }

        // Leere Delegation entfernen
        if entry.amount == Decimal::ZERO && entry.pending_rewards == Decimal::ZERO {
            self.delegations.remove(&key);
        }

        let now = Utc::now().timestamp();
        let request = UnstakeRequest {
            address: delegator.to_string(),
            amount,
            requested_at: now,
            available_at: now + UNSTAKE_LOCK_SECS,
        };

        self.unstake_queue.push(request.clone());

        println!(
            "[staking] 📤 Undelegation: {} STONE {} → {} (verfügbar in {} Tagen)",
            amount,
            &delegator[..12.min(delegator.len())],
            &validator[..12.min(validator.len())],
            UNSTAKE_LOCK_SECS / 86400,
        );

        Ok(request)
    }

    /// Verteilt Delegation-Rewards nach Split-Vereinbarung.
    ///
    /// Wird NACH der normalen Staker-Verteilung aufgerufen.
    /// Der Validator hat bereits den vollen Reward für delegierte Coins
    /// erhalten → wir verschieben `split_pct%` davon zum Delegator.
    fn distribute_delegation_rewards(&mut self, capped_reward: Decimal) {
        if self.total_delegated == Decimal::ZERO || self.delegations.is_empty() {
            return;
        }

        let keys: Vec<String> = self.delegations.keys().cloned().collect();
        for key in &keys {
            if let Some(entry) = self.delegations.get_mut(key) {
                if entry.amount <= Decimal::ZERO {
                    continue;
                }
                // Anteil dieser Delegation am Gesamtpool
                let share = entry.amount / self.total_staked;
                let reward_from_delegation = (capped_reward * share).round_dp(8);

                if reward_from_delegation > Decimal::ZERO {
                    // Delegator bekommt split_pct% des durch seine Delegation
                    // generierten Rewards (wird vom Validator-Anteil abgezogen)
                    let delegator_reward = (reward_from_delegation
                        * Decimal::from(entry.split_pct as u64)
                        / Decimal::from(100u64))
                    .round_dp(8);

                    entry.pending_rewards += delegator_reward;
                    entry.total_rewards += delegator_reward;

                    // Vom Validator abziehen (hat ihn bereits im Haupt-Loop bekommen)
                    if let Some(vs) = self.stakers.get_mut(&entry.validator) {
                        let deduct = delegator_reward.min(vs.pending_rewards);
                        vs.pending_rewards -= deduct;
                        vs.total_rewards -= deduct;
                    }
                }
            }
        }
    }

    /// Alle Delegationen eines Delegators.
    pub fn delegations_of(&self, delegator: &str) -> Vec<&DelegationEntry> {
        self.delegations.values()
            .filter(|d| d.delegator == delegator)
            .collect()
    }

    /// Alle Delegationen an einen Validator.
    pub fn delegations_to(&self, validator: &str) -> Vec<&DelegationEntry> {
        self.delegations.values()
            .filter(|d| d.validator == validator)
            .collect()
    }

    /// Effektiver Stake eines Validators (eigener Stake + Delegationen).
    pub fn effective_stake(&self, validator: &str) -> Decimal {
        let own = self.stakers.get(validator)
            .map(|s| s.staked_amount)
            .unwrap_or(Decimal::ZERO);
        own
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

    // ── Anti-Sybil: Validator-Eligibility ─────────────────────────────────

    /// Prüft ob eine Wallet-Adresse genug Stake hat um als Validator zu agieren.
    /// Anti-Sybil: Mindestens VALIDATOR_MIN_STAKE (500 STONE).
    pub fn is_validator_eligible(&self, wallet: &str) -> bool {
        self.stake_level(wallet).can_validate()
    }

    /// Prüft ob eine Wallet-Adresse Snapshots signieren darf.
    /// Mindestens SNAPSHOT_SIGNER_MIN_STAKE (250 STONE).
    pub fn is_snapshot_signer(&self, wallet: &str) -> bool {
        self.stake_level(wallet).can_sign_snapshots()
    }

    /// Gibt das Stake-Level einer Wallet-Adresse zurück.
    pub fn stake_level(&self, wallet: &str) -> StakeLevel {
        let amount = self.stakers.get(wallet)
            .map(|s| s.staked_amount)
            .unwrap_or(Decimal::ZERO);
        StakeLevel::from_stake(amount)
    }

    /// Gibt alle Wallets zurück die mindestens das angegebene Level haben.
    pub fn wallets_at_level(&self, min_level: StakeLevel) -> Vec<(String, Decimal)> {
        self.stakers.iter()
            .filter(|(_, entry)| StakeLevel::from_stake(entry.staked_amount) >= min_level)
            .map(|(addr, entry)| (addr.clone(), entry.staked_amount))
            .collect()
    }

    /// Gesamter Stake aller Wallets mit mindestens dem gegebenen Level.
    pub fn total_stake_at_level(&self, min_level: StakeLevel) -> Decimal {
        self.stakers.values()
            .filter(|entry| StakeLevel::from_stake(entry.staked_amount) >= min_level)
            .map(|entry| entry.staked_amount)
            .sum()
    }

    // ── Snapshot-Attestation ──────────────────────────────────────────────

    /// Verifiziert eine Liste von Snapshot-Attestations gegen den aktuellen Pool-Zustand.
    ///
    /// Gibt ein `SnapshotTrust`-Ergebnis zurück:
    /// - Quorum erreicht wenn ≥2/3 des eligiblen Stakes (Guardian+) den Snapshot signiert hat.
    pub fn verify_snapshot_attestations(
        &self,
        attestations: &[SnapshotAttestation],
        expected_block_height: u64,
        expected_archive_hash: &str,
        expected_state_root: &str,
    ) -> SnapshotTrust {
        let total_eligible_stake = self.total_stake_at_level(StakeLevel::Guardian);

        let mut valid_signatures = 0usize;
        let mut attested_stake = Decimal::ZERO;
        let mut seen_wallets = std::collections::HashSet::new();

        for att in attestations {
            // Prüfe ob die Attestation zum erwarteten Snapshot passt
            if att.block_height != expected_block_height
                || att.archive_hash != expected_archive_hash
                || att.state_root != expected_state_root
            {
                continue;
            }

            // Keine Doppelzählung
            if !seen_wallets.insert(att.signer_wallet.clone()) {
                continue;
            }

            // Prüfe ob Signer mindestens Guardian-Level hat
            if !self.is_snapshot_signer(&att.signer_wallet) {
                continue;
            }

            // Signatur verifizieren: message = "snapshot:{height}:{archive_hash}:{state_root}"
            let message = format!(
                "snapshot:{}:{}:{}",
                att.block_height, att.archive_hash, att.state_root
            );
            if crate::consensus::verify_block_signature_standalone(
                &message,
                &att.signer_wallet, // wallet = public_key_hex
                &att.signature_hex,
            ) {
                valid_signatures += 1;
                let stake = self.stakers.get(&att.signer_wallet)
                    .map(|s| s.staked_amount)
                    .unwrap_or(Decimal::ZERO);
                attested_stake += stake;
            }
        }

        // Quorum: ≥2/3 des eligiblen Stakes
        let quorum_reached = if total_eligible_stake > Decimal::ZERO {
            attested_stake * Decimal::from(3) >= total_eligible_stake * Decimal::from(2)
        } else {
            false
        };

        SnapshotTrust {
            valid_signatures,
            attested_stake,
            total_eligible_stake,
            quorum_reached,
        }
    }

    // ── Governance: Stake-gewichtetes Voting ──────────────────────────────

    /// Berechnet das Stimmgewicht einer Wallet für Governance/Report-Voting.
    /// Gewicht = gestakter Betrag (≥100 STONE nötig).
    /// Gibt 0 zurück wenn unter Mindest-Level.
    pub fn voting_weight(&self, wallet: &str) -> Decimal {
        let amount = self.stakers.get(wallet)
            .map(|s| s.staked_amount)
            .unwrap_or(Decimal::ZERO);
        if StakeLevel::from_stake(amount).can_vote_governance() {
            amount
        } else {
            Decimal::ZERO
        }
    }

    /// Berechnet ob ein stake-gewichtetes Vote-Ergebnis die Supermajorität erreicht hat.
    ///
    /// `votes`: (wallet, approve) Paare
    /// Gibt `Some(accepted)` zurück wenn genug Stake abgestimmt hat.
    /// Gibt `None` zurück wenn noch nicht genug Stimmen.
    pub fn evaluate_weighted_votes(
        &self,
        votes: &HashMap<String, bool>,
        min_level: StakeLevel,
    ) -> Option<bool> {
        let total_eligible = self.total_stake_at_level(min_level);
        if total_eligible == Decimal::ZERO {
            return None;
        }

        let mut total_voted = Decimal::ZERO;
        let mut approve_weight = Decimal::ZERO;

        for (wallet, &approved) in votes {
            let weight = self.voting_weight(wallet);
            if weight > Decimal::ZERO {
                total_voted += weight;
                if approved {
                    approve_weight += weight;
                }
            }
        }

        // Mindestens 51% des eligiblen Stakes muss abgestimmt haben
        let quorum = total_eligible * Decimal::new(51, 2);
        if total_voted < quorum {
            return None;
        }

        // Ergebnis: >50% der abgegebenen Stake-Gewichte
        Some(approve_weight * Decimal::from(2) > total_voted)
    }

    // ── Persistierung ─────────────────────────────────────────────────────

    /// Speichert den StakingPool in RocksDB.
    pub fn persist(&self) -> Result<(), String> {
        let db = super::open_token_db()
            .map_err(|e| format!("Staking DB: {e}"))?;

        let json = serde_json::to_string(self)
            .map_err(|e| format!("Staking serialize: {e}"))?;

        db.put(b"staking_pool", json.as_bytes())
            .map_err(|e| format!("Staking put: {e}"))?;

        Ok(())
    }

    /// Lädt den StakingPool aus RocksDB.
    pub fn load() -> Self {
        let db = match super::open_token_db() {
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

    /// Baut den StakingPool aus der Chain-History neu auf.
    ///
    /// Iteriert über alle Blöcke und wendet Stake/Unstake-TXs an.
    /// Wird beim Start aufgerufen wenn der persistierte Pool leer ist
    /// aber die Chain Stake-TXs enthält.
    pub fn rebuild_from_chain(blocks: &[crate::blockchain::Block]) -> Self {
        use super::transaction::TxType;
        let mut pool = StakingPool::new();
        let mut stake_count = 0u64;
        let mut unstake_count = 0u64;
        let mut delegate_count = 0u64;

        for block in blocks {
            for tx in &block.transactions {
                match tx.tx_type {
                    TxType::Stake => {
                        if pool.stake(&tx.from, tx.amount).is_ok() {
                            stake_count += 1;
                        }
                    }
                    TxType::Unstake => {
                        if pool.request_unstake(&tx.from, tx.amount).is_ok() {
                            unstake_count += 1;
                        }
                    }
                    TxType::Delegate => {
                        if pool.delegate(&tx.from, &tx.to, tx.amount, 70).is_ok() {
                            delegate_count += 1;
                        }
                    }
                    TxType::Undelegate => {
                        if pool.request_undelegate(&tx.from, &tx.to, tx.amount).is_ok() {
                            delegate_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        if stake_count > 0 || unstake_count > 0 || delegate_count > 0 {
            println!(
                "[staking] 🔄 Pool aus Chain rebuilt: {} Stakes, {} Unstakes, {} Delegations, {} Staker, {} STONE",
                stake_count, unstake_count, delegate_count, pool.stakers.len(), pool.total_staked,
            );
            if let Err(e) = pool.persist() {
                eprintln!("[staking] ⚠️  Pool-Persist nach Rebuild: {e}");
            }
        }

        pool
    }
}

impl Default for StakingPool {
    fn default() -> Self {
        Self::new()
    }
}
