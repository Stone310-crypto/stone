//! StoneCoin Genesis-Konfiguration
//!
//! Definiert die initiale Token-Verteilung beim Start der Chain.
//!
//! ## Supply-Verteilung (100.000.000 STONE)
//!
//! | Pool             | Anteil  | STONE      | Vesting            |
//! |------------------|---------|------------|--------------------|
//! | Mining Rewards   | 30%     | 30.000.000 | Halving-Emission   |
//! | Gaming Pool      | 45%     | 45.000.000 | Sofort (Play-2-Earn) |
//! | Treasury / Dev   |  7,5%   |  7.500.000 | 3 Jahre linear     |
//! | Governance       |  5%     |  5.000.000 | Grants/Voting      |
//! | Onboarding       |  5%     |  5.000.000 | Sofort (gesperrt)  |
//! | Founders         |  5%     |  5.000.000 | 4 Jahre linear     |
//! | Liquidity        |  2,5%   |  2.500.000 | Sofort             |
//!
//! ## Netzwerk-Modus
//!
//! Über `STONE_NETWORK=testnet|mainnet` wird gesteuert:
//! - **Testnet**: Genesis-Allokation an Test-Wallets, kein Vesting
//! - **Mainnet**: Echte Adressen, Vesting-Schedules aktiv
//!
//! Beim Testnet wird zusätzlich ein Faucet-Account mit 1.000.000 STONE angelegt.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use super::ledger::TokenLedger;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Testnet Faucet-Betrag: 1.000.000 STONE
const TESTNET_FAUCET_AMOUNT: &str = "1000000";

/// Maximales Supply (auch in ledger.rs definiert, hier zur Dokumentation)
const TOTAL_SUPPLY: &str = "100000000";

/// Adresse des Gaming-Pools (Play-to-Earn Auszahlungen).
pub const POOL_GAMING: &str = "pool:gaming";

/// Initial allokierter Betrag im Gaming-Pool.
pub const GAMING_POOL_AMOUNT: &str = "45000000";

// ─── Netzwerk-Modus ──────────────────────────────────────────────────────────

/// Netzwerk-Typ: Testnet oder Mainnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Testnet,
    Mainnet,
}

impl NetworkMode {
    /// Liest den Netzwerk-Modus aus der Umgebungsvariable `STONE_NETWORK`.
    /// Default: Testnet
    pub fn from_env() -> Self {
        match std::env::var("STONE_NETWORK")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "mainnet" | "main" => NetworkMode::Mainnet,
            _ => NetworkMode::Testnet,
        }
    }

    pub fn is_testnet(&self) -> bool {
        *self == NetworkMode::Testnet
    }
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkMode::Testnet => write!(f, "testnet"),
            NetworkMode::Mainnet => write!(f, "mainnet"),
        }
    }
}

// ─── Allokation ──────────────────────────────────────────────────────────────

/// Eine einzelne Genesis-Allokation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Empfänger-Adresse (Public-Key-Hex oder Bezeichner)
    pub address: String,
    /// Betrag in STONE
    pub amount: Decimal,
    /// Beschreibung (z.B. "Storage Rewards Pool")
    pub label: String,
    /// Vesting-Dauer in Monaten (0 = sofort verfügbar)
    pub vesting_months: u32,
}

// ─── Genesis-Konfiguration ──────────────────────────────────────────────────

/// Komplette Genesis-Konfiguration für die Token-Initialisierung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub network: NetworkMode,
    pub total_supply: Decimal,
    pub allocations: Vec<GenesisAllocation>,
}

impl GenesisConfig {
    /// Erstellt die Genesis-Konfiguration basierend auf dem Netzwerk-Modus.
    pub fn new(network: NetworkMode) -> Self {
        let total_supply: Decimal = TOTAL_SUPPLY.parse().unwrap();
        let allocations = match network {
            NetworkMode::Testnet => Self::testnet_allocations(total_supply),
            NetworkMode::Mainnet => Self::mainnet_allocations(total_supply),
        };

        GenesisConfig {
            network,
            total_supply,
            allocations,
        }
    }

    /// Erstellt die Genesis-Konfiguration aus der Umgebungsvariable.
    pub fn from_env() -> Self {
        Self::new(NetworkMode::from_env())
    }

    /// Testnet-Allokation: alles auf System-Pools + Faucet
    fn testnet_allocations(_total: Decimal) -> Vec<GenesisAllocation> {
        // Feste Beträge statt Prozente. Summe = 100M.
        vec![
            GenesisAllocation {
                address: "pool:mining_rewards".into(),
                amount: Decimal::new(30_000_000, 0),
                label: "Mining Rewards Pool".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: POOL_GAMING.into(),
                amount: Decimal::new(45_000_000, 0),
                label: "Gaming Pool (Play-to-Earn)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:governance".into(),
                amount: Decimal::new(5_000_000, 0),
                label: "Governance (Voting, Grants, Bounties)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:treasury".into(),
                amount: Decimal::new(7_500_000, 0),
                label: "Treasury / Development".into(),
                vesting_months: 0, // Testnet: kein Vesting
            },
            GenesisAllocation {
                address: "pool:onboarding".into(),
                amount: Decimal::new(5_000_000, 0),
                label: "Onboarding Pool (0.5 STONE/User, gesperrt)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:founders".into(),
                amount: Decimal::new(5_000_000, 0),
                label: "Founders".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:liquidity".into(),
                amount: Decimal::new(2_500_000, 0),
                label: "Liquidity Reserve".into(),
                vesting_months: 0,
            },
        ]
    }

    /// Mainnet-Allokation: echte Adressen mit Vesting
    fn mainnet_allocations(_total: Decimal) -> Vec<GenesisAllocation> {
        // Feste Beträge statt Prozente. Summe = 100M.
        vec![
            GenesisAllocation {
                address: "pool:mining_rewards".into(),
                amount: Decimal::new(30_000_000, 0),
                label: "Mining Rewards Pool".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: POOL_GAMING.into(),
                amount: Decimal::new(45_000_000, 0),
                label: "Gaming Pool (Play-to-Earn)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:governance".into(),
                amount: Decimal::new(5_000_000, 0),
                label: "Governance (Voting, Grants, Bounties)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:treasury".into(),
                amount: Decimal::new(7_500_000, 0),
                label: "Treasury / Development".into(),
                vesting_months: 36,
            },
            GenesisAllocation {
                address: "pool:onboarding".into(),
                amount: Decimal::new(5_000_000, 0),
                label: "Onboarding Pool (0.5 STONE/User, gesperrt)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:founders".into(),
                amount: Decimal::new(5_000_000, 0),
                label: "Founders".into(),
                vesting_months: 48,
            },
            GenesisAllocation {
                address: "pool:liquidity".into(),
                amount: Decimal::new(2_500_000, 0),
                label: "Liquidity Reserve".into(),
                vesting_months: 0,
            },
        ]
    }

    /// Gesamte Allokation berechnen (Validierung: muss == total_supply sein).
    pub fn total_allocated(&self) -> Decimal {
        self.allocations.iter().map(|a| a.amount).sum()
    }

    /// Validiert die Genesis-Konfiguration.
    pub fn validate(&self) -> Result<(), String> {
        let allocated = self.total_allocated();
        if allocated != self.total_supply {
            return Err(format!(
                "Allokation ({}) stimmt nicht mit Total Supply ({}) überein",
                allocated, self.total_supply
            ));
        }
        for a in &self.allocations {
            if a.amount <= Decimal::ZERO {
                return Err(format!("Allokation '{}' hat ungültigen Betrag: {}", a.label, a.amount));
            }
        }
        Ok(())
    }
}

// ─── Genesis anwenden ────────────────────────────────────────────────────────

/// Wendet die Genesis-Allokation auf den Ledger an.
///
/// Wird genau einmal beim allerersten Start aufgerufen (wenn der Ledger leer
/// ist und Block 0 noch keine TXs hat).
///
/// Gibt die erzeugten Mint-TXs zurück, die in den Genesis-Block eingefügt werden.
pub fn apply_genesis(ledger: &mut TokenLedger) -> Result<Vec<super::transaction::TokenTx>, String> {
    let config = GenesisConfig::from_env();

    // Validierung
    config.validate()?;

    // Prüfen ob Genesis schon angewendet wurde
    if ledger.total_supply() > Decimal::ZERO {
        println!("[token] Genesis bereits angewendet (Supply: {})", ledger.total_supply());
        return Ok(Vec::new());
    }

    println!(
        "[token] 🌱 Genesis-Allokation ({} – {} STONE Total Supply)",
        config.network, config.total_supply
    );

    let mut txs = Vec::new();

    for alloc in &config.allocations {
        // Mint direkt im Ledger
        ledger.mint(&alloc.address, alloc.amount)
            .map_err(|e| format!("Mint fehlgeschlagen für '{}': {e}", alloc.label))?;

        // Mint-TX für den Genesis-Block erstellen
        let tx = super::transaction::TokenTx {
            tx_id: String::new(), // wird unten berechnet
            tx_type: super::transaction::TxType::Mint,
            from: "system".to_string(),
            to: alloc.address.clone(),
            amount: alloc.amount,
            fee: Decimal::ZERO,
            nonce: 0,
            timestamp: 0, // Genesis-Timestamp
            signature: String::new(), // System-TXs brauchen keine Signatur
            memo: alloc.label.clone(),
            chain_id: format!("stone-{}", config.network),
            fee_tier: super::transaction::FeeTier::Priority,
            signed_by: None,
        };
        let tx_id = super::transaction::compute_tx_id(&tx);
        let tx = super::transaction::TokenTx { tx_id, ..tx };
        txs.push(tx);

        println!(
            "[token]   📦 {} → {} STONE (Vesting: {} Monate)",
            alloc.label, alloc.amount, alloc.vesting_months
        );

        // Vesting-Schedule registrieren (falls > 0 Monate)
        if alloc.vesting_months > 0 {
            let schedule = super::ledger::VestingSchedule {
                address: alloc.address.clone(),
                total_amount: alloc.amount,
                start_timestamp: chrono::Utc::now().timestamp(),
                duration_months: alloc.vesting_months,
                withdrawn: Decimal::ZERO,
            };
            ledger.add_vesting_schedule(schedule);
        }
    }

    // Testnet-Faucet
    if config.network.is_testnet() {
        let faucet_amount: Decimal = TESTNET_FAUCET_AMOUNT.parse().unwrap();
        println!(
            "[token]   🚰 Testnet-Faucet: {} STONE (aus Community Fund)",
            faucet_amount
        );
        // Faucet kommt aus dem Community-Pool (kein zusätzliches Mint)
        // → wird in Phase 2 implementiert (Transfer aus pool:community)
    }

    // Persistieren
    if let Err(e) = ledger.persist() {
        eprintln!("[token] ⚠️  Persistierung nach Genesis fehlgeschlagen: {e}");
    }

    println!(
        "[token] ✅ Genesis abgeschlossen: {} Allokationen, Supply: {}/{}",
        txs.len(),
        ledger.total_supply(),
        ledger.max_supply()
    );

    Ok(txs)
}

/// Einmalige Migration: Gaming-Pool mit 45M STONE auffüllen.
///
/// Wird bei jedem Node-Start aufgerufen. Idempotent: Wenn `pool:gaming`
/// bereits funded ist (oder Genesis frisch angewendet wurde, was den Pool
/// schon enthält), passiert nichts.
///
/// Auf bestehenden Chains (Genesis bereits angewendet, Pool existiert nicht)
/// wird einmalig 45M direkt in den Pool gemintet. Das erhöht das
/// `total_supply` um 45M auf 100M und benötigt entsprechend hohes
/// `MAX_SUPPLY` im Ledger.
pub fn migrate_pool_gaming(ledger: &mut TokenLedger) -> Result<bool, String> {
    let pool_balance = ledger.balance(POOL_GAMING);
    if pool_balance > Decimal::ZERO {
        return Ok(false);
    }
    let amount: Decimal = GAMING_POOL_AMOUNT
        .parse()
        .map_err(|e| format!("GAMING_POOL_AMOUNT parse: {e}"))?;
    ledger
        .mint(POOL_GAMING, amount)
        .map_err(|e| format!("Gaming-Pool Mint fehlgeschlagen: {e}"))?;
    if let Err(e) = ledger.persist() {
        eprintln!("[token] ⚠️  Persistierung nach Gaming-Pool-Migration fehlgeschlagen: {e}");
    }
    println!(
        "[token] 🎮 Gaming-Pool migriert: +{} STONE → {} (Supply: {}/{})",
        amount,
        POOL_GAMING,
        ledger.total_supply(),
        ledger.max_supply()
    );
    Ok(true)
}

/// Liest die Foundation Gaming-Wallet-Adresse aus der Umgebung
/// (`STONE_GAMING_POOL_MNEMONIC` → abgeleitete Public-Key-Adresse).
///
/// Gibt `None` zurück wenn die Variable nicht gesetzt oder das Mnemonic
/// ungültig ist (Server kann ohne Play-to-Earn-Wallet trotzdem laufen,
/// aber `/play-drop` schlägt fehl).
pub fn foundation_gaming_address() -> Option<String> {
    let mnemonic = std::env::var("STONE_GAMING_POOL_MNEMONIC").ok()?;
    let mnemonic = mnemonic.trim();
    if mnemonic.is_empty() {
        return None;
    }
    match crate::token::wallet::Wallet::from_mnemonic(mnemonic) {
        Ok(w) => Some(w.address()),
        Err(e) => {
            eprintln!(
                "[token] ⚠️  STONE_GAMING_POOL_MNEMONIC ungültig: {e} — Foundation-Wallet inaktiv"
            );
            None
        }
    }
}

/// Verschiebt die Gaming-Pool-Allokation auf die Foundation-Wallet,
/// damit Play-Drop-TXs vom Server signiert werden können.
///
/// Idempotent: Sobald die Foundation-Wallet ein Guthaben > 0 hat,
/// passiert nichts mehr.
pub fn unlock_gaming_pool_to_foundation(ledger: &mut TokenLedger) -> Result<bool, String> {
    let Some(addr) = foundation_gaming_address() else {
        return Ok(false);
    };
    let wallet_balance = ledger.balance(&addr);
    if wallet_balance > Decimal::ZERO {
        return Ok(false);
    }
    let pool_balance = ledger.balance(POOL_GAMING);
    if pool_balance <= Decimal::ZERO {
        return Ok(false);
    }
    // Direkter Ledger-Transfer (System-Operation, kein TX in der Chain).
    if let Err(e) = ledger.system_pool_transfer(POOL_GAMING, &addr, pool_balance) {
        return Err(format!("Pool-Transfer fehlgeschlagen: {e}"));
    }
    if let Err(e) = ledger.persist() {
        eprintln!(
            "[token] ⚠️  Persistierung nach Gaming-Pool-Unlock fehlgeschlagen: {e}"
        );
    }
    println!(
        "[token] 🎮 Gaming-Pool entsperrt: {} STONE → Foundation-Wallet {}",
        pool_balance,
        &addr[..16.min(addr.len())]
    );
    Ok(true)
}

// ─── Supply-Info ─────────────────────────────────────────────────────────────

/// Informationen über das Token-Supply (für API-Endpunkte).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SupplyInfo {
    pub network: String,
    pub total_supply: Decimal,
    pub max_supply: Decimal,
    pub circulating: Decimal,
    pub burned: Decimal,
    /// Kumulative Fees die durch TX-Gebühren verbrannt wurden
    pub fees_burned: Decimal,
    /// Vesting-gesperrte Token (noch nicht freigesetzt)
    pub vesting_locked: Decimal,
    pub accounts: usize,
}

impl SupplyInfo {
    pub fn from_ledger(ledger: &TokenLedger) -> Self {
        let config = GenesisConfig::from_env();
        let locked_pools: Decimal = ledger.balance("pool:mining_rewards")
            + ledger.balance("pool:governance")
            + ledger.balance("pool:treasury")
            + ledger.balance("pool:founders");

        // Vesting-gesperrte Token berechnen
        let now = chrono::Utc::now().timestamp();
        let vesting_locked: Decimal = ledger.all_vesting_schedules()
            .values()
            .map(|s| {
                let unreleased = s.total_amount - s.released_at(now);
                unreleased.max(Decimal::ZERO)
            })
            .sum();

        SupplyInfo {
            network: config.network.to_string(),
            total_supply: ledger.total_supply(),
            max_supply: ledger.max_supply(),
            circulating: ledger.total_supply() - locked_pools,
            burned: ledger.max_supply() - ledger.total_supply(),
            fees_burned: ledger.total_fees_burned(),
            vesting_locked,
            accounts: ledger.account_count(),
        }
    }
}
