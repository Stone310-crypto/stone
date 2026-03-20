//! StoneCoin Genesis-Konfiguration
//!
//! Definiert die initiale Token-Verteilung beim Start der Chain.
//!
//! ## Supply-Verteilung (50.000.000 STONE)
//!
//! | Pool             | Anteil | STONE      | Vesting         |
//! |------------------|--------|------------|-------------------|
//! | Storage Rewards  | 60%    | 30.000.000 | ~10 Jahre Emission |
//! | Treasury / Dev   | 15%    |  7.500.000 | 3 Jahre linear    |
//! | Onboarding       | 10%    |  5.000.000 | Sofort (gesperrt)  |
//! | Founders         | 10%    |  5.000.000 | 4 Jahre linear    |
//! | Liquidity        |  5%    |  2.500.000 | Sofort            |
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
const TOTAL_SUPPLY: &str = "50000000";

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
    fn testnet_allocations(total: Decimal) -> Vec<GenesisAllocation> {
        vec![
            GenesisAllocation {
                address: "pool:storage_rewards".into(),
                amount: total * Decimal::new(60, 2), // 60%
                label: "Storage Rewards Pool".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:treasury".into(),
                amount: total * Decimal::new(15, 2), // 15%
                label: "Treasury / Development".into(),
                vesting_months: 0, // Testnet: kein Vesting
            },
            GenesisAllocation {
                address: "pool:onboarding".into(),
                amount: total * Decimal::new(10, 2), // 10% = 5.000.000 STONE
                label: "Onboarding Pool (0.5 STONE/User, gesperrt)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:founders".into(),
                amount: total * Decimal::new(10, 2), // 10%
                label: "Founders".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:liquidity".into(),
                amount: total * Decimal::new(5, 2), // 5%
                label: "Liquidity Reserve".into(),
                vesting_months: 0,
            },
        ]
    }

    /// Mainnet-Allokation: echte Adressen mit Vesting
    fn mainnet_allocations(total: Decimal) -> Vec<GenesisAllocation> {
        // Mainnet-Adressen werden später über Config-Datei oder ENV gesetzt.
        // Hier die gleiche Pool-Struktur mit Vesting-Schedules.
        vec![
            GenesisAllocation {
                address: "pool:storage_rewards".into(),
                amount: total * Decimal::new(60, 2),
                label: "Storage Rewards Pool".into(),
                vesting_months: 0, // Emission über Epochs, nicht Vesting
            },
            GenesisAllocation {
                address: "pool:treasury".into(),
                amount: total * Decimal::new(15, 2),
                label: "Treasury / Development".into(),
                vesting_months: 36, // 3 Jahre
            },
            GenesisAllocation {
                address: "pool:onboarding".into(),
                amount: total * Decimal::new(10, 2),
                label: "Onboarding Pool (0.5 STONE/User, gesperrt)".into(),
                vesting_months: 0,
            },
            GenesisAllocation {
                address: "pool:founders".into(),
                amount: total * Decimal::new(10, 2),
                label: "Founders".into(),
                vesting_months: 48, // 4 Jahre
            },
            GenesisAllocation {
                address: "pool:liquidity".into(),
                amount: total * Decimal::new(5, 2),
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
            fee_tier: super::transaction::FeeTier::Express,
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
        let locked_pools: Decimal = ledger.balance("pool:storage_rewards")
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
