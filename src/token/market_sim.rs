//! Testnet Market Simulator
//!
//! Simuliert Coin-Preis-Schwankungen im Testnet mit einem kombinierten Modell:
//!
//! 1. **Fixer Basiskurs**: 1 STONE = 0.10 TC$ (Testnet-Dollar)
//! 2. **Simulierter Markt**: Angebot/Nachfrage-Modell mit kontrollierter Volatilität
//! 3. **Echte Trades**: Kauf/Verkauf über pool:market_reserve mit realen Blockchain-TXs
//!
//! ## Design-Prinzip: Einfach entfernbar
//!
//! - Alles hinter `#[cfg(feature = "testnet_market")]` oder `NetworkMode::Testnet`
//! - Ein einziger `tick()` Call im Post-Block-Hook
//! - Eigener State, keine Abhängigkeit auf bestehende Ledger-Logik
//! - Entfernen = Modul löschen + Integration auskommentieren
//!
//! ## Nutzung
//!
//! ```ignore
//! let mut sim = TestnetMarket::new(TestnetMarketConfig::default());
//! sim.tick(); // Wird alle ~30s nach einem Block aufgerufen
//! let price = sim.current_price();   // z.B. 0.1042 TC$
//! let info  = sim.market_info();     // Snapshot für API
//! ```

use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Pool-Adresse für den Markt-Reserve-Pool.
/// Nutzt den Liquidity-Pool der bereits in der Genesis-Allokation existiert.
pub const MARKET_RESERVE_POOL: &str = "pool:liquidity";

/// Standard TC$-Startguthaben für neue Nutzer
pub const DEFAULT_TC_DOLLAR_BALANCE: f64 = 10_000.0;

/// Handelsgebühr in Prozent
pub const TRADE_FEE_PCT: f64 = 0.5;

// ═══════════════════════════════════════════════════════════════════════════════
//  Konfiguration
// ═══════════════════════════════════════════════════════════════════════════════

/// Konfiguration für die Testnet-Marktsimulation.
/// Alle Werte sind bewusst einfach gehalten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetMarketConfig {
    /// Simulator aktiv? (false = kein Tick, kein API-Output)
    pub enabled: bool,
    /// Fixer Basiskurs: 1 STONE = X TC$ (Testnet-Dollar)
    pub base_price: f64,
    /// Anfängliches simuliertes Angebot (normalisiert auf 1.0)
    pub initial_supply: f64,
    /// Anfängliche simulierte Nachfrage (normalisiert auf 1.0)
    pub initial_demand: f64,
    /// Volatilität pro Tick (0.0 = stabil, 0.1 = ±10% Schwankung)
    pub volatility: f64,
    /// Minimaler Multiplikator (Preis fällt nie unter base_price * min_multiplier)
    pub min_multiplier: f64,
    /// Maximaler Multiplikator (Preis steigt nie über base_price * max_multiplier)
    pub max_multiplier: f64,
    /// Mean-Reversion-Stärke (0.0 = keine, 1.0 = sofortige Rückkehr zum Basis)
    pub mean_reversion: f64,
    /// Trend-Persistenz: Wie stark beeinflusst der letzte Tick den nächsten
    pub momentum: f64,
    /// Maximale Anzahl gespeicherter Preis-Einträge (für History)
    pub max_history: usize,
}

impl Default for TestnetMarketConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_price: 0.10,         // 1 STONE = 0.10 TC$
            initial_supply: 1.0,
            initial_demand: 1.0,
            volatility: 0.05,         // ±5% Schwankung pro Tick
            min_multiplier: 0.5,      // Min: 0.05 TC$
            max_multiplier: 3.0,      // Max: 0.30 TC$
            mean_reversion: 0.02,     // Langsame Rückkehr zum Basispreis
            momentum: 0.3,            // 30% Trend-Persistenz
            max_history: 2880,        // ~24h bei 30s Block-Time
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Preis-Eintrag
// ═══════════════════════════════════════════════════════════════════════════════

/// Ein einzelner Preis-Snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricePoint {
    /// Unix-Timestamp
    pub timestamp: i64,
    /// Preis in TC$ (Testnet-Dollar)
    pub price: f64,
    /// Angebot-Multiplikator (1.0 = normal)
    pub supply: f64,
    /// Nachfrage-Multiplikator (1.0 = normal)
    pub demand: f64,
    /// Block-Höhe bei diesem Tick
    pub block_height: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Trade-Datenmodelle
// ═══════════════════════════════════════════════════════════════════════════════

/// Ein ausgeführter Markt-Trade (wird persistiert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeRecord {
    pub trade_id: String,
    pub timestamp: i64,
    pub side: TradeSide,
    /// STONE-Menge
    pub amount: f64,
    /// TC$ pro STONE zum Zeitpunkt des Trades
    pub price_per_coin: f64,
    /// Gesamtwert in TC$
    pub total_value: f64,
    /// Gebühr in TC$
    pub fee_amount: f64,
    /// TX-ID der Blockchain-Transaktion (STONE-Transfer)
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TradeSide {
    #[serde(rename = "buy")]
    Buy,
    #[serde(rename = "sell")]
    Sell,
}

/// Ergebnis eines Trade-Versuchs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeResult {
    pub ok: bool,
    pub trade_id: String,
    pub tx_id: String,
    pub side: TradeSide,
    pub amount: f64,
    pub price_per_coin: f64,
    pub total_value: f64,
    pub fee_amount: f64,
    pub tc_balance_after: f64,
}

/// TC$-Kontostand + Portfolio-Übersicht für eine Adresse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketBalance {
    pub address: String,
    pub tc_dollar_balance: f64,
    pub current_price: f64,
    pub trades: Vec<TradeRecord>,
    pub total_bought: f64,
    pub total_sold: f64,
    pub total_invested_tc: f64,
    pub total_returned_tc: f64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Market State
// ═══════════════════════════════════════════════════════════════════════════════

/// Testnet-Marktsimulator.
///
/// Kombiniert fixen Basiskurs mit simuliertem Angebot/Nachfrage-Modell.
/// Zustand wird in-memory gehalten und kann optional persistiert werden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetMarket {
    pub config: TestnetMarketConfig,
    /// Aktuelles simuliertes Angebot (normalisiert, Startwert 1.0)
    pub supply: f64,
    /// Aktuelle simulierte Nachfrage (normalisiert, Startwert 1.0)
    pub demand: f64,
    /// Letzter Momentum-Wert für Trend-Persistenz
    pub last_momentum: f64,
    /// Preis-History (Ring-Buffer)
    pub history: VecDeque<PricePoint>,
    /// Gesamtanzahl Ticks seit Start
    pub tick_count: u64,
    /// Zeitpunkt der Erstellung
    pub created_at: i64,
    /// TC$-Guthaben pro Wallet-Adresse (Testnet-Dollar für Markt-Trades)
    #[serde(default)]
    pub tc_balances: HashMap<String, f64>,
    /// Trade-History pro Wallet-Adresse (letzte Trades)
    #[serde(default)]
    pub trade_history: HashMap<String, Vec<TradeRecord>>,
}

impl TestnetMarket {
    /// Neuen Simulator mit gegebener Konfiguration erstellen.
    pub fn new(config: TestnetMarketConfig) -> Self {
        Self {
            supply: config.initial_supply,
            demand: config.initial_demand,
            last_momentum: 0.0,
            history: VecDeque::new(),
            tick_count: 0,
            created_at: Utc::now().timestamp(),
            tc_balances: HashMap::new(),
            trade_history: HashMap::new(),
            config,
        }
    }

    /// Aktuellen Preis in TC$ berechnen.
    ///
    /// Formel: `base_price * (demand / supply)`
    /// Mit Clamping auf [min_multiplier, max_multiplier].
    pub fn current_price(&self) -> f64 {
        let multiplier = if self.supply > 0.0 {
            self.demand / self.supply
        } else {
            1.0
        };
        let clamped = multiplier.clamp(self.config.min_multiplier, self.config.max_multiplier);
        self.config.base_price * clamped
    }

    /// Fixen Basiskurs zurückgeben (ohne Marktschwankungen).
    pub fn base_price(&self) -> f64 {
        self.config.base_price
    }

    /// Coin-Betrag in TC$ (Testnet-Dollar) umrechnen.
    pub fn to_testnet_dollars(&self, coins: f64) -> f64 {
        coins * self.current_price()
    }

    /// Coin-Betrag zum fixen Kurs umrechnen (stabile Variante).
    pub fn to_testnet_dollars_fixed(&self, coins: f64) -> f64 {
        coins * self.config.base_price
    }

    /// Formatierte Preis-Anzeige: "12.50 TC$"
    pub fn display_value(&self, coins: f64) -> String {
        format!("{:.2} TC$", self.to_testnet_dollars(coins))
    }

    /// Formatierte Preis-Anzeige zum fixen Kurs: "10.00 TC$"
    pub fn display_value_fixed(&self, coins: f64) -> String {
        format!("{:.2} TC$", self.to_testnet_dollars_fixed(coins))
    }

    /// Einen Simulations-Tick ausführen (wird pro Block aufgerufen).
    ///
    /// Aktualisiert Angebot und Nachfrage mit:
    /// 1. Zufälligem Rauschen (innerhalb Volatilität)
    /// 2. Mean-Reversion (Tendenz zurück zum Gleichgewicht)
    /// 3. Momentum (vorherige Richtung beeinflusst aktuelle)
    pub fn tick(&mut self, block_height: u64) {
        let mut rng = rand::thread_rng();

        // ── 1. Zufälliges Rauschen ────────────────────────────────────
        let noise: f64 = rng.gen_range(-1.0..1.0) * self.config.volatility;

        // ── 2. Mean-Reversion ─────────────────────────────────────────
        // Zieht demand/supply zurück zum Gleichgewicht (1.0)
        let reversion = (1.0 - self.demand / self.supply) * self.config.mean_reversion;

        // ── 3. Momentum ──────────────────────────────────────────────
        let trend = self.last_momentum * self.config.momentum;

        // ── Kombinierter Impuls ───────────────────────────────────────
        let impulse = noise + reversion + trend;
        self.last_momentum = impulse;

        // ── Demand anpassen ───────────────────────────────────────────
        self.demand *= 1.0 + impulse;
        self.demand = self.demand.clamp(
            self.config.min_multiplier * self.supply,
            self.config.max_multiplier * self.supply,
        );

        // ── Supply leichte Drift (simuliert Mining/Burning) ──────────
        let supply_drift: f64 = rng.gen_range(-0.002..0.003); // Leichte Inflation
        self.supply *= 1.0 + supply_drift;
        self.supply = self.supply.clamp(0.5, 3.0);

        // ── Preis-Punkt speichern ─────────────────────────────────────
        let point = PricePoint {
            timestamp: Utc::now().timestamp(),
            price: self.current_price(),
            supply: self.supply,
            demand: self.demand,
            block_height,
        };
        self.history.push_back(point);
        if self.history.len() > self.config.max_history {
            self.history.pop_front();
        }

        self.tick_count += 1;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  TC$ Balance & Trading
    // ═══════════════════════════════════════════════════════════════════

    /// TC$-Guthaben einer Adresse (erstellt Default-Guthaben bei erstem Zugriff).
    pub fn tc_balance(&mut self, address: &str) -> f64 {
        *self.tc_balances
            .entry(address.to_string())
            .or_insert(DEFAULT_TC_DOLLAR_BALANCE)
    }

    /// TC$-Guthaben ohne Auto-Erstellen (für Read-Only).
    pub fn tc_balance_read(&self, address: &str) -> f64 {
        self.tc_balances
            .get(address)
            .copied()
            .unwrap_or(DEFAULT_TC_DOLLAR_BALANCE)
    }

    /// Prüft ob ein Kauf möglich ist und gibt die Details zurück.
    /// Erstellt KEINE Transaktion — das macht der API-Handler.
    pub fn prepare_buy(&mut self, address: &str, stone_amount: f64) -> Result<(f64, f64, f64), String> {
        if stone_amount <= 0.0 {
            return Err("Betrag muss positiv sein".into());
        }
        let price = self.current_price();
        let total_tc = stone_amount * price;
        let fee = total_tc * TRADE_FEE_PCT / 100.0;
        let cost = total_tc + fee;
        let balance = self.tc_balance(address);
        if balance < cost {
            return Err(format!(
                "Nicht genug TC$: Guthaben {:.2}, benötigt {:.2} ({:.2} + {:.2} Gebühr)",
                balance, cost, total_tc, fee
            ));
        }
        Ok((price, total_tc, fee))
    }

    /// Bucht einen Kauf: TC$ abziehen, Trade speichern.
    /// Wird aufgerufen NACHDEM die echte STONE-TX im Mempool ist.
    pub fn confirm_buy(&mut self, address: &str, stone_amount: f64, price: f64, tx_id: &str) -> TradeResult {
        let total_tc = stone_amount * price;
        let fee = total_tc * TRADE_FEE_PCT / 100.0;
        let cost = total_tc + fee;

        // TC$ abziehen
        let balance = self.tc_balances.entry(address.to_string()).or_insert(DEFAULT_TC_DOLLAR_BALANCE);
        *balance -= cost;
        let balance_after = *balance;

        let trade_id = format!("trade-{}", uuid::Uuid::new_v4());
        let record = TradeRecord {
            trade_id: trade_id.clone(),
            timestamp: Utc::now().timestamp(),
            side: TradeSide::Buy,
            amount: stone_amount,
            price_per_coin: price,
            total_value: total_tc,
            fee_amount: fee,
            tx_id: tx_id.to_string(),
        };

        // Trade-History (max 100 pro User)
        let trades = self.trade_history.entry(address.to_string()).or_default();
        trades.push(record);
        if trades.len() > 100 {
            trades.drain(0..trades.len() - 100);
        }

        // Kauf beeinflusst Nachfrage leicht (+)
        self.demand *= 1.0 + (stone_amount * 0.001).min(0.02);
        self.demand = self.demand.clamp(
            self.config.min_multiplier * self.supply,
            self.config.max_multiplier * self.supply,
        );

        TradeResult {
            ok: true,
            trade_id,
            tx_id: tx_id.to_string(),
            side: TradeSide::Buy,
            amount: stone_amount,
            price_per_coin: price,
            total_value: total_tc,
            fee_amount: fee,
            tc_balance_after: balance_after,
        }
    }

    /// Prüft ob ein Verkauf möglich ist.
    /// STONE-Balance wird vom API-Handler über den Ledger geprüft.
    pub fn prepare_sell(&self, _address: &str, stone_amount: f64) -> Result<(f64, f64, f64), String> {
        if stone_amount <= 0.0 {
            return Err("Betrag muss positiv sein".into());
        }
        let price = self.current_price();
        let total_tc = stone_amount * price;
        let fee = total_tc * TRADE_FEE_PCT / 100.0;
        Ok((price, total_tc, fee))
    }

    /// Bucht einen Verkauf: TC$ gutschreiben, Trade speichern.
    /// Wird aufgerufen NACHDEM die echte STONE-TX im Mempool ist.
    pub fn confirm_sell(&mut self, address: &str, stone_amount: f64, price: f64, tx_id: &str) -> TradeResult {
        let total_tc = stone_amount * price;
        let fee = total_tc * TRADE_FEE_PCT / 100.0;
        let payout = total_tc - fee;

        // TC$ gutschreiben
        let balance = self.tc_balances.entry(address.to_string()).or_insert(DEFAULT_TC_DOLLAR_BALANCE);
        *balance += payout;
        let balance_after = *balance;

        let trade_id = format!("trade-{}", uuid::Uuid::new_v4());
        let record = TradeRecord {
            trade_id: trade_id.clone(),
            timestamp: Utc::now().timestamp(),
            side: TradeSide::Sell,
            amount: stone_amount,
            price_per_coin: price,
            total_value: total_tc,
            fee_amount: fee,
            tx_id: tx_id.to_string(),
        };

        let trades = self.trade_history.entry(address.to_string()).or_default();
        trades.push(record);
        if trades.len() > 100 {
            trades.drain(0..trades.len() - 100);
        }

        // Verkauf beeinflusst Nachfrage leicht (-)
        self.demand *= 1.0 - (stone_amount * 0.001).min(0.02);
        self.demand = self.demand.clamp(
            self.config.min_multiplier * self.supply,
            self.config.max_multiplier * self.supply,
        );

        TradeResult {
            ok: true,
            trade_id,
            tx_id: tx_id.to_string(),
            side: TradeSide::Sell,
            amount: stone_amount,
            price_per_coin: price,
            total_value: total_tc,
            fee_amount: fee,
            tc_balance_after: balance_after,
        }
    }

    /// Gibt die Markt-Balance-Infos einer Adresse zurück.
    pub fn market_balance(&self, address: &str) -> MarketBalance {
        let trades = self.trade_history.get(address).cloned().unwrap_or_default();
        let total_bought: f64 = trades.iter()
            .filter(|t| matches!(t.side, TradeSide::Buy))
            .map(|t| t.amount)
            .sum();
        let total_sold: f64 = trades.iter()
            .filter(|t| matches!(t.side, TradeSide::Sell))
            .map(|t| t.amount)
            .sum();
        let total_invested: f64 = trades.iter()
            .filter(|t| matches!(t.side, TradeSide::Buy))
            .map(|t| t.total_value + t.fee_amount)
            .sum();
        let total_returned: f64 = trades.iter()
            .filter(|t| matches!(t.side, TradeSide::Sell))
            .map(|t| t.total_value - t.fee_amount)
            .sum();

        MarketBalance {
            address: address.to_string(),
            tc_dollar_balance: self.tc_balance_read(address),
            current_price: self.current_price(),
            trades,
            total_bought,
            total_sold,
            total_invested_tc: total_invested,
            total_returned_tc: total_returned,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Analytics
    // ═══════════════════════════════════════════════════════════════════

    /// Letzte N Preis-Punkte (für Charts).
    pub fn price_history(&self, count: usize) -> Vec<&PricePoint> {
        self.history.iter().rev().take(count).collect::<Vec<_>>().into_iter().rev().collect()
    }

    /// 24h-Hoch.
    pub fn high_24h(&self) -> f64 {
        let cutoff = Utc::now().timestamp() - 86400;
        self.history
            .iter()
            .filter(|p| p.timestamp >= cutoff)
            .map(|p| p.price)
            .fold(f64::NEG_INFINITY, f64::max)
            .max(self.current_price())
    }

    /// 24h-Tief.
    pub fn low_24h(&self) -> f64 {
        let cutoff = Utc::now().timestamp() - 86400;
        self.history
            .iter()
            .filter(|p| p.timestamp >= cutoff)
            .map(|p| p.price)
            .fold(f64::INFINITY, f64::min)
            .min(self.current_price())
    }

    /// 24h-Änderung in Prozent.
    pub fn change_24h_pct(&self) -> f64 {
        let cutoff = Utc::now().timestamp() - 86400;
        let oldest = self.history
            .iter()
            .find(|p| p.timestamp >= cutoff)
            .map(|p| p.price);
        match oldest {
            Some(old) if old > 0.0 => ((self.current_price() - old) / old) * 100.0,
            _ => 0.0,
        }
    }

    /// Durchschnittspreis der letzten N Ticks.
    pub fn moving_average(&self, ticks: usize) -> f64 {
        let recent: Vec<f64> = self.history
            .iter()
            .rev()
            .take(ticks)
            .map(|p| p.price)
            .collect();
        if recent.is_empty() {
            return self.current_price();
        }
        recent.iter().sum::<f64>() / recent.len() as f64
    }

    // ═══════════════════════════════════════════════════════════════════
    //  API-Snapshot
    // ═══════════════════════════════════════════════════════════════════

    /// Kompletter Markt-Snapshot für die API.
    pub fn market_info(&self) -> MarketInfo {
        MarketInfo {
            enabled: self.config.enabled,
            mode: "simulated".to_string(),
            base_price: self.config.base_price,
            current_price: self.current_price(),
            supply_index: self.supply,
            demand_index: self.demand,
            high_24h: self.high_24h(),
            low_24h: self.low_24h(),
            change_24h_pct: self.change_24h_pct(),
            moving_avg_10: self.moving_average(10),
            moving_avg_50: self.moving_average(50),
            volatility: self.config.volatility,
            tick_count: self.tick_count,
            currency: "TC$".to_string(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Persistierung (optional)
    // ═══════════════════════════════════════════════════════════════════

    /// State als JSON speichern.
    pub fn save(&self) -> Result<(), String> {
        let path = format!("{}/testnet_market.json", crate::blockchain::data_dir());
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("Speichern fehlgeschlagen: {e}"))?;
        Ok(())
    }

    /// State aus JSON laden (oder Default erstellen).
    pub fn load_or_default() -> Self {
        let path = format!("{}/testnet_market.json", crate::blockchain::data_dir());
        match std::fs::read_to_string(&path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
                eprintln!("[market_sim] ⚠️ Laden fehlgeschlagen ({e}), verwende Default");
                Self::new(TestnetMarketConfig::default())
            }),
            Err(_) => Self::new(TestnetMarketConfig::default()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  API-Datenmodell
// ═══════════════════════════════════════════════════════════════════════════════

/// Markt-Informationen für die REST-API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketInfo {
    pub enabled: bool,
    pub mode: String,
    pub base_price: f64,
    pub current_price: f64,
    pub supply_index: f64,
    pub demand_index: f64,
    pub high_24h: f64,
    pub low_24h: f64,
    pub change_24h_pct: f64,
    pub moving_avg_10: f64,
    pub moving_avg_50: f64,
    pub volatility: f64,
    pub tick_count: u64,
    pub currency: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_price() {
        let market = TestnetMarket::new(TestnetMarketConfig::default());
        let price = market.current_price();
        assert!((price - 0.10).abs() < 0.001, "Startpreis sollte ~0.10 sein, war {price}");
    }

    #[test]
    fn test_fixed_display() {
        let market = TestnetMarket::new(TestnetMarketConfig::default());
        assert_eq!(market.display_value_fixed(100.0), "10.00 TC$");
    }

    #[test]
    fn test_tick_changes_price() {
        let mut market = TestnetMarket::new(TestnetMarketConfig::default());
        let initial = market.current_price();
        // Nach 100 Ticks sollte sich der Preis verändert haben
        for i in 0..100 {
            market.tick(i);
        }
        // Preis sollte sich bewegt haben (sehr unwahrscheinlich dass er exakt gleich bleibt)
        let after = market.current_price();
        assert!(
            (after - initial).abs() > 0.0001,
            "Preis sollte sich nach 100 Ticks verändert haben"
        );
    }

    #[test]
    fn test_price_stays_in_bounds() {
        let mut market = TestnetMarket::new(TestnetMarketConfig {
            volatility: 0.5, // Hohe Volatilität zum Testen
            ..TestnetMarketConfig::default()
        });
        for i in 0..1000 {
            market.tick(i);
            let price = market.current_price();
            let min = market.config.base_price * market.config.min_multiplier;
            let max = market.config.base_price * market.config.max_multiplier;
            assert!(
                price >= min && price <= max,
                "Preis {price} außerhalb der Grenzen [{min}, {max}] bei Tick {i}"
            );
        }
    }

    #[test]
    fn test_history_limited() {
        let mut market = TestnetMarket::new(TestnetMarketConfig {
            max_history: 10,
            ..TestnetMarketConfig::default()
        });
        for i in 0..50 {
            market.tick(i);
        }
        assert!(market.history.len() <= 10);
    }

    #[test]
    fn test_market_info() {
        let market = TestnetMarket::new(TestnetMarketConfig::default());
        let info = market.market_info();
        assert!(info.enabled);
        assert_eq!(info.mode, "simulated");
        assert_eq!(info.currency, "TC$");
        assert!((info.base_price - 0.10).abs() < 0.001);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut market = TestnetMarket::new(TestnetMarketConfig::default());
        for i in 0..10 {
            market.tick(i);
        }
        let json = serde_json::to_string(&market).unwrap();
        let restored: TestnetMarket = serde_json::from_str(&json).unwrap();
        assert!((market.current_price() - restored.current_price()).abs() < 0.0001);
        assert_eq!(market.tick_count, restored.tick_count);
    }
}
