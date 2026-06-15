//! Preis-Oracle für die Game-Economy.
//!
//! Ein `PriceOracle` liefert den aktuellen STONE→USD-Wechselkurs.
//! Der Marktplatz nutzt ihn beim `buy_item()`, um USD-Listings in den
//! tatsächlich zu zahlenden STONE-Betrag umzurechnen.
//!
//! ## Architektur (Entscheidung: lokaler Oracle, Parameter-injiziert)
//!
//! Der Oracle wird *nicht* im `GameEconomyStore` gespeichert, sondern als
//! Parameter in `list_item`/`buy_item` reingereicht. Vorteile:
//!   - kein doppelter State (TestnetMarket hält seinen Preis weiter selbst)
//!   - keine Locks im Inneren des Stores
//!   - trivial testbar via `FixedOracle`
//!
//! Aufrufer (HTTP-API):
//! ```ignore
//! let market = state.testnet_market.read().unwrap();
//! let oracle = MarketSimOracle(&*market);
//! store.buy_item(&listing_id, &buyer, &oracle)?;
//! ```

use rust_decimal::Decimal;

/// Liefert den aktuellen STONE→USD-Kurs.
///
/// Implementierungen müssen einen positiven Kurs zurückgeben. `resolve_price_stone`
/// behandelt 0/negativ als Fehler.
pub trait PriceOracle {
    /// 1 STONE = X USD (z.B. `Decimal::ONE` für 1:1, `Decimal::from(20)` wenn STONE auf 20$ steht).
    fn usd_per_stone(&self) -> Decimal;
    /// Quellen-Label fürs Audit/UI ("testnet_sim", "fixed", …).
    fn source(&self) -> &'static str;
}

/// Konstanter Kurs. Für Tests und Mainnet-Bootstrap (manueller Preis).
#[derive(Debug, Clone, Copy)]
pub struct FixedOracle(pub Decimal);

impl FixedOracle {
    pub fn new(usd_per_stone: Decimal) -> Self { Self(usd_per_stone) }
}

impl PriceOracle for FixedOracle {
    fn usd_per_stone(&self) -> Decimal { self.0 }
    fn source(&self) -> &'static str { "fixed" }
}

/// Adapter: nutzt den existierenden TestnetMarket-Simulator als Preis-Quelle.
///
/// `TestnetMarket::current_price()` liefert TC$ pro STONE (f64). Wir interpretieren
/// TC$ 1:1 als USD (Testnet-Konvention) und konvertieren in `Decimal`.
pub struct MarketSimOracle<'a>(pub &'a crate::token::market_sim::TestnetMarket);

impl<'a> PriceOracle for MarketSimOracle<'a> {
    fn usd_per_stone(&self) -> Decimal {
        // f64 → Decimal mit 8 Nachkommastellen. Fallback auf 1.0 wenn NaN/Inf.
        let p = self.0.current_price();
        if !p.is_finite() || p <= 0.0 {
            return Decimal::ONE;
        }
        Decimal::from_f64_retain(p).unwrap_or(Decimal::ONE)
    }
    fn source(&self) -> &'static str { "testnet_sim" }
}

// ───────────────────────────────────────────────────────────────────────────
//  Resolver
// ───────────────────────────────────────────────────────────────────────────

use super::{GameEconomyError, PriceMode};

/// Resultat von `resolve_price_stone`.
#[derive(Debug, Clone)]
pub struct ResolvedPrice {
    /// Tatsächlich zu zahlender STONE-Betrag (auf 8 Nachkommastellen gerundet).
    pub stone: Decimal,
    /// USD-Snapshot — nur gesetzt bei `PriceMode::Usd`, sonst `None`.
    pub usd: Option<Decimal>,
    /// Quelle des USD-Snapshots, leer bei reinen Stone-Modi.
    pub oracle_source: String,
}

/// Wandelt einen `PriceMode` (oder Legacy-Stone-Betrag) in einen konkreten
/// STONE-Betrag um. Bei `Usd` wird der Oracle befragt.
///
/// Parameter:
///   - `price_mode`: optionaler neuer Preis-Modus
///   - `legacy_stone`: Fallback wenn `price_mode == None` (= MarketListing.price)
///   - `oracle`: Quelle des USD-Kurses
pub fn resolve_price_stone(
    price_mode: &Option<PriceMode>,
    legacy_stone: Decimal,
    oracle: &dyn PriceOracle,
) -> Result<ResolvedPrice, GameEconomyError> {
    match price_mode {
        None => Ok(ResolvedPrice {
            stone: legacy_stone,
            usd: None,
            oracle_source: String::new(),
        }),
        Some(PriceMode::Stone { amount }) => Ok(ResolvedPrice {
            stone: *amount,
            usd: None,
            oracle_source: String::new(),
        }),
        Some(PriceMode::Usd { amount }) => {
            let rate = oracle.usd_per_stone();
            if rate <= Decimal::ZERO {
                return Err(GameEconomyError::InvalidState {
                    reason: format!("Oracle-Preis ungültig ({rate}) — Quelle: {}", oracle.source()),
                });
            }
            let stone = (amount / rate).round_dp(8);
            Ok(ResolvedPrice {
                stone,
                usd: Some(*amount),
                oracle_source: oracle.source().to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn legacy_stone_passthrough() {
        let r = resolve_price_stone(&None, d("7.5"), &FixedOracle(d("1"))).unwrap();
        assert_eq!(r.stone, d("7.5"));
        assert!(r.usd.is_none());
    }

    #[test]
    fn stone_mode_passthrough() {
        let r = resolve_price_stone(
            &Some(PriceMode::Stone { amount: d("10") }),
            d("0"),
            &FixedOracle(d("99")),
        ).unwrap();
        assert_eq!(r.stone, d("10"));
        assert!(r.usd.is_none());
    }

    #[test]
    fn usd_mode_with_rate_one() {
        // 1 STONE = 1 USD → 10 USD = 10 STONE
        let r = resolve_price_stone(
            &Some(PriceMode::Usd { amount: d("10") }),
            d("0"),
            &FixedOracle(d("1")),
        ).unwrap();
        assert_eq!(r.stone, d("10"));
        assert_eq!(r.usd, Some(d("10")));
        assert_eq!(r.oracle_source, "fixed");
    }

    #[test]
    fn usd_mode_with_rate_twenty() {
        // 1 STONE = 20 USD → 10 USD = 0.5 STONE
        let r = resolve_price_stone(
            &Some(PriceMode::Usd { amount: d("10") }),
            d("0"),
            &FixedOracle(d("20")),
        ).unwrap();
        assert_eq!(r.stone, d("0.5"));
        assert_eq!(r.usd, Some(d("10")));
    }

    #[test]
    fn usd_mode_rejects_zero_rate() {
        let err = resolve_price_stone(
            &Some(PriceMode::Usd { amount: d("10") }),
            d("0"),
            &FixedOracle(d("0")),
        ).unwrap_err();
        match err {
            GameEconomyError::InvalidState { .. } => {}
            other => panic!("expected InvalidState, got {other:?}"),
        }
    }
}
