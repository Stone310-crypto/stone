// ─── Rarity-Sanity Guard ──────────────────────────────────────────────────────
//
// Optionale Plausibilitäts-Schranke für Listing-Preise in USD pro Rarität.
//
// - `hard = false`: Überschreitungen werden als Warnung (`listing.warnings`)
//   gespeichert, das Listing bleibt erlaubt.
// - `hard = true`:  Überschreitungen führen zu `GameEconomyError::InvalidInput`.
//
// Default-Limits (USD je Item, deutlich oberhalb des „normalen" Bereichs):
//   Common     → 5
//   Uncommon   → 25
//   Rare       → 100
//   Epic       → 500
//   Legendary  → 10 000
//
// Die Limits sind bewusst weich gewählt: Sie sollen offensichtliche Falschpreise
// (100 STONE für Common bei 1 USD/STONE = 100 USD) abfangen, nicht den
// freien Markt deckeln. Power-User können den Guard ausschalten oder selbst
// kalibrieren.

use std::collections::HashMap;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use super::{GameEconomyError, ItemRarity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarityPriceGuard {
    /// Max-USD-Wert pro Rarität.
    pub max_usd: HashMap<ItemRarity, Decimal>,
    /// Wenn `true`: Überschreitung → Fehler. Sonst nur Warnung.
    pub hard: bool,
}

impl Default for RarityPriceGuard {
    fn default() -> Self {
        let mut m = HashMap::new();
        m.insert(ItemRarity::Common,    Decimal::new(5, 0));
        m.insert(ItemRarity::Uncommon,  Decimal::new(25, 0));
        m.insert(ItemRarity::Rare,      Decimal::new(100, 0));
        m.insert(ItemRarity::Epic,      Decimal::new(500, 0));
        m.insert(ItemRarity::Legendary, Decimal::new(10_000, 0));
        Self { max_usd: m, hard: false }
    }
}

impl RarityPriceGuard {
    /// Prüft `price_usd` gegen das Limit der Rarität.
    ///
    /// Rückgabe:
    ///   - `Ok(None)`        → im Limit
    ///   - `Ok(Some(msg))`   → über Limit, aber `hard == false`
    ///   - `Err(...)`        → über Limit und `hard == true`
    pub fn check(
        &self,
        rarity: &ItemRarity,
        price_usd: Decimal,
    ) -> Result<Option<String>, GameEconomyError> {
        let Some(limit) = self.max_usd.get(rarity) else {
            return Ok(None);
        };
        if price_usd <= *limit {
            return Ok(None);
        }
        let msg = format!(
            "Preis {price_usd} USD überschreitet Rarity-Limit ({rarity} ≤ {limit} USD)"
        );
        if self.hard {
            Err(GameEconomyError::InvalidInput { reason: msg })
        } else {
            Ok(Some(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_below_limit_passes() {
        let g = RarityPriceGuard::default();
        assert!(g.check(&ItemRarity::Common, Decimal::new(3, 0)).unwrap().is_none());
    }

    #[test]
    fn common_above_limit_warns_soft() {
        let g = RarityPriceGuard::default();
        let res = g.check(&ItemRarity::Common, Decimal::new(50, 0)).unwrap();
        assert!(res.is_some());
    }

    #[test]
    fn common_above_limit_rejects_hard() {
        let g = RarityPriceGuard { hard: true, ..RarityPriceGuard::default() };
        let err = g.check(&ItemRarity::Common, Decimal::new(50, 0)).unwrap_err();
        match err {
            GameEconomyError::InvalidInput { .. } => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn legendary_within_default_passes() {
        let g = RarityPriceGuard::default();
        assert!(g.check(&ItemRarity::Legendary, Decimal::new(5_000, 0)).unwrap().is_none());
    }
}
