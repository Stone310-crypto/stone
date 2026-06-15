// ─── Game Wallet Verwaltung ───────────────────────────────────────────────────

use chrono::Utc;
use rust_decimal::Decimal;

use super::*;

impl GameEconomyStore {
    // ═════════════════════════════════════════════════════════════════════
    //  §3 Game Wallet Verwaltung
    // ═════════════════════════════════════════════════════════════════════

    /// Erstellt ein Game-Wallet direkt (ohne Consent-Flow, z.B. für eigene Spiele).
    pub fn create_game_wallet(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
        display_name: &str,
        daily_limit: Decimal,
        permissions: Vec<GamePermission>,
    ) -> Result<GameWallet, GameEconomyError> {
        let wallet_addr = derive_game_wallet(owner_wallet, game_id);

        if self.game_wallets.contains_key(&wallet_addr) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Game-Wallet für {} in {}", &owner_wallet[..12.min(owner_wallet.len())], game_id),
            });
        }

        // Wenn Spiel registriert ist, Limit prüfen
        if let Some(game) = self.registered_games.get(game_id) {
            if daily_limit > game.max_wallet_limit {
                return Err(GameEconomyError::InvalidAmount {
                    reason: format!("Limit ({}) > Game-Maximum ({})", daily_limit, game.max_wallet_limit),
                });
            }
        }

        let now = Utc::now().timestamp();
        let gw = GameWallet {
            owner_wallet: owner_wallet.to_string(),
            game_wallet: wallet_addr.clone(),
            game_id: game_id.to_string(),
            display_name: display_name.to_string(),
            daily_limit,
            spent_today: Decimal::ZERO,
            limit_reset_at: next_midnight_utc(now),
            consent: ConsentStatus::Approved { at: now },
            allowed_permissions: permissions,
            frozen: false,
            created_at: now,
            last_active: now,
        };

        self.game_wallets.insert(wallet_addr, gw.clone());
        self.audit(game_id, owner_wallet, "wallet_created", serde_json::json!({
            "game_wallet": &gw.game_wallet,
            "daily_limit": daily_limit.to_string(),
        }), true);

        Ok(gw)
    }

    /// Alle Game-Wallets eines Besitzers.
    pub fn wallets_of(&self, owner_wallet: &str) -> Vec<&GameWallet> {
        self.game_wallets.values()
            .filter(|gw| gw.owner_wallet == owner_wallet)
            .collect()
    }

    /// Game-Wallet nach Adresse abrufen.
    pub fn get_game_wallet(&self, game_wallet_addr: &str) -> Option<&GameWallet> {
        self.game_wallets.get(game_wallet_addr)
    }

    /// Game-Wallet eines Spielers in einem bestimmten Spiel.
    pub fn find_game_wallet(&self, owner: &str, game_id: &str) -> Option<&GameWallet> {
        let addr = derive_game_wallet(owner, game_id);
        self.game_wallets.get(&addr)
    }

    /// Nutzer friert sein Game-Wallet ein.
    pub fn freeze_wallet(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
    ) -> Result<(), GameEconomyError> {
        let addr = derive_game_wallet(owner_wallet, game_id);
        let gw = self.game_wallets.get_mut(&addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.owner_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized { reason: "Nicht dein Wallet".into() });
        }

        gw.frozen = true;
        gw.consent = ConsentStatus::Revoked {
            at: Utc::now().timestamp(),
            reason: "Vom Nutzer eingefroren".into(),
        };
        self.audit(game_id, owner_wallet, "wallet_frozen", serde_json::json!({}), true);
        Ok(())
    }

    /// Nutzer gibt sein Game-Wallet wieder frei.
    pub fn unfreeze_wallet(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
    ) -> Result<(), GameEconomyError> {
        let addr = derive_game_wallet(owner_wallet, game_id);
        let gw = self.game_wallets.get_mut(&addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.owner_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized { reason: "Nicht dein Wallet".into() });
        }

        gw.frozen = false;
        gw.consent = ConsentStatus::Approved { at: Utc::now().timestamp() };
        self.audit(game_id, owner_wallet, "wallet_unfrozen", serde_json::json!({}), true);
        Ok(())
    }

    /// Nutzer passt sein tägliches Limit an.
    pub fn set_daily_limit(
        &mut self,
        owner_wallet: &str,
        game_id: &str,
        new_limit: Decimal,
    ) -> Result<(), GameEconomyError> {
        if new_limit < Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount {
                reason: "Limit darf nicht negativ sein".into(),
            });
        }

        // Prüfe Game-Maximum
        if let Some(game) = self.registered_games.get(game_id) {
            if new_limit > game.max_wallet_limit {
                return Err(GameEconomyError::InvalidAmount {
                    reason: format!("Limit ({}) > Game-Maximum ({})", new_limit, game.max_wallet_limit),
                });
            }
        }

        let addr = derive_game_wallet(owner_wallet, game_id);
        let gw = self.game_wallets.get_mut(&addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.owner_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized { reason: "Nicht dein Wallet".into() });
        }

        let old = gw.daily_limit;
        gw.daily_limit = new_limit;
        self.audit(game_id, owner_wallet, "limit_changed", serde_json::json!({
            "old": old.to_string(), "new": new_limit.to_string(),
        }), true);

        Ok(())
    }

    /// Prüft ob eine Aktion für ein Game-Wallet erlaubt ist.
    /// Prüft: Spiel aktiv + Wallet nicht frozen + Consent approved + Permission vorhanden.
    pub fn check_wallet_action(
        &self,
        game_wallet_addr: &str,
        required_permission: GamePermission,
    ) -> Result<&GameWallet, GameEconomyError> {
        let gw = self.game_wallets.get(game_wallet_addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if gw.frozen {
            return Err(GameEconomyError::WalletFrozen { game_id: gw.game_id.clone() });
        }

        if !matches!(gw.consent, ConsentStatus::Approved { .. }) {
            return Err(GameEconomyError::Unauthorized {
                reason: "Wallet hat keinen genehmigten Consent".into(),
            });
        }

        if !gw.has_permission(required_permission) {
            return Err(GameEconomyError::PermissionDenied {
                action: format!("'{}' nicht genehmigt für dieses Wallet", required_permission),
            });
        }

        // Spiel-Status prüfen
        if let Some(game) = self.registered_games.get(&gw.game_id) {
            if !matches!(game.status, GameStatus::Active | GameStatus::Dormant { .. }) {
                return Err(GameEconomyError::GameSuspended {
                    game_id: gw.game_id.clone(),
                    reason: "Spiel nicht aktiv".into(),
                });
            }
        }

        Ok(gw)
    }

    /// Prüft Daily Limit und registriert Ausgabe.
    pub fn enforce_daily_limit(
        &mut self,
        game_wallet_addr: &str,
        amount: Decimal,
    ) -> Result<(), GameEconomyError> {
        let gw = self.game_wallets.get_mut(game_wallet_addr)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Game-Wallet".into() })?;

        if !gw.can_spend(amount) {
            return Err(GameEconomyError::DailyLimitExceeded {
                limit: gw.daily_limit,
                spent: gw.spent_today,
                requested: amount,
            });
        }

        gw.record_spend(amount);
        Ok(())
    }

}
