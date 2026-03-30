// ─── Game Registry & Consent ──────────────────────────────────────────────────

use chrono::Utc;
use rust_decimal::Decimal;

use super::*;

impl GameEconomyStore {
    // ═════════════════════════════════════════════════════════════════════
    //  §1 Game Registry
    // ═════════════════════════════════════════════════════════════════════

    /// Registriert ein neues Spiel. Gibt den API-Key zurück (wird nur EINMAL angezeigt).
    pub fn register_game(
        &mut self,
        game_id: &str,
        name: &str,
        description: &str,
        website: &str,
        developer_wallet: &str,
        max_wallet_limit: Decimal,
        permissions: Vec<GamePermission>,
    ) -> Result<(RegisteredGame, String), GameEconomyError> {
        if self.registered_games.contains_key(game_id) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Spiel '{game_id}'"),
            });
        }

        if game_id.len() < 3 || game_id.len() > 64 {
            return Err(GameEconomyError::InvalidInput {
                reason: "Game-ID muss 3-64 Zeichen lang sein".into(),
            });
        }

        if max_wallet_limit <= Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount {
                reason: "Max-Wallet-Limit muss positiv sein".into(),
            });
        }

        let (api_key, api_key_hash) = generate_api_key(game_id, developer_wallet);
        let now = Utc::now().timestamp();

        let game = RegisteredGame {
            game_id: game_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            website: website.to_string(),
            developer_wallet: developer_wallet.to_string(),
            api_key_hash,
            max_wallet_limit,
            permissions,
            status: GameStatus::Active,
            created_at: now,
            updated_at: now,
        };

        self.registered_games.insert(game_id.to_string(), game.clone());
        self.audit(game_id, developer_wallet, "register_game", serde_json::json!({
            "name": name, "permissions_count": game.permissions.len(),
        }), true);

        Ok((game, api_key))
    }

    /// Validiert einen API-Key und gibt das zugehörige Spiel zurück.
    pub fn validate_api_key(&self, api_key: &str) -> Result<&RegisteredGame, GameEconomyError> {
        let hash = hash_api_key(api_key);
        let game = self.registered_games.values()
            .find(|g| g.api_key_hash == hash)
            .ok_or_else(|| GameEconomyError::Unauthorized {
                reason: "Ungültiger API-Key".into(),
            })?;

        match &game.status {
            GameStatus::Active => Ok(game),
            GameStatus::Suspended { reason, .. } => Err(GameEconomyError::GameSuspended {
                game_id: game.game_id.clone(),
                reason: reason.clone(),
            }),
            GameStatus::Blacklisted { reason } => Err(GameEconomyError::GameBlacklisted {
                game_id: game.game_id.clone(),
                reason: reason.clone(),
            }),
        }
    }

    /// Gibt ein registriertes Spiel zurück (public info, kein API-Key nötig).
    pub fn get_game(&self, game_id: &str) -> Option<&RegisteredGame> {
        self.registered_games.get(game_id)
    }

    /// Prüft ob ein Spiel eine bestimmte Berechtigung hat.
    pub fn game_has_permission(&self, game_id: &str, perm: GamePermission) -> bool {
        self.registered_games.get(game_id)
            .map(|g| g.permissions.contains(&perm))
            .unwrap_or(false)
    }

    /// Spiel suspendieren (Admin).
    pub fn suspend_game(
        &mut self,
        game_id: &str,
        reason: &str,
        until: Option<i64>,
    ) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        game.status = GameStatus::Suspended { reason: reason.to_string(), until };
        game.updated_at = Utc::now().timestamp();
        self.audit(game_id, "", "suspend_game", serde_json::json!({ "reason": reason }), true);
        Ok(())
    }

    /// Spiel permanent blacklisten (Admin).
    pub fn blacklist_game(
        &mut self,
        game_id: &str,
        reason: &str,
    ) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        game.status = GameStatus::Blacklisted { reason: reason.to_string() };
        game.updated_at = Utc::now().timestamp();
        // Alle Wallets dieses Spiels einfrieren
        for gw in self.game_wallets.values_mut() {
            if gw.game_id == game_id {
                gw.frozen = true;
            }
        }
        self.audit(game_id, "", "blacklist_game", serde_json::json!({ "reason": reason }), true);
        Ok(())
    }

    /// Spiel reaktivieren (Admin).
    pub fn reactivate_game(&mut self, game_id: &str) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        game.status = GameStatus::Active;
        game.updated_at = Utc::now().timestamp();
        Ok(())
    }

    /// Prüft ob das Wallet der registrierte Game-Server ist.
    pub fn is_game_server(&self, game_id: &str, wallet: &str) -> bool {
        self.registered_games.get(game_id)
            .map(|g| g.developer_wallet == wallet)
            .unwrap_or(false)
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §2 User Consent
    // ═════════════════════════════════════════════════════════════════════

    /// Spiel stellt Consent-Anfrage an einen Nutzer.
    ///
    /// Der Nutzer sieht in seiner App einen Dialog:
    /// "Chain Empires möchte eine Spiel-Wallet erstellen.
    ///  Limit: 100 Coins/Tag. Aktionen: Kaufen, Verkaufen."
    pub fn request_consent(
        &mut self,
        game_id: &str,
        player_wallet: &str,
        requested_limit: Decimal,
        requested_permissions: Vec<GamePermission>,
    ) -> Result<ConsentRequest, GameEconomyError> {
        let game = self.registered_games.get(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;

        if !matches!(game.status, GameStatus::Active) {
            return Err(GameEconomyError::GameSuspended {
                game_id: game_id.to_string(),
                reason: "Spiel ist nicht aktiv".into(),
            });
        }

        // Limit darf nicht höher als das Game-Maximum sein
        if requested_limit > game.max_wallet_limit {
            return Err(GameEconomyError::InvalidAmount {
                reason: format!(
                    "Angefragtes Limit ({}) überschreitet Game-Maximum ({})",
                    requested_limit, game.max_wallet_limit
                ),
            });
        }

        // Nur Permissions beantragen, die das Spiel selbst hat
        for perm in &requested_permissions {
            if !game.permissions.contains(perm) {
                return Err(GameEconomyError::PermissionDenied {
                    action: format!("Spiel hat keine '{}' Berechtigung", perm),
                });
            }
        }

        // Bereits offene Anfrage oder existierendes Wallet?
        let wallet_addr = derive_game_wallet(player_wallet, game_id);
        if self.game_wallets.contains_key(&wallet_addr) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Game-Wallet für diesen Spieler in '{game_id}'"),
            });
        }

        // Offene Anfrage?
        let has_pending = self.consent_requests.values().any(|cr| {
            cr.game_id == game_id
                && cr.player_wallet == player_wallet
                && cr.status == ConsentRequestStatus::Pending
                && cr.expires_at > Utc::now().timestamp()
        });
        if has_pending {
            return Err(GameEconomyError::AlreadyExists {
                what: "Offene Consent-Anfrage".into(),
            });
        }

        let now = Utc::now().timestamp();
        let request_id = generate_id("CSR", &format!("{game_id}:{player_wallet}"));

        let request = ConsentRequest {
            request_id: request_id.clone(),
            game_id: game_id.to_string(),
            game_name: game.name.clone(),
            player_wallet: player_wallet.to_string(),
            requested_limit,
            requested_permissions,
            status: ConsentRequestStatus::Pending,
            created_at: now,
            expires_at: now + CONSENT_TTL_SECS,
        };

        self.consent_requests.insert(request_id, request.clone());
        self.audit(game_id, player_wallet, "consent_requested", serde_json::json!({
            "limit": requested_limit.to_string(),
        }), true);

        Ok(request)
    }

    /// Nutzer sieht seine offenen Consent-Anfragen.
    pub fn pending_consents(&self, player_wallet: &str) -> Vec<&ConsentRequest> {
        let now = Utc::now().timestamp();
        self.consent_requests.values()
            .filter(|cr| {
                cr.player_wallet == player_wallet
                    && cr.status == ConsentRequestStatus::Pending
                    && cr.expires_at > now
            })
            .collect()
    }

    /// Nutzer genehmigt Consent-Anfrage → Game-Wallet wird erstellt.
    pub fn approve_consent(
        &mut self,
        player_wallet: &str,
        request_id: &str,
    ) -> Result<GameWallet, GameEconomyError> {
        let cr = self.consent_requests.get_mut(request_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Consent-Request '{request_id}'"),
            })?;

        if cr.player_wallet != player_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Consent gehört einem anderen Spieler".into(),
            });
        }

        if cr.status != ConsentRequestStatus::Pending {
            return Err(GameEconomyError::InvalidState {
                reason: "Consent-Anfrage ist nicht mehr offen".into(),
            });
        }

        if cr.expires_at <= Utc::now().timestamp() {
            cr.status = ConsentRequestStatus::Expired;
            return Err(GameEconomyError::InvalidState {
                reason: "Consent-Anfrage ist abgelaufen".into(),
            });
        }

        cr.status = ConsentRequestStatus::Approved;

        let game_id = cr.game_id.clone();
        let limit = cr.requested_limit;
        let permissions = cr.requested_permissions.clone();

        // Game-Wallet erstellen
        let now = Utc::now().timestamp();
        let wallet_addr = derive_game_wallet(player_wallet, &game_id);

        let gw = GameWallet {
            owner_wallet: player_wallet.to_string(),
            game_wallet: wallet_addr.clone(),
            game_id: game_id.clone(),
            display_name: String::new(),
            daily_limit: limit,
            spent_today: Decimal::ZERO,
            limit_reset_at: next_midnight_utc(now),
            consent: ConsentStatus::Approved { at: now },
            allowed_permissions: permissions,
            frozen: false,
            created_at: now,
            last_active: now,
        };

        self.game_wallets.insert(wallet_addr, gw.clone());
        self.audit(&game_id, player_wallet, "consent_approved", serde_json::json!({
            "limit": limit.to_string(),
            "game_wallet": &gw.game_wallet,
        }), true);

        Ok(gw)
    }

    /// Nutzer lehnt Consent-Anfrage ab.
    pub fn reject_consent(
        &mut self,
        player_wallet: &str,
        request_id: &str,
    ) -> Result<(), GameEconomyError> {
        let cr = self.consent_requests.get_mut(request_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Consent-Request '{request_id}'"),
            })?;

        if cr.player_wallet != player_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Consent gehört einem anderen Spieler".into(),
            });
        }

        if cr.status != ConsentRequestStatus::Pending {
            return Err(GameEconomyError::InvalidState {
                reason: "Consent-Anfrage ist nicht mehr offen".into(),
            });
        }

        cr.status = ConsentRequestStatus::Rejected;
        let game_id = cr.game_id.clone();
        self.audit(&game_id, player_wallet, "consent_rejected", serde_json::json!({}), true);
        Ok(())
    }

}
