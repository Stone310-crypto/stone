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
        genres: Vec<GameGenre>,
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

        validate_genres(&genres)?;

        let (api_key, api_key_hash) = generate_api_key(game_id, developer_wallet);
        let now = Utc::now().timestamp();

        let game = RegisteredGame {
            game_id: game_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            website: website.to_string(),
            genres,
            developer_wallet: developer_wallet.to_string(),
            api_key_hash,
            max_wallet_limit,
            permissions,
            authorized_servers: Vec::new(),
            status: GameStatus::Active,
            created_at: now,
            updated_at: now,
            last_owner_heartbeat: now,
            inherited_game_ids: Vec::new(),
            successor_of: None,
        };

        self.registered_games.insert(game_id.to_string(), game.clone());
        self.audit(game_id, developer_wallet, "register_game", serde_json::json!({
            "name": name,
            "permissions_count": game.permissions.len(),
            "genres": game.genres.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
        }), true);

        Ok((game, api_key))
    }

    pub fn update_game_genres(
    &mut self,
    game_id: &str,
    caller_wallet: &str,
    new_genres: Vec<GameGenre>,
) -> Result<(), GameEconomyError> {
    let game = self.registered_games.get_mut(game_id)
        .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;

    if game.developer_wallet != caller_wallet {
        return Err(GameEconomyError::Unauthorized {
            reason: "Nur der Owner darf Genres updaten".into(),
        });
    }

    validate_genres(&new_genres)?;

    game.genres = new_genres.clone();
    game.updated_at = Utc::now().timestamp();
    
    self.audit(game_id, caller_wallet, "update_genres", serde_json::json!({
        "genres": new_genres.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
    }), true);

    Ok(())
}
    /// Validiert einen API-Key (Klartext) und gibt das zugehörige Spiel zurück.
    pub fn validate_api_key(&self, api_key: &str) -> Result<&RegisteredGame, GameEconomyError> {
        let hash = hash_api_key(api_key);
        self.validate_api_key_hash(&hash)
    }

    /// Validiert einen bereits gehashten API-Key-Hash (ohne Re-Hash).
    /// Security: Der Client hasht den Key lokal und sendet nur den Hash.
    /// Kein API-Key-Klartext über die Leitung.
    pub fn validate_api_key_hash(&self, key_hash: &str) -> Result<&RegisteredGame, GameEconomyError> {
        let game = self.registered_games.values()
            .find(|g| g.api_key_hash == key_hash)
            .ok_or_else(|| GameEconomyError::Unauthorized {
                reason: "Ungültiger API-Key".into(),
            })?;

        match &game.status {
            GameStatus::Active | GameStatus::Dormant { .. } => Ok(game),
            GameStatus::Suspended { reason, .. } => Err(GameEconomyError::GameSuspended {
                game_id: game.game_id.clone(),
                reason: reason.clone(),
            }),
            GameStatus::Blacklisted { reason } => Err(GameEconomyError::GameBlacklisted {
                game_id: game.game_id.clone(),
                reason: reason.clone(),
            }),
            GameStatus::Abandoned { .. } => Err(GameEconomyError::GameSuspended {
                game_id: game.game_id.clone(),
                reason: "Spiel ist als verlassen markiert – Community-Fork möglich".into(),
            }),
            GameStatus::Forked { successor, .. } => Err(GameEconomyError::GameAlreadyForked {
                game_id: game.game_id.clone(),
                successor: successor.clone(),
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

    /// Rotiert den API-Key eines Spiels. Gibt den neuen Klartext-Key zurück.
    /// Der alte Key wird sofort ungültig. Caller-seitige Authentifizierung
    /// (Owner-Signatur o.ä.) muss VOR diesem Aufruf erfolgt sein.
    pub fn rotate_api_key(&mut self, game_id: &str) -> Result<String, GameEconomyError> {
        let (api_key, api_key_hash, owner) = {
            let game = self.registered_games.get_mut(game_id)
                .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
            let (api_key, api_key_hash) = generate_api_key(game_id, &game.developer_wallet);
            game.api_key_hash = api_key_hash.clone();
            game.updated_at = Utc::now().timestamp();
            (api_key, api_key_hash, game.developer_wallet.clone())
        };
        let _ = api_key_hash;
        self.audit(game_id, &owner, "rotate_api_key", serde_json::json!({}), true);
        Ok(api_key)
    }

    /// TOTP-Secret für Owner-2FA setzen/rotieren.
    /// Das Secret wird als Base32 gespeichert und nie über öffentliche APIs ausgegeben.
    pub fn set_owner_totp_secret(
        &mut self,
        game_id: &str,
        secret_b32: &str,
    ) -> Result<(), GameEconomyError> {
        let owner = {
            let game = self.registered_games.get_mut(game_id)
                .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
            game.updated_at = Utc::now().timestamp();
            game.developer_wallet.clone()
        };
        self.owner_totp_secrets
            .insert(game_id.to_string(), secret_b32.to_string());
        self.audit(game_id, &owner, "set_owner_totp_secret", serde_json::json!({}), true);
        Ok(())
    }

    /// TOTP-Secret für ein Spiel lesen (falls eingerichtet).
    pub fn owner_totp_secret(&self, game_id: &str) -> Option<&str> {
        self.owner_totp_secrets.get(game_id).map(|s| s.as_str())
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

    /// Prüft ob das Wallet als Game-Server agieren darf:
    /// - der eingetragene Owner (`developer_wallet`) **oder**
    /// - ein aktiver, nicht-revozierter `authorized_servers`-Eintrag.
    pub fn is_game_server(&self, game_id: &str, wallet: &str) -> bool {
        let Some(g) = self.registered_games.get(game_id) else { return false; };
        if g.developer_wallet == wallet { return true; }
        g.authorized_servers.iter().any(|s| s.pubkey == wallet && s.revoked_at.is_none())
    }

    /// Prüft, ob das Wallet eine bestimmte Permission im Spiel ausüben darf.
    /// Owner: alle Spiel-Permissions. Server-Key: Schnittmenge aus Spiel-Permissions
    /// und (falls gesetzt) der Sub-Scope-Liste des Keys.
    pub fn server_can(&self, game_id: &str, wallet: &str, perm: GamePermission) -> bool {
        let Some(g) = self.registered_games.get(game_id) else { return false; };
        if !g.permissions.contains(&perm) { return false; }
        if g.developer_wallet == wallet { return true; }
        g.authorized_servers.iter().any(|s| {
            s.pubkey == wallet
                && s.revoked_at.is_none()
                && (s.permissions.is_empty() || s.permissions.contains(&perm))
        })
    }

    // ── Server-Key-Management ───────────────────────────────────────────

    /// Fügt einen neuen Server-Key zu einem Spiel hinzu. Nur der Owner darf das.
    /// Idempotent: ist der Key bereits aktiv eingetragen, wird ein Fehler
    /// zurückgegeben (vermeidet stilles Überschreiben des Labels).
    pub fn add_server_key(
        &mut self,
        game_id: &str,
        caller_wallet: &str,
        new_server_pubkey: &str,
        label: &str,
        permissions: Vec<GamePermission>,
    ) -> Result<ServerKey, GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        if game.developer_wallet != caller_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Nur der Owner darf Server-Keys verwalten".into(),
            });
        }
        if new_server_pubkey.is_empty() {
            return Err(GameEconomyError::InvalidInput { reason: "Server-Pubkey fehlt".into() });
        }
        if new_server_pubkey == game.developer_wallet {
            return Err(GameEconomyError::InvalidInput {
                reason: "Owner-Key ist bereits implizit autorisiert".into(),
            });
        }
        if game.authorized_servers.iter().any(|s| s.pubkey == new_server_pubkey && s.revoked_at.is_none()) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Server-Key {new_server_pubkey} (aktiv)"),
            });
        }
        let now = Utc::now().timestamp();
        let entry = ServerKey {
            pubkey: new_server_pubkey.to_string(),
            label: label.to_string(),
            permissions,
            added_at: now,
            revoked_at: None,
        };
        game.authorized_servers.push(entry.clone());
        game.updated_at = now;
        self.audit(game_id, caller_wallet, "add_server_key", serde_json::json!({
            "pubkey": new_server_pubkey, "label": label,
        }), true);
        Ok(entry)
    }

    /// Revoziert einen Server-Key. Nur Owner. Markiert revoked_at statt zu löschen,
    /// damit der Audit-Trail erhalten bleibt.
    pub fn revoke_server_key(
        &mut self,
        game_id: &str,
        caller_wallet: &str,
        server_pubkey: &str,
    ) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        if game.developer_wallet != caller_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Nur der Owner darf Server-Keys verwalten".into(),
            });
        }
        let now = Utc::now().timestamp();
        let entry = game.authorized_servers.iter_mut()
            .find(|s| s.pubkey == server_pubkey && s.revoked_at.is_none())
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("aktiver Server-Key {server_pubkey}"),
            })?;
        entry.revoked_at = Some(now);
        game.updated_at = now;
        self.audit(game_id, caller_wallet, "revoke_server_key", serde_json::json!({
            "pubkey": server_pubkey,
        }), true);
        Ok(())
    }

    /// Liste aller (auch revozierten) Server-Keys eines Spiels.
    pub fn list_server_keys(&self, game_id: &str) -> Vec<ServerKey> {
        self.registered_games.get(game_id)
            .map(|g| g.authorized_servers.clone())
            .unwrap_or_default()
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
