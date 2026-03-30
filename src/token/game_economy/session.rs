// ─── Sessions, Wallet-Links, Audit & Leaderboard ─────────────────────────────

use chrono::Utc;

use super::*;

impl GameEconomyStore {
    // ═════════════════════════════════════════════════════════════════════
    //  §6 SDK Sessions
    // ═════════════════════════════════════════════════════════════════════

    pub fn create_session(
        &mut self,
        wallet: &str,
        game_id: &str,
        permissions: Vec<GamePermission>,
    ) -> SdkSession {
        let now = Utc::now().timestamp();
        let token = generate_id("SDK", &format!("{wallet}:{game_id}:{now}"));

        let session = SdkSession {
            token: token.clone(),
            wallet: wallet.to_string(),
            game_id: game_id.to_string(),
            permissions,
            created_at: now,
            expires_at: now + SESSION_TTL_SECS,
            active: true,
        };

        self.sessions.insert(token, session.clone());
        session
    }

    pub fn validate_session(&self, token: &str) -> Option<&SdkSession> {
        let session = self.sessions.get(token)?;
        if !session.active || Utc::now().timestamp() > session.expires_at { return None; }
        Some(session)
    }

    pub fn revoke_session(&mut self, token: &str) -> Result<(), GameEconomyError> {
        let session = self.sessions.get_mut(token)
            .ok_or_else(|| GameEconomyError::NotFound { what: "Session".into() })?;
        session.active = false;
        Ok(())
    }

    pub fn cleanup_expired_sessions(&mut self) {
        let now = Utc::now().timestamp();
        self.sessions.retain(|_, s| s.active && s.expires_at > now);
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §7 Wallet Links
    // ═════════════════════════════════════════════════════════════════════

    pub fn link_wallet(&mut self, player_id: &str, game_id: &str, wallet: &str) -> WalletLink {
        let key = format!("{game_id}:{player_id}");
        let link = WalletLink {
            player_id: player_id.to_string(),
            game_id: game_id.to_string(),
            wallet: wallet.to_string(),
            linked_at: Utc::now().timestamp(),
        };
        self.wallet_links.insert(key, link.clone());
        link
    }

    pub fn find_wallet_link(&self, player_id: &str, game_id: &str) -> Option<&WalletLink> {
        let key = format!("{game_id}:{player_id}");
        self.wallet_links.get(&key)
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §8 Audit-Log
    // ═════════════════════════════════════════════════════════════════════

    /// Loggt eine SDK-Aktion.
    pub fn audit(
        &mut self,
        game_id: &str,
        wallet: &str,
        action: &str,
        details: serde_json::Value,
        success: bool,
    ) {
        let entry = AuditLogEntry {
            entry_id: generate_id("AUD", &format!("{game_id}:{wallet}:{action}")),
            timestamp: Utc::now().timestamp(),
            game_id: game_id.to_string(),
            wallet: wallet.to_string(),
            action: action.to_string(),
            details,
            success,
        };
        self.audit_log.push(entry);

        // Trim wenn zu groß
        if self.audit_log.len() > MAX_AUDIT_ENTRIES {
            let drain_count = self.audit_log.len() - MAX_AUDIT_ENTRIES;
            self.audit_log.drain(..drain_count);
        }
    }

    /// Audit-Log für einen Spieler (über alle Spiele hinweg).
    pub fn audit_log_for_player(&self, wallet: &str, limit: usize) -> Vec<&AuditLogEntry> {
        self.audit_log.iter()
            .rev()
            .filter(|e| e.wallet == wallet)
            .take(limit)
            .collect()
    }

    /// Audit-Log für ein bestimmtes Spiel.
    pub fn audit_log_for_game(&self, game_id: &str, limit: usize) -> Vec<&AuditLogEntry> {
        self.audit_log.iter()
            .rev()
            .filter(|e| e.game_id == game_id)
            .take(limit)
            .collect()
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §9 Leaderboard
    // ═════════════════════════════════════════════════════════════════════

    pub fn leaderboard(&self, game_id: &str, limit: usize) -> Vec<LeaderboardEntry> {
        let mut player_stats: HashMap<String, (usize, Decimal)> = HashMap::new();

        for item in self.items.values() {
            if item.game_id == game_id && !item.burned {
                let entry = player_stats.entry(item.owner.clone()).or_default();
                entry.0 += 1;
                if let Some(history) = self.price_history.get(&item.item_id) {
                    if let Some(last) = history.last() {
                        entry.1 += last.price;
                    }
                }
            }
        }

        let mut board: Vec<LeaderboardEntry> = player_stats.into_iter()
            .map(|(wallet, (items, value))| LeaderboardEntry {
                wallet, item_count: items, estimated_value: value,
            })
            .collect();

        board.sort_by(|a, b| b.estimated_value.cmp(&a.estimated_value));
        board.truncate(limit);
        board
    }

}
