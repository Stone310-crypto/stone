// ─── Community-Fork & Successor-Übergang ─────────────────────────────────────
//
// Ein Spiel, dessen Owner inaktiv ist, kann von einem Community-Mitglied
// fortgeführt werden. Die Items der bisherigen Spieler bleiben unverändert
// in ihren Wallets liegen – der Nachfolger erhält lediglich das Recht, sie
// in Quests/Crafting/Marketplace weiter zu nutzen.
//
// Lebenszyklus eines Spiels:
//
//   Active ──30d ohne Heartbeat──▶ Dormant
//       │                            │
//       │                            ├─Owner-Heartbeat──▶ Active
//       │                            │
//       │                          +60d
//       │                            │
//       └────────────────────────▶ Abandoned ──Fork-Antrag──▶ Forked
//                                                              │
//                                                       Successor erhält
//                                                       inherited_game_ids
//                                                       += predecessor

use chrono::Utc;
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};
use std::str::FromStr;

use super::*;

impl GameEconomyStore {
    // ═════════════════════════════════════════════════════════════════════
    //  Heartbeat & Dormancy
    // ═════════════════════════════════════════════════════════════════════

    /// Setzt den Heartbeat des Spiels auf jetzt, falls `wallet` der Owner
    /// oder ein aktiver Server-Key ist. Wird von SDK-Handlern bei jeder
    /// owner-/server-authentifizierten Aktion aufgerufen.
    ///
    /// Verlässt zusätzlich automatisch den `Dormant`-Zustand (Owner ist zurück).
    /// `Abandoned`/`Forked` werden hier NICHT zurückgesetzt – diese Übergänge
    /// brauchen ihren eigenen Workflow (`cancel_fork_by_owner`, Governance).
    pub fn touch_owner_heartbeat(&mut self, game_id: &str, wallet: &str) {
        let now = Utc::now().timestamp();
        let Some(game) = self.registered_games.get_mut(game_id) else { return };

        let is_authoritative = game.developer_wallet == wallet
            || game.authorized_servers.iter()
                .any(|s| s.pubkey == wallet && s.revoked_at.is_none());
        if !is_authoritative { return; }

        game.last_owner_heartbeat = now;
        if matches!(game.status, GameStatus::Dormant { .. }) {
            game.status = GameStatus::Active;
            game.updated_at = now;
        }
    }

    /// Berechnet den dynamischen Status anhand von `last_owner_heartbeat`,
    /// ohne den Store zu verändern. Nützlich für read-only Calls / UI.
    pub fn effective_status(&self, game_id: &str, now: i64) -> Option<GameStatus> {
        let g = self.registered_games.get(game_id)?;
        let base = g.status.clone();
        // Persistente Sonderzustände dominieren.
        if matches!(base,
            GameStatus::Suspended { .. }
            | GameStatus::Blacklisted { .. }
            | GameStatus::Abandoned { .. }
            | GameStatus::Forked { .. }
        ) {
            return Some(base);
        }
        let hb = if g.last_owner_heartbeat > 0 { g.last_owner_heartbeat } else { g.created_at };
        let silence = now.saturating_sub(hb);
        if silence >= GAME_ABANDON_SECS {
            Some(GameStatus::Abandoned { since: hb + GAME_ABANDON_SECS })
        } else if silence >= GAME_DORMANT_SECS {
            Some(GameStatus::Dormant { since: hb + GAME_DORMANT_SECS })
        } else {
            Some(GameStatus::Active)
        }
    }

    /// Persistiert die Dormancy-Übergänge in den Store. Wird typischerweise
    /// aus dem `economy_tick`-Loop pro Block aufgerufen.
    pub fn tick_dormancy(&mut self, now: i64) {
        // Erst Snapshot der IDs, um Borrow-Konflikt zu vermeiden.
        let ids: Vec<String> = self.registered_games.keys().cloned().collect();
        for id in ids {
            let Some(target) = self.effective_status(&id, now) else { continue };
            let game = self.registered_games.get_mut(&id).unwrap();
            // Persistente Zustände nie überschreiben.
            if matches!(game.status,
                GameStatus::Suspended { .. }
                | GameStatus::Blacklisted { .. }
                | GameStatus::Forked { .. }
            ) {
                continue;
            }
            if game.status != target {
                let prev = game.status.clone();
                game.status = target.clone();
                game.updated_at = now;
                self.audit(&id, "", "dormancy_transition", serde_json::json!({
                    "from": prev, "to": target,
                }), true);
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    //  Owner-getriggerter Transfer (Friedliche Übergabe)
    // ═════════════════════════════════════════════════════════════════════

    /// Owner übergibt sein Spiel explizit an ein neues developer_wallet.
    /// Geht in jedem Status außer Blacklisted/Forked.
    pub fn transfer_ownership(
        &mut self,
        game_id: &str,
        caller_wallet: &str,
        new_owner: &str,
    ) -> Result<(), GameEconomyError> {
        let game = self.registered_games.get_mut(game_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Spiel '{game_id}'") })?;
        if game.developer_wallet != caller_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Nur der Owner darf das Spiel übergeben".into(),
            });
        }
        if matches!(game.status, GameStatus::Blacklisted { .. }) {
            return Err(GameEconomyError::InvalidState {
                reason: "Blacklisted-Spiel kann nicht übergeben werden".into(),
            });
        }
        if let GameStatus::Forked { successor, .. } = &game.status {
            return Err(GameEconomyError::GameAlreadyForked {
                game_id: game.game_id.clone(),
                successor: successor.clone(),
            });
        }
        let now = Utc::now().timestamp();
        let prev = game.developer_wallet.clone();
        game.developer_wallet = new_owner.to_string();
        game.updated_at = now;
        game.last_owner_heartbeat = now;
        if matches!(game.status, GameStatus::Dormant { .. } | GameStatus::Abandoned { .. }) {
            game.status = GameStatus::Active;
        }
        self.audit(game_id, caller_wallet, "transfer_ownership", serde_json::json!({
            "from": prev, "to": new_owner,
        }), true);
        Ok(())
    }

    // ═════════════════════════════════════════════════════════════════════
    //  Fork-Antrag
    // ═════════════════════════════════════════════════════════════════════

    /// Reicht einen Fork-Antrag für ein verlassenes Spiel ein.
    ///
    /// Bedingungen:
    /// - Vorgänger existiert und ist effektiv `Abandoned`.
    /// - `new_game_id` ist noch frei.
    /// - `stake_amount >= FORK_MIN_BOND_STONE`.
    /// - Es läuft kein offener Antrag mit gleicher `new_game_id`. Für
    ///   denselben Vorgänger entstehen mehrere konkurrierende Anträge
    ///   als separate Proposals – höchster Bond gewinnt am Ende.
    ///
    /// **Hinweis:** Das tatsächliche Locken der STONE im
    /// `pool:fork:<new_game_id>` muss der Caller im Ledger machen, bevor
    /// er diesen Aufruf macht. Diese Funktion erfasst nur den State.
    pub fn propose_fork(
        &mut self,
        predecessor_game_id: &str,
        new_game_id: &str,
        new_name: &str,
        claimant_pubkey: &str,
        stake_amount: Decimal,
        now: i64,
    ) -> Result<ForkProposal, GameEconomyError> {
        // 1) Vorgänger muss existieren & effektiv "Abandoned" sein.
        let predecessor = self.registered_games.get(predecessor_game_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Vorgänger-Spiel '{predecessor_game_id}'"),
            })?;
        if let GameStatus::Forked { successor, .. } = &predecessor.status {
            return Err(GameEconomyError::GameAlreadyForked {
                game_id: predecessor_game_id.to_string(),
                successor: successor.clone(),
            });
        }
        let eff = self.effective_status(predecessor_game_id, now).unwrap();
        if !matches!(eff, GameStatus::Abandoned { .. }) {
            return Err(GameEconomyError::GameNotAbandoned {
                game_id: predecessor_game_id.to_string(),
            });
        }

        // 2) Stake-Untergrenze prüfen.
        let min_bond = Decimal::from_str(FORK_MIN_BOND_STONE)
            .unwrap_or(Decimal::from(1000));
        if stake_amount < min_bond {
            return Err(GameEconomyError::InvalidAmount {
                reason: format!("Stake-Bond unter Minimum {min_bond} STONE"),
            });
        }

        // 3) new_game_id darf nicht existieren.
        if self.registered_games.contains_key(new_game_id) {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Spiel '{new_game_id}'"),
            });
        }

        // 4) Kein zweiter offener Antrag mit derselben new_game_id.
        if self.fork_proposals.values().any(|p| {
            p.new_game_id == new_game_id
            && matches!(p.status, ForkProposalStatus::Pending | ForkProposalStatus::Challenged)
        }) {
            let p = self.fork_proposals.values()
                .find(|p| p.new_game_id == new_game_id)
                .unwrap();
            return Err(GameEconomyError::ForkProposalActive {
                proposal_id: p.proposal_id.clone(),
            });
        }

        // 5) Proposal anlegen.
        let proposal_id = {
            let mut h = Sha256::new();
            h.update(format!("fork:{predecessor_game_id}:{new_game_id}:{now}").as_bytes());
            format!("fp_{}", hex::encode(&h.finalize()[..12]))
        };
        let proposal = ForkProposal {
            proposal_id: proposal_id.clone(),
            predecessor_game_id: predecessor_game_id.to_string(),
            new_game_id: new_game_id.to_string(),
            new_name: new_name.to_string(),
            claimant_pubkey: claimant_pubkey.to_string(),
            stake_amount,
            created_at: now,
            challenge_until: now + FORK_CHALLENGE_SECS,
            status: ForkProposalStatus::Pending,
            challengers: HashMap::new(),
            bond_pool: format!("{FORK_BOND_POOL}:{predecessor_game_id}:{new_game_id}"),
            bond_tx_ids: HashMap::new(),
            bonds_refunded: Vec::new(),
        };
        self.fork_proposals.insert(proposal_id.clone(), proposal.clone());
        self.audit(predecessor_game_id, claimant_pubkey, "fork_propose", serde_json::json!({
            "proposal_id": proposal_id,
            "new_game_id": new_game_id,
            "stake": stake_amount.to_string(),
        }), true);
        Ok(proposal)
    }

    /// Speichert die Bond-TX-ID eines Bewerbers (Claimant oder Challenger).
    /// Wird vom HTTP-Handler nach erfolgreichem Mempool-Submit aufgerufen,
    /// damit Refund/Sweep später deterministisch laufen können.
    pub fn record_fork_bond_tx(
        &mut self,
        proposal_id: &str,
        pubkey: &str,
        tx_id: &str,
    ) -> Result<(), GameEconomyError> {
        let p = self.fork_proposals.get_mut(proposal_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Fork-Antrag '{proposal_id}'"),
            })?;
        p.bond_tx_ids.insert(pubkey.to_string(), tx_id.to_string());
        Ok(())
    }

    /// Liefert die Bond-Pool-Adresse für ein Proposal (für Refund-Sweeps).
    pub fn fork_bond_pool(&self, proposal_id: &str) -> Option<String> {
        self.fork_proposals.get(proposal_id).map(|p| p.bond_pool.clone())
    }

    /// Plant die nächsten ausstehenden Bond-Auszahlungen für ein Proposal.
    ///
    /// Idempotent: bereits ausgezahlte Pubkeys (`bonds_refunded`) werden
    /// übersprungen. Der Sweeper-Handler iteriert über das Ergebnis, baut je
    /// einen `TxType::ForkBondRefund` daraus und markiert nach erfolgreichem
    /// Mempool-Submit über `mark_bond_refunded` als ausgezahlt.
    ///
    /// Status-Logik:
    /// - `Finalized` und `now >= challenge_until + FORK_BOND_VEST_SECS`
    ///     → Sieger bekommt `winner_vest`, Verlierer (alle Challenger außer
    ///       Sieger) bekommen `loser_refund`.
    /// - `Finalized` und `now <  challenge_until + FORK_BOND_VEST_SECS`
    ///     → nur Verlierer (Sieger noch im Vesting).
    /// - `Cancelled`
    ///     → Claimant + alle Challenger bekommen `owner_veto` zurück.
    /// - `Pending` / `Challenged`
    ///     → leer (nichts zu sweepen).
    pub fn plan_bond_sweep(
        &self,
        proposal_id: &str,
        now: i64,
    ) -> Result<Vec<(String, Decimal, &'static str)>, GameEconomyError> {
        let p = self.fork_proposals.get(proposal_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Fork-Antrag '{proposal_id}'"),
            })?;
        let mut out: Vec<(String, Decimal, &'static str)> = Vec::new();
        let already: std::collections::HashSet<&String> = p.bonds_refunded.iter().collect();
        match &p.status {
            ForkProposalStatus::Pending | ForkProposalStatus::Challenged => { /* nichts */ }
            ForkProposalStatus::Cancelled { .. } => {
                // Claimant
                if !already.contains(&p.claimant_pubkey) {
                    out.push((p.claimant_pubkey.clone(), p.stake_amount, "owner_veto"));
                }
                for (pk, st) in &p.challengers {
                    if !already.contains(pk) {
                        out.push((pk.clone(), *st, "owner_veto"));
                    }
                }
            }
            ForkProposalStatus::Finalized => {
                // Sieger bestimmen: höchster Stake (Claimant gewinnt Ties).
                let mut winner = p.claimant_pubkey.clone();
                let mut win_stake = p.stake_amount;
                for (pk, st) in &p.challengers {
                    if *st > win_stake {
                        win_stake = *st;
                        winner = pk.clone();
                    }
                }
                let vest_end = p.challenge_until + FORK_BOND_VEST_SECS;
                // Verlierer sofort.
                if winner != p.claimant_pubkey && !already.contains(&p.claimant_pubkey) {
                    out.push((p.claimant_pubkey.clone(), p.stake_amount, "loser_refund"));
                }
                for (pk, st) in &p.challengers {
                    if pk != &winner && !already.contains(pk) {
                        out.push((pk.clone(), *st, "loser_refund"));
                    }
                }
                // Sieger nach Vesting.
                if now >= vest_end && !already.contains(&winner) {
                    out.push((winner, win_stake, "winner_vest"));
                }
            }
        }
        Ok(out)
    }

    /// Markiert einen Pubkey als ausgezahlt. Wird vom Sweeper nach
    /// erfolgreichem Submit der `ForkBondRefund`-TX aufgerufen.
    pub fn mark_bond_refunded(
        &mut self,
        proposal_id: &str,
        pubkey: &str,
    ) -> Result<(), GameEconomyError> {
        let p = self.fork_proposals.get_mut(proposal_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Fork-Antrag '{proposal_id}'"),
            })?;
        if !p.bonds_refunded.iter().any(|x| x == pubkey) {
            p.bonds_refunded.push(pubkey.to_string());
        }
        Ok(())
    }

    /// Konkurrierender Bewerber gibt einen höheren Bond ab.
    /// Wechselt das Proposal von `Pending` → `Challenged`.
    pub fn challenge_fork(
        &mut self,
        proposal_id: &str,
        challenger_pubkey: &str,
        stake_amount: Decimal,
        now: i64,
    ) -> Result<(), GameEconomyError> {
        let p = self.fork_proposals.get_mut(proposal_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Fork-Antrag '{proposal_id}'"),
            })?;
        if !matches!(p.status, ForkProposalStatus::Pending | ForkProposalStatus::Challenged) {
            return Err(GameEconomyError::InvalidState {
                reason: "Antrag ist nicht mehr offen".into(),
            });
        }
        if now >= p.challenge_until {
            return Err(GameEconomyError::InvalidState {
                reason: "Challenge-Periode ist abgelaufen".into(),
            });
        }
        if challenger_pubkey == p.claimant_pubkey {
            return Err(GameEconomyError::InvalidInput {
                reason: "Antragsteller kann sich nicht selbst challengen".into(),
            });
        }
        let prev = p.challengers.entry(challenger_pubkey.to_string()).or_insert(Decimal::ZERO);
        if stake_amount <= *prev {
            return Err(GameEconomyError::InvalidAmount {
                reason: "Neuer Bond muss höher als vorheriger sein".into(),
            });
        }
        *prev = stake_amount;
        p.status = ForkProposalStatus::Challenged;
        let pid = p.proposal_id.clone();
        let predecessor = p.predecessor_game_id.clone();
        self.audit(&predecessor, challenger_pubkey, "fork_challenge", serde_json::json!({
            "proposal_id": pid,
            "stake": stake_amount.to_string(),
        }), true);
        Ok(())
    }

    /// Owner-Veto: ist der Owner zurück, kann er einen Antrag abbrechen,
    /// solange dieser noch nicht finalisiert wurde.
    pub fn cancel_fork_by_owner(
        &mut self,
        proposal_id: &str,
        owner_wallet: &str,
    ) -> Result<(), GameEconomyError> {
        let p = self.fork_proposals.get(proposal_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Fork-Antrag '{proposal_id}'"),
            })?
            .clone();
        let predecessor = self.registered_games.get(&p.predecessor_game_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Vorgänger '{}'", p.predecessor_game_id),
            })?;
        if predecessor.developer_wallet != owner_wallet {
            return Err(GameEconomyError::Unauthorized {
                reason: "Nur der Owner darf vetoieren".into(),
            });
        }
        if matches!(p.status, ForkProposalStatus::Finalized) {
            return Err(GameEconomyError::InvalidState {
                reason: "Antrag ist bereits finalisiert".into(),
            });
        }
        let entry = self.fork_proposals.get_mut(proposal_id).unwrap();
        entry.status = ForkProposalStatus::Cancelled { reason: "owner_veto".into() };
        // Auch der Heartbeat wird aufgefrischt – wenn der Owner aktiv war,
        // um zu vetoieren, ist er offensichtlich da.
        let pid = p.predecessor_game_id.clone();
        self.touch_owner_heartbeat(&pid, owner_wallet);
        self.audit(&pid, owner_wallet, "fork_cancel", serde_json::json!({
            "proposal_id": proposal_id,
        }), true);
        Ok(())
    }

    /// Finalisiert einen Fork nach Ablauf der Challenge-Periode:
    /// - höchster Stake gewinnt
    /// - Vorgänger geht in `Forked { successor }` über
    /// - Neuer `RegisteredGame` wird mit `successor_of` + `inherited_game_ids`
    ///   angelegt; der API-Key wird zurückgegeben.
    ///
    /// Permissions werden vom Vorgänger geerbt; das developer_wallet ist
    /// der `claimant_pubkey` des Siegers.
    pub fn finalize_fork(
        &mut self,
        proposal_id: &str,
        now: i64,
    ) -> Result<(RegisteredGame, String), GameEconomyError> {
        let p = self.fork_proposals.get(proposal_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Fork-Antrag '{proposal_id}'"),
            })?
            .clone();
        if matches!(p.status, ForkProposalStatus::Finalized | ForkProposalStatus::Cancelled { .. }) {
            return Err(GameEconomyError::InvalidState {
                reason: "Antrag bereits abgeschlossen".into(),
            });
        }
        if now < p.challenge_until {
            return Err(GameEconomyError::ForkChallengeOpen {
                proposal_id: p.proposal_id.clone(),
                until: p.challenge_until,
            });
        }

        // Sieger ermitteln (höchster Stake; bei Gleichstand gewinnt der Originalantragsteller).
        let mut winner_pubkey = p.claimant_pubkey.clone();
        let mut winner_stake = p.stake_amount;
        for (pk, st) in &p.challengers {
            if *st > winner_stake {
                winner_stake = *st;
                winner_pubkey = pk.clone();
            }
        }

        // Vorgänger als Forked markieren.
        let predecessor = self.registered_games.get_mut(&p.predecessor_game_id)
            .ok_or_else(|| GameEconomyError::NotFound {
                what: format!("Vorgänger '{}'", p.predecessor_game_id),
            })?;

        // Security Fix: Prüfen ob der Vorgänger bereits durch einen anderen
        // konkurrierenden Proposal geforkt wurde. Ohne diesen Check könnten
        // zwei parallele `finalize_fork`-Aufrufe beide durchkommen und
        // zwei Nachfolger parallel Ansprüche auf die Items des Vorgängers
        // erheben.
        if matches!(predecessor.status, GameStatus::Forked { .. }) {
            let existing_successor = match &predecessor.status {
                GameStatus::Forked { successor, .. } => successor.clone(),
                _ => unreachable!(),
            };
            return Err(GameEconomyError::InvalidState {
                reason: format!(
                    "Vorgänger '{}' wurde bereits durch '{}' geforkt",
                    p.predecessor_game_id, existing_successor,
                ),
            });
        }

        let inherited_perms = predecessor.permissions.clone();
        let inherited_max_limit = predecessor.max_wallet_limit;
        let inherited_genres = predecessor.genres.clone();
        predecessor.status = GameStatus::Forked {
            successor: p.new_game_id.clone(),
            at: now,
        };
        predecessor.updated_at = now;

        // Neuer RegisteredGame.
        let (api_key, api_key_hash) = {
            // generate_api_key ist privat; bauen wir hier denselben Mechanismus.
            let raw = {
                let mut h = Sha256::new();
                h.update(format!("stone:sdk-key:{}:{}:{now}", p.new_game_id, winner_pubkey).as_bytes());
                format!("sk_{}", hex::encode(h.finalize()))
            };
            let hash = {
                let mut h = Sha256::new();
                h.update(raw.as_bytes());
                hex::encode(h.finalize())
            };
            (raw, hash)
        };
        let successor_game = RegisteredGame {
            game_id: p.new_game_id.clone(),
            name: p.new_name.clone(),
            description: format!("Community-Fork von '{}'", p.predecessor_game_id),
            website: String::new(),
            developer_wallet: winner_pubkey.clone(),
            api_key_hash,
            max_wallet_limit: inherited_max_limit,
            permissions: inherited_perms,
            genres: inherited_genres,
            authorized_servers: Vec::new(),
            status: GameStatus::Active,
            created_at: now,
            updated_at: now,
            last_owner_heartbeat: now,
            inherited_game_ids: vec![p.predecessor_game_id.clone()],
            successor_of: Some(p.predecessor_game_id.clone()),
        };
        self.registered_games.insert(p.new_game_id.clone(), successor_game.clone());

        // Proposal als finalisiert markieren.
        let entry = self.fork_proposals.get_mut(proposal_id).unwrap();
        entry.status = ForkProposalStatus::Finalized;

        self.audit(&p.predecessor_game_id, &winner_pubkey, "fork_finalize", serde_json::json!({
            "proposal_id": proposal_id,
            "new_game_id": p.new_game_id,
            "winner_stake": winner_stake.to_string(),
        }), true);

        Ok((successor_game, api_key))
    }

    // ═════════════════════════════════════════════════════════════════════
    //  Successor-Berechtigung auf Items
    // ═════════════════════════════════════════════════════════════════════

    /// Prüft, ob ein Spiel-Server-Aufrufer (Owner oder Server-Key) ein Item
    /// mit `item_game_id` mutieren darf, wenn er gerade in
    /// `acting_game_id` agiert.
    ///
    /// Erlaubt, falls:
    /// - `acting_game_id == item_game_id` (klassisch, eigenes Item) **oder**
    /// - `acting_game_id` ist (transitiv) Nachfolger von `item_game_id`.
    pub fn can_act_on_item(&self, acting_game_id: &str, item_game_id: &str) -> bool {
        if acting_game_id == item_game_id { return true; }
        let Some(acting) = self.registered_games.get(acting_game_id) else { return false };
        if acting.inherited_game_ids.iter().any(|g| g == item_game_id) {
            return true;
        }
        // Transitive Erbschaft: durchlaufe successor_of-Kette des Vorgängers.
        // Anti-Loop: maximal 8 Hops.
        let mut current = acting.successor_of.clone();
        for _ in 0..8 {
            let Some(ref c) = current else { break };
            if c == item_game_id { return true; }
            current = self.registered_games.get(c).and_then(|g| g.successor_of.clone());
        }
        false
    }

    /// Convenience: gibt die geerbten Game-IDs zurück (inkl. transitiv).
    pub fn inherited_chain(&self, game_id: &str) -> Vec<String> {
        let mut out = Vec::new();
        let Some(g) = self.registered_games.get(game_id) else { return out };
        out.extend(g.inherited_game_ids.iter().cloned());
        let mut current = g.successor_of.clone();
        for _ in 0..8 {
            let Some(c) = current else { break };
            if !out.contains(&c) { out.push(c.clone()); }
            current = self.registered_games.get(&c).and_then(|g| g.successor_of.clone());
        }
        out
    }

    /// Erweiterte Server-Authorisierung: erlaubt einem Server-Key auch dann,
    /// für `target_game_id` zu handeln, wenn er nur Owner/Server eines
    /// Nachfolger-Spiels ist, das `target_game_id` (transitiv) geerbt hat.
    ///
    /// Anwendung: ein Community-Fork (`new_game_id`) darf Rewards/Drops im
    /// Namen des verlassenen Vorgängers (`target_game_id`) ausstellen, ohne
    /// dass ein neuer Server-Key im alten Spiel eingetragen werden muss.
    ///
    /// Reihenfolge:
    /// 1. Klassischer Direkt-Check (`is_game_server(target, wallet)`).
    /// 2. Andernfalls: durchlaufe alle registrierten Spiele und prüfe, ob
    ///    `wallet` dort Server-Key ist **und** `can_act_on_item(g, target)`
    ///    erfüllt (d.h. das Spiel ist Nachfolger des Ziels).
    pub fn is_game_server_or_successor(&self, target_game_id: &str, wallet: &str) -> bool {
        if self.is_game_server(target_game_id, wallet) { return true; }
        for (g_id, _) in &self.registered_games {
            if g_id == target_game_id { continue; }
            if self.is_game_server(g_id, wallet)
                && self.can_act_on_item(g_id, target_game_id)
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() -> GameEconomyStore { GameEconomyStore::new() }

    fn register(store: &mut GameEconomyStore, id: &str, owner: &str) {
        store.register_game(
            id, id, "", "", owner,
            Decimal::from(1000),
            vec![GamePermission::Basic, GamePermission::Assets, GamePermission::Marketplace],
            vec![GameGenre::Custom],
        ).unwrap();
    }

    #[test]
    fn dormancy_transitions() {
        let mut s = fresh_store();
        register(&mut s, "game-x", "ownerX");
        let created = s.registered_games["game-x"].created_at;
        // < dormant: Active.
        assert_eq!(s.effective_status("game-x", created + 10).unwrap(), GameStatus::Active);
        // > dormant, < abandoned: Dormant.
        let t = created + GAME_DORMANT_SECS + 1;
        let st = s.effective_status("game-x", t).unwrap();
        assert!(matches!(st, GameStatus::Dormant { .. }));
        // > abandoned: Abandoned.
        let t = created + GAME_ABANDON_SECS + 1;
        let st = s.effective_status("game-x", t).unwrap();
        assert!(matches!(st, GameStatus::Abandoned { .. }));
    }

    #[test]
    fn heartbeat_resets_dormant() {
        let mut s = fresh_store();
        register(&mut s, "game-x", "ownerX");
        // Künstlich Dormant setzen.
        let g = s.registered_games.get_mut("game-x").unwrap();
        g.last_owner_heartbeat = Utc::now().timestamp() - GAME_DORMANT_SECS - 100;
        g.status = GameStatus::Dormant { since: g.last_owner_heartbeat };
        s.touch_owner_heartbeat("game-x", "ownerX");
        assert!(matches!(s.registered_games["game-x"].status, GameStatus::Active));
    }

    #[test]
    fn fork_requires_abandoned() {
        let mut s = fresh_store();
        register(&mut s, "game-x", "ownerX");
        let now = s.registered_games["game-x"].created_at + 10;
        let err = s.propose_fork("game-x", "game-x-community", "X (Community)", "claim", Decimal::from(2000), now);
        assert!(matches!(err, Err(GameEconomyError::GameNotAbandoned { .. })));
    }

    #[test]
    fn full_fork_flow() {
        let mut s = fresh_store();
        register(&mut s, "game-x", "ownerX");
        // Vorgänger künstlich verlassen.
        let g = s.registered_games.get_mut("game-x").unwrap();
        g.last_owner_heartbeat = Utc::now().timestamp() - GAME_ABANDON_SECS - 100;
        let now = Utc::now().timestamp();
        let prop = s.propose_fork("game-x", "game-x-c", "X (Community)", "claim1", Decimal::from(2000), now)
            .expect("propose ok");
        // Konkurrierender Bewerber überbietet.
        s.challenge_fork(&prop.proposal_id, "claim2", Decimal::from(3000), now + 60).unwrap();
        // Frühe Finalisierung scheitert.
        assert!(matches!(
            s.finalize_fork(&prop.proposal_id, now + 60),
            Err(GameEconomyError::ForkChallengeOpen { .. })
        ));
        // Nach Ablauf → claim2 gewinnt.
        let (succ, _api) = s.finalize_fork(&prop.proposal_id, now + FORK_CHALLENGE_SECS + 1).unwrap();
        assert_eq!(succ.developer_wallet, "claim2");
        assert_eq!(succ.successor_of.as_deref(), Some("game-x"));
        assert_eq!(succ.inherited_game_ids, vec!["game-x".to_string()]);
        // Vorgänger ist jetzt Forked.
        assert!(matches!(s.registered_games["game-x"].status, GameStatus::Forked { .. }));
        // Successor darf Items aus "game-x" anfassen.
        assert!(s.can_act_on_item("game-x-c", "game-x"));
        assert!(!s.can_act_on_item("game-x-c", "irgendwasanderes"));
    }

    #[test]
    fn owner_can_veto_fork() {
        let mut s = fresh_store();
        register(&mut s, "game-x", "ownerX");
        let g = s.registered_games.get_mut("game-x").unwrap();
        g.last_owner_heartbeat = Utc::now().timestamp() - GAME_ABANDON_SECS - 100;
        let now = Utc::now().timestamp();
        let prop = s.propose_fork("game-x", "game-x-c", "X (Community)", "claim", Decimal::from(2000), now).unwrap();
        s.cancel_fork_by_owner(&prop.proposal_id, "ownerX").unwrap();
        let p = &s.fork_proposals[&prop.proposal_id];
        assert!(matches!(p.status, ForkProposalStatus::Cancelled { .. }));
        // Owner-Heartbeat ist nun aktuell, Spiel wieder Active.
        assert!(matches!(s.registered_games["game-x"].status, GameStatus::Active));
    }
}
