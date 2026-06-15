//! Post-Block-Hooks – Verarbeitung nach Block-Commit
//!
//! Alle Hooks die nach einem committed Block ausgeführt werden:
//! Staking, Slashing, Reputation, Chat-Policy, Governance, HTLC, Market-Sim, Checkpoints.

use crate::blockchain::Block;
use crate::consensus::{load_or_create_validator_key, local_validator_pubkey_hex};
use crate::token::transaction::{TokenTx, TxType, compute_tx_id};
use chrono::Utc;
use rust_decimal::Decimal;
use std::sync::Arc;

use super::MasterNodeState;
use super::types::NodeEvent;

impl MasterNodeState {
    /// Kanonische Validator-Identität für Slashing/Jail:
    /// bevorzugt unveränderlicher Ed25519-PubKey, fallback node_id.
    fn canonical_validator_id(node_id: &str, validator_pub_key: &str) -> String {
        if !validator_pub_key.is_empty() {
            validator_pub_key.to_string()
        } else {
            node_id.to_string()
        }
    }

    /// Öffentlicher Wrapper für alle Post-Block-Hooks.
    /// Wird vom Mining-Submit-Handler aufgerufen.
    pub fn run_post_block_hooks(state: &Arc<Self>, block: &Block) {
        Self::post_block_staking(state, block);
        Self::post_block_slashing(state, block);
        Self::post_block_reputation(state, block);
        Self::post_block_chat_policy(state, block, None);
        Self::post_block_governance(state);
        Self::post_block_market_sim(state, block);
        Self::post_block_htlc(state, block);
    }

    /// Testnet-Markt-Simulation: Tick + Persist (nur Testnet).
    /// Entfernen: Diese Fn + testnet_market Feld + market_sim Modul löschen.
    fn post_block_market_sim(state: &Arc<Self>, block: &Block) {
        let mut market = state.testnet_market.write().unwrap_or_else(|e| e.into_inner());
        if !market.config.enabled {
            return;
        }
        market.tick(block.index);
        if let Err(e) = market.save() {
            eprintln!("[market_sim] Persist fehlgeschlagen: {e}");
        }
    }

    /// HTLC Post-Block-Hook: Verarbeitet HTLC-TXs im Block und prüft abgelaufene Contracts.
    fn post_block_htlc(state: &Arc<Self>, block: &Block) {
        Self::process_htlc_txs(state, &block.transactions, block.index);
    }

    /// Verarbeitet HTLC-TXs aus einem Block (oder Sync) und prüft abgelaufene Contracts.
    /// Kann sowohl nach eigenem Mining als auch nach P2P/HTTP-Sync aufgerufen werden.
    pub fn process_htlc_txs(state: &Arc<Self>, txs: &[TokenTx], block_index: u64) {
        use crate::token::htlc::{
            parse_htlc_create_memo, parse_htlc_claim_memo, parse_htlc_refund_memo,
            HTLC_ESCROW_POOL,
        };

        let mut store = state.htlc_store.write().unwrap_or_else(|e| e.into_inner());
        let mut changed = false;

        // 1. HTLC-TXs aus dem Block im Store verarbeiten
        for tx in txs {
            match tx.tx_type {
                TxType::HtlcCreate => {
                    if let Ok(params) = parse_htlc_create_memo(&tx.memo) {
                        let contract_id = format!("htlc-{}", &tx.tx_id[..16]);
                        let _contract = store.create(
                            contract_id.clone(),
                            tx.from.clone(),
                            params.receiver.clone(),
                            tx.amount,
                            params.hash_lock,
                            params.time_lock,
                            block_index,
                            params.price,
                        );
                        println!(
                            "[htlc] ✅ Contract {} erstellt: {} → {} ({} STONE)",
                            &contract_id[..12], &tx.from[..8.min(tx.from.len())],
                            if params.receiver.is_empty() { "offen" } else { &params.receiver[..8.min(params.receiver.len())] },
                            tx.amount,
                        );
                        changed = true;
                    }
                }
                TxType::HtlcClaim => {
                    if let Ok(params) = parse_htlc_claim_memo(&tx.memo) {
                        // TX-Timestamp statt Wallclock verwenden, damit Claims
                        // auch beim Chain-Replay korrekt verbucht werden.
                        let tx_time = tx.timestamp;
                        if let Err(e) = store.claim(&params.htlc_id, &params.preimage, &tx.tx_id, tx_time) {
                            eprintln!("[htlc] Claim fehlgeschlagen für {}: {e}", &params.htlc_id[..12.min(params.htlc_id.len())]);
                        } else {
                            println!("[htlc] ✅ Contract {} claimed", &params.htlc_id[..12.min(params.htlc_id.len())]);
                            changed = true;
                        }
                    }
                }
                TxType::HtlcRefund => {
                    if let Ok(params) = parse_htlc_refund_memo(&tx.memo) {
                        let tx_time = tx.timestamp;
                        if let Err(e) = store.refund(&params.htlc_id, &tx.tx_id, tx_time) {
                            eprintln!("[htlc] Refund fehlgeschlagen für {}: {e}", &params.htlc_id[..12.min(params.htlc_id.len())]);
                        } else {
                            println!("[htlc] ✅ Contract {} refunded", &params.htlc_id[..12.min(params.htlc_id.len())]);
                            changed = true;
                        }
                    }
                }
                _ => {}
            }
        }

        // 2. Abgelaufene Contracts → automatische Refund-TXs in den Mempool
        //    Nur wenn noch keine Refund-TX für diesen Contract im Mempool liegt
        //    UND der Escrow-Pool genug Balance hat.
        let now = Utc::now().timestamp();
        // Collect into owned data so the borrow on `store` is released
        // (needed to call store.refund() for orphaned contracts below).
        let expired: Vec<(String, String, Decimal)> = store.find_expired(now)
            .into_iter()
            .map(|c| (c.id.clone(), c.sender.clone(), c.amount))
            .collect();
        if !expired.is_empty() {
            let mut remaining_escrow = {
                let ledger = state.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                ledger.balance(HTLC_ESCROW_POOL)
            };

            // Sammle HTLC-IDs für die bereits ein Refund im Mempool pending ist
            let pending = state.mempool.pending_txs();
            let pending_refund_ids: std::collections::HashSet<String> = pending.iter()
                .filter(|tx| tx.tx_type == TxType::HtlcRefund)
                .filter_map(|tx| {
                    serde_json::from_str::<crate::token::HtlcRefundParams>(&tx.memo)
                        .ok()
                        .map(|p| p.htlc_id)
                })
                .collect();

            for (id, sender, amount) in &expired {
                if pending_refund_ids.contains(id) {
                    continue; // Refund-TX existiert bereits im Mempool
                }
                // Escrow hat nicht genug Balance → Contract direkt als Refunded markieren.
                // Das passiert z.B. wenn nach Chain-Reset der HTLC-Store replay
                // die Claims nicht korrekt verbucht hat (Timelock-Check vs. Wallclock).
                if remaining_escrow < *amount {
                    eprintln!(
                        "[htlc] ⚠️ Escrow reicht nicht für Refund {} ({} < {}), markiere als settled",
                        &id[..12.min(id.len())], remaining_escrow, amount,
                    );
                    let _ = store.refund(id, "system:escrow-empty", now);
                    changed = true;
                    continue;
                }
                let mut refund_tx = TokenTx {
                    tx_id: String::new(),
                    tx_type: TxType::HtlcRefund,
                    from: HTLC_ESCROW_POOL.to_string(),
                    to: sender.clone(),
                    amount: *amount,
                    fee: Decimal::ZERO,
                    nonce: 0,
                    memo: serde_json::to_string(&crate::token::HtlcRefundParams {
                        htlc_id: id.clone(),
                    }).unwrap_or_default(),
                    timestamp: now,
                    signature: "system".to_string(),
                    chain_id: crate::token::transaction::default_chain_id(),
                    fee_tier: crate::token::transaction::FeeTier::default(),
                    signed_by: None,
                };
                refund_tx.tx_id = compute_tx_id(&refund_tx);
                if let Err(e) = state.mempool.add_tx(refund_tx, None) {
                    eprintln!("[htlc] Auto-Refund TX fehlgeschlagen: {e}");
                } else {
                    remaining_escrow -= amount;
                    println!(
                        "[htlc] ⏰ Auto-Refund für abgelaufenen Contract {} → {}",
                        &id[..12.min(id.len())],
                        &sender[..8.min(sender.len())],
                    );
                    changed = true;
                }
            }
        }

        if changed {
            if let Err(e) = store.persist() {
                eprintln!("[htlc] Store-Persist fehlgeschlagen: {e}");
            }
        }
    }

    /// Staking Epoch-Verarbeitung nach einem committed Block.
    fn post_block_staking(state: &Arc<Self>, block: &Block) {
        let mut pool = state.staking_pool.write().unwrap_or_else(|e| e.into_inner());

        // 1. Epoch-Tick (rückt nur den Counter vor, keine Pool-basierte Emission mehr)
        let reward_pool_balance = {
            let ledger = state.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            ledger.balance("pool:mining_rewards")
        };
        let _epoch_tick = pool.process_epoch(block.index, reward_pool_balance);

        // 2. Gebühren-Verteilung aus pool:staker_fees (alle Staker, Node-Ops mit Bonus)
        let fee_pool_balance = {
            let ledger = state.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            ledger.balance(crate::token::reputation::STAKER_FEE_POOL)
        };
        if fee_pool_balance > rust_decimal::Decimal::ZERO {
            let node_op_wallets = {
                let registry = state.reputation_registry.read().unwrap_or_else(|e| e.into_inner());
                registry.active_operator_wallets()
            };
            let fee_payouts = pool.distribute_fee_income(fee_pool_balance, &node_op_wallets);
            if !fee_payouts.is_empty() {
                let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                for (addr, amount) in &fee_payouts {
                    if let Err(e) = ledger.credit_fee_reward(addr, *amount) {
                        eprintln!("[staking] Fee-Reward an {}… fehlgeschlagen: {e}",
                            &addr[..12.min(addr.len())]);
                    }
                }
            }
        }

        // 3. Fällige Unstakes freigeben
        let matured = pool.drain_matured_unstakes();
        if !matured.is_empty() {
            let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
            for req in &matured {
                ledger.release_unstake_escrow(&req.address, req.amount);
            }
            if let Err(e) = ledger.persist() {
                eprintln!("[staking] Ledger-Persist nach Unstake-Release: {e}");
            }
        }

        // 4. StakingPool persistieren
        let fee_distributed = fee_pool_balance > rust_decimal::Decimal::ZERO;
        if fee_distributed || !matured.is_empty() {
            if let Err(e) = pool.persist() {
                eprintln!("[staking] Pool-Persist: {e}");
            }
        }
    }

    /// Slashing-Prüfung nach einem committed Block.
    ///
    /// 1. Markiert den Block-Signer als aktiv (Downtime-Tracker)
    /// 2. Entlässt Validatoren mit abgelaufener Jail-Zeit
    /// 3. Prüft alle aktiven Validatoren auf Downtime
    /// 4. Bei Double-Signing wird automatisch geslasht
    fn post_block_slashing(state: &Arc<Self>, block: &Block) {
        use crate::consensus::{
            SLASH_JAIL_DURATION_SECS,
        };

        let mut slash_store = state.slashing_store.write().unwrap_or_else(|e| e.into_inner());

        // 1. Block-Signer als aktiv markieren (kanonisch über PubKey)
        if !block.signer.is_empty() {
            let signer_pubkey = {
                let vs = state.validator_set.read().unwrap_or_else(|e| e.into_inner());
                vs.get(&block.signer)
                    .map(|v| v.public_key_hex.clone())
                    .unwrap_or_else(|| block.validator_pub_key.clone())
            };
            let signer_canonical = Self::canonical_validator_id(&block.signer, &signer_pubkey);
            slash_store.mark_active(&signer_canonical, block.index);
            // Rückwärtskompatibel: alte node_id-basierte Historie weiterführen.
            slash_store.mark_active(&block.signer, block.index);
        }

        // 2. Abgelaufene Jails aufheben → Validator bleibt inaktiv (Cooldown)
        //    Muss sich durch einen PoW-Block beweisen um wieder aktiv zu werden.
        let released = slash_store.release_expired_jails();
        if !released.is_empty() {
            for vid in &released {
                println!("[slashing] 🔓 Validator '{}' aus Jail entlassen — bleibt inaktiv (Cooldown, muss durch Admin oder Stake re-aktiviert werden)", vid);
            }
        }

        // 3. Downtime-Check für alle aktiven Validatoren
        let validators: Vec<(String, String)> = {
            let vs = state.validator_set.read().unwrap_or_else(|e| e.into_inner());
            vs.validators.iter()
                .filter(|v| v.active)
                .filter(|v| v.node_id != block.signer) // Signer ist ja aktiv
                .map(|v| {
                    (
                        v.node_id.clone(),
                        Self::canonical_validator_id(&v.node_id, &v.public_key_hex),
                    )
                })
                .collect()
        };

        for (vid, canonical_id) in &validators {
            // Bereits gejailed? Dann nicht nochmal prüfen
            if slash_store.is_jailed(canonical_id) || slash_store.is_jailed(vid) {
                continue;
            }

            let offense = slash_store
                .check_downtime(canonical_id, block.index)
                .or_else(|| slash_store.check_downtime(vid, block.index));

            if let Some(offense) = offense {
                // Wallet-Adresse des Validators ermitteln (falls bekannt)
                let wallet_addr = Self::resolve_validator_wallet(state, vid);

                let slashed_amount = if let Some(ref wallet) = wallet_addr {
                    let mut pool = state.staking_pool.write().unwrap_or_else(|e| e.into_inner());
                    let stake = pool.stakers.get(wallet)
                        .map(|s| s.staked_amount)
                        .unwrap_or(rust_decimal::Decimal::ZERO);
                    let penalty = stake * rust_decimal::Decimal::from(offense.penalty_percent())
                        / rust_decimal::Decimal::from(100u64);
                    pool.slash(wallet, penalty)
                } else {
                    rust_decimal::Decimal::ZERO
                };

                let record = slash_store.record_slash(
                    canonical_id,
                    wallet_addr.as_deref(),
                    offense,
                    slashed_amount,
                    block.index,
                );

                // Validator deaktivieren (Jail)
                {
                    let mut vs = state.validator_set.write().unwrap_or_else(|e| e.into_inner());
                    vs.set_active(vid, false);
                }

                eprintln!(
                    "[slashing] ⚠️  {} – {} STONE geslasht, Jail für {} Stunden",
                    record.offense.description(),
                    record.slashed_amount,
                    SLASH_JAIL_DURATION_SECS / 3600,
                );

                state.events.publish(NodeEvent::ValidatorSlashed {
                    validator_id: vid.clone(),
                    offense: record.offense.description(),
                    slashed_amount: record.slashed_amount.clone(),
                    timestamp: record.timestamp,
                });
            }
        }
    }

    /// Equivocation-Evidence → Slashing + Jail + Deaktivierung.
    ///
    /// Wird aus den P2P-Event-Handlern (master_server, stone_miner, setup)
    /// aufgerufen, wenn der `EquivocationTracker` einen Double-Sign erkennt.
    pub fn slash_equivocation(state: &Arc<Self>, evidence: &crate::consensus::EquivocationEvidence) {
        use crate::consensus::SlashingOffense;

        // Validator-NodeId via pub_key auflösen
        let (validator_node_id, validator_pubkey, wallet_addr) = {
            let vs = state.validator_set.read().unwrap_or_else(|e| e.into_inner());
            let found = vs.validators.iter().find(|v| v.public_key_hex == evidence.validator_pub_key);
            match found {
                Some(v) => (
                    v.node_id.clone(),
                    v.public_key_hex.clone(),
                    Self::resolve_validator_wallet(state, &v.node_id),
                ),
                None => (
                    evidence.validator_pub_key.clone(),
                    evidence.validator_pub_key.clone(),
                    None,
                ),
            }
        };
        let canonical_validator_id = Self::canonical_validator_id(&validator_node_id, &validator_pubkey);

        let offense = SlashingOffense::DoubleSigning {
            block_index: evidence.block_index,
            hash_a: evidence.hash_a.clone(),
            hash_b: evidence.hash_b.clone(),
        };

        let slashed_amount = if let Some(ref wallet) = wallet_addr {
            let mut pool = state.staking_pool.write().unwrap_or_else(|e| e.into_inner());
            let stake = pool.stakers.get(wallet)
                .map(|s| s.staked_amount)
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let penalty = stake * rust_decimal::Decimal::from(offense.penalty_percent())
                / rust_decimal::Decimal::from(100u64);
            pool.slash(wallet, penalty)
        } else {
            rust_decimal::Decimal::ZERO
        };

        let mut slash_store = state.slashing_store.write().unwrap_or_else(|e| e.into_inner());
        let record = slash_store.record_slash(
            &canonical_validator_id,
            wallet_addr.as_deref(),
            offense,
            slashed_amount,
            evidence.block_index,
        );
        drop(slash_store);

        // Validator deaktivieren
        {
            let mut vs = state.validator_set.write().unwrap_or_else(|e| e.into_inner());
            vs.set_active(&validator_node_id, false);
        }

        eprintln!(
            "[slashing] ⚠️  EQUIVOCATION SLASH: {} – {} STONE geslasht (Block #{}, hashes: {}…/{}…)",
            validator_node_id,
            record.slashed_amount,
            evidence.block_index,
            &evidence.hash_a[..12.min(evidence.hash_a.len())],
            &evidence.hash_b[..12.min(evidence.hash_b.len())],
        );

        state.events.publish(NodeEvent::ValidatorSlashed {
            validator_id: validator_node_id,
            offense: record.offense.description(),
            slashed_amount: record.slashed_amount,
            timestamp: record.timestamp,
        });
    }

    /// Reputation-System nach einem committed Block aktualisieren.
    ///
    /// 1. Block-Signer als aktiven Node registrieren (falls noch nicht bekannt)
    /// 2. Heartbeat + Block-Signed für den Signer aufzeichnen
    /// 3. Alle Scores neu berechnen
    /// 4. Falls Distribution-Intervall erreicht: Pool ausschütten
    fn post_block_reputation(state: &Arc<Self>, block: &Block) {
        let mut registry = state.reputation_registry.write().unwrap_or_else(|e| e.into_inner());

        // 1. Block-Signer registrieren & Heartbeat
        if !block.signer.is_empty() {
            let signer_wallet = {
                // Wallet-Adresse des Signers ermitteln
                if block.signer == state.node_id {
                    let signing_key = load_or_create_validator_key();
                    local_validator_pubkey_hex(&signing_key)
                } else {
                    // Für Remote-Nodes: validator_pub_key aus dem Block verwenden
                    if !block.validator_pub_key.is_empty() {
                        block.validator_pub_key.clone()
                    } else {
                        block.signer.clone()
                    }
                }
            };
            registry.register_node(&block.signer, &signer_wallet);
            registry.record_heartbeat(&block.signer);
            registry.record_block_signed(&block.signer);
        }

        // 2. Scores aktualisieren
        registry.compute_all_scores();

        // 3. Distribution prüfen (alle 720 Blöcke)
        if registry.distribution_due(block.index) {
            let pool_balance = {
                let ledger = state.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                ledger.balance(crate::token::reputation::NODE_OPERATOR_POOL)
            };

            let payouts = registry.calculate_distribution(pool_balance, block.index);
            if !payouts.is_empty() {
                let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                let mut total_paid = rust_decimal::Decimal::ZERO;
                for (addr, amount) in &payouts {
                    if let Err(e) = ledger.credit_operator_reward(addr, *amount) {
                        eprintln!("[reputation] Reward-Gutschrift an {}… fehlgeschlagen: {e}",
                            &addr[..16.min(addr.len())]);
                    } else {
                        total_paid += amount;
                    }
                }
                if total_paid > rust_decimal::Decimal::ZERO {
                    println!(
                        "[reputation] 💰 Distribution Block #{}: {} STONE an {} Nodes verteilt",
                        block.index, total_paid, payouts.len()
                    );
                    if let Err(e) = ledger.persist() {
                        eprintln!("[reputation] Ledger-Persist nach Distribution: {e}");
                    }
                }
            }
        }

        // 4. Registry persistieren
        if let Err(e) = registry.persist() {
            eprintln!("[reputation] Registry-Persist: {e}");
        }
    }

    /// Governance-Hook: Proposals auswerten, Timelocks pruefen, Rewards auszahlen.
    fn post_block_governance(state: &Arc<Self>) {
        let mut gov = state.governance.write().unwrap_or_else(|e| e.into_inner());

        // 1. Abgelaufene Proposals aufraeumen
        gov.expire_old_proposals();

        // 2. Timelock-Pruefung: Accepted -> Ready
        let ready_ids = gov.check_timelocks();

        // 3. Ready-Proposals ausfuehren (inkl. Grant-Payouts)
        for pid in &ready_ids {
            match gov.mark_executed(pid) {
                Ok(Some((recipient, amount, memo))) => {
                    drop(gov);
                    {
                        let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                        if let Err(e) = ledger.credit_governance_payout(&recipient, amount, &memo) {
                            eprintln!("[governance] Payout fehlgeschlagen: {e}");
                        }
                    }
                    gov = state.governance.write().unwrap_or_else(|e| e.into_inner());
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[governance] mark_executed Fehler: {e}");
                }
            }
        }

        // 4. Voting-Rewards + Moderation-Rewards auszahlen
        let voting_payouts = gov.drain_voting_rewards();
        let moderation_payouts = gov.drain_moderation_rewards();
        if let Err(e) = gov.persist() {
            eprintln!("[governance] Persist fehlgeschlagen: {e}");
        }
        drop(gov);

        if !voting_payouts.is_empty() || !moderation_payouts.is_empty() {
            let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
            for (wallet, amount, memo) in voting_payouts.iter().chain(moderation_payouts.iter()) {
                if let Err(e) = ledger.credit_governance_payout(wallet, *amount, memo) {
                    eprintln!("[governance] Reward fehlgeschlagen: {e}");
                }
            }
            if !voting_payouts.is_empty() {
                println!("[governance] {} Voting-Rewards ausgezahlt", voting_payouts.len());
            }
            if !moderation_payouts.is_empty() {
                println!("[governance] {} Moderation-Rewards ausgezahlt", moderation_payouts.len());
            }
        }
    }

    /// Chat-Policy nach einem committed Block: TTL-Tracking + GC + Report-Finalisierung.
    ///
    /// 1. Neue ChatMessage-TXs im Block → TTL-Eintrag erstellen
    /// 2. Garbage Collection: Abgelaufene Nachrichten-Content löschen
    /// 3. Pending Reports prüfen und ggf. finalisieren
    fn post_block_chat_policy(state: &Arc<Self>, block: &Block, chat_index: Option<&std::sync::Arc<std::sync::Mutex<crate::chat::ChatIndex>>>) {
        let mut policy = state.chat_policy.write().unwrap_or_else(|e| e.into_inner());

        // 1a. Neue ChatMessage-TXs tracken (Backward-Compat: alte Einzelnachrichten)
        for tx in &block.transactions {
            if tx.tx_type != TxType::ChatMessage {
                continue;
            }
            // msg_id und TTL aus Memo extrahieren
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&tx.memo) {
                let msg_id = data["msg_id"].as_str().unwrap_or("").to_string();
                if msg_id.is_empty() {
                    continue;
                }
                let ttl_str = data["ttl"].as_str().unwrap_or("30d");
                let ttl = crate::chat_policy::MessageTtl::from_str_or_default(ttl_str);

                policy.track_message(
                    &msg_id,
                    &tx.tx_id,
                    &tx.from,
                    &tx.to,
                    ttl,
                    tx.timestamp,
                    block.index,
                );
            }
        }

        // 1b. Chat-Batch-Nachrichten aus Merkle-Batches tracken
        for batch in &block.chat_batches {
            for msg in &batch.messages {
                // Falls bereits getrackt (z.B. vom Sender-Node), nur block_index aktualisieren
                if let Some(entry) = policy.ttl_entries.get_mut(&msg.msg_id) {
                    if entry.block_index == 0 {
                        entry.block_index = block.index;
                    }
                } else {
                    // Neuer Eintrag (empfangener Batch von anderem Node)
                    policy.track_message(
                        &msg.msg_id,
                        &batch.merkle_root,
                        &msg.from_wallet,
                        &msg.to_wallet,
                        crate::chat_policy::MessageTtl::default(),
                        msg.timestamp,
                        block.index,
                    );
                }
            }
        }

        // 2. Garbage Collection: Abgelaufene Nachrichten-Content löschen
        if let Some(chat_idx_arc) = chat_index {
            let mut chat_idx = chat_idx_arc.lock().unwrap_or_else(|e| e.into_inner());
            let purged = crate::chat_policy::gc_expired_messages(&mut policy, &mut chat_idx);
            if purged > 0 {
                crate::chat::save_chat_index(&chat_idx);
            }
        }

        // 3. Pending Reports finalisieren (Timeout etc.) – stake-gewichtet
        let stake_weights: std::collections::HashMap<String, rust_decimal::Decimal> = {
            let pool = state.staking_pool.read().unwrap_or_else(|e| e.into_inner());
            pool.stakers.iter()
                .filter(|(_, entry)| crate::token::StakeLevel::from_stake(entry.staked_amount).can_validate())
                .map(|(addr, entry)| (addr.clone(), entry.staked_amount))
                .collect()
        };
        let finalized = policy.finalize_all_pending(Some(&stake_weights));
        for (report_id, accepted, msg_id, reported_wallet) in &finalized {
            if *accepted {
                // Content im Chat-Index löschen
                if let Some(chat_idx_arc) = chat_index {
                    let mut chat_idx = chat_idx_arc.lock().unwrap_or_else(|e| e.into_inner());
                    crate::chat_policy::purge_message_content(&mut chat_idx, msg_id);
                    crate::chat::save_chat_index(&chat_idx);
                }

                // Reporter- und Voter-Wallets für Moderation-Rewards einsammeln
                if let Some(archived) = policy.report_archive.iter().rev().find(|r| r.report_id == *report_id) {
                    let reporter_wallet_reward = archived.reporter_wallet.clone();
                    // Vote-Keys in der MessageReport sind Node-IDs → lookup Wallets aus GovernanceStore
                    let voter_wallets: Vec<String> = {
                        let gov = state.governance.read().unwrap_or_else(|e| e.into_inner());
                        archived.votes.keys()
                            .filter_map(|node_id| {
                                gov.trusted_nodes.get(node_id).map(|tn| tn.wallet.clone())
                            })
                            .collect()
                    };
                    if !reporter_wallet_reward.is_empty() {
                        let mut gov = state.governance.write().unwrap_or_else(|e| e.into_inner());
                        gov.queue_moderation_reward(reporter_wallet_reward, voter_wallets);
                    }
                }

                // Slash
                let slash_amount = {
                    let pool = state.staking_pool.read().unwrap_or_else(|e| e.into_inner());
                    let staked = pool.stakers.get(reported_wallet)
                        .map(|s| s.staked_amount)
                        .unwrap_or(Decimal::ZERO);
                    staked * Decimal::from(crate::chat_policy::REPORT_SLASH_PCT)
                        / Decimal::from(100u32)
                };

                if slash_amount > Decimal::ZERO {
                    let mut pool = state.staking_pool.write().unwrap_or_else(|e| e.into_inner());
                    let actual = pool.slash(reported_wallet, slash_amount);
                    drop(pool);

                    let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                    ledger.credit_to_operator_pool(actual);
                    if let Err(e) = ledger.persist() {
                        eprintln!("[token] ⚠️  Ledger persist nach Slash fehlgeschlagen: {e}");
                    }

                    println!(
                        "[chat-policy] ⚖️  Report {} auto-finalisiert: {} STONE geslasht",
                        &report_id[..8.min(report_id.len())], actual,
                    );
                }
            }
        }

        // Persistieren (wenn sich etwas geändert hat)
        let changed = policy.total_messages_tracked > 0 || !finalized.is_empty();
        if changed {
            if let Err(e) = policy.persist() {
                eprintln!("[chat-policy] Persist: {e}");
            }
        }
    }

    /// Versucht die Wallet-Adresse eines Validators aufzulösen.
    /// Sucht in der Node-Wallet-Konfiguration (gleiche node_id = gleiche wallet).
    fn resolve_validator_wallet(state: &Arc<Self>, validator_id: &str) -> Option<String> {
        // Wenn es unsere eigene Node ist
        if validator_id == state.node_id {
            return std::env::var("STONE_NODE_WALLET").ok();
        }
        // Für Remote-Validatoren: in der Trust-Registry nach wallet suchen
        // (Erweiterbar in Zukunft)
        None
    }

    /// Finality-Checkpoint nach einem committed Block erstellen (alle CHECKPOINT_INTERVAL Blöcke).
    pub(crate) async fn post_block_checkpoint(state: &Arc<Self>, block: &Block) {
        let should_create = {
            let store = state.checkpoint_store.read().unwrap_or_else(|e| e.into_inner());
            store.should_create_checkpoint(block.index)
        };
        if !should_create {
            return;
        }

        let required = {
            let vs = state.validator_set.read().unwrap_or_else(|e| e.into_inner());
            let active = vs.active_count();
            if active <= 1 { 1 } else { (active * 2) / 3 + 1 }
        };

        let mut checkpoint = crate::consensus::Checkpoint::new(
            block.index,
            block.hash.clone(),
            required,
        );

        // Lokal signieren
        let signing_key = load_or_create_validator_key();
        checkpoint.sign(&state.node_id, &signing_key);

        let finalized = checkpoint.is_finalized();
        {
            let mut store = state.checkpoint_store.write().unwrap_or_else(|e| e.into_inner());
            store.add_or_update(checkpoint.clone());
        }

        if finalized {
            println!(
                "[checkpoint] ✅ Block #{} finalisiert (single-node) – unwiderruflich",
                block.index
            );
        } else {
            println!(
                "[checkpoint] 📌 Checkpoint für Block #{} erstellt ({}/{} Signaturen, warte auf Peers)",
                block.index, 1, required
            );
        }

        // An Peers broadcasten (fire-and-forget, async)
        let peer_urls: Vec<String> = {
            let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
            peers.iter()
                .filter(|p| p.is_healthy())
                .map(|p| p.url.clone())
                .collect()
        };
        if !peer_urls.is_empty() {
            let cp_json = serde_json::to_vec(&checkpoint).unwrap_or_default();
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();
            for peer in &peer_urls {
                let url = format!("{}/api/v1/checkpoint", peer.trim_end_matches('/'));
                match client.post(&url)
                    .header("Content-Type", "application/json")
                    .body(cp_json.clone())
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            println!("[checkpoint] → Checkpoint für #{} an {} gesendet", block.index, peer);
                        }
                    }
                    Err(e) => {
                        eprintln!("[checkpoint] Senden an {} fehlgeschlagen: {e}", peer);
                    }
                }
            }
        }
    }
}
