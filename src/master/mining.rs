//! Mining – Block-Erstellung, Template-Management, PoW-Submission

use crate::blockchain::{Block, StoneChain};
use crate::consensus::{load_or_create_validator_key, local_validator_pubkey_hex, sign_block};
use crate::token::transaction::{TokenTx, TxType, compute_tx_id};
use chrono::Utc;
use rust_decimal::Decimal;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{MasterNodeState, MiningTemplate, MiningSubmission};
use super::types::NodeEvent;
use super::{TARGET_BLOCK_TIME_SECS, MINING_INTERVAL_SECS, INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL, MIN_BLOCK_REWARD, TEMPLATE_REFRESH_SECS};

/// Gossipsub-Tag für Miner-Connect-Nachrichten (Byte 0 der Payload).
pub const MINER_GOSSIP_KIND_CONNECT: u8 = 0;
/// Gossipsub-Tag für Miner-Heartbeat-Nachrichten.
pub const MINER_GOSSIP_KIND_HEARTBEAT: u8 = 1;

impl MasterNodeState {
    // ─── Block-Mining (Interval-Mining) ───────────────────────────────────────

    /// Berechnet den Block-Reward für einen gegebenen Block-Index.
    ///
    /// Schema: `INITIAL_BLOCK_REWARD / 2^(block_index / HALVING_INTERVAL)`
    /// Gibt `Decimal::ZERO` zurück wenn Reward < MIN oder Reward-Pool leer.
    ///
    /// `pool_balance` = Balance von pool:mining_rewards (woraus Rewards kommen).
    pub fn calculate_block_reward(block_index: u64, pool_balance: Decimal) -> Decimal {
        let min_reward: Decimal = MIN_BLOCK_REWARD.parse().unwrap_or_else(|_| Decimal::new(1, 8));

        // Reward-Pool leer?
        if pool_balance <= Decimal::ZERO {
            return Decimal::ZERO;
        }

        let mut reward: Decimal = INITIAL_BLOCK_REWARD.parse()
            .unwrap_or_else(|_| Decimal::new(10, 0));

        // Halving: Reward halbiert sich alle HALVING_INTERVAL Blöcke
        let halvings = block_index / HALVING_INTERVAL;
        for _ in 0..halvings.min(64) {
            reward /= Decimal::new(2, 0);
            if reward < min_reward {
                return Decimal::ZERO;
            }
        }

        // Nicht mehr als der Pool-Rest
        if reward > pool_balance {
            reward = pool_balance;
        }

        reward.round_dp(8)
    }

    /// Erstellt eine System-Reward-TX für den Block-Validator.
    fn create_reward_tx(validator_wallet: &str, amount: Decimal, block_index: u64) -> TokenTx {
        Self::create_reward_tx_to(validator_wallet, amount, block_index, "Mining Reward")
    }

    /// Generische Reward-TX (System): pool:mining_rewards → `to_addr`.
    fn create_reward_tx_to(
        to_addr: &str,
        amount: Decimal,
        block_index: u64,
        memo_suffix: &str,
    ) -> TokenTx {
        let chain_id = std::env::var("STONE_NETWORK")
            .map(|n| {
                if n == "mainnet" || n == "main" {
                    "stone-mainnet".to_string()
                } else {
                    "stone-testnet".to_string()
                }
            })
            .unwrap_or_else(|_| "stone-testnet".to_string());

        let mut tx = TokenTx {
            tx_id: String::new(),
            tx_type: TxType::Reward,
            from: "pool:mining_rewards".to_string(),
            to: to_addr.to_string(),
            amount,
            fee: Decimal::ZERO,
            nonce: 0,
            timestamp: 0, // System-TXs need no wall-clock timestamp; non-determinism avoided
            signature: String::new(), // System-TXs brauchen keine Signatur
            memo: format!("Block #{block_index} {memo_suffix}"),
            chain_id,
            fee_tier: crate::token::FeeTier::Priority,
            signed_by: None,
        };
        tx.tx_id = compute_tx_id(&tx);
        tx
    }

    /// Splittet den Auto-Block-Reward auf die drei Netzwerk-Pools:
    ///   40% → `pool:onboarding`     (Startguthaben für neue Nutzer)
    ///   20% → `pool:bug_bounty`     (Tester- und Audit-Belohnungen)
    ///   40% → bleibt in `pool:mining_rewards` (zukünftige Miner-Rewards)
    ///
    /// Liefert die zwei tatsächlich nötigen Transfer-TXs zurück (die 40% in
    /// `pool:mining_rewards` werden gar nicht erst entnommen). 0 STONE
    /// Anteile werden ausgelassen.
    fn create_auto_block_split_rewards(
        total: Decimal,
        block_index: u64,
    ) -> Vec<TokenTx> {
        if total <= Decimal::ZERO {
            return Vec::new();
        }
        // Decimal-Mathematik: 40% / 20% mit 8 Nachkommastellen
        let pct_40 = (total * Decimal::new(40, 2)).round_dp(8);
        let pct_20 = (total * Decimal::new(20, 2)).round_dp(8);
        let mut out = Vec::new();
        if pct_40 > Decimal::ZERO {
            out.push(Self::create_reward_tx_to(
                "pool:onboarding",
                pct_40,
                block_index,
                "Auto-Block Reward → Onboarding (40%)",
            ));
        }
        if pct_20 > Decimal::ZERO {
            out.push(Self::create_reward_tx_to(
                "pool:bug_bounty",
                pct_20,
                block_index,
                "Auto-Block Reward → Bug-Bounty (20%)",
            ));
        }
        out
    }

    /// Sammelt pending ChallengeResponses und validiert sie gegen offene Challenges in der Chain.
    ///
    /// Gibt gültige Responses zurück, OHNE sie aus dem Pending-Buffer zu entfernen.
    fn collect_pending_challenge_responses(
        &self,
        chain: &StoneChain,
    ) -> Vec<crate::storage_proof::ChallengeResponse> {
        let pending = self.pending_challenge_responses.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_empty() {
            return Vec::new();
        }

        let current_block = chain.blocks.len() as u64;

        // Sammle alle offenen Challenges aus den letzten DEADLINE Blöcken
        let lookback = crate::storage_proof::CHALLENGE_DEADLINE_BLOCKS as usize + 5;
        let start = chain.blocks.len().saturating_sub(lookback);
        let open_challenges: Vec<&crate::storage_proof::NetworkChallenge> = chain.blocks[start..]
            .iter()
            .flat_map(|b| b.storage_challenges.iter())
            .filter(|c| c.deadline_block >= current_block)
            .collect();

        // Sammle alle schon beantworteten Challenge-IDs
        let answered: std::collections::HashSet<&str> = chain.blocks[start..]
            .iter()
            .flat_map(|b| b.challenge_responses.iter())
            .map(|r| r.challenge_id.as_str())
            .collect();

        // Nur Responses für offene, noch nicht beantwortete Challenges aufnehmen
        let store = crate::storage::ChunkStore::new().ok();

        let valid_responses: Vec<crate::storage_proof::ChallengeResponse> = pending
            .iter()
            .filter(|resp| {
                // Challenge existiert und ist offen?
                let challenge = open_challenges.iter().find(|c| c.challenge_id == resp.challenge_id);
                match challenge {
                    None => {
                        println!("[storage-challenge] ⚠ Response für unbekannte Challenge {} ignoriert", &resp.challenge_id[..12.min(resp.challenge_id.len())]);
                        false
                    }
                    Some(challenge) => {
                        if answered.contains(resp.challenge_id.as_str()) {
                            println!("[storage-challenge] ⚠ Challenge {} schon beantwortet", &resp.challenge_id[..12.min(resp.challenge_id.len())]);
                            return false;
                        }
                        match crate::storage_proof::verify_challenge_response(
                            challenge,
                            resp,
                            store.as_ref(),
                            current_block,
                        ) {
                            Ok(()) => true,
                            Err(e) => {
                                println!("[storage-challenge] ❌ Invalid response: {e}");
                                false
                            }
                        }
                    }
                }
            })
            .cloned()
            .collect();

        valid_responses
    }

    /// Erstellt einen neuen Block (auch ohne Dokumente) mit Mempool-TXs und Block-Reward.
    ///
    /// Wird vom Mining-Loop alle `MINING_INTERVAL_SECS` Sekunden aufgerufen.
    /// Prüft PoA-Berechtigung und erstellt den Block nur wenn diese Node
    /// der ausgewählte Validator ist.
    ///
    /// Single-Node-Modus: Block wird direkt committed.
    /// Multi-Node-Modus: Verwende `prepare_mining_block()` + `commit_mining_block()`.
    pub fn mint_block(&self) -> Result<Block, String> {
        self.mint_block_inner(false)
    }

    /// Auto-Block: gleicher Ablauf wie `mint_block`, aber der Block-Reward wird
    /// gemäß Auto-Block-Schema (40/20/40 → Onboarding/Bug-Bounty/Mining-Pool)
    /// auf die Netzwerk-Pools verteilt statt an den Validator ausgeschüttet.
    pub fn mint_auto_block(&self) -> Result<Block, String> {
        self.mint_block_inner(true)
    }

    fn mint_block_inner(&self, auto_mode: bool) -> Result<Block, String> {
        let block = self.prepare_mining_block(auto_mode)?;
        match self.commit_mining_block(block.clone()) {
            Ok(()) => Ok(block),
            Err(e) => {
                // CRITICAL: TXs wurden aus dem Mempool entnommen aber der Block konnte
                // nicht committed werden. TXs zurück in den Mempool legen!
                let mut restored = 0u32;
                for tx in &block.transactions {
                    // System-TXs nicht zurücklegen (Reward, Memorial) — aber Faucet-Mints schon!
                    if tx.tx_type == TxType::Reward
                        || tx.tx_type == crate::token::transaction::TxType::Memorial
                    {
                        continue;
                    }
                    if tx.tx_type == TxType::Mint && tx.from != "system:faucet" {
                        continue;
                    }
                    if let Ok(()) = self.mempool.add_tx(tx.clone(), None) {
                        restored += 1;
                    }
                }
                if restored > 0 {
                    eprintln!(
                        "[mining] ⚠️ Block-Commit fehlgeschlagen, {} TXs zurück in Mempool: {e}",
                        restored
                    );
                }
                // Chat-Batches zurückrollen (Nachrichten wieder auf Pending setzen)
                for batch in &block.chat_batches {
                    self.message_pool.unbatch(&batch.merkle_root);
                }
                Err(e)
            }
        }
    }

    // ─── Competitive PoW: Block-Template für externe Miner ─────────────────

    /// Erstellt ein Block-Template für externe Miner (ohne PoW).
    ///
    /// Der Block wird vollständig vorbereitet (TXs, Reward, Signatur) aber
    /// das Argon2id-PoW-Puzzle wird NICHT gelöst. Das Template enthält alle
    /// Daten die ein externer Miner braucht um den PoW zu lösen.
    ///
    /// Das Template wird in `current_mining_template` gespeichert und kann
    /// per `GET /api/v1/mining/template` abgerufen werden.
    pub fn prepare_block_template(&self) -> Result<MiningTemplate, String> {
        // Validator-Schlüssel laden
        let signing_key = load_or_create_validator_key();
        let validator_wallet = local_validator_pubkey_hex(&signing_key);

        // Reward-Wallet bestimmen
        let reward_wallet = {
            let mw = self.mining_wallet.read().unwrap_or_else(|e| e.into_inner());
            mw.clone().unwrap_or_else(|| validator_wallet.clone())
        };

        // ── Block-Reward berechnen ──────────────────────────────────────
        let (reward_amount, next_index, _prev_hash) = {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let next_idx = chain.blocks.len() as u64;
            let prev = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            let ledger = self.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            let pool_balance = ledger.balance("pool:mining_rewards");
            (Self::calculate_block_reward(next_idx, pool_balance), next_idx, prev)
        };

        // ── Alte Template-TXs zurück in Mempool ─────────────────────────
        // Wenn ein altes Template existiert dessen Block nicht committed wurde,
        // müssen dessen User-TXs zurück in den Mempool bevor neu gedrained wird.
        // Ohne diesen Schritt gehen TXs verloren wenn ein Peer-Block das
        // Template invalidiert (z.B. Faucet-TXs im Testnet).
        {
            let tmpl = self.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
            if let Some((_, ref old_block)) = *tmpl {
                self.restore_block_txs(old_block);
            }
        }

        // ── Gate: KEINE leeren Templates (kein Spam-Mining). ────────────
        // Der Miner soll nur Templates bekommen wenn echte Nutzlast anliegt:
        //   - TXs im Mempool (lokal ODER per Gossip), ODER
        //   - ein Chat-Batch bereit ist.
        // Ohne diesen Check mined der Miner leere Blöcke → block_timer wird
        // ständig resetted → Auto-Block kommt nie zum Zug.
        let has_pending_tx = self.mempool.pending_count() > 0;
        let chat_batch_ready = self.message_pool.batch_ready();
        if !has_pending_tx && !chat_batch_ready {
            // Keine Nutzlast → kein Template. Miner pausiert, Auto-Block übernimmt.
            return Err("Mining: Mempool leer — kein Template".into());
        }

        // ── Mempool-TXs + Reward-TX sammeln ────────────────────────────
        let mut pending_txs = self.mempool.drain_all_for_block();
        let user_tx_count = pending_txs.len(); // vor reward

        if reward_amount > Decimal::ZERO {
            let reward_tx = Self::create_reward_tx(&reward_wallet, reward_amount, next_index);
            pending_txs.push(reward_tx);
        }

        // ── Pre-Block-Validierung: Ungültige TXs herausfiltern ──────────
        // Verhindert dass TXs mit unzureichender Balance oder falscher Nonce
        // in den Block aufgenommen werden (Double-Spend-Schutz).
        let pending_txs = {
            let ledger = self.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            let mut valid = ledger.filter_valid_txs(&pending_txs);
            // Deterministic ordering: sort by tx_id (SHA-256 hash) after fee tier sort.
            // Fee-tier sort happens in drain_all_for_block, but within each tier,
            // insertion order (which differs per node) would determine order.
            // Sorting by tx_id guarantees identical blocks on all nodes.
            valid.sort_by(|a, b| a.tx_id.cmp(&b.tx_id));

            // Abgelehnte User-TXs mit zukünftiger Nonce zurück in den Mempool legen.
            // Diese TXs könnten gültig werden wenn vorherige TXs eintreffen.
            let valid_ids: std::collections::HashSet<&str> =
                valid.iter().map(|tx| tx.tx_id.as_str()).collect();
            let mut requeued = 0usize;
            let mut discarded = 0usize;
            for tx in &pending_txs {
                if valid_ids.contains(tx.tx_id.as_str()) {
                    continue;
                }
                // System-TXs nicht requeuen
                if matches!(tx.tx_type, TxType::Reward | TxType::Mint | TxType::Memorial) {
                    continue;
                }
                // Bereits verarbeitete TXs (Duplikate) endgültig verwerfen
                if ledger.is_processed_tx(&tx.tx_id) {
                    discarded += 1;
                    self.mempool.mark_known(&tx.tx_id);
                    continue;
                }
                // Nonce >= erwartet → TX könnte zukünftig gültig werden → zurücklegen
                let expected_nonce = ledger.nonce(&tx.from);
                if tx.nonce >= expected_nonce {
                    if self.mempool.requeue_tx(tx.clone()) {
                        requeued += 1;
                    } else {
                        discarded += 1;
                        println!(
                            "[mining] 🗑️  TX {} endgültig verworfen: Requeue-Limit erreicht (Nonce {} erwartet {})",
                            &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce,
                        );
                    }
                } else {
                    discarded += 1;
                    // Endgültig ungültige TX als "known" markieren damit
                    // Mempool-Sync sie nicht erneut vom Peer holt.
                    self.mempool.mark_known(&tx.tx_id);
                    println!(
                        "[mining] 🗑️  TX {} verworfen: Nonce {} < erwartet {} ({:?})",
                        &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce, tx.tx_type,
                    );
                }
            }
            if requeued > 0 || discarded > 0 {
                println!(
                    "[mining] 📊 Block-Filter: {} User-TXs gedrained, {} valid, {} requeued, {} verworfen",
                    user_tx_count, valid.len().saturating_sub(1), requeued, discarded,
                );
            }

            valid
        };

        // ── Chat-Nachrichten batchen ────────────────────────────────────
        let chat_batches = if self.message_pool.batch_ready() {
            let drained = self.message_pool.drain_for_batch();
            if !drained.is_empty() {
                let msg_ids: Vec<String> = drained.iter().map(|m| m.msg_id.clone()).collect();
                match crate::merkle_batch::build_batch(&drained) {
                    Some((anchor, _tree)) => {
                        self.message_pool.mark_batched(&msg_ids, &anchor.merkle_root);
                        vec![anchor]
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ── Block vorbereiten (ohne PoW) ────────────────────────────────
        let signer = self.node_id.clone();
        let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut block = chain.prepare_block(
            Vec::new(),
            Vec::new(),
            pending_txs,
            "system".to_string(),
            signer,
            &self.cluster_key,
            self.role.clone(),
            chat_batches,
        );
        drop(chain);

        // ── Block-Signierung ────────────────────────────────────────────
        let sig = sign_block(&signing_key, &block.hash);
        block.validator_pub_key = validator_wallet.clone();
        block.validator_signature = sig;

        // ── Storage Challenges ──────────────────────────────────────────
        {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let chunk_refs = crate::storage_proof::collect_chunk_refs(&chain);
            if !chunk_refs.is_empty() {
                let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
                let mut known_wallets: Vec<String> = vs.validators.iter()
                    .filter(|v| v.active)
                    .filter_map(|v| if v.public_key_hex.is_empty() { None } else { Some(v.public_key_hex.clone()) })
                    .collect();
                {
                    let trust = self.trust_registry.read().unwrap_or_else(|e| e.into_inner());
                    for entry in trust.iter() {
                        if !entry.public_key_hex.is_empty() && !known_wallets.contains(&entry.public_key_hex) {
                            known_wallets.push(entry.public_key_hex.clone());
                        }
                    }
                }
                let challenges = crate::storage_proof::generate_network_challenges(
                    &block.previous_hash, block.index, &chunk_refs, &known_wallets, &validator_wallet,
                );
                block.storage_challenges = challenges;

                // Challenge-Responses aufnehmen (keine Rewards mehr, nur Tracking)
                let responses = self.collect_pending_challenge_responses(&chain);
                if !responses.is_empty() {
                    block.challenge_responses = responses;
                }

                // Block-Hash neu berechnen
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                block.validator_signature = sign_block(&signing_key, &block.hash);
            }
        }

        // ── PoW-Difficulty bestimmen ────────────────────────────────────
        let difficulty = {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            crate::consensus::get_current_pow_difficulty(&chain.blocks, block.index)
        };
        block.pow_difficulty = difficulty;

        // ── PoS/PoW Hybrid: Effektive Difficulty berechnen ───────────────
        let eff_difficulty = {
            let pool = self.staking_pool.read().unwrap_or_else(|e| e.into_inner());
            let miner_stake = pool.stakers.get(&validator_wallet)
                .map(|e| e.staked_amount)
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let total_staked = pool.total_staked;
            crate::consensus::effective_pow_difficulty(difficulty, miner_stake, total_staked)
        };
        block.effective_difficulty = eff_difficulty;

        // ── Kumulative Difficulty setzen ─────────────────────────────────
        {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let parent_cd = chain.blocks.last()
                .map(|b| b.cumulative_difficulty)
                .unwrap_or(0);
            block.cumulative_difficulty = parent_cd
                + crate::blockchain::block_work_effective(eff_difficulty, difficulty);
        }

        // Template-ID: Hash aus Block-Index + Timestamp + prev_hash
        let template_id = {
            use sha2::{Sha256, Digest};
            let mut h = Sha256::new();
            h.update(block.index.to_le_bytes());
            h.update(block.timestamp.to_le_bytes());
            h.update(block.previous_hash.as_bytes());
            hex::encode(h.finalize())[..16].to_string()
        };

        let template = MiningTemplate {
            block_index: block.index,
            previous_hash: block.previous_hash.clone(),
            difficulty,
            effective_difficulty: eff_difficulty,
            timestamp: block.timestamp,
            validator_pubkey: validator_wallet.clone(),
            block_hash_pre_pow: block.hash.clone(),
            tx_count: block.transactions.len(),
            reward: reward_amount.to_string(),
            template_id: template_id.clone(),
        };

        println!(
            "[mining] 📋 Template #{} erstellt: Block #{}, {} TXs, d={}/{}, Reward: {} STONE",
            &template_id[..8], block.index, block.transactions.len(),
            eff_difficulty, difficulty, reward_amount,
        );

        // Template + Block speichern
        {
            let mut tmpl = self.current_mining_template.write().unwrap_or_else(|e| e.into_inner());
            *tmpl = Some((template.clone(), block));
        }

        Ok(template)
    }

    /// Nimmt eine PoW-Lösung eines externen Miners entgegen und committed den Block.
    ///
    /// 1. Prüft ob das Template noch aktuell ist
    /// 2. Verifiziert den Argon2id-PoW
    /// 3. Setzt PoW-Felder im Block
    /// 4. Committed den Block + Broadcast
    pub fn submit_mining_solution(
        &self,
        submission: &MiningSubmission,
    ) -> Result<Block, String> {
        // Template laden und prüfen
        let (template, mut block) = {
            let tmpl = self.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
            match tmpl.as_ref() {
                Some((t, b)) => {
                    if t.template_id != submission.template_id {
                        return Err("Template-ID stimmt nicht überein (veraltet?)".into());
                    }
                    (t.clone(), b.clone())
                }
                None => return Err("Kein aktives Mining-Template vorhanden".into()),
            }
        };

        // Chain-Konsistenz: Ist der Block noch der nächste?
        {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let expected = chain.blocks.len() as u64;
            if block.index != expected {
                // Template ist veraltet (zwischenzeitlich neuer Block empfangen)
                // TXs zurück in Mempool
                self.restore_block_txs(&block);
                // Template invalidieren
                *self.current_mining_template.write().unwrap_or_else(|e| e.into_inner()) = None;
                return Err(format!(
                    "Block #{} veraltet (Chain ist bei #{})", block.index, expected
                ));
            }
        }

        // PoW verifizieren (gegen effective_difficulty = Stake-reduziertes Target)
        let verify_difficulty = if template.effective_difficulty > 0 {
            template.effective_difficulty
        } else {
            template.difficulty
        };
        if verify_difficulty > 0 {
            let valid = crate::consensus::verify_argon2_pow(
                &block.previous_hash,
                block.index,
                &template.validator_pubkey,
                submission.nonce,
                &submission.pow_hash,
                verify_difficulty,
            );
            if !valid {
                return Err("Ungültiger Argon2id-PoW (Hash oder Difficulty falsch)".into());
            }
        }

        // PoW-Felder setzen
        block.pow_nonce = submission.nonce;
        block.pow_hash = submission.pow_hash.clone();
        block.pow_difficulty = template.difficulty;
        block.effective_difficulty = template.effective_difficulty;

        // Hash + Signaturen neu berechnen (PoW-Felder fließen in Block-Hash ein)
        block.hash = crate::blockchain::calculate_hash(&block);
        block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
        let signing_key = load_or_create_validator_key();
        block.validator_signature = sign_block(&signing_key, &block.hash);

        // Template invalidieren (wurde gelöst)
        *self.current_mining_template.write().unwrap_or_else(|e| e.into_inner()) = None;

        // Block committen
        self.commit_mining_block(block.clone())?;

        println!(
            "[mining] ✅ Externer PoW akzeptiert: Block #{}, nonce={}, d={}/{}",
            block.index, submission.nonce, template.effective_difficulty, template.difficulty,
        );

        Ok(block)
    }

    /// Stellt TXs eines gescheiterten Blocks zurück in den Mempool.
    fn restore_block_txs(&self, block: &Block) {
        for tx in &block.transactions {
            // System-TXs nicht zurücklegen (Reward, Memorial) — aber Faucet-Mints schon!
            if tx.tx_type == TxType::Reward
                || tx.tx_type == crate::token::transaction::TxType::Memorial
            {
                continue;
            }
            // Mint-TXs nur zurücklegen wenn sie vom Faucet kommen (system:faucet)
            if tx.tx_type == TxType::Mint && tx.from != "system:faucet" {
                continue;
            }
            let _ = self.mempool.add_tx(tx.clone(), None);
        }
        for batch in &block.chat_batches {
            self.message_pool.unbatch(&batch.merkle_root);
        }
    }

    // ─── Mining-Wallet Persistierung ───────────────────────────────────────

    fn mining_config_path() -> String {
        let dir = std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string());
        format!("{dir}/mining_config.json")
    }

    pub(crate) fn load_mining_wallet() -> Option<String> {
        let path = Self::mining_config_path();
        let data = std::fs::read_to_string(&path).ok()?;
        let config: serde_json::Value = serde_json::from_str(&data).ok()?;
        config.get("mining_wallet")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    pub fn save_mining_wallet(wallet: &Option<String>) {
        let path = Self::mining_config_path();
        let config = serde_json::json!({
            "mining_wallet": wallet.as_deref().unwrap_or(""),
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        if let Ok(json) = serde_json::to_string_pretty(&config) {
            if let Err(e) = std::fs::write(&path, json) {
                eprintln!("[mining] ⚠ Konnte mining_config.json nicht speichern: {e}");
            }
        }
    }

    /// Gibt die aktive Reward-Wallet zurück: mining_wallet falls gesetzt, sonst validator_wallet.
    pub fn effective_reward_wallet(&self) -> String {
        let mw = self.mining_wallet.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref wallet) = *mw {
            wallet.clone()
        } else {
            let signing_key = load_or_create_validator_key();
            local_validator_pubkey_hex(&signing_key)
        }
    }

    /// Erstellt einen neuen Mining-Block **ohne** ihn zu committen.
    ///
    /// Der Block ist vollständig (Hash, Validator-Signatur) und kann
    /// an Peers zur Abstimmung gesendet werden.
    /// Erst `commit_mining_block()` wendet ihn auf Chain, Ledger und StakingPool an.
    ///
    /// `auto_mode = true` aktiviert das Auto-Block-Reward-Schema (40/20/40
    /// Onboarding/Bug-Bounty/Mining-Pool) anstelle der einzelnen Validator-
    /// Belohnung.
    pub fn prepare_mining_block(&self, auto_mode: bool) -> Result<Block, String> {
        // ── Validator-Schlüssel laden (Wallet = Ed25519 Public Key Hex) ───
        let signing_key = load_or_create_validator_key();
        let validator_wallet = local_validator_pubkey_hex(&signing_key);

        // ── Reward-Wallet bestimmen: gebundene Mining-Wallet oder Validator-Wallet
        let reward_wallet = {
            let mw = self.mining_wallet.read().unwrap_or_else(|e| e.into_inner());
            mw.clone().unwrap_or_else(|| validator_wallet.clone())
        };

        // ── PoA-Check: Round-Robin Validator-Rotation + Lite-PoW Fallback ──
        // Lock-Ordnung: chain zuerst (Daten cachen) → drop → dann validator_set
        let (chain_next_index, _chain_prev_hash) = {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let idx = chain.blocks.len() as u64;
            let hash = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            (idx, hash)
        };
        // Phase 1: Round-Robin — Jeder aktive Validator kommt der Reihe nach dran.
        // Phase 2: Lite-PoW Fallback — wenn der Primäre ausfällt, darf jeder
        //          aktive Validator mit einem gelösten PoW-Puzzle einspringen.
        // Lock-Sicherheit: std::sync::RwLock ist NICHT reentrant und die Lock-
        // Ordnung ist chain → validator_set. Daher BEIDES vor dem vs-Guard
        // berechnen: build_selection_context() liest selbst validator_set
        // (sonst rekursiver Read-Deadlock), last_block_age braucht chain.lock()
        // (sonst chain↔validator_set in falscher Reihenfolge).
        let (stakes, jailed, wallet_map) = self.build_selection_context();
        let last_block_age = {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.blocks.last()
                .map(|b| (Utc::now().timestamp() - b.timestamp) as u64)
                .unwrap_or(u64::MAX)
        };
        let mut is_pow_fallback = false;
        let validators_present;
        {
            let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
            validators_present = !vs.validators.is_empty();
            if validators_present {
                if !vs.is_active_validator(&self.node_id) {
                    return Err("Mining: Node ist kein aktiver Validator".into());
                }

                // Mindest-Validator-Anzahl prüfen
                let active = vs.active_count();
                if active < 2 {
                    // Einzelner Validator: Round-Robin/PoA deaktiviert, direkt minen
                    println!(
                        "[mining] ⚠️ Nur {} aktiver Validator — PoA-Rotation deaktiviert",
                        active
                    );
                } else {
                    if active < 3 {
                        println!(
                            "[mining] ⚠️ Nur {} aktive Validatoren — BFT-Sicherheit eingeschränkt (min. 3 empfohlen)",
                            active
                        );
                    }

                // Beide Algorithmen prüfen: gewichtete Auswahl (= Peer-Validierung)
                // UND Round-Robin (= lokale Rotation). Primary wenn einer zutrifft.
                let is_weighted_turn = vs.is_selected_validator_weighted(
                    &self.node_id, &_chain_prev_hash, chain_next_index,
                    &stakes, &jailed, &wallet_map,
                );
                let is_rr_turn = vs.is_round_robin_turn(&self.node_id, chain_next_index, &jailed);
                let is_primary = is_weighted_turn || is_rr_turn;

                if !is_primary {
                    // Nicht unser Slot. Prüfe ob der primäre Validator seinen Slot
                    // verpasst hat (last_block_age oben vor dem vs-Guard berechnet,
                    // um chain.lock() unter gehaltenem validator_set zu vermeiden).
                    // Fallback erst nach 2× MINING_INTERVAL (gibt dem Primären genug Zeit)
                    let fallback_threshold = MINING_INTERVAL_SECS * 2;
                    if last_block_age < fallback_threshold {
                        let selected = vs.select_validator_round_robin(chain_next_index, &jailed)
                            .map(|v| v.node_id.clone())
                            .unwrap_or_else(|| "?".into());
                        return Err(format!(
                            "Mining: Node '{}' nicht ausgewählt für Block #{chain_next_index} (→ '{selected}')",
                            self.node_id
                        ));
                    }

                    // Primärer Validator hat seinen Slot verpasst → Lite-PoW Fallback
                    println!(
                        "[mining] ⚡ Round-Robin Fallback für Block #{}: Primärer Validator hat {}s nicht produziert – löse Lite-PoW",
                        chain_next_index, last_block_age
                    );
                    is_pow_fallback = true;
                }
                } // end active >= 2
            }
        }

        // ── Single-Miner-Gate für die Bootstrap-Phase (kein Validator-Set) ──
        // Ohne registriertes Validator-Set gibt es keine Leader-Rotation – sonst
        // würde JEDE Node mit Auto-Mining denselben Block #N bauen → Forks. Daher:
        // im Auto-Modus ohne Validator-Set mint nur die DESIGNIERTE Node
        // (STONE_AUTO_MINER=1). Solo-Betrieb (keine verbundenen Peers) mint immer,
        // damit Single-Node-Dev weiterhin funktioniert. Sobald ein echtes
        // Validator-Set registriert ist, greift wieder die PoA-Rotation oben.
        if auto_mode && !validators_present {
            let designated = std::env::var("STONE_AUTO_MINER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !designated {
                let connected_peers = self.peers.read()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter(|p| p.status == super::PeerStatus::Healthy)
                    .count();
                if connected_peers > 0 {
                    return Err(format!(
                        "auto-mine übersprungen: nicht designierter Miner (STONE_AUTO_MINER) \
                         ohne Validator-Set bei {connected_peers} Peer(s) — verhindert Parallel-Mining/Forks"
                    ));
                }
            }
        }

        // ── Block-Reward berechnen ────────────────────────────────────────
        let (reward_amount, next_index) = {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let next_idx = chain.blocks.len() as u64;
            let ledger = self.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            let pool_balance = ledger.balance("pool:mining_rewards");
            (Self::calculate_block_reward(next_idx, pool_balance), next_idx)
        };

        // ── Mempool-TXs + Reward-TX sammeln ──────────────────────────────
        let mut pending_txs = self.mempool.drain_all_for_block();
        let user_tx_count = pending_txs.len(); // vor reward

        // Log ChatMessage TXs für Debugging
        let chat_tx_count = pending_txs.iter()
            .filter(|tx| tx.tx_type == TxType::ChatMessage)
            .count();
        if chat_tx_count > 0 {
            println!(
                "[mining] 💬 {} ChatMessage TX(s) werden in Block #{} aufgenommen",
                chat_tx_count, next_index
            );
        }

        // Reward-TX hinzufügen (falls Reward > 0)
        let has_user_txs = !pending_txs.is_empty();
        if reward_amount > Decimal::ZERO {
            if auto_mode {
                // Auto-Block: Reward auf Netzwerk-Pools splitten
                // 40% Onboarding + 20% Bug-Bounty werden transferiert,
                // 40% bleiben in pool:mining_rewards (gar nicht erst entnommen).
                let split_txs = Self::create_auto_block_split_rewards(reward_amount, next_index);
                if !split_txs.is_empty() {
                    println!(
                        "[auto-mining] 💰 Reward {} STONE → split: 40% Onboarding, 20% Bug-Bounty, 40% Mining-Pool (verbleibt)",
                        reward_amount
                    );
                }
                pending_txs.extend(split_txs);
            } else {
                let reward_tx = Self::create_reward_tx(&reward_wallet, reward_amount, next_index);
                pending_txs.push(reward_tx);
            }
        }

        // ── Pre-Block-Validierung: Ungültige TXs herausfiltern ──────────
        let pending_txs = {
            let ledger = self.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            let valid = ledger.filter_valid_txs(&pending_txs);

            // Abgelehnte User-TXs mit zukünftiger Nonce zurück in den Mempool legen
            let valid_ids: std::collections::HashSet<&str> =
                valid.iter().map(|tx| tx.tx_id.as_str()).collect();
            let mut requeued = 0usize;
            let mut discarded = 0usize;
            for tx in &pending_txs {
                if valid_ids.contains(tx.tx_id.as_str()) {
                    continue;
                }
                if matches!(tx.tx_type, TxType::Reward | TxType::Mint | TxType::Memorial) {
                    continue;
                }
                // Bereits verarbeitete TXs (Duplikate) endgültig verwerfen
                if ledger.is_processed_tx(&tx.tx_id) {
                    discarded += 1;
                    self.mempool.mark_known(&tx.tx_id);
                    continue;
                }
                let expected_nonce = ledger.nonce(&tx.from);
                if tx.nonce >= expected_nonce {
                    if self.mempool.requeue_tx(tx.clone()) {
                        requeued += 1;
                    } else {
                        discarded += 1;
                        println!(
                            "[mining] 🗑️  TX {} endgültig verworfen: Requeue-Limit erreicht (Nonce {} erwartet {})",
                            &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce,
                        );
                    }
                } else {
                    discarded += 1;
                    // Endgültig ungültige TX als "known" markieren damit
                    // Mempool-Sync sie nicht erneut vom Peer holt.
                    self.mempool.mark_known(&tx.tx_id);
                    println!(
                        "[mining] 🗑️  TX {} verworfen: Nonce {} < erwartet {} ({:?})",
                        &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce, tx.tx_type,
                    );
                }
            }
            if requeued > 0 || discarded > 0 {
                println!(
                    "[mining] 📊 Block-Filter: {} User-TXs gedrained, {} valid, {} requeued, {} verworfen",
                    user_tx_count, valid.len().saturating_sub(1), requeued, discarded,
                );
            }

            valid
        };

        // Blöcke werden IMMER erzeugt — auch ohne User-TXs.
        // Der Block-Reward, Network-Challenges und Shard-Repair-Rewards
        // sind allein schon Grund genug einen Block zu minen.
        // Leere Blöcke treiben die Chain voran und ermöglichen:
        //  - Regelmäßige Storage-Challenges
        //  - Repair-Reward-Auszahlung
        //  - Konsistente Block-Time für das Netzwerk
        if !has_user_txs {
            println!(
                "[mining] Block #{next_index}: keine User-TXs → Reward-only Block"
            );
        }

        // ── Chat-Nachrichten aus dem MessagePool batchen ──────────────────
        let chat_batches = if self.message_pool.batch_ready() {
            let drained = self.message_pool.drain_for_batch();
            if !drained.is_empty() {
                let msg_ids: Vec<String> = drained.iter().map(|m| m.msg_id.clone()).collect();
                match crate::merkle_batch::build_batch(&drained) {
                    Some((anchor, _tree)) => {
                        println!(
                            "[mining] 📦 Chat-Batch: {} Nachrichten, seq {}-{}, root: {}…",
                            anchor.batch_size,
                            anchor.seq_start,
                            anchor.seq_end,
                            &anchor.merkle_root[..12],
                        );
                        // Nachrichten als "batched" markieren
                        self.message_pool.mark_batched(&msg_ids, &anchor.merkle_root);
                        vec![anchor]
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ── Block vorbereiten (ohne Commit in die Chain) ──────────────────
        let signer = self.node_id.clone();
        let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut block = chain.prepare_block(
            Vec::new(),
            Vec::new(),
            pending_txs,
            "system".to_string(),
            signer,
            &self.cluster_key,
            self.role.clone(),
            chat_batches,
        );

        // ── PoA: Block-Signierung ────────────────────────────────────────
        let sig = sign_block(&signing_key, &block.hash);
        block.validator_pub_key = validator_wallet.clone();
        block.validator_signature = sig;

        // ── Network Storage Challenges: Challenge andere Nodes ───────────
        {
            let chunk_refs = crate::storage_proof::collect_chunk_refs(&chain);
            if !chunk_refs.is_empty() {
                // Bekannte Validator-Wallets sammeln
                let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
                let mut known_wallets: Vec<String> = vs.validators.iter()
                    .filter(|v| v.active)
                    .filter_map(|v| if v.public_key_hex.is_empty() { None } else { Some(v.public_key_hex.clone()) })
                    .collect();
                // Auch Peers' Wallets aus Trust-Registry einbeziehen
                {
                    let trust = self.trust_registry.read().unwrap_or_else(|e| e.into_inner());
                    for entry in trust.iter() {
                        if !entry.public_key_hex.is_empty() && !known_wallets.contains(&entry.public_key_hex) {
                            known_wallets.push(entry.public_key_hex.clone());
                        }
                    }
                }

                let challenges = crate::storage_proof::generate_network_challenges(
                    &block.previous_hash,
                    block.index,
                    &chunk_refs,
                    &known_wallets,
                    &validator_wallet,
                );

                if !challenges.is_empty() {
                    println!(
                        "[storage-challenge] 📋 Block #{}: {} Network-Challenges erstellt",
                        block.index, challenges.len()
                    );
                    for c in &challenges {
                        println!(
                            "[storage-challenge]   → Node {}… Chunk {}… Offset {} (Deadline: #{})",
                            &c.target_wallet[..12.min(c.target_wallet.len())],
                            &c.chunk_hash[..12.min(c.chunk_hash.len())],
                            c.offset,
                            c.deadline_block
                        );
                    }
                }

                // Challenges hinzufügen und Block-Hash neu berechnen
                block.storage_challenges = challenges;

                // Pending ChallengeResponses aufnehmen (keine Rewards mehr, nur Tracking)
                let responses = self.collect_pending_challenge_responses(&chain);
                if !responses.is_empty() {
                    println!(
                        "[storage-challenge] ✅ {} Challenge-Responses in Block #{} aufgenommen",
                        responses.len(), block.index
                    );
                }
                block.challenge_responses = responses;

                // Pending Shard-Repairs aufnehmen (keine Rewards mehr, nur Tracking)
                {
                    let mut repairs = self.pending_repair_rewards.lock().unwrap_or_else(|e| e.into_inner());
                    if !repairs.is_empty() {
                        println!(
                            "[shard-repair] 🔧 {} Shard-Repairs in Block #{} aufgenommen",
                            repairs.len(), block.index
                        );
                        repairs.clear();
                    }
                }

                // Block-Hash neu berechnen (weil storage_challenges den Hash beeinflusst)
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                let new_sig = sign_block(&signing_key, &block.hash);
                block.validator_signature = new_sig;
            }
        }

        // Outer chain-Lock hier explizit freigeben, sonst Deadlock im
        // PoW-Block weiter unten (std::sync::Mutex ist nicht reentrant).
        drop(chain);

        // ── Lite-PoW lösen (nur bei Fallback-Mining) ─────────────────────
        // ── PoW lösen: Argon2id hat Vorrang, Lite-PoW nur als Fallback ──
        {
            use crate::consensus::{
                get_current_pow_difficulty, solve_argon2_pow,
                ARGON2_POW_ACTIVATION_BLOCK,
            };
            let chain_ref = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let difficulty = get_current_pow_difficulty(&chain_ref.blocks, block.index);
            drop(chain_ref);

            if block.index >= ARGON2_POW_ACTIVATION_BLOCK && difficulty > 0 {
                // Argon2id PoW (primär)
                println!(
                    "[mining] ⛏️  Starte Argon2id-PoW für Block #{} (Difficulty: {} Bits, Memory: 64 MiB)…",
                    block.index, difficulty,
                );
                let (nonce, pow_hash) = solve_argon2_pow(
                    &block.previous_hash,
                    block.index,
                    &validator_wallet,
                    difficulty,
                );
                block.pow_nonce = nonce;
                block.pow_hash = pow_hash;
                block.pow_difficulty = difficulty;

                // Hash + Signaturen neu berechnen (pow_hash + pow_difficulty fließen in Block-Hash ein)
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                block.validator_signature = sign_block(&signing_key, &block.hash);
            } else if is_pow_fallback && crate::consensus::BLOCK_POW_ENABLED {
                // Lite-PoW nur wenn Argon2id nicht aktiv ist
                use crate::consensus::{solve_lite_pow, BLOCK_POW_DIFFICULTY};
                let pow_nonce = solve_lite_pow(
                    &block.previous_hash,
                    block.index,
                    &self.node_id,
                    BLOCK_POW_DIFFICULTY,
                );
                block.pow_nonce = pow_nonce;
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                block.validator_signature = sign_block(&signing_key, &block.hash);
                println!(
                    "[mining] 🔨 Lite-PoW gelöst für Block #{}: nonce={pow_nonce} (difficulty={})",
                    block.index, BLOCK_POW_DIFFICULTY
                );
            } else if is_pow_fallback {
                // PoA-Fallback ohne PoW: Round-Robin-Übernahme nach Timeout, kein Puzzle.
                println!(
                    "[mining] ⚡ PoA-Fallback Block #{}: primärer Validator hat Slot verpasst – Übernahme ohne PoW",
                    block.index
                );
            }
        }

        println!(
            "[mining] ⛏️  Block #{} vorbereitet – {} TXs, Reward: {} STONE → {}{}{}",
            block.index,
            block.transactions.len(),
            reward_amount,
            &reward_wallet[..16.min(reward_wallet.len())],
            if is_pow_fallback { " [PoW-Fallback]" } else { "" },
            if !block.pow_hash.is_empty() { format!(" [Argon2id: d={}]", block.pow_difficulty) } else { String::new() },
        );

        Ok(block)
    }

    /// Committed einen vorbereiteten Block: Chain, Ledger, StakingPool, Metriken, Events.
    ///
    /// Wird nach erfolgreicher Voting-Phase (Multi-Node) oder direkt (Single-Node) aufgerufen.
    pub fn commit_mining_block(&self, block: Block) -> Result<(), String> {
        let signing_key = load_or_create_validator_key();
        let validator_wallet = local_validator_pubkey_hex(&signing_key);

        // ── Block in die Chain einfügen ───────────────────────────────────
        {
            let mut chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            // Prüfe dass Block zum nächsten Index passt
            let expected_idx = chain.blocks.len() as u64;
            if block.index != expected_idx {
                return Err(format!(
                    "Block-Index {} passt nicht (erwartet: {})", block.index, expected_idx
                ));
            }
            chain.commit_block(block.clone());
        }

        // ── Token-TXs im Ledger verarbeiten ──────────────────────────────
        if !block.transactions.is_empty() {
            let receipts;
            {
                let mut ledger = self.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                // Fee-Split: Validator-Wallet setzen BEVOR TXs verarbeitet werden
                ledger.set_current_validator(Some(validator_wallet.clone()));
                // TXs wurden bereits durch filter_valid_txs() validiert →
                // Trotzdem Balance/Nonce prüfen (kein replay_mode), damit
                // auch per Gossip empfangene Blöcke korrekt geprüft werden.
                receipts = ledger.apply_block_txs(&block.transactions, block.index);
                ledger.set_current_validator(None);

                // ── Staking-TXs im StakingPool verarbeiten ────────────────────
                self.apply_staking_from_txs(&block.transactions, &receipts);

                // Sync-Marker aktualisieren (wichtig für Replay-Schutz)
                ledger.set_last_synced_block(block.index);
            }
            // ── Persist außerhalb des Write-Locks ────────────────────────
            // Der Write-Lock (token_ledger.write()) wird VOR persist() freigegeben,
            // damit HTTP-Requests (die token_ledger.read() brauchen) nicht blockieren.
            // persist() liest nur die In-Memory-Daten (die nach dem Lock-Drop
            // unverändert bleiben, da das Mining single-threaded ist).
            // RocksDB-I/O kann Hunderte von ms dauern — ohne Lock-Freigabe
            // erscheint die Node währenddessen als "tot" (keine API-Antworten).
            if !receipts.is_empty() {
                if let Err(e) = self.token_ledger.read().unwrap_or_else(|e| e.into_inner()).persist() {
                    eprintln!("[mining] Ledger-Persistierung nach Block #{} fehlgeschlagen: {e}", block.index);
                }
            }
        }

        // Block wurde bereits durch commit_block() → persist_last_block() persistiert.

        // ── Chat-Batch-Messages als confirmed markieren ───────────────────
        for batch in &block.chat_batches {
            let msg_ids = self.message_pool.msg_ids_for_batch(&batch.merkle_root);
            if !msg_ids.is_empty() {
                // Batch-Record für Proof-Generierung speichern
                let msgs = self.message_pool.messages_in_seq_range(batch.seq_start, batch.seq_end);
                self.message_pool.store_batch_record(&batch.merkle_root, &msgs, block.index);

                self.message_pool.mark_confirmed(&msg_ids, block.index);
                println!(
                    "[mining] ✅ Chat-Batch bestätigt: {} Nachrichten in Block #{}",
                    msg_ids.len(), block.index,
                );
            }
        }

        // ── Validator-Statistik aktualisieren ─────────────────────────────
        {
            let mut vs_w = self.validator_set.write().unwrap_or_else(|e| e.into_inner());
            if let Some(v) = vs_w.get_mut(&self.node_id) {
                v.blocks_signed += 1;
                vs_w.save();
            }
        }

        // ── Events ───────────────────────────────────────────────────────
        self.events.publish(NodeEvent::BlockAdded {
            index: block.index,
            hash: block.hash.clone(),
            docs: 0,
            owner: "system".into(),
            timestamp: block.timestamp,
        });

        for tx in &block.transactions {
            self.events.publish(NodeEvent::TokenTransfer {
                tx_id: tx.tx_id.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount.to_string(),
                tx_type: tx.tx_type.to_string(),
                block_index: block.index,
            });
        }

        // ── Mining-Metriken aktualisieren ─────────────────────────────────
        self.metrics.blocks_mined.fetch_add(1, Ordering::Relaxed);
        self.metrics.last_block_timestamp.store(block.timestamp as u64, Ordering::Relaxed);

        use rust_decimal::prelude::ToPrimitive;
        // Reward aus der Reward-TX extrahieren
        let reward_amount = block.transactions.iter()
            .find(|tx| tx.tx_type == TxType::Reward)
            .map(|tx| tx.amount)
            .unwrap_or(Decimal::ZERO);
        let reward_milli = (reward_amount * Decimal::new(1000, 0))
            .to_u64()
            .unwrap_or(0);
        self.metrics.total_rewards_milli.fetch_add(reward_milli, Ordering::Relaxed);

        let chat_count = block.transactions.iter()
            .filter(|tx| tx.tx_type == TxType::ChatMessage)
            .count() as u64;
        if chat_count > 0 {
            self.metrics.chat_messages_mined.fetch_add(chat_count, Ordering::Relaxed);
        }

        println!(
            "[mining] ✅ Block #{} committed – {} TXs, Validator: {}",
            block.index,
            block.transactions.len(),
            &validator_wallet[..16.min(validator_wallet.len())],
        );

        // ── Block-Timer zurücksetzen & Miner-Stat erhöhen ─────────────────
        {
            if let Ok(mut t) = self.block_timer.lock() {
                t.reset();
            }
            // Wenn der Block-Signer (validator_pub_key) zu einem registrierten
            // Miner gehört, dessen blocks_found Zähler inkrementieren.
            if let Ok(mut reg) = self.miner_registry.write() {
                reg.record_block_found(&block.validator_pub_key);
            }
        }

        // ── Auto-Snapshot (alle SNAPSHOT_INTERVAL Blöcke, NUR Bootstrap-Nodes) ──
        if crate::snapshot::should_create_snapshot(block.index)
            && crate::network::is_bootstrap_node()
        {
            let genesis_hash = {
                let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
                chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default()
            };
            let latest_hash = block.hash.clone();
            let height = block.index;
            std::thread::spawn(move || {
                match crate::snapshot::create_snapshot(height, &genesis_hash, &latest_hash) {
                    Ok((_path, meta)) => {
                        eprintln!(
                            "[snapshot] 📸 Auto-Snapshot bei Block #{}: {:.1} MB",
                            meta.block_height,
                            meta.archive_size as f64 / 1_048_576.0
                        );
                    }
                    Err(e) => eprintln!("[snapshot] ⚠️  Auto-Snapshot fehlgeschlagen: {e}"),
                }
            });
        }

        Ok(())
    }

    /// Hintergrund-Task: Continuous Mining-Loop (Competitive PoW).
    ///
    /// Statt timer-basiertem Intervall-Mining (PoA) wird jetzt:
    /// 1. Kontinuierlich ein Block-Template bereitgehalten
    /// 2. Externe Miner lösen das Argon2id-PoW per API (`/mining/template` + `/mining/submit`)
    /// 3. Gossip-Blöcke von anderen Nodes invalidieren das lokale Template
    /// 4. Template wird alle TEMPLATE_REFRESH_SECS Sekunden aktualisiert
    pub fn start_mining_loop(state: Arc<Self>) {
        println!(
            "[mining] ⛏️  Competitive-PoW Mining-Loop gestartet (Target: {}s, Reward: {} STONE, Halving: alle {} Blöcke)",
            TARGET_BLOCK_TIME_SECS, INITIAL_BLOCK_REWARD, HALVING_INTERVAL
        );

        tokio::spawn(async move {
            // Erste Wartezeit: 15s (P2P-Netzwerk aufbauen lassen)
            tokio::time::sleep(Duration::from_secs(15)).await;

            let template_interval = Duration::from_secs(TEMPLATE_REFRESH_SECS);
            let mut ticker = tokio::time::interval(template_interval);
            let mut last_template_height: u64 = 0;

            loop {
                ticker.tick().await;

                // ── Initial-Sync abwarten ─────────────────────────────────
                if !state.metrics.initial_sync_done.load(Ordering::Relaxed) {
                    let uptime = Utc::now().timestamp() - state.started_at;
                    let sync_timeout = 60_i64; // 60s Sync-Timeout für schnellere Block-Time
                    if uptime < sync_timeout {
                        continue;
                    }
                    println!("[mining] ⏰ Initial-Sync Timeout ({}s) – starte Mining", sync_timeout);
                    state.metrics.initial_sync_done.store(true, Ordering::Relaxed);

                    // Token-Ledger aus synced Chain rebuilden
                    {
                        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                        if chain.blocks.len() > 1 {
                            let rebuilt = crate::token::TokenLedger::rebuild_from_chain(&chain.blocks);
                            let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                            *ledger = rebuilt;
                            println!(
                                "[token] 🔄 Ledger nach Initial-Sync rebuilt: {} Accounts, Supply: {}",
                                ledger.account_count(),
                                ledger.total_supply()
                            );
                        }
                    }
                }

                // Mining-Throttle prüfen
                {
                    let throttle = state.metrics.mining_throttle_pct.load(Ordering::Relaxed);
                    if throttle == 0 {
                        continue; // Mining komplett deaktiviert
                    }
                }

                // Nicht minen wenn Peers weiter sind
                {
                    let our_height = state.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                    let max_peer_height = {
                        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
                        peers.iter()
                            .filter(|p| p.is_healthy())
                            .map(|p| p.block_height)
                            .max()
                            .unwrap_or(0)
                    };
                    if max_peer_height > our_height + 1 {
                        // Template-TXs zurück in Mempool legen bevor invalidiert wird
                        {
                            let tmpl = state.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
                            if let Some((_, ref old_block)) = *tmpl {
                                state.restore_block_txs(old_block);
                            }
                        }
                        *state.current_mining_template.write().unwrap_or_else(|e| e.into_inner()) = None;
                        continue;
                    }
                }

                // Mempool: abgelaufene TXs bereinigen (alle 30s)
                let current_height = state.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                if current_height != last_template_height {
                    let evicted = state.mempool.evict_expired();
                    if evicted > 0 {
                        println!("[mining] 🧹 {} abgelaufene TXs aus Mempool entfernt", evicted);
                    }
                }

                // ── Stall-Warnung ────────────────────────────────────────
                {
                    let pending = state.mempool.pending_count();
                    if pending > 0 {
                        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(last) = chain.blocks.last() {
                            let age = Utc::now().timestamp() - last.timestamp;
                            if age > (TARGET_BLOCK_TIME_SECS as i64 * 5) {
                                println!(
                                    "[mining] ⚠ Stall: {} pending TXs, letzter Block vor {}s (kein Miner aktiv?)",
                                    pending, age,
                                );
                            }
                        }
                    }
                }

                // ── Template aktualisieren ────────────────────────────────
                // Nur neues Template erstellen wenn:
                // 1. Noch kein Template vorhanden, oder
                // 2. Neuer Block seit letztem Template (Height hat sich geändert)
                let needs_new_template = {
                    let tmpl = state.current_mining_template.read().unwrap_or_else(|e| e.into_inner());
                    match tmpl.as_ref() {
                        Some((t, _)) => t.block_index != current_height,
                        None => true,
                    }
                };

                if needs_new_template {
                    match state.prepare_block_template() {
                        Ok(template) => {
                            last_template_height = template.block_index;
                        }
                        Err(e) => {
                            if !e.contains("kein aktiver") {
                                eprintln!("[mining] Template-Fehler: {e}");
                            }
                        }
                    }
                }

                // ── Post-Block-Hooks für Gossip-Blöcke ───────────────────
                // Checkpoint-Prüfung
                if current_height > 0 && current_height % 100 == 0 {
                    let block = {
                        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                        chain.blocks.last().cloned()
                    };
                    if let Some(block) = block {
                        Self::post_block_checkpoint(&state, &block).await;
                    }
                }
            }
        });
    }

    /// Startet den Auto-Block-Timer.
    ///
    /// Produziert alle `auto_timeout_secs` einen Block, wenn:
    /// - Auto-Mining in der Config aktiviert ist,
    /// - der Initial-Sync abgeschlossen ist,
    /// - kein CPU-Miner (mit gültigem Heartbeat) aktiv ist,
    /// - kein Minecraft-Server mit aktiven Spielern verbunden ist (PoP-Mining),
    /// - seit dem letzten Block mehr als `auto_timeout_secs` vergangen sind.
    ///
    /// Hard-Fallback: Selbst bei "aktiven" Minern wird nach
    /// `HARD_FALLBACK_MULT × auto_timeout_secs` ein Block erzeugt.
    pub fn start_block_timer(state: Arc<Self>, pop_mining: crate::pop_mining::PopMiningState) {
        if !state.auto_mining_config.enabled {
            println!("[auto-mining] 🚫 disabled per config – BlockTimer startet nicht");
            return;
        }
        let timeout = state.auto_mining_config.auto_timeout_secs;
        let hb_timeout = state.auto_mining_config.heartbeat_timeout_secs;
        println!(
            "[auto-mining] ⏲️  BlockTimer gestartet: timeout={timeout}s, miner_hb_timeout={hb_timeout}s"
        );

        tokio::spawn(async move {
            // Grace-Period nach Start damit P2P & Sync greifen
            tokio::time::sleep(Duration::from_secs(20)).await;
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut heartbeat_tick: u64 = 0;

            loop {
                ticker.tick().await;
                heartbeat_tick = heartbeat_tick.wrapping_add(1);

                // Warten bis Initial-Sync fertig — wenn nach 60s noch nicht
                // gesetzt, forcieren wir den Start. Auf einer frischen Node
                // (nur Genesis, keine Peers) würde das Flag sonst nie gesetzt.
                if !state.metrics.initial_sync_done.load(Ordering::Relaxed) {
                    let uptime = (chrono::Utc::now().timestamp() - state.started_at).max(0) as u64;
                    if uptime < 60 {
                        continue;
                    }
                    // Prüfe ob die Chain schon >1 Blöcke hat ODER ob wir
                    // allein im Netzwerk sind (keine Peers → keine Sync-Quelle)
                    let chain_ok = {
                        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                        chain.blocks.len() > 1
                    };
                    let has_peers = {
                        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
                        !peers.is_empty()
                    };
                    if !chain_ok && has_peers {
                        continue; // Warte auf Sync von Peers
                    }
                    state.metrics.initial_sync_done.store(true, Ordering::Relaxed);
                    println!(
                        "[auto-mining] ✓ Initial-Sync per Fallback bestätigt \
                         (uptime={uptime}s, chain={} blk, peers={})",
                        if chain_ok { "ok" } else { "genesis-only" },
                        has_peers,
                    );
                }

                // HINWEIS: mining_throttle_pct ist absichtlich KEIN Stop-Kriterium.
                // Throttle steuert nur die Bonus-Mining-Loop in stone-master; der
                // Auto-Block-Timer ist ein Liveness-Mechanismus und muss auch auf
                // Master-Nodes ohne Mining-Loop (throttle=0) Blöcke produzieren.

                // ── CPU-Miner aufräumen ──────────────────────────────────────
                let hb_timeout = state.auto_mining_config.heartbeat_timeout_secs;
                let (cleaned, has_cpu_miners) = {
                    let mut reg = state
                        .miner_registry
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    let n = reg.cleanup_inactive();
                    (n, reg.has_active_miners())
                };
                if cleaned > 0 {
                    println!(
                        "[auto-mining] 🧹 {cleaned} inaktive CPU-Miner entfernt"
                    );
                }

                // ── PoP-Mining: aktive Minecraft-Server prüfen ───────────────
                // Ein Minecraft-Server gilt als aktiv wenn ein Spieler in den
                // letzten heartbeat_timeout_secs einen Block abgebaut hat
                // (Plugin meldet via POST /api/v1/sdk/mining/activity, throttled 1/15s).
                let has_pop_activity = pop_mining.has_recent_activity(hb_timeout);

                // Timer pausiert wenn CPU-Miner ODER aktive PoP-Gameplay-Aktivität
                let has_active = has_cpu_miners || has_pop_activity;

                if !has_active && (cleaned > 0 || has_pop_activity) {
                    println!(
                        "[auto-mining] Timer LÄUFT (cpu_miners={has_cpu_miners}, pop_active={has_pop_activity})"
                    );
                }

                // ── Heartbeat: Logge alle 30s den Timer-Status, damit man
                // in den Logs sehen kann ob der Timer läuft.
                if heartbeat_tick % 30 == 0 {
                    let pending = state.mempool.pending_count();
                    let elapsed = state.block_timer.lock().map(|t| t.elapsed_secs()).unwrap_or(0);
                    let height = state.chain.lock().unwrap_or_else(|e| e.into_inner()).blocks.len() as u64;
                    println!(
                        "[auto-mining] 💓 Heartbeat: Height={height}, PendingTXs={pending}, Elapsed={elapsed}s, \
                         HasMiners={has_active}, AutoTimeout={}s, Threshold={}s",
                        state.auto_mining_config.auto_timeout_secs,
                        if has_active {
                            state.auto_mining_config.auto_timeout_secs.saturating_mul(
                                crate::master::miner_registry::HARD_FALLBACK_MULT
                            )
                        } else {
                            state.auto_mining_config.auto_timeout_secs
                        },
                    );
                }

                // Timer prüfen
                let should_mine = {
                    let t = state.block_timer.lock().unwrap_or_else(|e| e.into_inner());
                    t.should_auto_mine(has_active)
                };
                if !should_mine {
                    continue;
                }

                // ── Round-Robin Pre-Check: Nur der designierte Validator darf den
                // Auto-Block-Timer auslösen. Alle anderen Nodes warten auf den
                // Gossip-Block der ausgewählten Node. Ohne diesen Check versuchen
                // ALLE Nodes gleichzeitig `mint_auto_block()` → Mempool-Drain-Races,
                // unnötige Fehlerlogs und verschwendete CPU-Zyklen.
                // Der volle Check (mit Jailed-Set, Backup-Proposer) erfolgt weiterhin
                // in `prepare_mining_block()` — dieser Pre-Check filtert nur den
                // offensichtlichen Fall "nicht mein Slot" heraus.
                //
                // LOCK-ORDER (wie prepare_mining_block): chain + build_selection_context
                // VOR validator_set lesen, da build_selection_context() selbst
                // validator_set.read() aufruft und std::sync::RwLock NICHT reentrant ist.
                {
                    // Phase 1: chain + selection context (VOR validator_set-Lock)
                    let next_index = {
                        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                        chain.blocks.len() as u64
                    };
                    let (_, jailed, _) = state.build_selection_context();

                    // Phase 2: validator_set lesen + Round-Robin-Check
                    let vs = state.validator_set.read().unwrap_or_else(|e| e.into_inner());
                    if !vs.validators.is_empty() {
                        let is_my_turn = vs.is_round_robin_turn(&state.node_id, next_index, &jailed);
                        if !is_my_turn {
                            let selected = vs.select_validator_round_robin(next_index, &jailed)
                                .map(|v| v.node_id.as_str())
                                .unwrap_or("?");
                            if next_index % 10 == 0 {
                                println!(
                                    "[auto-mining] ⏭️  Block #{}: nicht mein Slot (designiert: '{}', ich: '{}')",
                                    next_index, selected, &state.node_id,
                                );
                            }
                            continue;
                        }
                        println!(
                            "[auto-mining] 🎯 Block #{}: MEIN Round-Robin-Slot – starte Auto-Block",
                            next_index,
                        );
                    }
                }

                // Gate: KEINE leeren Blöcke (Spam-Schutz). Ein Auto-Block entsteht
                // nur wenn echte Nutzlast anliegt:
                //   - mindestens eine TX im Mempool (lokal ODER per Gossip), ODER
                //   - ein Chat-Batch bereit ist, ODER
                //   - aktive PoP-Gameplay-Aktivität läuft.
                // Hinweis: Früher zählten nur LOKALE TXs (Fork-Workaround). Das ist
                // nicht mehr nötig — Parallel-Mining wird jetzt durch das
                // Single-Miner-/Validator-Gate in prepare_mining_block verhindert.
                // Dadurch nimmt der designierte Miner auch gegossipte TXs auf.
                let has_pending_tx = state.mempool.pending_count() > 0;
                let chat_batch_ready = state.message_pool.batch_ready();
                if !has_pending_tx && !chat_batch_ready && !has_pop_activity {
                    continue;
                }

                // Nur dieser Node soll Auto-Block bauen wenn er ausgewählter
                // Validator ist (Round-Robin oder Stake-Weighted). Sonst
                // parallele Auto-Blöcke auf allen Masters → Forks.
                // Die bestehende Template-Prepare-Funktion prüft das bereits.
                // ── Block in spawn_blocking minen ────────────────────────
                // mint_auto_block() enthält Argon2id-PoW (64 MiB, ~Sekunden)
                // und persist_last_block() (RocksDB I/O). Beide würden den
                // Tokio-Runtime-Thread blockieren → P2P-Requests timeout →
                // Sync-Stall-Detector reißt Verbindungen ab.
                let state_clone = state.clone();
                let mine_result = tokio::task::spawn_blocking(move || {
                    state_clone.mint_auto_block()
                }).await;
                match mine_result {
                    Ok(Ok(block)) => {
                        let tx_count = state.mempool.pending_count();
                        println!(
                            "[auto-mining] ⛏️  Auto-Block #{} produziert ({} TXs, tx={}, chat={}, pop_active={}, seit {}s)",
                            block.index,
                            tx_count,
                            has_pending_tx,
                            chat_batch_ready,
                            has_pop_activity,
                            state.block_timer.lock().map(|t| t.elapsed_secs()).unwrap_or(0)
                        );
                        // Broadcast + reset
                        {
                            let tx = state.block_broadcast_tx.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(ref sender) = *tx {
                                let _ = sender.send(block.clone());
                            }
                        }
                        if let Ok(mut t) = state.block_timer.lock() {
                            t.reset();
                        }
                    }
                    Ok(Err(e)) => {
                        // Häufiger Fall: "kein aktiver Validator" auf dieser Node → still ignorieren
                        if !e.contains("kein aktiver") && !e.contains("nicht der aktuelle") && !e.contains("auto-mine übersprungen") {
                            eprintln!("[auto-mining] ⚠ Auto-Block fehlgeschlagen: {e}");
                        }
                        if let Ok(mut t) = state.block_timer.lock() {
                            t.reset();
                        }
                    }
                    Err(join_err) => {
                        eprintln!("[auto-mining] ⚠ spawn_blocking fehlgeschlagen: {join_err}");
                    }
                }
            }
        });
    }
}
