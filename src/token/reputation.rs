//! Node-Operator Reputation & Fee-Share System
//!
//! Tracks node reputation based on:
//! - **Uptime**: How long the node has been continuously reachable
//! - **Blocks Signed**: How many blocks this node has produced/validated
//! - **Correct Behavior**: No slashing events, no jailing history
//!
//! ## Fee-Split Model
//!
//! Every TX fee is split:
//! | Destination           | Share | Purpose                    |
//! |-----------------------|-------|----------------------------|
//! | Burn (deflation)      | 50%   | Reduces total supply       |
//! | Block Validator       | 30%   | Immediate mining incentive |
//! | `pool:node_operators` | 20%   | Distributed by reputation  |
//!
//! ## Distribution
//!
//! Every `DISTRIBUTION_INTERVAL` blocks, `pool:node_operators` is distributed
//! proportionally to all active nodes based on their reputation score (0-100).

use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Pool-Adresse für Node-Operator-Rewards (Fee-Share)
pub const NODE_OPERATOR_POOL: &str = "pool:node_operators";

/// Pool-Adresse für Staker-Fee-Rewards (proportional nach Stake verteilt)
pub const STAKER_FEE_POOL: &str = "pool:staker_fees";

/// Verteilungsintervall in Blöcken (alle ~6 Stunden bei 30s Blocks)
pub const DISTRIBUTION_INTERVAL: u64 = 720;

/// Fee-Split Anteile (Summe = 100)
/// 20% burn, 37% miner, 28% staker-pool, 10% node-operator-pool, 5% governance
pub const FEE_BURN_PCT: u64 = 20;
pub const FEE_VALIDATOR_PCT: u64 = 37;
pub const FEE_STAKER_PCT: u64 = 28;
pub const FEE_NODE_POOL_PCT: u64 = 10;
pub const FEE_GOVERNANCE_PCT: u64 = 5;

/// Maximaler Reputation-Score
pub const MAX_REPUTATION_SCORE: u64 = 100;

/// Uptime-Gewichtung (40% des Scores)
const UPTIME_WEIGHT: f64 = 0.40;
/// Blocks-Signed-Gewichtung (35% des Scores)
const BLOCKS_WEIGHT: f64 = 0.35;
/// Good-Behavior-Gewichtung (25% des Scores — Abzüge bei Slashing/Jailing)
const BEHAVIOR_WEIGHT: f64 = 0.25;

/// Mindest-Uptime in Sekunden um Score > 0 zu bekommen (1 Stunde)
const MIN_UPTIME_SECS: i64 = 3600;

// ─── Node-Reputation ─────────────────────────────────────────────────────────

/// Reputation-Eintrag für einen einzelnen Node-Betreiber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReputation {
    /// Node-ID (identisch mit ValidatorInfo.node_id)
    pub node_id: String,
    /// Wallet-Adresse des Validators (für Auszahlung)
    pub wallet_address: String,
    /// Letzter bekannter Uptime-Ping (Unix-Timestamp)
    pub last_seen: i64,
    /// Zähler: korrekt signierte Blöcke
    pub blocks_signed: u64,
    /// Zähler: Anzahl erhaltener Slashings
    pub slash_count: u32,
    /// Zähler: Gesamte Jail-Tage
    pub total_jail_days: u32,
    /// Letzte Score-Berechnung
    pub computed_score: u64,
    /// Zeitpunkt der letzten Aktualisierung
    pub updated_at: i64,
    /// Zeitpunkt der ersten Registrierung
    pub registered_at: i64,
    /// Gesamte bisher erhaltene Operator-Rewards
    pub total_rewards_received: Decimal,
}

impl NodeReputation {
    pub fn new(node_id: String, wallet_address: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            node_id,
            wallet_address,
            last_seen: now,
            blocks_signed: 0,
            slash_count: 0,
            total_jail_days: 0,
            computed_score: 0,
            updated_at: now,
            registered_at: now,
            total_rewards_received: Decimal::ZERO,
        }
    }

    /// Berechnet den aktuellen Reputation-Score (0-100).
    pub fn compute_score(&mut self, avg_blocks_in_network: u64) -> u64 {
        let now = Utc::now().timestamp();

        // ── 1. Uptime-Score (0-100) ──────────────────────────────────────
        let uptime_secs = now - self.registered_at;
        let time_since_seen = now - self.last_seen;
        let uptime_score = if uptime_secs < MIN_UPTIME_SECS {
            0.0 // Zu neu
        } else if time_since_seen > 300 {
            // Nicht kürzlich gesehen — Score sinkt exponentiell
            let hours_offline = time_since_seen as f64 / 3600.0;
            (100.0 * (-hours_offline / 24.0_f64).exp()).max(0.0) // t½ ≈ 24h
        } else {
            100.0 // Online und gesund
        };

        // ── 2. Block-Produktion-Score (0-100) ────────────────────────────
        let blocks_score = if avg_blocks_in_network == 0 {
            if self.blocks_signed > 0 { 100.0 } else { 0.0 }
        } else {
            let ratio = self.blocks_signed as f64 / avg_blocks_in_network as f64;
            (ratio * 100.0).min(100.0)
        };

        // ── 3. Behavior-Score (100 - Abzüge) ────────────────────────────
        let slash_penalty = self.slash_count as f64 * 20.0; // -20 pro Slash
        let jail_penalty = self.total_jail_days as f64 * 5.0; // -5 pro Jail-Tag
        let behavior_score = (100.0 - slash_penalty - jail_penalty).max(0.0);

        // ── Gewichteter Gesamtscore ──────────────────────────────────────
        let total = uptime_score * UPTIME_WEIGHT
            + blocks_score * BLOCKS_WEIGHT
            + behavior_score * BEHAVIOR_WEIGHT;

        self.computed_score = (total.round() as u64).min(MAX_REPUTATION_SCORE);
        self.updated_at = now;
        self.computed_score
    }
}

// ─── Reputation-Registry ─────────────────────────────────────────────────────

/// Verwaltet die Reputation aller bekannten Node-Betreiber.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationRegistry {
    /// Node-ID → Reputation
    pub nodes: HashMap<String, NodeReputation>,
    /// Letzter Block in dem eine Distribution stattfand
    pub last_distribution_block: u64,
    /// Gesamte bisher verteilte Operator-Rewards
    pub total_distributed: Decimal,
}

impl ReputationRegistry {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            last_distribution_block: 0,
            total_distributed: Decimal::ZERO,
        }
    }

    /// Registriert oder aktualisiert einen Node.
    pub fn register_node(&mut self, node_id: &str, wallet_address: &str) {
        let entry = self.nodes.entry(node_id.to_string()).or_insert_with(|| {
            println!(
                "[reputation] 📋 Neuer Node registriert: {} (Wallet: {}…)",
                node_id,
                &wallet_address[..12.min(wallet_address.len())]
            );
            NodeReputation::new(node_id.to_string(), wallet_address.to_string())
        });
        // Wallet-Adresse aktualisieren (falls geändert)
        entry.wallet_address = wallet_address.to_string();
    }

    /// Heartbeat: Node als "gesehen" markieren.
    pub fn record_heartbeat(&mut self, node_id: &str) {
        if let Some(entry) = self.nodes.get_mut(node_id) {
            entry.last_seen = Utc::now().timestamp();
        }
    }

    /// Block-Signierung für einen Node verbuchen.
    pub fn record_block_signed(&mut self, node_id: &str) {
        if let Some(entry) = self.nodes.get_mut(node_id) {
            entry.blocks_signed += 1;
            entry.last_seen = Utc::now().timestamp();
        }
    }

    /// Slashing-Event verbuchen.
    pub fn record_slash(&mut self, node_id: &str) {
        if let Some(entry) = self.nodes.get_mut(node_id) {
            entry.slash_count += 1;
        }
    }

    /// Jail-Tage hinzufügen.
    pub fn record_jail(&mut self, node_id: &str, days: u32) {
        if let Some(entry) = self.nodes.get_mut(node_id) {
            entry.total_jail_days += days;
        }
    }

    /// Berechnet alle Scores neu und gibt die Sortierung zurück.
    ///
    /// Rückgabe: Vec<(node_id, wallet_address, score)> sortiert nach Score desc.
    pub fn compute_all_scores(&mut self) -> Vec<(String, String, u64)> {
        // Durchschnittliche Blocks pro Node berechnen
        let total_blocks: u64 = self.nodes.values().map(|n| n.blocks_signed).sum();
        let node_count = self.nodes.len().max(1) as u64;
        let avg_blocks = total_blocks / node_count;

        let mut scores: Vec<(String, String, u64)> = self
            .nodes
            .values_mut()
            .map(|entry| {
                let score = entry.compute_score(avg_blocks);
                (entry.node_id.clone(), entry.wallet_address.clone(), score)
            })
            .collect();

        scores.sort_by(|a, b| b.2.cmp(&a.2));
        scores
    }

    /// Prüft ob eine Distribution fällig ist.
    pub fn distribution_due(&self, current_block: u64) -> bool {
        current_block >= self.last_distribution_block + DISTRIBUTION_INTERVAL
    }

    /// Gibt die Wallet-Adressen aller aktiven Node-Betreiber zurück.
    ///
    /// "Aktiv" = in den letzten 10 Minuten gesehen UND Score > 0.
    pub fn active_operator_wallets(&self) -> std::collections::HashSet<String> {
        let now = Utc::now().timestamp();
        self.nodes.values()
            .filter(|n| now - n.last_seen < 600 && n.computed_score > 0)
            .map(|n| n.wallet_address.clone())
            .collect()
    }

    /// Berechnet die Ausschüttung aus `pool:node_operators`.
    ///
    /// Gibt eine Liste von (wallet_address, amount) zurück.
    /// Der Pool-Betrag wird proportional nach Reputation-Score verteilt.
    pub fn calculate_distribution(
        &mut self,
        pool_balance: Decimal,
        current_block: u64,
    ) -> Vec<(String, Decimal)> {
        if pool_balance <= Decimal::ZERO {
            self.last_distribution_block = current_block;
            return Vec::new();
        }

        let scores = self.compute_all_scores();

        // Nur Nodes mit Score > 0 berücksichtigen
        let eligible: Vec<_> = scores.iter().filter(|(_, _, s)| *s > 0).collect();
        if eligible.is_empty() {
            self.last_distribution_block = current_block;
            return Vec::new();
        }

        let total_score: u64 = eligible.iter().map(|(_, _, s)| *s).sum();
        if total_score == 0 {
            self.last_distribution_block = current_block;
            return Vec::new();
        }

        let mut distributions: Vec<(String, Decimal)> = Vec::new();
        let mut distributed_total = Decimal::ZERO;

        for (node_id, wallet, score) in &eligible {
            let share = Decimal::from(*score) / Decimal::from(total_score);
            let amount = (pool_balance * share).round_dp(8);
            if amount > Decimal::ZERO {
                distributions.push((wallet.clone(), amount));
                distributed_total += amount;

                // Tracking aktualisieren
                if let Some(entry) = self.nodes.get_mut(node_id.as_str()) {
                    entry.total_rewards_received += amount;
                }
            }
        }

        self.last_distribution_block = current_block;
        self.total_distributed += distributed_total;

        if !distributions.is_empty() {
            println!(
                "[reputation] 💰 Distribution: {} STONE an {} Nodes (Block #{}, Pool-Rest: {})",
                distributed_total,
                distributions.len(),
                current_block,
                pool_balance - distributed_total,
            );
        }

        distributions
    }

    /// Kompakte Zusammenfassung für API-Responses.
    pub fn summary(&self) -> ReputationSummary {
        let active_count = self.nodes.values()
            .filter(|n| Utc::now().timestamp() - n.last_seen < 600)
            .count();
        let total_score: u64 = self.nodes.values().map(|n| n.computed_score).sum();
        let avg_score = if self.nodes.is_empty() { 0 } else { total_score / self.nodes.len() as u64 };

        ReputationSummary {
            registered_nodes: self.nodes.len(),
            total_nodes: self.nodes.len(),
            active_nodes: active_count,
            avg_score,
            total_distributed: self.total_distributed,
            last_distribution_block: self.last_distribution_block,
        }
    }

    /// Alle Nodes mit Reputation-Info (für API).
    pub fn all_nodes_info(&self) -> Vec<NodeReputationInfo> {
        self.nodes.values().map(|n| self.to_node_info(n)).collect()
    }

    /// Detail-Info zu einer bestimmten Node (für API).
    pub fn node_info(&self, node_id: &str) -> Option<NodeReputationInfo> {
        self.nodes.get(node_id).map(|n| self.to_node_info(n))
    }

    fn to_node_info(&self, n: &NodeReputation) -> NodeReputationInfo {
        let now = Utc::now().timestamp();
        let age = now - n.last_seen;
        let uptime_status = if age < 120 {
            "online".to_string()
        } else if age < 600 {
            "idle".to_string()
        } else {
            format!("offline ({}min)", age / 60)
        };

        NodeReputationInfo {
            node_id: n.node_id.clone(),
            wallet_address: n.wallet_address.clone(),
            score: n.computed_score,
            uptime_status,
            blocks_signed: n.blocks_signed,
            slash_count: n.slash_count,
            total_rewards: n.total_rewards_received,
            registered_at: n.registered_at,
            last_seen: n.last_seen,
        }
    }

    // ── Persistierung ─────────────────────────────────────────────────────

    pub fn persist(&self) -> Result<(), String> {
        let db = super::open_token_db()
            .map_err(|e| format!("Reputation DB: {e}"))?;

        let json = serde_json::to_string(self)
            .map_err(|e| format!("Reputation serialize: {e}"))?;

        db.put(b"reputation_registry", json.as_bytes())
            .map_err(|e| format!("Reputation put: {e}"))?;

        Ok(())
    }

    pub fn load() -> Self {
        let db = match super::open_token_db() {
            Ok(db) => db,
            Err(_) => return ReputationRegistry::new(),
        };

        match db.get(b"reputation_registry") {
            Ok(Some(bytes)) => {
                match serde_json::from_slice::<ReputationRegistry>(&bytes) {
                    Ok(reg) => {
                        println!(
                            "[reputation] 📂 Registry geladen: {} Nodes, {} STONE verteilt",
                            reg.nodes.len(), reg.total_distributed,
                        );
                        reg
                    }
                    Err(e) => {
                        eprintln!("[reputation] ⚠️ Deserialisierung fehlgeschlagen: {e}");
                        ReputationRegistry::new()
                    }
                }
            }
            _ => ReputationRegistry::new(),
        }
    }
}

// ─── API-Typen ───────────────────────────────────────────────────────────────

/// Kompakte Zusammenfassung für Dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSummary {
    pub registered_nodes: usize,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub avg_score: u64,
    pub total_distributed: Decimal,
    pub last_distribution_block: u64,
}

/// Node-Reputation Detailansicht für API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReputationInfo {
    pub node_id: String,
    pub wallet_address: String,
    pub score: u64,
    pub uptime_status: String,
    pub blocks_signed: u64,
    pub slash_count: u32,
    pub total_rewards: Decimal,
    pub registered_at: i64,
    pub last_seen: i64,
}

// ─── Fee-Split Hilfsfunktion ─────────────────────────────────────────────────

/// Berechnet die Fee-Aufteilung für eine Transaktionsgebühr.
///
/// Rückgabe: `(burn_amount, validator_amount, staker_amount, pool_amount)`
///
/// | Anteil     | Prozent | Empfänger                                 |
/// |------------|---------|---------------------------------------------|
/// | Burn       |  20%    | Deflation (Supply-Reduktion)                |
/// | Miner      |  37%    | Block-Produzent (aktueller Validator)        |
/// | Staker     |  28%    | pool:staker_fees (proportional nach Stake)   |
/// | Node-Ops   |  10%    | pool:node_operators (Reputation-gewichtet)   |
/// | Governance |   5%    | pool:governance (Refill aus Netzaktivität)   |
pub fn split_fee(fee: Decimal) -> (Decimal, Decimal, Decimal, Decimal, Decimal) {
    if fee <= Decimal::ZERO {
        return (Decimal::ZERO, Decimal::ZERO, Decimal::ZERO, Decimal::ZERO, Decimal::ZERO);
    }

    let hundred = Decimal::from(100u64);
    let burn = (fee * Decimal::from(FEE_BURN_PCT) / hundred).round_dp(8);
    let validator = (fee * Decimal::from(FEE_VALIDATOR_PCT) / hundred).round_dp(8);
    let staker = (fee * Decimal::from(FEE_STAKER_PCT) / hundred).round_dp(8);
    let governance = (fee * Decimal::from(FEE_GOVERNANCE_PCT) / hundred).round_dp(8);
    // Node-Ops bekommt den Rest (vermeidet Rundungsfehler)
    let pool = fee - burn - validator - staker - governance;

    (burn, validator, staker, pool, governance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_split() {
        let fee = Decimal::new(1, 2); // 0.01 STONE
        let (burn, validator, staker, pool, governance) = split_fee(fee);
        assert_eq!(burn + validator + staker + pool + governance, fee, "Fee-Split muss sich zu 100% aufaddieren");
        assert!(burn > Decimal::ZERO);
        assert!(validator > Decimal::ZERO);
        assert!(staker > Decimal::ZERO);
        assert!(pool > Decimal::ZERO);
        assert!(governance > Decimal::ZERO);
    }

    #[test]
    fn test_reputation_score() {
        let mut rep = NodeReputation::new("test-node".into(), "abc123".into());
        rep.blocks_signed = 100;
        let score = rep.compute_score(100);
        assert!(score > 0, "Score sollte > 0 sein für aktiven Node");
        assert!(score <= MAX_REPUTATION_SCORE);
    }

    #[test]
    fn test_score_with_slashing() {
        let mut rep = NodeReputation::new("test-node".into(), "abc123".into());
        rep.blocks_signed = 100;
        rep.slash_count = 3;
        rep.total_jail_days = 5;
        let score = rep.compute_score(100);
        // Behavior: 100 - 60 - 25 = 15 → gewichtet 0.25 * 15 = 3.75
        assert!(score < 80, "Score sollte durch Slashing gesenkt werden: {score}");
    }
}
