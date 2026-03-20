//! Governance-Modul für StoneCoin
//!
//! ## Architektur
//!
//! **Trusted Node Registry**
//! Nodes die ≥ 30 Tage aktiv + Mindest-Stake (100 STONE) + kein Slashing →
//! stimmberechtigt als "Trusted Node".
//!
//! **Dual-Voting (50/50)**
//! Jede Abstimmung wird doppelt gewichtet:
//! - 50% Node-Voting:  1 Trusted Node = 1 Stimme (Sybil-geschützt durch Stake + Uptime)
//! - 50% Stake-Voting: Gewicht proportional zum Stake
//! Verhindert Machtkonzentration von beiden Seiten.
//!
//! **Multisig Bootstrap (3-of-5)**
//! Kritische Parameter (Supply, Pool-Größen, Slashing-Regeln) erfordern
//! 3 von 5 Bootstrap-Signaturen zusätzlich zur Governance-Abstimmung.
//!
//! **48h Timelock**
//! Jede angenommene Änderung tritt erst nach 48h in Kraft.
//! Gibt der Community Zeit für Widerstand oder Hard Fork.

use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Minimale Tage als aktive Node für Trusted-Status
pub const TRUSTED_NODE_MIN_DAYS: i64 = 30;

/// Mindest-Stake für Trusted Node (100 STONE)
pub const TRUSTED_NODE_MIN_STAKE: &str = "100";

/// Timelock nach Annahme: 48 Stunden in Sekunden
pub const PROPOSAL_TIMELOCK_SECS: i64 = 48 * 3600;

/// Quorum: Mindestens 51% der stimmberechtigten Nodes müssen abstimmen
pub const NODE_VOTE_QUORUM_PCT: u8 = 51;

/// Quorum: Mindestens 51% des stimmberechtigten Stakes muss abstimmen
pub const STAKE_VOTE_QUORUM_PCT: u8 = 51;

/// Majority: >50% der Stimmen müssen zustimmen
pub const VOTE_MAJORITY_PCT: u8 = 50;

/// Multisig-Schwelle: 3 von 5 Bootstrap-Nodes
pub const MULTISIG_THRESHOLD: usize = 3;

/// Maximale Anzahl Bootstrap-Signaturen (Gruppengröße)
pub const MULTISIG_GROUP_SIZE: usize = 5;

/// Maximale Laufzeit eines Proposals: 7 Tage
pub const PROPOSAL_LIFETIME_SECS: i64 = 7 * 24 * 3600;

// ─── Trusted Node Registry ──────────────────────────────────────────────────

/// Status einer Node in der Trusted-Registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedNodeStatus {
    /// Noch nicht qualifiziert (zu wenig Tage, zu wenig Stake, etc.)
    Pending,
    /// Voll qualifiziert: aktiv ≥30d, Mindest-Stake, kein Slashing
    Trusted,
    /// Aberkannt: nach Slashing oder Stake-Entzug
    Revoked,
}

/// Eintrag in der Trusted Node Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedNode {
    /// Node-ID (z.B. Public-Key-Hex oder Peer-ID)
    pub node_id: String,
    /// Wallet-Adresse des Node-Betreibers
    pub wallet: String,
    /// Zeitpunkt der Registrierung (Unix-Timestamp)
    pub registered_at: i64,
    /// Aktueller Status
    pub status: TrustedNodeStatus,
    /// Letzter Zeitpunkt der Qualifizierungs-Prüfung
    pub last_checked: i64,
}

// ─── Governance Proposals ────────────────────────────────────────────────────

/// Kategorie eines Proposals – bestimmt ob Multisig erforderlich ist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCategory {
    /// Unkritisch: Nur Dual-Voting (50/50 Node + Stake)
    Standard,
    /// Kritisch: Zusätzlich 3-of-5 Multisig erforderlich
    /// (Supply-Änderungen, Pool-Größen, Slashing-Parameter, Bootstrap-Keys)
    Critical,
}

/// Status eines Proposals im Lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Abstimmung läuft
    Voting,
    /// Angenommen, aber noch in der 48h-Timelock-Phase
    Accepted { execute_after: i64 },
    /// Timelock abgelaufen → kann ausgeführt werden
    Ready,
    /// Ausgeführt
    Executed { executed_at: i64 },
    /// Abgelehnt (Quorum verfehlt oder Mehrheit dagegen)
    Rejected { reason: String },
    /// Abgelaufen (Laufzeit überschritten ohne Ergebnis)
    Expired,
    /// Durch Veto blockiert (Multisig gescheitert bei Critical)
    Vetoed,
}

/// Eine einzelne Stimme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter: String,          // node_id oder wallet
    pub approve: bool,
    pub timestamp: i64,
    pub stake_weight: Decimal,  // 0 bei Node-Vote, Stake-Betrag bei Stake-Vote
}

/// Ein Governance-Proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Eindeutige Proposal-ID (Hash aus Titel + Timestamp)
    pub id: String,
    /// Titel / Kurzbeschreibung
    pub title: String,
    /// Ausführliche Beschreibung der Änderung
    pub description: String,
    /// Kategorie (Standard / Critical)
    pub category: ProposalCategory,
    /// Wer hat den Proposal erstellt
    pub proposer: String,
    /// Erstellungs-Zeitpunkt
    pub created_at: i64,
    /// Ablauf-Zeitpunkt (created_at + PROPOSAL_LIFETIME_SECS)
    pub expires_at: i64,
    /// Status
    pub status: ProposalStatus,

    // ── Node-Voting (1 Node = 1 Stimme) ──
    pub node_votes: Vec<Vote>,

    // ── Stake-Voting (gewichtet nach Stake) ──
    pub stake_votes: Vec<Vote>,

    // ── Multisig (nur bei Critical) ──
    /// Bootstrap-Signaturen (node_id → signiert?)
    pub multisig_approvals: HashMap<String, bool>,
}

// ─── Governance Store ────────────────────────────────────────────────────────

/// Persistenter Governance-State.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStore {
    /// Trusted Node Registry
    pub trusted_nodes: HashMap<String, TrustedNode>,
    /// Aktive und abgeschlossene Proposals
    pub proposals: Vec<Proposal>,
    /// Bootstrap-Node-IDs für Multisig (3-of-5)
    pub bootstrap_signers: Vec<String>,
    /// Letzte Aktualisierung
    pub last_updated: i64,
}

impl GovernanceStore {
    pub fn new() -> Self {
        Self {
            trusted_nodes: HashMap::new(),
            proposals: Vec::new(),
            bootstrap_signers: Vec::new(),
            last_updated: Utc::now().timestamp(),
        }
    }

    // ── Trusted Node Registry ────────────────────────────────────────────

    /// Registriert eine Node in der Registry (startet als Pending).
    pub fn register_node(&mut self, node_id: &str, wallet: &str) {
        let now = Utc::now().timestamp();
        self.trusted_nodes.entry(node_id.to_string()).or_insert_with(|| {
            println!(
                "[governance] 📋 Node registriert: {} (Wallet: {})",
                &node_id[..12.min(node_id.len())],
                &wallet[..12.min(wallet.len())],
            );
            TrustedNode {
                node_id: node_id.to_string(),
                wallet: wallet.to_string(),
                registered_at: now,
                status: TrustedNodeStatus::Pending,
                last_checked: now,
            }
        });
    }

    /// Prüft alle Nodes gegen die Trusted-Kriterien und aktualisiert Status.
    ///
    /// Kriterien für `Trusted`:
    /// - ≥ 30 Tage registriert
    /// - Mindest-Stake (100 STONE) im StakingPool
    /// - Kein Slashing-Record (offense_count == 0)
    pub fn refresh_trusted_status(
        &mut self,
        staker_stakes: &HashMap<String, Decimal>,
        slashing_offenses: &HashMap<String, u64>,
    ) {
        let now = Utc::now().timestamp();
        let min_stake: Decimal = TRUSTED_NODE_MIN_STAKE.parse().unwrap();
        let min_age_secs = TRUSTED_NODE_MIN_DAYS * 86400;

        for node in self.trusted_nodes.values_mut() {
            node.last_checked = now;

            let age_ok = (now - node.registered_at) >= min_age_secs;
            let stake = staker_stakes
                .get(&node.wallet)
                .copied()
                .unwrap_or(Decimal::ZERO);
            let stake_ok = stake >= min_stake;
            let no_slashing = slashing_offenses
                .get(&node.node_id)
                .copied()
                .unwrap_or(0) == 0;

            let was_trusted = node.status == TrustedNodeStatus::Trusted;
            if age_ok && stake_ok && no_slashing {
                if node.status != TrustedNodeStatus::Trusted {
                    println!(
                        "[governance] ✅ Node wird Trusted: {} ({}d aktiv, {} STONE, 0 Slashes)",
                        &node.node_id[..12.min(node.node_id.len())],
                        (now - node.registered_at) / 86400,
                        stake,
                    );
                }
                node.status = TrustedNodeStatus::Trusted;
            } else {
                if node.status == TrustedNodeStatus::Trusted {
                    let reason = if !stake_ok {
                        "Stake unter Minimum"
                    } else if !no_slashing {
                        "Slashing-Vergehen"
                    } else {
                        "Kriterien nicht erfüllt"
                    };
                    println!(
                        "[governance] ❌ Trusted-Status entzogen: {} ({})",
                        &node.node_id[..12.min(node.node_id.len())],
                        reason,
                    );
                    node.status = TrustedNodeStatus::Revoked;
                } else if !was_trusted {
                    node.status = TrustedNodeStatus::Pending;
                }
            }
        }
    }

    /// Alle aktuell Trusted Nodes.
    pub fn trusted_node_ids(&self) -> Vec<String> {
        self.trusted_nodes
            .values()
            .filter(|n| n.status == TrustedNodeStatus::Trusted)
            .map(|n| n.node_id.clone())
            .collect()
    }

    /// Anzahl Trusted Nodes.
    pub fn trusted_count(&self) -> usize {
        self.trusted_nodes
            .values()
            .filter(|n| n.status == TrustedNodeStatus::Trusted)
            .count()
    }

    /// Prüft ob eine Node stimmberechtigt ist (Trusted).
    pub fn is_eligible_voter(&self, node_id: &str) -> bool {
        self.trusted_nodes
            .get(node_id)
            .map(|n| n.status == TrustedNodeStatus::Trusted)
            .unwrap_or(false)
    }

    // ── Bootstrap Multisig ───────────────────────────────────────────────

    /// Setzt die initialen Bootstrap-Signer (einmal beim Setup).
    /// Genau 5 Node-IDs erwartet.
    pub fn set_bootstrap_signers(&mut self, signers: Vec<String>) -> Result<(), GovernanceError> {
        if signers.len() != MULTISIG_GROUP_SIZE {
            return Err(GovernanceError::InvalidMultisigGroup {
                expected: MULTISIG_GROUP_SIZE,
                got: signers.len(),
            });
        }
        println!(
            "[governance] 🔐 Bootstrap-Multisig gesetzt: {} Signer",
            signers.len(),
        );
        self.bootstrap_signers = signers;
        Ok(())
    }

    // ── Proposal-Lifecycle ───────────────────────────────────────────────

    /// Erstellt ein neues Proposal.
    pub fn create_proposal(
        &mut self,
        proposer: &str,
        title: &str,
        description: &str,
        category: ProposalCategory,
    ) -> Result<String, GovernanceError> {
        // Proposer muss Trusted sein
        if !self.is_eligible_voter(proposer) {
            return Err(GovernanceError::NotEligible {
                node_id: proposer.to_string(),
            });
        }

        let now = Utc::now().timestamp();
        let id = compute_proposal_id(title, now);

        let multisig_approvals = if category == ProposalCategory::Critical {
            self.bootstrap_signers
                .iter()
                .map(|s| (s.clone(), false))
                .collect()
        } else {
            HashMap::new()
        };

        let proposal = Proposal {
            id: id.clone(),
            title: title.to_string(),
            description: description.to_string(),
            category,
            proposer: proposer.to_string(),
            created_at: now,
            expires_at: now + PROPOSAL_LIFETIME_SECS,
            status: ProposalStatus::Voting,
            node_votes: Vec::new(),
            stake_votes: Vec::new(),
            multisig_approvals,
        };

        println!(
            "[governance] 📜 Neues Proposal: [{}] \"{}\" von {} ({:?})",
            &id[..8],
            title,
            &proposer[..12.min(proposer.len())],
            proposal.category,
        );

        self.proposals.push(proposal);
        Ok(id)
    }

    /// Node-Vote: 1 Trusted Node = 1 Stimme (ungewichtet).
    pub fn vote_as_node(
        &mut self,
        proposal_id: &str,
        node_id: &str,
        approve: bool,
    ) -> Result<(), GovernanceError> {
        if !self.is_eligible_voter(node_id) {
            return Err(GovernanceError::NotEligible {
                node_id: node_id.to_string(),
            });
        }

        let proposal = self
            .find_proposal_mut(proposal_id)?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovernanceError::ProposalNotVoting {
                id: proposal_id.to_string(),
            });
        }

        // Doppel-Vote verhindern
        if proposal.node_votes.iter().any(|v| v.voter == node_id) {
            return Err(GovernanceError::AlreadyVoted {
                voter: node_id.to_string(),
            });
        }

        proposal.node_votes.push(Vote {
            voter: node_id.to_string(),
            approve,
            timestamp: Utc::now().timestamp(),
            stake_weight: Decimal::ZERO,
        });

        Ok(())
    }

    /// Stake-Vote: Gewichtet nach gestaketem Betrag.
    pub fn vote_as_staker(
        &mut self,
        proposal_id: &str,
        wallet: &str,
        approve: bool,
        stake_amount: Decimal,
    ) -> Result<(), GovernanceError> {
        let gov_min: Decimal = TRUSTED_NODE_MIN_STAKE.parse().unwrap();
        if stake_amount < gov_min {
            return Err(GovernanceError::InsufficientStake {
                wallet: wallet.to_string(),
                stake: stake_amount,
                min: gov_min,
            });
        }

        let proposal = self.find_proposal_mut(proposal_id)?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovernanceError::ProposalNotVoting {
                id: proposal_id.to_string(),
            });
        }

        if proposal.stake_votes.iter().any(|v| v.voter == wallet) {
            return Err(GovernanceError::AlreadyVoted {
                voter: wallet.to_string(),
            });
        }

        proposal.stake_votes.push(Vote {
            voter: wallet.to_string(),
            approve,
            timestamp: Utc::now().timestamp(),
            stake_weight: stake_amount,
        });

        Ok(())
    }

    /// Multisig-Approval durch einen Bootstrap-Signer (nur bei Critical).
    pub fn approve_multisig(
        &mut self,
        proposal_id: &str,
        signer_id: &str,
    ) -> Result<(), GovernanceError> {
        if !self.bootstrap_signers.contains(&signer_id.to_string()) {
            return Err(GovernanceError::NotBootstrapSigner {
                node_id: signer_id.to_string(),
            });
        }

        let proposal = self.find_proposal_mut(proposal_id)?;

        if proposal.category != ProposalCategory::Critical {
            return Err(GovernanceError::MultisigNotRequired {
                id: proposal_id.to_string(),
            });
        }

        match &proposal.status {
            ProposalStatus::Voting | ProposalStatus::Accepted { .. } => {}
            _ => {
                return Err(GovernanceError::ProposalNotVoting {
                    id: proposal_id.to_string(),
                });
            }
        }

        if let Some(approved) = proposal.multisig_approvals.get_mut(signer_id) {
            *approved = true;
        }

        Ok(())
    }

    // ── Auswertung & Timelock ────────────────────────────────────────────

    /// Wertet ein Proposal aus und aktualisiert den Status.
    ///
    /// **Dual-Voting-Formel:**
    /// - Node-Score:  (approve_count / total_voted) → 0.0 bis 1.0
    /// - Stake-Score: (approve_weight / total_voted_weight) → 0.0 bis 1.0
    /// - Ergebnis = 0.5 × Node-Score + 0.5 × Stake-Score
    /// - Angenommen wenn Ergebnis > 50% UND beide Quoren erreicht
    ///
    /// Bei `Critical`: Zusätzlich ≥3 von 5 Multisig-Approvals nötig.
    /// Bei Annahme: Status → `Accepted { execute_after: now + 48h }`
    pub fn evaluate_proposal(
        &mut self,
        proposal_id: &str,
        total_trusted_nodes: usize,
        total_eligible_stake: Decimal,
    ) -> Result<ProposalStatus, GovernanceError> {
        let proposal = self.find_proposal_mut(proposal_id)?;
        let now = Utc::now().timestamp();

        // Abgelaufen?
        if now > proposal.expires_at && proposal.status == ProposalStatus::Voting {
            proposal.status = ProposalStatus::Expired;
            return Ok(ProposalStatus::Expired);
        }

        if proposal.status != ProposalStatus::Voting {
            return Ok(proposal.status.clone());
        }

        // ── Node-Voting-Auswertung ──
        let node_total_voted = proposal.node_votes.len();
        let node_approve = proposal.node_votes.iter().filter(|v| v.approve).count();
        let node_quorum_met = total_trusted_nodes > 0
            && (node_total_voted * 100) >= (total_trusted_nodes * NODE_VOTE_QUORUM_PCT as usize);
        let node_score = if node_total_voted > 0 {
            node_approve as f64 / node_total_voted as f64
        } else {
            0.0
        };

        // ── Stake-Voting-Auswertung ──
        let stake_total_voted: Decimal = proposal
            .stake_votes
            .iter()
            .map(|v| v.stake_weight)
            .sum();
        let stake_approve: Decimal = proposal
            .stake_votes
            .iter()
            .filter(|v| v.approve)
            .map(|v| v.stake_weight)
            .sum();
        let stake_quorum_met = total_eligible_stake > Decimal::ZERO
            && stake_total_voted * Decimal::from(100)
                >= total_eligible_stake * Decimal::from(STAKE_VOTE_QUORUM_PCT);
        let stake_score = if stake_total_voted > Decimal::ZERO {
            stake_approve.to_string().parse::<f64>().unwrap_or(0.0)
                / stake_total_voted.to_string().parse::<f64>().unwrap_or(1.0)
        } else {
            0.0
        };

        // ── Dual-Score: 50% Node + 50% Stake ──
        let dual_score = 0.5 * node_score + 0.5 * stake_score;
        let both_quorums = node_quorum_met && stake_quorum_met;
        let majority = dual_score > (VOTE_MAJORITY_PCT as f64 / 100.0);

        println!(
            "[governance] 📊 Proposal [{}]: Node {}/{} ({:.0}%), Stake {}/{} ({:.0}%), Score={:.1}%, Quorum={}",
            &proposal.id[..8],
            node_approve,
            node_total_voted,
            node_score * 100.0,
            stake_approve,
            stake_total_voted,
            stake_score * 100.0,
            dual_score * 100.0,
            both_quorums,
        );

        if !both_quorums {
            // Noch nicht genug Stimmen — bleibt im Voting
            return Ok(ProposalStatus::Voting);
        }

        if !majority {
            proposal.status = ProposalStatus::Rejected {
                reason: format!(
                    "Dual-Score {:.1}% < {}% (Node: {:.0}%, Stake: {:.0}%)",
                    dual_score * 100.0,
                    VOTE_MAJORITY_PCT,
                    node_score * 100.0,
                    stake_score * 100.0,
                ),
            };
            return Ok(proposal.status.clone());
        }

        // ── Critical: Multisig prüfen ──
        if proposal.category == ProposalCategory::Critical {
            let sig_count = proposal
                .multisig_approvals
                .values()
                .filter(|&&v| v)
                .count();
            if sig_count < MULTISIG_THRESHOLD {
                println!(
                    "[governance] ⏳ Proposal [{}] hat Dual-Vote bestanden, wartet auf Multisig ({}/{})",
                    &proposal.id[..8],
                    sig_count,
                    MULTISIG_THRESHOLD,
                );
                // Bleibt im Voting bis Multisig erreicht
                return Ok(ProposalStatus::Voting);
            }
        }

        // ── Angenommen → 48h Timelock starten ──
        let execute_after = now + PROPOSAL_TIMELOCK_SECS;
        proposal.status = ProposalStatus::Accepted { execute_after };

        println!(
            "[governance] ✅ Proposal [{}] angenommen! Timelock bis {} (48h)",
            &proposal.id[..8],
            chrono::DateTime::from_timestamp(execute_after, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "?".to_string()),
        );

        Ok(proposal.status.clone())
    }

    /// Prüft ob Proposals aus dem Timelock bereit zur Ausführung sind.
    /// Gibt die IDs der bereiten Proposals zurück.
    pub fn check_timelocks(&mut self) -> Vec<String> {
        let now = Utc::now().timestamp();
        let mut ready = Vec::new();

        for proposal in &mut self.proposals {
            if let ProposalStatus::Accepted { execute_after } = proposal.status {
                if now >= execute_after {
                    proposal.status = ProposalStatus::Ready;
                    println!(
                        "[governance] 🔓 Proposal [{}] \"{}\" → Ready (Timelock abgelaufen)",
                        &proposal.id[..8],
                        proposal.title,
                    );
                    ready.push(proposal.id.clone());
                }
            }
        }

        ready
    }

    /// Markiert ein Proposal als ausgeführt.
    pub fn mark_executed(&mut self, proposal_id: &str) -> Result<(), GovernanceError> {
        let proposal = self.find_proposal_mut(proposal_id)?;
        if proposal.status != ProposalStatus::Ready {
            return Err(GovernanceError::ProposalNotReady {
                id: proposal_id.to_string(),
            });
        }
        proposal.status = ProposalStatus::Executed {
            executed_at: Utc::now().timestamp(),
        };
        println!(
            "[governance] ⚡ Proposal [{}] \"{}\" ausgeführt",
            &proposal.id[..8],
            proposal.title,
        );
        Ok(())
    }

    /// Räumt abgelaufene Proposals auf (Status → Expired).
    pub fn expire_old_proposals(&mut self) {
        let now = Utc::now().timestamp();
        for proposal in &mut self.proposals {
            if proposal.status == ProposalStatus::Voting && now > proposal.expires_at {
                proposal.status = ProposalStatus::Expired;
                println!(
                    "[governance] ⏰ Proposal [{}] \"{}\" abgelaufen",
                    &proposal.id[..8],
                    proposal.title,
                );
            }
        }
    }

    // ── Query-Helpers ────────────────────────────────────────────────────

    pub fn active_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .iter()
            .filter(|p| matches!(p.status, ProposalStatus::Voting | ProposalStatus::Accepted { .. }))
            .collect()
    }

    pub fn proposal_by_id(&self, id: &str) -> Option<&Proposal> {
        self.proposals.iter().find(|p| p.id == id)
    }

    // ── Persistence ──────────────────────────────────────────────────────

    const DB_KEY: &'static [u8] = b"governance_store";

    pub fn persist(&self) -> Result<(), String> {
        let db = super::open_token_db()?;
        let json = serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))?;
        db.put(Self::DB_KEY, &json).map_err(|e| format!("db put: {e}"))?;
        Ok(())
    }

    pub fn load() -> Self {
        match super::open_token_db() {
            Ok(db) => match db.get(Self::DB_KEY) {
                Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                    eprintln!("[governance] ⚠️  Deserialize fehlgeschlagen: {e}");
                    Self::new()
                }),
                _ => Self::new(),
            },
            Err(e) => {
                eprintln!("[governance] ⚠️  DB nicht verfügbar: {e}");
                Self::new()
            }
        }
    }

    // ── Internal ─────────────────────────────────────────────────────────

    fn find_proposal_mut(&mut self, id: &str) -> Result<&mut Proposal, GovernanceError> {
        self.proposals
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| GovernanceError::ProposalNotFound {
                id: id.to_string(),
            })
    }
}

impl Default for GovernanceStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Governance Info (API-freundlich) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceInfo {
    pub trusted_nodes: usize,
    pub pending_nodes: usize,
    pub active_proposals: usize,
    pub total_proposals: usize,
    pub bootstrap_signers: usize,
    pub timelock_hours: i64,
}

impl GovernanceStore {
    pub fn info(&self) -> GovernanceInfo {
        GovernanceInfo {
            trusted_nodes: self.trusted_count(),
            pending_nodes: self
                .trusted_nodes
                .values()
                .filter(|n| n.status == TrustedNodeStatus::Pending)
                .count(),
            active_proposals: self.active_proposals().len(),
            total_proposals: self.proposals.len(),
            bootstrap_signers: self.bootstrap_signers.len(),
            timelock_hours: PROPOSAL_TIMELOCK_SECS / 3600,
        }
    }
}

// ─── Error Type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceError {
    NotEligible { node_id: String },
    InsufficientStake { wallet: String, stake: Decimal, min: Decimal },
    AlreadyVoted { voter: String },
    ProposalNotFound { id: String },
    ProposalNotVoting { id: String },
    ProposalNotReady { id: String },
    NotBootstrapSigner { node_id: String },
    MultisigNotRequired { id: String },
    InvalidMultisigGroup { expected: usize, got: usize },
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEligible { node_id } => write!(f, "Node {node_id} ist nicht stimmberechtigt (nicht Trusted)"),
            Self::InsufficientStake { wallet, stake, min } => write!(f, "Wallet {wallet}: Stake {stake} < Min {min}"),
            Self::AlreadyVoted { voter } => write!(f, "{voter} hat bereits abgestimmt"),
            Self::ProposalNotFound { id } => write!(f, "Proposal {id} nicht gefunden"),
            Self::ProposalNotVoting { id } => write!(f, "Proposal {id} ist nicht im Voting-Status"),
            Self::ProposalNotReady { id } => write!(f, "Proposal {id} ist nicht Ready"),
            Self::NotBootstrapSigner { node_id } => write!(f, "{node_id} ist kein Bootstrap-Signer"),
            Self::MultisigNotRequired { id } => write!(f, "Proposal {id} ist Standard (kein Multisig nötig)"),
            Self::InvalidMultisigGroup { expected, got } => write!(f, "Multisig-Gruppe: {got} statt {expected} Signer"),
        }
    }
}

impl std::error::Error for GovernanceError {}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Berechnet eine deterministische Proposal-ID aus Titel und Timestamp.
fn compute_proposal_id(title: &str, timestamp: i64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    title.hash(&mut hasher);
    timestamp.hash(&mut hasher);
    format!("GOV-{:016x}", hasher.finish())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_store() -> GovernanceStore {
        let mut store = GovernanceStore::new();
        // 5 Bootstrap-Signer
        store
            .set_bootstrap_signers(vec![
                "boot1".into(),
                "boot2".into(),
                "boot3".into(),
                "boot4".into(),
                "boot5".into(),
            ])
            .unwrap();

        // 3 Nodes registrieren
        store.register_node("node_a", "wallet_a");
        store.register_node("node_b", "wallet_b");
        store.register_node("node_c", "wallet_c");

        // Manuell auf Trusted setzen (in Tests umgehen wir die 30-Tage-Prüfung)
        for n in store.trusted_nodes.values_mut() {
            n.status = TrustedNodeStatus::Trusted;
        }

        store
    }

    #[test]
    fn test_trusted_node_lifecycle() {
        let mut store = GovernanceStore::new();
        store.register_node("n1", "w1");
        assert_eq!(store.trusted_count(), 0);

        // Nicht alt genug + kein Stake → bleibt Pending
        let stakes: HashMap<String, Decimal> = HashMap::new();
        let slashes: HashMap<String, u64> = HashMap::new();
        store.refresh_trusted_status(&stakes, &slashes);
        assert_eq!(store.trusted_count(), 0);

        // Hack: Registrierung auf vor 31 Tagen setzen
        store.trusted_nodes.get_mut("n1").unwrap().registered_at =
            Utc::now().timestamp() - 31 * 86400;

        // Stake erfüllt, kein Slashing
        let mut stakes = HashMap::new();
        stakes.insert("w1".to_string(), Decimal::from(200));
        store.refresh_trusted_status(&stakes, &slashes);
        assert_eq!(store.trusted_count(), 1);

        // Slashing → Revoked
        let mut slashes = HashMap::new();
        slashes.insert("n1".to_string(), 1);
        store.refresh_trusted_status(&stakes, &slashes);
        assert_eq!(store.trusted_count(), 0);
        assert_eq!(
            store.trusted_nodes.get("n1").unwrap().status,
            TrustedNodeStatus::Revoked,
        );
    }

    #[test]
    fn test_standard_proposal_dual_voting() {
        let mut store = setup_store();

        // Proposal erstellen
        let id = store
            .create_proposal("node_a", "Test Proposal", "Beschreibung", ProposalCategory::Standard)
            .unwrap();

        // Alle 3 Nodes stimmen zu (Node-Vote)
        store.vote_as_node(&id, "node_a", true).unwrap();
        store.vote_as_node(&id, "node_b", true).unwrap();
        store.vote_as_node(&id, "node_c", true).unwrap();

        // Stake-Votes: 200 + 150 approve, 100 reject
        store
            .vote_as_staker(&id, "wallet_a", true, Decimal::from(200))
            .unwrap();
        store
            .vote_as_staker(&id, "wallet_b", true, Decimal::from(150))
            .unwrap();
        store
            .vote_as_staker(&id, "wallet_c", false, Decimal::from(100))
            .unwrap();

        // Auswertung: 3 Trusted Nodes, 450 STONE eligible stake
        let result = store
            .evaluate_proposal(&id, 3, Decimal::from(450))
            .unwrap();

        match result {
            ProposalStatus::Accepted { execute_after } => {
                // 48h Timelock
                let now = Utc::now().timestamp();
                assert!(execute_after > now);
                assert!(execute_after <= now + PROPOSAL_TIMELOCK_SECS + 1);
            }
            other => panic!("Erwartet Accepted, bekam: {:?}", other),
        }
    }

    #[test]
    fn test_critical_proposal_needs_multisig() {
        let mut store = setup_store();

        let id = store
            .create_proposal("node_a", "Critical Change", "Desc", ProposalCategory::Critical)
            .unwrap();

        // Alle stimmen zu
        store.vote_as_node(&id, "node_a", true).unwrap();
        store.vote_as_node(&id, "node_b", true).unwrap();
        store.vote_as_node(&id, "node_c", true).unwrap();
        store.vote_as_staker(&id, "wallet_a", true, Decimal::from(200)).unwrap();
        store.vote_as_staker(&id, "wallet_b", true, Decimal::from(200)).unwrap();
        store.vote_as_staker(&id, "wallet_c", true, Decimal::from(100)).unwrap();

        // Ohne Multisig → bleibt Voting
        let result = store.evaluate_proposal(&id, 3, Decimal::from(500)).unwrap();
        assert_eq!(result, ProposalStatus::Voting);

        // 2 von 5 Multisig → noch nicht genug
        store.approve_multisig(&id, "boot1").unwrap();
        store.approve_multisig(&id, "boot2").unwrap();
        let result = store.evaluate_proposal(&id, 3, Decimal::from(500)).unwrap();
        assert_eq!(result, ProposalStatus::Voting);

        // 3 von 5 → Accepted!
        store.approve_multisig(&id, "boot3").unwrap();
        let result = store.evaluate_proposal(&id, 3, Decimal::from(500)).unwrap();
        assert!(matches!(result, ProposalStatus::Accepted { .. }));
    }

    #[test]
    fn test_rejected_proposal() {
        let mut store = setup_store();

        let id = store
            .create_proposal("node_a", "Bad Proposal", "Desc", ProposalCategory::Standard)
            .unwrap();

        // 1 approve, 2 reject (Node)
        store.vote_as_node(&id, "node_a", true).unwrap();
        store.vote_as_node(&id, "node_b", false).unwrap();
        store.vote_as_node(&id, "node_c", false).unwrap();

        // Stake: 100 approve, 300 reject
        store.vote_as_staker(&id, "wallet_a", true, Decimal::from(100)).unwrap();
        store.vote_as_staker(&id, "wallet_b", false, Decimal::from(200)).unwrap();
        store.vote_as_staker(&id, "wallet_c", false, Decimal::from(100)).unwrap();

        let result = store.evaluate_proposal(&id, 3, Decimal::from(400)).unwrap();
        assert!(matches!(result, ProposalStatus::Rejected { .. }));
    }

    #[test]
    fn test_double_vote_prevented() {
        let mut store = setup_store();
        let id = store
            .create_proposal("node_a", "Dup Vote", "Desc", ProposalCategory::Standard)
            .unwrap();

        store.vote_as_node(&id, "node_a", true).unwrap();
        let err = store.vote_as_node(&id, "node_a", false);
        assert!(err.is_err());
    }

    #[test]
    fn test_timelock_flow() {
        let mut store = setup_store();
        let id = store
            .create_proposal("node_a", "Timelock Test", "Desc", ProposalCategory::Standard)
            .unwrap();

        // Direkt auf Accepted setzen (für Timelock-Test)
        let now = Utc::now().timestamp();
        let proposal = store.find_proposal_mut(&id).unwrap();
        proposal.status = ProposalStatus::Accepted {
            execute_after: now - 1, // schon abgelaufen
        };

        let ready = store.check_timelocks();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], id);

        // Ausführen
        store.mark_executed(&id).unwrap();
        assert!(matches!(
            store.proposal_by_id(&id).unwrap().status,
            ProposalStatus::Executed { .. },
        ));
    }

    #[test]
    fn test_non_eligible_cannot_propose() {
        let mut store = GovernanceStore::new();
        store.register_node("pending_node", "wallet");
        // Node ist Pending, nicht Trusted
        let err = store.create_proposal("pending_node", "Test", "Desc", ProposalCategory::Standard);
        assert!(err.is_err());
    }
}
