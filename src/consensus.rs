//! Proof-of-Authority Konsensus-Schicht
//!
//! # Überblick
//!
//! Stone verwendet einen PoA-Mechanismus (Proof-of-Authority):
//!
//! 1. **Validator-Whitelist** – nur bekannte, registrierte Nodes dürfen Blöcke erstellen.
//!    Jeder Validator hat eine Node-ID und einen Ed25519-Public-Key.
//!    Die Liste wird persistent in `{data_dir}/validators.json` gespeichert.
//!
//! 2. **Block-Signatur** – der Validator signiert den Block-Hash mit seinem Ed25519-Schlüssel.
//!    Peers prüfen diese Signatur beim Accept eines fremden Blocks.
//!
//! 3. **Voting** – bei einem Konflikt (Fork) schickt der aktive Proposer einen `BlockProposal`
//!    an alle Peers. Jeder Validator antwortet mit einer `VoteMessage` (accept/reject).
//!    Eine Supermajorität (⌊2/3⌋ + 1 der bekannten Validatoren) ist ausreichend.
//!
//! 4. **Fork-Erkennung & Auflösung** – wenn zwei Blöcke mit gleichem Index aber
//!    verschiedenen Hashes existieren, wird der Block mit:
//!    a) der gültigsten Validator-Signatur, und
//!    b) der meisten Folge-Blöcke (longest-chain)
//!    bevorzugt. Bei Gleichstand gewinnt der lexikographisch kleinere Hash.

use crate::blockchain::{Block, data_dir};
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    ed25519::signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;
use sha2::{Sha256, Digest};

// ─── Validator-Info ──────────────────────────────────────────────────────────

/// Ein registrierter Validator im PoA-Netzwerk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Node-ID (z.B. "node-1", Hostname, UUID)
    pub node_id: String,
    /// Ed25519-Public-Key als 64-Zeichen-Hex (32 Byte)
    pub public_key_hex: String,
    /// Optionaler Anzeigename
    #[serde(default)]
    pub name: String,
    /// HTTP-Endpunkt der Validator-Node (für Voting)
    #[serde(default)]
    pub endpoint: String,
    /// Zeitpunkt der Aufnahme (Unix-Sekunden)
    #[serde(default)]
    pub added_at: i64,
    /// Aktiv / Deaktiviert (weiche Sperre ohne Löschen)
    #[serde(default = "bool_true")]
    pub active: bool,
    /// Anzahl signierter Blöcke (Statistik)
    #[serde(default)]
    pub blocks_signed: u64,
}

fn bool_true() -> bool { true }

impl ValidatorInfo {
    pub fn new(node_id: impl Into<String>, public_key_hex: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            public_key_hex: public_key_hex.into(),
            name: String::new(),
            endpoint: String::new(),
            added_at: Utc::now().timestamp(),
            active: true,
            blocks_signed: 0,
        }
    }

    /// Ed25519-Public-Key aus Hex dekodieren
    pub fn verifying_key(&self) -> Result<VerifyingKey, String> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| format!("PubKey Hex ungültig: {e}"))?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| "PubKey muss 32 Byte sein".to_string())?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("PubKey ungültig: {e}"))
    }

    /// Block-Hash-Signatur verifizieren
    pub fn verify_block_signature(&self, block_hash: &str, signature_hex: &str) -> bool {
        if signature_hex.is_empty() { return false; }
        let Ok(vk) = self.verifying_key() else { return false; };
        let Ok(sig_bytes) = hex::decode(signature_hex) else { return false; };
        let Ok(arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false; };
        let sig = Signature::from_bytes(&arr);
        vk.verify(block_hash.as_bytes(), &sig).is_ok()
    }
}

// ─── Validator-Set ───────────────────────────────────────────────────────────

/// Persistente Whitelist aller bekannten Validatoren.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    fn path() -> String {
        format!("{}/validators.json", data_dir())
    }

    pub fn load() -> Self {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => ValidatorSet::default(),
        }
    }

    pub fn save(&self) {
        let path = Self::path();
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, s);
        }
    }

    /// Validator aufnehmen (oder aktualisieren falls node_id bereits vorhanden)
    pub fn add(&mut self, info: ValidatorInfo) {
        if let Some(existing) = self.validators.iter_mut().find(|v| v.node_id == info.node_id) {
            *existing = info;
        } else {
            self.validators.push(info);
        }
        self.save();
    }

    /// Validator entfernen
    pub fn remove(&mut self, node_id: &str) -> bool {
        let before = self.validators.len();
        self.validators.retain(|v| v.node_id != node_id);
        let removed = self.validators.len() < before;
        if removed { self.save(); }
        removed
    }

    /// Validator (de-)aktivieren
    pub fn set_active(&mut self, node_id: &str, active: bool) -> bool {
        if let Some(v) = self.validators.iter_mut().find(|v| v.node_id == node_id) {
            v.active = active;
            self.save();
            return true;
        }
        false
    }

    /// Prüfen ob node_id ein aktiver Validator ist
    pub fn is_active_validator(&self, node_id: &str) -> bool {
        self.validators.iter().any(|v| v.node_id == node_id && v.active)
    }

    /// Validator per node_id finden
    pub fn get(&self, node_id: &str) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| v.node_id == node_id)
    }

    /// Validator per node_id finden (mutable)
    pub fn get_mut(&mut self, node_id: &str) -> Option<&mut ValidatorInfo> {
        self.validators.iter_mut().find(|v| v.node_id == node_id)
    }

    /// Anzahl aktiver Validatoren
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.active).count()
    }

    /// Supermajorität: ⌊2/3⌋ + 1 der aktiven Validatoren
    pub fn supermajority_threshold(&self) -> usize {
        let n = self.active_count();
        if n == 0 { return 1; }
        (n * 2 / 3) + 1
    }

    /// Einfache Mehrheit: > 50%
    pub fn simple_majority_threshold(&self) -> usize {
        let n = self.active_count();
        if n == 0 { return 1; }
        (n / 2) + 1
    }

    /// Block-Signatur durch einen bekannten aktiven Validator prüfen
    pub fn verify_block(
        &self,
        block_hash: &str,
        signer_node_id: &str,
        signature_hex: &str,
    ) -> BlockVerifyResult {
        if self.validators.is_empty() {
            // Kein Validator konfiguriert → PoA deaktiviert, alles erlaubt
            return BlockVerifyResult::NoValidatorsConfigured;
        }
        let Some(validator) = self.get(signer_node_id) else {
            return BlockVerifyResult::UnknownValidator;
        };
        if !validator.active {
            return BlockVerifyResult::ValidatorInactive;
        }
        if validator.verify_block_signature(block_hash, signature_hex) {
            BlockVerifyResult::Valid
        } else {
            BlockVerifyResult::InvalidSignature
        }
    }

    // ─── Stake-gewichtete Validator-Auswahl ────────────────────────────────────
    //
    // Pro Block wird deterministisch ein Validator ausgewählt:
    //   1. Seed = SHA256(prev_hash || block_index)
    //   2. Jeder aktive, nicht-gejailte Validator bekommt ein Gewicht (Stake + Basis-Gewicht)
    //   3. Gewichtete Auswahl: U64 aus Seed → position in kumulativer Gewichtsliste
    //
    // Validatoren ohne Stake bekommen ein Basis-Gewicht von 1 STONE,
    // damit sie in Single-Node/Testnet trotzdem ausgewählt werden können.

    /// Wählt deterministisch einen aktiven Validator für einen bestimmten Block-Slot.
    ///
    /// - `stakes`: Mapping von Wallet-Adresse → gestakter Betrag.
    ///   Wenn leer, wird gleichmäßig rotiert (Legacy-Verhalten).
    /// - `jailed`: Set von Validator-IDs die derzeit im Jail sind.
    /// - `wallet_map`: Mapping von Validator-Node-ID → Wallet-Adresse.
    ///
    /// Gibt `None` zurück wenn keine aktiven Validatoren vorhanden sind.
    pub fn select_validator_weighted(
        &self,
        prev_hash: &str,
        block_index: u64,
        stakes: &HashMap<String, rust_decimal::Decimal>,
        jailed: &std::collections::HashSet<String>,
        wallet_map: &HashMap<String, String>,
    ) -> Option<&ValidatorInfo> {
        let active: Vec<&ValidatorInfo> = self.validators.iter()
            .filter(|v| v.active)
            .filter(|v| !jailed.contains(&v.node_id))
            .collect();
        if active.is_empty() {
            return None;
        }

        // SHA256-Seed (deterministisch)
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(block_index.to_le_bytes());
        let hash = hasher.finalize();
        let seed = u64::from_le_bytes(hash[24..32].try_into().unwrap());

        // Basis-Gewicht: 1 STONE (damit Validatoren ohne Stake mitmachen können)
        let base_weight = rust_decimal::Decimal::ONE;

        // Gewichte berechnen: Stake + Basis (alles in ganzen STONE-Einheiten als u64)
        let weights: Vec<u64> = active.iter().map(|v| {
            let wallet = wallet_map.get(&v.node_id);
            let stake = wallet
                .and_then(|w| stakes.get(w))
                .copied()
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let total = stake + base_weight;
            // In "milli-STONE" umrechnen für Ganzzahl-Genauigkeit (× 1000)
            use rust_decimal::prelude::ToPrimitive;
            (total * rust_decimal::Decimal::from(1000u64))
                .to_u64()
                .unwrap_or(1000) // Fallback: 1 STONE
        }).collect();

        let total_weight: u64 = weights.iter().sum();
        if total_weight == 0 {
            // Fallback: gleichmäßig
            let idx = (seed % active.len() as u64) as usize;
            return Some(active[idx]);
        }

        // Gewichtete Auswahl via kumulativer Summe
        let position = seed % total_weight;
        let mut cumulative: u64 = 0;
        for (i, &w) in weights.iter().enumerate() {
            cumulative += w;
            if position < cumulative {
                return Some(active[i]);
            }
        }

        // Fallback (sollte nie passieren)
        Some(active[active.len() - 1])
    }

    /// Legacy-Methode: Wählt Validator ohne Stake-Gewichtung (gleichmäßig).
    ///
    /// Für Rückwärtskompatibilität und Fälle wo kein StakingPool verfügbar ist.
    pub fn select_validator(&self, prev_hash: &str, block_index: u64) -> Option<&ValidatorInfo> {
        let active: Vec<&ValidatorInfo> = self.validators.iter()
            .filter(|v| v.active)
            .collect();
        if active.is_empty() {
            return None;
        }
        // Deterministische Auswahl via SHA256
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(block_index.to_le_bytes());
        let hash = hasher.finalize();
        let seed = u64::from_le_bytes(hash[24..32].try_into().unwrap());
        let idx = (seed % active.len() as u64) as usize;
        Some(active[idx])
    }

    /// Prüft ob eine bestimmte Node-ID der ausgewählte Validator für diesen Slot ist (stake-gewichtet).
    pub fn is_selected_validator_weighted(
        &self,
        node_id: &str,
        prev_hash: &str,
        block_index: u64,
        stakes: &HashMap<String, rust_decimal::Decimal>,
        jailed: &std::collections::HashSet<String>,
        wallet_map: &HashMap<String, String>,
    ) -> bool {
        if self.validators.is_empty() {
            return true; // PoA deaktiviert
        }
        match self.select_validator_weighted(prev_hash, block_index, stakes, jailed, wallet_map) {
            Some(v) => v.node_id == node_id,
            None => true, // Keine aktiven Validatoren
        }
    }

    /// Prüft ob eine bestimmte Node-ID der ausgewählte Validator für diesen Slot ist.
    ///
    /// Gibt `true` zurück wenn:
    /// - Keine Validatoren konfiguriert sind (PoA deaktiviert → jeder darf)
    /// - Die Node-ID der ausgewählte Validator ist
    pub fn is_selected_validator(
        &self,
        node_id: &str,
        prev_hash: &str,
        block_index: u64,
    ) -> bool {
        if self.validators.is_empty() {
            return true; // PoA deaktiviert
        }
        match self.select_validator(prev_hash, block_index) {
            Some(v) => v.node_id == node_id,
            None => true, // Keine aktiven Validatoren
        }
    }

    /// Bestimmt den Backup-Rang einer Node für einen bestimmten Block-Slot.
    ///
    /// Gibt `Some(rank)` zurück wenn die Node als Backup-Proposer infrage kommt:
    /// - rank=1 → erster Backup (darf nach 1× MINING_INTERVAL einspringen)
    /// - rank=2 → zweiter Backup (nach 2× MINING_INTERVAL)
    /// - usw.
    ///
    /// Gibt `None` zurück wenn die Node kein aktiver Validator ist oder
    /// der primäre Proposer ist (rank=0 wäre der primäre).
    pub fn backup_proposer_rank(
        &self,
        node_id: &str,
        prev_hash: &str,
        block_index: u64,
        stakes: &HashMap<String, rust_decimal::Decimal>,
        jailed: &std::collections::HashSet<String>,
        wallet_map: &HashMap<String, String>,
    ) -> Option<usize> {
        let active: Vec<&ValidatorInfo> = self.validators.iter()
            .filter(|v| v.active)
            .filter(|v| !jailed.contains(&v.node_id))
            .collect();
        if active.len() <= 1 {
            return None; // Kein Backup möglich
        }

        // Gleicher SHA256-Seed wie select_validator_weighted
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(block_index.to_le_bytes());
        let hash = hasher.finalize();
        let seed = u64::from_le_bytes(hash[24..32].try_into().unwrap());

        let base_weight = rust_decimal::Decimal::ONE;
        let weights: Vec<u64> = active.iter().map(|v| {
            let wallet = wallet_map.get(&v.node_id);
            let stake = wallet
                .and_then(|w| stakes.get(w))
                .copied()
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let total = stake + base_weight;
            use rust_decimal::prelude::ToPrimitive;
            (total * rust_decimal::Decimal::from(1000u64))
                .to_u64()
                .unwrap_or(1000)
        }).collect();

        let total_weight: u64 = weights.iter().sum();
        if total_weight == 0 {
            // Fallback: einfache Index-Rotation
            let primary_idx = (seed % active.len() as u64) as usize;
            for rank in 1..active.len() {
                let idx = (primary_idx + rank) % active.len();
                if active[idx].node_id == node_id {
                    return Some(rank);
                }
            }
            return None;
        }

        // Sortierte Reihenfolge nach gewichteter Position:
        // Primärer Validator = Position im kumulativen Gewicht.
        // Backup-Reihenfolge = nächste Validatoren in der kumulativen Liste (wraparound).
        let position = seed % total_weight;
        let mut cumulative: u64 = 0;
        let mut primary_idx = active.len() - 1;
        for (i, &w) in weights.iter().enumerate() {
            cumulative += w;
            if position < cumulative {
                primary_idx = i;
                break;
            }
        }

        // Backup-Rang bestimmen: nächste Validatoren nach dem Primary
        for rank in 1..active.len() {
            let idx = (primary_idx + rank) % active.len();
            if active[idx].node_id == node_id {
                return Some(rank);
            }
        }

        None
    }

    /// Block-Signatur + randomisierte Validator-Auswahl verifizieren.
    ///
    /// Erweiterte Version von `verify_block` die zusätzlich prüft ob der Signer
    /// für diesen Block-Slot der ausgewählte Validator war (SHA256-basiert).
    /// `prev_hash` ist der Hash des vorherigen Blocks (oder "genesis" für Block #0).
    pub fn verify_block_with_selection(
        &self,
        block_hash: &str,
        signer_node_id: &str,
        signature_hex: &str,
        prev_hash: &str,
        block_index: u64,
    ) -> BlockVerifyResult {
        // Basis-Prüfung (Signatur + Validator-Status)
        let basic = self.verify_block(block_hash, signer_node_id, signature_hex);
        if !basic.is_acceptable() {
            return basic;
        }
        // Bei NoValidatorsConfigured → keine weitere Prüfung
        if basic == BlockVerifyResult::NoValidatorsConfigured {
            return basic;
        }
        // Prüfe ob der Signer der ausgewählte Validator für diesen Slot war.
        // Auch Backup-Proposer (rank 1-3) sind erlaubt — sie springen ein
        // wenn der primäre Validator seinen Slot verpasst hat.
        if self.is_selected_validator(signer_node_id, prev_hash, block_index) {
            return BlockVerifyResult::Valid;
        }
        // Prüfe ob der Signer ein Backup-Proposer ist (rank 1..3)
        let empty_stakes = HashMap::new();
        let empty_jailed = std::collections::HashSet::new();
        let wallet_map: HashMap<String, String> = self.validators.iter()
            .filter(|v| v.active && !v.public_key_hex.is_empty())
            .map(|v| (v.node_id.clone(), v.public_key_hex.clone()))
            .collect();
        if let Some(rank) = self.backup_proposer_rank(
            signer_node_id, prev_hash, block_index,
            &empty_stakes, &empty_jailed, &wallet_map,
        ) {
            if rank <= 3 {
                return BlockVerifyResult::Valid;
            }
        }
        BlockVerifyResult::NotSelectedValidator
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockVerifyResult {
    /// Keine Validatoren konfiguriert → PoA inaktiv, Block akzeptiert
    NoValidatorsConfigured,
    /// Signatur gültig, Validator bekannt und aktiv
    Valid,
    /// Signer ist nicht in der Whitelist
    UnknownValidator,
    /// Validator bekannt aber deaktiviert
    ValidatorInactive,
    /// Signatur mathematisch falsch
    InvalidSignature,
    /// Signatur gültig, aber dieser Validator war nicht der ausgewählte für diesen Slot
    NotSelectedValidator,
}

impl BlockVerifyResult {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::NoValidatorsConfigured | Self::Valid)
    }
}

// ─── Block-Signierung ─────────────────────────────────────────────────────────

/// Block-Hash mit einem Validator-Schlüssel signieren.
/// Gibt die Signatur als 128-Zeichen-Hex zurück.
pub fn sign_block(signing_key: &SigningKey, block_hash: &str) -> String {
    let sig: Signature = signing_key.sign(block_hash.as_bytes());
    hex::encode(sig.to_bytes())
}

// ─── Block-Proposal ──────────────────────────────────────────────────────────

/// Ein Validator schlägt einen neuen Block vor.
/// Wird an alle bekannten Validator-Peers geschickt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    /// Der vorgeschlagene Block
    pub block: Block,
    /// Node-ID des Proposers
    pub proposer_id: String,
    /// Ed25519-Signatur über block.hash (128 Hex-Zeichen)
    pub proposer_signature: String,
    /// Vorschlags-Zeitpunkt
    pub proposed_at: i64,
    /// Runden-Nummer (für Deduplizierung)
    pub round: u64,
}

impl BlockProposal {
    pub fn new(block: Block, proposer_id: String, signing_key: &SigningKey, round: u64) -> Self {
        let sig = sign_block(signing_key, &block.hash);
        Self {
            block,
            proposer_id,
            proposer_signature: sig,
            proposed_at: Utc::now().timestamp(),
            round,
        }
    }

    /// Signatur des Proposers gegen seinen Public Key prüfen
    pub fn verify_proposer(&self, validator_set: &ValidatorSet) -> bool {
        matches!(
            validator_set.verify_block(&self.block.hash, &self.proposer_id, &self.proposer_signature),
            BlockVerifyResult::Valid | BlockVerifyResult::NoValidatorsConfigured
        )
    }
}

// ─── 2-Phase BFT Voting ───────────────────────────────────────────────────────

/// Phase des BFT-Konsensus:
/// 1. **PreVote** – Validator signalisiert Bereitschaft, den Block zu akzeptieren
/// 2. **PreCommit** – Nachdem ⅔+1 Pre-Votes vorliegen, bestätigt der Validator
///    seine unwiderrufliche Zustimmung.
/// Block wird erst committed wenn ⅔+1 Pre-Commits eingegangen sind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VotePhase {
    PreVote,
    PreCommit,
}

impl Default for VotePhase {
    fn default() -> Self { VotePhase::PreVote }
}

/// Abstimmungs-Nachricht eines Validators für einen vorgeschlagenen Block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Runden-Nummer (muss mit Proposal übereinstimmen)
    pub round: u64,
    /// Hash des Blocks über den abgestimmt wird
    pub block_hash: String,
    /// Node-ID des Abstimmenden
    pub voter_id: String,
    /// true = Zustimmung, false = Ablehnung
    pub accept: bool,
    /// Ed25519-Signatur über (phase_byte || round.to_le_bytes() || block_hash || accept_byte)
    pub signature: String,
    /// Zeitpunkt
    pub voted_at: i64,
    /// BFT-Phase: PreVote oder PreCommit
    #[serde(default)]
    pub phase: VotePhase,
    /// Optionale Begründung bei Ablehnung
    #[serde(default)]
    pub reason: String,
}

impl VoteMessage {
    pub fn new(
        round: u64,
        block_hash: String,
        voter_id: String,
        accept: bool,
        signing_key: &SigningKey,
        reason: String,
    ) -> Self {
        Self::new_with_phase(round, block_hash, voter_id, accept, signing_key, reason, VotePhase::PreVote)
    }

    /// Erstellt eine VoteMessage mit expliziter Phase (PreVote oder PreCommit).
    pub fn new_with_phase(
        round: u64,
        block_hash: String,
        voter_id: String,
        accept: bool,
        signing_key: &SigningKey,
        reason: String,
        phase: VotePhase,
    ) -> Self {
        let mut msg = Vec::new();
        msg.push(match phase { VotePhase::PreVote => 0x01, VotePhase::PreCommit => 0x02 });
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(block_hash.as_bytes());
        msg.push(if accept { 1 } else { 0 });
        let sig: Signature = signing_key.sign(&msg);
        Self {
            round,
            block_hash,
            voter_id,
            accept,
            signature: hex::encode(sig.to_bytes()),
            voted_at: Utc::now().timestamp(),
            phase,
            reason,
        }
    }

    /// Signatur verifizieren (phasenabhängig)
    pub fn verify(&self, validator_set: &ValidatorSet) -> bool {
        let Some(v) = validator_set.get(&self.voter_id) else { return false; };
        let Ok(vk) = v.verifying_key() else { return false; };
        let Ok(sig_bytes) = hex::decode(&self.signature) else { return false; };
        let Ok(arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false; };
        let sig = Signature::from_bytes(&arr);
        let mut msg = Vec::new();
        msg.push(match self.phase { VotePhase::PreVote => 0x01, VotePhase::PreCommit => 0x02 });
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(self.block_hash.as_bytes());
        msg.push(if self.accept { 1 } else { 0 });
        vk.verify(&msg, &sig).is_ok()
    }
}

/// Anfrage für Phase 2 (Pre-Commit):
/// Der Proposer sendet die gesammelten Pre-Votes als Beweis, dass ⅔+1
/// Pre-Votes vorliegen. Empfänger verifizieren dies und senden dann
/// ihre Pre-Commit-Stimme zurück.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreCommitRequest {
    /// Runden-Nummer
    pub round: u64,
    /// Hash des Blocks
    pub block_hash: String,
    /// Node-ID des Proposers
    pub proposer_id: String,
    /// Gesammelte Pre-Vote-Nachrichten als Beweis
    pub pre_votes: Vec<VoteMessage>,
}

// ─── Voting-Tally ─────────────────────────────────────────────────────────────

/// Sammelt Stimmen für eine laufende 2-Phase-BFT Konsensus-Runde.
///
/// **Ablauf:**
/// 1. `PreVote`-Phase: Validators signalisieren Bereitschaft
/// 2. Wenn ⅔+1 Pre-Votes → Übergang zu `PreCommit`-Phase  
/// 3. `PreCommit`-Phase: Validators bestätigen unwiderruflich
/// 4. Wenn ⅔+1 Pre-Commits → Block wird committed
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VotingRound {
    pub round: u64,
    pub block_hash: String,
    pub proposer_id: String,
    pub started_at: i64,
    /// Aktuelle Phase der Runde
    #[serde(default)]
    pub phase: VotePhase,
    /// Phase 1: voter_id → PreVote
    #[serde(default)]
    pub pre_votes: HashMap<String, VoteMessage>,
    /// Phase 2: voter_id → PreCommit
    #[serde(default)]
    pub pre_commits: HashMap<String, VoteMessage>,
    /// Legacy-Feld für Kompatibilität (= pre_votes)
    #[serde(default)]
    pub votes: HashMap<String, VoteMessage>,
    pub finalized: bool,
    pub accepted: bool,
}

impl VotingRound {
    pub fn new(round: u64, block_hash: String, proposer_id: String) -> Self {
        Self {
            round,
            block_hash,
            proposer_id,
            started_at: Utc::now().timestamp(),
            phase: VotePhase::PreVote,
            pre_votes: HashMap::new(),
            pre_commits: HashMap::new(),
            votes: HashMap::new(),
            finalized: false,
            accepted: false,
        }
    }

    /// Pre-Vote hinzufügen (Phase 1). Nur gültig wenn Phase == PreVote.
    pub fn add_pre_vote(&mut self, vote: VoteMessage, validator_set: &ValidatorSet) -> Result<(), String> {
        if vote.round != self.round {
            return Err(format!("Falsche Runde: {} ≠ {}", vote.round, self.round));
        }
        if vote.block_hash != self.block_hash {
            return Err("Block-Hash stimmt nicht überein".into());
        }
        if vote.phase != VotePhase::PreVote {
            return Err(format!("Erwartete PreVote, erhielt {:?}", vote.phase));
        }
        if !vote.verify(validator_set) {
            return Err("Ungültige PreVote-Signatur".into());
        }
        self.pre_votes.insert(vote.voter_id.clone(), vote.clone());
        // Legacy-Kompatibilität
        self.votes.insert(vote.voter_id.clone(), vote);
        Ok(())
    }

    /// Pre-Commit hinzufügen (Phase 2). Nur gültig wenn Phase == PreCommit.
    pub fn add_pre_commit(&mut self, vote: VoteMessage, validator_set: &ValidatorSet) -> Result<(), String> {
        if self.phase != VotePhase::PreCommit {
            return Err("Runde ist noch nicht in PreCommit-Phase".into());
        }
        if vote.round != self.round {
            return Err(format!("Falsche Runde: {} ≠ {}", vote.round, self.round));
        }
        if vote.block_hash != self.block_hash {
            return Err("Block-Hash stimmt nicht überein".into());
        }
        if vote.phase != VotePhase::PreCommit {
            return Err(format!("Erwartete PreCommit, erhielt {:?}", vote.phase));
        }
        if !vote.verify(validator_set) {
            return Err("Ungültige PreCommit-Signatur".into());
        }
        self.pre_commits.insert(vote.voter_id.clone(), vote);
        Ok(())
    }

    /// Legacy-Kompatibilität: add_vote leitet an add_pre_vote weiter.
    pub fn add_vote(&mut self, vote: VoteMessage, validator_set: &ValidatorSet) -> Result<(), String> {
        if vote.phase == VotePhase::PreCommit {
            self.add_pre_commit(vote, validator_set)
        } else {
            self.add_pre_vote(vote, validator_set)
        }
    }

    /// Pre-Vote Auswertung: Supermajorität bei Pre-Votes erreicht?
    pub fn tally_pre_votes(&self, validator_set: &ValidatorSet) -> VoteTally {
        let accepts = self.pre_votes.values().filter(|v| v.accept).count();
        let rejects = self.pre_votes.values().filter(|v| !v.accept).count();
        let total_active = validator_set.active_count();
        let threshold = validator_set.supermajority_threshold();
        VoteTally {
            accepts,
            rejects,
            abstentions: total_active.saturating_sub(self.pre_votes.len()),
            total_validators: total_active,
            threshold,
            quorum_reached: accepts >= threshold,
        }
    }

    /// Pre-Commit Auswertung: Supermajorität bei Pre-Commits erreicht?
    pub fn tally_pre_commits(&self, validator_set: &ValidatorSet) -> VoteTally {
        let accepts = self.pre_commits.values().filter(|v| v.accept).count();
        let rejects = self.pre_commits.values().filter(|v| !v.accept).count();
        let total_active = validator_set.active_count();
        let threshold = validator_set.supermajority_threshold();
        VoteTally {
            accepts,
            rejects,
            abstentions: total_active.saturating_sub(self.pre_commits.len()),
            total_validators: total_active,
            threshold,
            quorum_reached: accepts >= threshold,
        }
    }

    /// Übergang zur PreCommit-Phase (nach ⅔+1 Pre-Votes).
    pub fn advance_to_precommit(&mut self) {
        self.phase = VotePhase::PreCommit;
    }

    /// Gibt die gesammelten Pre-Votes als Vec zurück (für PreCommitRequest).
    pub fn collected_pre_votes(&self) -> Vec<VoteMessage> {
        self.pre_votes.values().filter(|v| v.accept).cloned().collect()
    }

    /// Legacy: tally() wirkt auf die aktuelle Phase.
    pub fn tally(&self, validator_set: &ValidatorSet) -> VoteTally {
        match self.phase {
            VotePhase::PreVote => self.tally_pre_votes(validator_set),
            VotePhase::PreCommit => self.tally_pre_commits(validator_set),
        }
    }

    /// Finalisiert die Runde anhand der PreCommit-Stimmen.
    pub fn finalize(&mut self, validator_set: &ValidatorSet) -> VoteTally {
        let tally = self.tally_pre_commits(validator_set);
        self.finalized = true;
        self.accepted = tally.quorum_reached;
        tally
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTally {
    pub accepts: usize,
    pub rejects: usize,
    pub abstentions: usize,
    pub total_validators: usize,
    pub threshold: usize,
    pub quorum_reached: bool,
}

// ─── Finality: Checkpoints ────────────────────────────────────────────────────

/// Intervall in Blöcken zwischen Checkpoints.
/// Bei 30s Mining-Interval = alle ~50 Minuten ein Checkpoint.
pub const CHECKPOINT_INTERVAL: u64 = 100;

/// Maximale Reorg-Tiefe: Kein Rollback über den letzten Checkpoint hinaus.
/// Verhindert Long-Range-Attacks und macht Blöcke ab dem Checkpoint unwiderruflich.
pub const MAX_REORG_DEPTH: u64 = CHECKPOINT_INTERVAL;

/// Ein Checkpoint markiert einen unwiderruflichen Punkt in der Chain.
///
/// Einmal finalisiert (⅔+1 Signaturen), kann kein Reorg/Rollback über diesen
/// Block hinaus stattfinden. Clients können sich auf Checkpoints verlassen
/// um zu wissen, ab wann eine TX endgültig ist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block-Index an dem der Checkpoint erstellt wurde
    pub block_index: u64,
    /// Hash des Blocks an diesem Index
    pub block_hash: String,
    /// Signaturen der Validatoren: node_id → Ed25519-Signatur über (block_index || block_hash)
    pub signatures: HashMap<String, String>,
    /// Anzahl Signaturen bei Finalisierung
    pub signature_count: usize,
    /// Minimal benötigte Signaturen (⅔+1 zum Zeitpunkt der Erstellung)
    pub required_signatures: usize,
    /// Zeitpunkt der Checkpoint-Erstellung (Unix-Sekunden)
    pub created_at: i64,
    /// Ob der Checkpoint finalisiert (genug Signaturen) ist
    pub finalized: bool,
}

impl Checkpoint {
    /// Erstellt einen neuen Checkpoint für einen bestimmten Block.
    pub fn new(block_index: u64, block_hash: String, required: usize) -> Self {
        Self {
            block_index,
            block_hash,
            signatures: HashMap::new(),
            signature_count: 0,
            required_signatures: required,
            created_at: Utc::now().timestamp(),
            finalized: false,
        }
    }

    /// Nachricht die von Validatoren signiert wird: "CHECKPOINT:block_index:block_hash"
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = b"CHECKPOINT:".to_vec();
        msg.extend_from_slice(&self.block_index.to_le_bytes());
        msg.push(b':');
        msg.extend_from_slice(self.block_hash.as_bytes());
        msg
    }

    /// Eigene Signatur hinzufügen
    pub fn sign(&mut self, node_id: &str, signing_key: &SigningKey) {
        let msg = self.signing_message();
        let sig: Signature = signing_key.sign(&msg);
        self.signatures.insert(node_id.to_string(), hex::encode(sig.to_bytes()));
        self.signature_count = self.signatures.len();
        if self.signature_count >= self.required_signatures {
            self.finalized = true;
        }
    }

    /// Signatur eines Validators verifizieren und hinzufügen
    pub fn add_signature(
        &mut self,
        node_id: &str,
        signature_hex: &str,
        validator_set: &ValidatorSet,
    ) -> Result<(), String> {
        // Validator muss bekannt und aktiv sein
        let validator = validator_set.get(node_id)
            .ok_or_else(|| format!("Unbekannter Validator: {node_id}"))?;
        if !validator.active {
            return Err(format!("Validator '{node_id}' ist inaktiv"));
        }

        // Signatur verifizieren
        let vk = validator.verifying_key()
            .map_err(|e| format!("PubKey-Fehler für '{node_id}': {e}"))?;
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| format!("Signatur-Hex ungültig: {e}"))?;
        let arr: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| "Signatur muss 64 Byte sein".to_string())?;
        let sig = Signature::from_bytes(&arr);

        let msg = self.signing_message();
        vk.verify(&msg, &sig)
            .map_err(|_| format!("Ungültige Signatur von '{node_id}'"))?;

        self.signatures.insert(node_id.to_string(), signature_hex.to_string());
        self.signature_count = self.signatures.len();
        if self.signature_count >= self.required_signatures {
            self.finalized = true;
        }
        Ok(())
    }

    /// Ist der Checkpoint finalisiert (genug Signaturen)?
    pub fn is_finalized(&self) -> bool {
        self.finalized && self.signature_count >= self.required_signatures
    }
}

/// Persistente Checkpoint-Verwaltung.
///
/// Checkpoints werden in `{data_dir}/checkpoints.json` gespeichert und bei
/// jedem Node-Start geladen. Sie schützen vor Reorgs über finalisierte Blöcke
/// hinaus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckpointStore {
    /// Alle Checkpoints, nach block_index sortiert
    pub checkpoints: Vec<Checkpoint>,
}

impl CheckpointStore {
    fn path() -> String {
        format!("{}/checkpoints.json", data_dir())
    }

    pub fn load() -> Self {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(), s);
        }
    }

    /// Checkpoint hinzufügen oder aktualisieren (nach block_index sortiert halten)
    pub fn add_or_update(&mut self, checkpoint: Checkpoint) {
        if let Some(existing) = self.checkpoints.iter_mut()
            .find(|c| c.block_index == checkpoint.block_index)
        {
            // Signaturen zusammenführen
            for (k, v) in &checkpoint.signatures {
                existing.signatures.insert(k.clone(), v.clone());
            }
            existing.signature_count = existing.signatures.len();
            if existing.signature_count >= existing.required_signatures {
                existing.finalized = true;
            }
        } else {
            self.checkpoints.push(checkpoint);
            self.checkpoints.sort_by_key(|c| c.block_index);
        }
        self.save();
    }

    /// Höchster finalisierter Checkpoint
    pub fn latest_finalized(&self) -> Option<&Checkpoint> {
        self.checkpoints.iter().rev().find(|c| c.is_finalized())
    }

    /// Höchster Checkpoint (finalisiert oder nicht)
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    /// Prüft ob ein Reorg bis zu `reorg_target_index` erlaubt ist.
    ///
    /// Gibt `Err` zurück wenn ein finalisierter Checkpoint verletzt würde.
    pub fn check_reorg_allowed(&self, reorg_target_index: u64) -> Result<(), String> {
        if let Some(cp) = self.latest_finalized() {
            if reorg_target_index <= cp.block_index {
                return Err(format!(
                    "Reorg bis Block #{} nicht erlaubt: Checkpoint bei Block #{} ist finalisiert \
                     ({} von {} Signaturen). Blöcke bis einschließlich #{} sind unwiderruflich.",
                    reorg_target_index, cp.block_index,
                    cp.signature_count, cp.required_signatures, cp.block_index,
                ));
            }
        }
        Ok(())
    }

    /// Prüft ob für einen bestimmten Block-Index ein Checkpoint erstellt werden sollte.
    pub fn should_create_checkpoint(&self, block_index: u64) -> bool {
        if block_index == 0 { return false; }
        if block_index % CHECKPOINT_INTERVAL != 0 { return false; }
        // Bereits einen Checkpoint für diesen Index?
        !self.checkpoints.iter().any(|c| c.block_index == block_index)
    }

    /// Checkpoint für einen Block-Index finden
    pub fn get(&self, block_index: u64) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.block_index == block_index)
    }

    /// Anzahl finalisierter Checkpoints
    pub fn finalized_count(&self) -> usize {
        self.checkpoints.iter().filter(|c| c.is_finalized()).count()
    }
}

// ─── Slashing-Mechanismus ────────────────────────────────────────────────────

/// Konstanten für Slashing-Penaltys.
///
/// - `SLASH_DOUBLE_SIGN_PERCENT`:  Strafe bei Double-Signing (% vom Stake)
/// - `SLASH_DOWNTIME_PERCENT`:     Strafe bei Downtime (% vom Stake)
/// - `SLASH_INVALID_BLOCK_PERCENT`: Strafe bei ungültigem Block-Vorschlag
/// - `DOWNTIME_THRESHOLD_BLOCKS`:  Wie viele Blöcke ein Validator fehlen darf bevor Downtime-Slash
/// - `SLASH_JAIL_DURATION_SECS`:   Wie lange ein geslashter Validator gesperrt wird
pub const SLASH_DOUBLE_SIGN_PERCENT: u64 = 5;    // 5% vom Stake
pub const SLASH_DOWNTIME_PERCENT: u64 = 1;       // 1% vom Stake
pub const SLASH_INVALID_BLOCK_PERCENT: u64 = 10;  // 10% vom Stake
pub const DOWNTIME_THRESHOLD_BLOCKS: u64 = 50;   // ~25 Min bei 30s Intervall
pub const SLASH_JAIL_DURATION_SECS: i64 = 86400; // 24 Stunden

/// Art des Verstoßes im Slashing-System
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlashingOffense {
    /// Validator hat zwei verschiedene Blöcke für denselben Index signiert
    DoubleSigning {
        block_index: u64,
        hash_a: String,
        hash_b: String,
    },
    /// Validator war für zu viele aufeinanderfolgende Blöcke offline
    Downtime {
        missed_blocks: u64,
        from_index: u64,
        to_index: u64,
    },
    /// Validator hat einen ungültigen Block vorgeschlagen
    InvalidBlockProposal {
        block_index: u64,
        reason: String,
    },
}

impl SlashingOffense {
    /// Strafe als Prozentsatz des Stakes
    pub fn penalty_percent(&self) -> u64 {
        match self {
            SlashingOffense::DoubleSigning { .. } => SLASH_DOUBLE_SIGN_PERCENT,
            SlashingOffense::Downtime { .. } => SLASH_DOWNTIME_PERCENT,
            SlashingOffense::InvalidBlockProposal { .. } => SLASH_INVALID_BLOCK_PERCENT,
        }
    }

    /// Beschreibung für Logs / UI
    pub fn description(&self) -> String {
        match self {
            SlashingOffense::DoubleSigning { block_index, hash_a, hash_b } => {
                format!(
                    "Double-Signing bei Block #{}: {} vs. {}",
                    block_index,
                    &hash_a[..16.min(hash_a.len())],
                    &hash_b[..16.min(hash_b.len())]
                )
            }
            SlashingOffense::Downtime { missed_blocks, from_index, to_index } => {
                format!(
                    "Downtime: {} Blöcke verpasst (#{} bis #{})",
                    missed_blocks, from_index, to_index
                )
            }
            SlashingOffense::InvalidBlockProposal { block_index, reason } => {
                format!("Ungültiger Block #{}: {}", block_index, reason)
            }
        }
    }
}

/// Ein Slashing-Eintrag für die Audit-Historie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    /// Validator der bestraft wurde
    pub validator_id: String,
    /// Wallet-Adresse des Validators (für Stake-Abzug)
    pub wallet_address: Option<String>,
    /// Art des Verstoßes
    pub offense: SlashingOffense,
    /// Strafe in Prozent vom Stake
    pub penalty_percent: u64,
    /// Tatsächlich abgezogener Betrag (STONE)
    pub slashed_amount: String,
    /// Wurde der Validator gejailed?
    pub jailed: bool,
    /// Jail-Endzeit (Unix-Sekunden), None wenn nicht gejailed
    pub jail_until: Option<i64>,
    /// Block bei dem der Verstoß festgestellt wurde
    pub detected_at_block: u64,
    /// Zeitpunkt (Unix-Sekunden)
    pub timestamp: i64,
}

/// Persistenter Slashing-Store.
///
/// Speichert alle Slashing-Events und den Jail-Status von Validatoren.
/// Persistenz in `{data_dir}/slashing.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlashingStore {
    /// Alle Slashing-Records (chronologisch)
    pub records: Vec<SlashingRecord>,
    /// Jail-Registry: validator_id → jail_until (Unix-Sekunden)
    pub jailed: HashMap<String, i64>,
    /// Downtime-Tracker: validator_id → letzer Block bei dem der Validator aktiv war
    pub last_active_block: HashMap<String, u64>,
}

impl SlashingStore {
    fn path() -> String {
        format!("{}/slashing.json", data_dir())
    }

    pub fn load() -> Self {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(), s);
        }
    }

    /// Prüft ob ein Validator derzeit im Jail ist.
    pub fn is_jailed(&self, validator_id: &str) -> bool {
        if let Some(&until) = self.jailed.get(validator_id) {
            Utc::now().timestamp() < until
        } else {
            false
        }
    }

    /// Entlässt Validatoren deren Jail-Zeit abgelaufen ist.
    /// Gibt die IDs der entlassenen Validatoren zurück.
    pub fn release_expired_jails(&mut self) -> Vec<String> {
        let now = Utc::now().timestamp();
        let released: Vec<String> = self.jailed.iter()
            .filter(|(_, &until)| now >= until)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &released {
            self.jailed.remove(id);
        }
        if !released.is_empty() {
            self.save();
        }
        released
    }

    /// Markiert einen Validator als aktiv bei einem bestimmten Block.
    pub fn mark_active(&mut self, validator_id: &str, block_index: u64) {
        self.last_active_block.insert(validator_id.to_string(), block_index);
    }

    /// Prüft ob ein Validator die Downtime-Schwelle überschritten hat.
    pub fn check_downtime(&self, validator_id: &str, current_block: u64) -> Option<SlashingOffense> {
        if let Some(&last_active) = self.last_active_block.get(validator_id) {
            let missed = current_block.saturating_sub(last_active);
            if missed >= DOWNTIME_THRESHOLD_BLOCKS {
                return Some(SlashingOffense::Downtime {
                    missed_blocks: missed,
                    from_index: last_active + 1,
                    to_index: current_block,
                });
            }
        }
        // Wenn der Validator noch nie aktiv war, kein Slash
        None
    }

    /// Registriert einen Slashing-Event.
    ///
    /// Gibt den `SlashingRecord` zurück. Die tatsächliche Stake-Reduktion
    /// muss vom Caller via `StakingPool` durchgeführt werden.
    pub fn record_slash(
        &mut self,
        validator_id: &str,
        wallet_address: Option<&str>,
        offense: SlashingOffense,
        slashed_amount: rust_decimal::Decimal,
        current_block: u64,
    ) -> SlashingRecord {
        let now = Utc::now().timestamp();
        let jail_until = now + SLASH_JAIL_DURATION_SECS;

        let record = SlashingRecord {
            validator_id: validator_id.to_string(),
            wallet_address: wallet_address.map(|s| s.to_string()),
            penalty_percent: offense.penalty_percent(),
            slashed_amount: slashed_amount.to_string(),
            offense,
            jailed: true,
            jail_until: Some(jail_until),
            detected_at_block: current_block,
            timestamp: now,
        };

        // Validator jailed
        self.jailed.insert(validator_id.to_string(), jail_until);
        self.records.push(record.clone());
        self.save();

        record
    }

    /// Anzahl Slashing-Events für einen Validator
    pub fn offense_count(&self, validator_id: &str) -> usize {
        self.records.iter().filter(|r| r.validator_id == validator_id).count()
    }

    /// Gesamtbetrag der geslashten STONE für einen Validator
    pub fn total_slashed(&self, validator_id: &str) -> rust_decimal::Decimal {
        self.records.iter()
            .filter(|r| r.validator_id == validator_id)
            .filter_map(|r| r.slashed_amount.parse::<rust_decimal::Decimal>().ok())
            .sum()
    }
}

// ─── Fork-Erkennung & Auflösung ──────────────────────────────────────────────

/// Ein Fork-Kandidat: ein Block auf einem bestimmten Index der eine Alternative darstellt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkCandidate {
    pub block_index: u64,
    pub block_hash: String,
    pub signer_id: String,
    pub validator_signature: String,
    /// Anzahl der Folge-Blöcke auf diesem Ast (chain length after this block)
    pub chain_length_after: u64,
    /// Zeitpunkt der Erstellung
    pub timestamp: i64,
    /// Signatur gültig laut ValidatorSet
    pub signature_valid: bool,
    /// Stake-Gewicht des Signers (in STONE, 0 wenn unbekannt)
    #[serde(default)]
    pub signer_stake_weight: u64,
}

/// Ergebnis der Fork-Auflösung
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkResolution {
    pub winning_hash: String,
    pub reason: ForkResolutionReason,
    pub candidates: Vec<ForkCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkResolutionReason {
    /// Nur ein Kandidat mit gültiger Validator-Signatur
    OnlyValidSignature,
    /// Längerer Ast gewinnt (longest-chain)
    LongestChain,
    /// Höherer Stake-Gewicht gewinnt (bei gleicher Länge)
    HighestStakeWeight,
    /// Gleiche Länge + gleiches Gewicht → lexikographisch kleinerer Hash
    LexicographicTiebreak,
    /// Kein Validator konfiguriert → erster Block gewinnt
    NoValidatorsFirstWins,
}

/// Löst einen Fork auf (stake-gewichtet).
///
/// Priorität:
/// 1. Nur Blöcke mit gültiger Validator-Signatur (wenn PoA aktiv)
/// 2. Längerer Folge-Chain (longest-chain rule)
/// 3. **Höheres kumulatives Stake-Gewicht** (bei gleicher Chain-Länge)
/// 4. Lexikographisch kleinerer Hash (deterministischer Tiebreak)
pub fn resolve_fork(
    candidates: Vec<ForkCandidate>,
    validator_set: &ValidatorSet,
) -> Option<ForkResolution> {
    if candidates.is_empty() { return None; }

    let ranked = candidates.clone();

    if validator_set.validators.is_empty() {
        return Some(ForkResolution {
            winning_hash: ranked[0].block_hash.clone(),
            reason: ForkResolutionReason::NoValidatorsFirstWins,
            candidates,
        });
    }

    // Nur gültig signierte Kandidaten
    let valid_only: Vec<_> = ranked.iter().filter(|c| c.signature_valid).cloned().collect();
    if valid_only.len() == 1 {
        return Some(ForkResolution {
            winning_hash: valid_only[0].block_hash.clone(),
            reason: ForkResolutionReason::OnlyValidSignature,
            candidates,
        });
    }

    let pool = if valid_only.is_empty() { ranked.clone() } else { valid_only };

    // Längster Ast
    let max_len = pool.iter().map(|c| c.chain_length_after).max().unwrap_or(0);
    let longest: Vec<_> = pool.iter().filter(|c| c.chain_length_after == max_len).cloned().collect();

    if longest.len() == 1 {
        return Some(ForkResolution {
            winning_hash: longest[0].block_hash.clone(),
            reason: ForkResolutionReason::LongestChain,
            candidates,
        });
    }

    // Bei gleicher Länge: höchstes Stake-Gewicht
    let max_stake = longest.iter().map(|c| c.signer_stake_weight).max().unwrap_or(0);
    let heaviest: Vec<_> = longest.iter().filter(|c| c.signer_stake_weight == max_stake).cloned().collect();

    if heaviest.len() == 1 {
        return Some(ForkResolution {
            winning_hash: heaviest[0].block_hash.clone(),
            reason: ForkResolutionReason::HighestStakeWeight,
            candidates,
        });
    }

    // Tiebreak: lexikographisch kleinster Hash
    let winner = heaviest.iter().min_by(|a, b| a.block_hash.cmp(&b.block_hash)).unwrap();
    Some(ForkResolution {
        winning_hash: winner.block_hash.clone(),
        reason: ForkResolutionReason::LexicographicTiebreak,
        candidates,
    })
}

/// Stake-gewichtete Fork-Choice für Sync: Vergleicht zwei Chain-Äste.
///
/// Gibt `true` zurück wenn die Peer-Chain bevorzugt werden sollte.
///
/// Kriterien (in dieser Reihenfolge):
/// 1. Längere Chain gewinnt
/// 2. Bei gleicher Länge: höheres kumulatives Stake-Gewicht
/// 3. Bei Gleichstand: deterministischer Tiebreak über Block-Hash am Fork-Punkt
///    (lexikographisch kleinerer Hash gewinnt, damit alle Nodes konvergieren)
pub fn should_prefer_peer_chain(
    local_len: u64,
    peer_len: u64,
    local_cumulative_stake: u64,
    peer_cumulative_stake: u64,
) -> (bool, &'static str) {
    if peer_len > local_len {
        return (true, "Peer-Chain ist länger");
    }
    if peer_len < local_len {
        return (false, "Lokale Chain ist länger");
    }
    // Gleiche Länge → Stake-Gewicht entscheidet
    if peer_cumulative_stake > local_cumulative_stake {
        return (true, "Gleiche Länge, Peer hat mehr Stake-Gewicht");
    }
    if peer_cumulative_stake < local_cumulative_stake {
        return (false, "Gleiche Länge, lokaler Stake höher");
    }
    // Bei exakt gleichem Stake+Länge → Caller muss Hash-Tiebreaker nutzen
    (false, "Gleiche Länge und Stake – Hash-Tiebreak nötig")
}

/// Erweiterte Fork-Choice mit Hash-Tiebreaker.
///
/// Wenn `should_prefer_peer_chain` bei Gleichstand endet, vergleicht diese
/// Funktion die Block-Hashes am Fork-Punkt: der lexikographisch kleinere Hash
/// gewinnt, damit alle Nodes zum selben Ergebnis kommen.
pub fn should_prefer_peer_chain_with_hashes(
    local_len: u64,
    peer_len: u64,
    local_cumulative_stake: u64,
    peer_cumulative_stake: u64,
    local_fork_hash: &str,
    peer_fork_hash: &str,
) -> (bool, &'static str) {
    let (prefer, reason) = should_prefer_peer_chain(
        local_len, peer_len, local_cumulative_stake, peer_cumulative_stake,
    );
    // Wenn das Ergebnis eindeutig ist, nutze es
    if local_len != peer_len || local_cumulative_stake != peer_cumulative_stake {
        return (prefer, reason);
    }
    // Tiebreak: lexikographisch kleinerer Block-Hash am Fork-Punkt gewinnt
    if peer_fork_hash < local_fork_hash {
        return (true, "Hash-Tiebreak: Peer-Block hat kleineren Hash");
    }
    (false, "Hash-Tiebreak: lokaler Block hat kleineren/gleichen Hash")
}

/// Berechnet das kumulative Stake-Gewicht einer Chain ab einem bestimmten Index.
///
/// Summiert die Stake-Gewichte aller Block-Signer ab `from_index`.
pub fn cumulative_stake_weight(
    blocks: &[crate::blockchain::Block],
    from_index: usize,
    stakes: &HashMap<String, rust_decimal::Decimal>,
    wallet_map: &HashMap<String, String>,
) -> u64 {
    use rust_decimal::prelude::ToPrimitive;
    blocks[from_index..].iter()
        .map(|b| {
            let wallet = wallet_map.get(&b.signer);
            let stake = wallet
                .and_then(|w| stakes.get(w))
                .copied()
                .unwrap_or(rust_decimal::Decimal::ZERO);
            // In ganzen STONE-Einheiten
            stake.to_u64().unwrap_or(0)
        })
        .sum()
}

/// Erkennt Forks in einer Chain: mehrere Blöcke mit demselben `previous_hash`
/// → unterschiedliche Äste auf demselben Index.
pub fn detect_forks(blocks: &[Block]) -> Vec<Vec<ForkCandidate>> {
    // Gruppiere Blöcke nach (index, previous_hash)
    let mut by_index: HashMap<u64, Vec<&Block>> = HashMap::new();
    for b in blocks {
        by_index.entry(b.index).or_default().push(b);
    }

    let mut forks = Vec::new();
    for (_, group) in &by_index {
        if group.len() > 1 {
            let candidates = group.iter().map(|b| ForkCandidate {
                block_index: b.index,
                block_hash: b.hash.clone(),
                signer_id: b.signer.clone(),
                validator_signature: b.validator_signature.clone(),
                chain_length_after: blocks.iter().filter(|x| x.index > b.index).count() as u64,
                timestamp: b.timestamp,
                signature_valid: false, // caller fills this in with ValidatorSet
                signer_stake_weight: 0, // caller fills this with StakingPool data
            }).collect();
            forks.push(candidates);
        }
    }
    forks
}

// ─── Validator-Schlüsselpaar (lokal, für diese Node) ─────────────────────────

/// Encrypted key file format:
/// `STONE_ENC_V1` (12 bytes magic) || salt (16 bytes) || nonce (12 bytes) || ciphertext (48 bytes)
/// Total: 88 bytes
///
/// Ciphertext = AES-256-GCM(key_derived_from_argon2id(passphrase, salt), nonce, signing_key_bytes)
/// = 32 bytes plaintext + 16 bytes GCM tag = 48 bytes
const ENCRYPTED_KEY_MAGIC: &[u8; 12] = b"STONE_ENC_V1";
const ENCRYPTED_KEY_TOTAL: usize = 12 + 16 + 12 + 48; // magic + salt + nonce + ciphertext

/// Leitet einen AES-256-Key aus einer Passphrase via Argon2id ab.
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    use argon2::Argon2;

    let mut key = [0u8; 32];
    // Argon2id mit Standard-Parametern (19 MiB, 2 Iterationen, 1 Thread)
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("Argon2id KDF");
    key
}

/// Verschlüsselt einen 32-Byte Signing-Key mit AES-256-GCM.
fn encrypt_validator_key(key_bytes: &[u8; 32], passphrase: &str) -> Vec<u8> {
    use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}};
    use aes_gcm::aead::generic_array::GenericArray;
    use rand::RngCore;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let aes_key = derive_key_from_passphrase(passphrase, &salt);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, key_bytes.as_slice())
        .expect("AES-GCM Encryption");

    let mut out = Vec::with_capacity(ENCRYPTED_KEY_TOTAL);
    out.extend_from_slice(ENCRYPTED_KEY_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Entschlüsselt einen Validator-Key aus dem verschlüsselten Format.
fn decrypt_validator_key(data: &[u8], passphrase: &str) -> Result<[u8; 32], String> {
    use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}};
    use aes_gcm::aead::generic_array::GenericArray;

    if data.len() != ENCRYPTED_KEY_TOTAL {
        return Err(format!("Ungültige Dateigröße: {} (erwartet {})", data.len(), ENCRYPTED_KEY_TOTAL));
    }
    if &data[..12] != ENCRYPTED_KEY_MAGIC {
        return Err("Ungültiges Dateiformat (Magic-Bytes falsch)".into());
    }

    let salt: [u8; 16] = data[12..28].try_into().unwrap();
    let nonce_bytes: [u8; 12] = data[28..40].try_into().unwrap();
    let ciphertext = &data[40..];

    let aes_key = derive_key_from_passphrase(passphrase, &salt);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Entschlüsselung fehlgeschlagen – falsches Passwort?".to_string())?;

    let arr: [u8; 32] = plaintext.try_into()
        .map_err(|_| "Entschlüsselter Key hat falsche Länge".to_string())?;
    Ok(arr)
}

/// Prüft ob eine Datei im verschlüsselten Format vorliegt.
fn is_encrypted_key_file(data: &[u8]) -> bool {
    data.len() == ENCRYPTED_KEY_TOTAL && data.starts_with(ENCRYPTED_KEY_MAGIC)
}

/// Lädt oder erstellt das Ed25519-Schlüsselpaar dieser Validator-Node.
///
/// ## Verschlüsselung
///
/// Wenn die Umgebungsvariable `STONE_VALIDATOR_PASSPHRASE` gesetzt ist,
/// wird der Key mit Argon2id + AES-256-GCM verschlüsselt auf Disk gespeichert.
///
/// - **Neue Datei:** Key wird verschlüsselt gespeichert als `validator_key.enc`
/// - **Bestehende Klartext-Datei:** Wird automatisch migriert (verschlüsselt, Klartext gelöscht)
/// - **Ohne Passphrase:** Fallback auf Klartext `validator_key.bin` (mit Warnung)
///
/// ## Dateien
///
/// - `{data_dir}/validator_key.enc` — verschlüsselter Key (88 Bytes)
/// - `{data_dir}/validator_key.bin` — Klartext-Key (32 Bytes, Legacy)
pub fn load_or_create_validator_key() -> SigningKey {
    let dir = data_dir();
    let enc_path = format!("{}/validator_key.enc", dir);
    let plain_path = format!("{}/validator_key.bin", dir);
    let passphrase = std::env::var("STONE_VALIDATOR_PASSPHRASE").ok()
        .filter(|s| !s.trim().is_empty());

    // ── Fall 1: Verschlüsselte Datei existiert ───────────────────────────
    if let Ok(data) = std::fs::read(&enc_path) {
        if is_encrypted_key_file(&data) {
            let Some(ref pass) = passphrase else {
                eprintln!(
                    "[consensus] ❌ Verschlüsselter Key gefunden aber STONE_VALIDATOR_PASSPHRASE nicht gesetzt!"
                );
                eprintln!(
                    "[consensus]    Setze die Umgebungsvariable oder lösche {} für einen neuen Key.",
                    enc_path
                );
                std::process::exit(1);
            };
            match decrypt_validator_key(&data, pass) {
                Ok(bytes) => {
                    println!("[consensus] 🔐 Validator-Key entschlüsselt geladen (AES-256-GCM)");
                    return SigningKey::from_bytes(&bytes);
                }
                Err(e) => {
                    eprintln!("[consensus] ❌ Validator-Key Entschlüsselung fehlgeschlagen: {e}");
                    eprintln!("[consensus]    Prüfe STONE_VALIDATOR_PASSPHRASE.");
                    std::process::exit(1);
                }
            }
        }
    }

    // ── Fall 2: Klartext-Datei existiert ─────────────────────────────────
    if let Ok(bytes) = std::fs::read(&plain_path) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().unwrap();
            let key = SigningKey::from_bytes(&arr);

            if let Some(ref pass) = passphrase {
                // Migration: Klartext → Verschlüsselt
                let encrypted = encrypt_validator_key(&arr, pass);
                if let Err(e) = std::fs::write(&enc_path, &encrypted) {
                    eprintln!("[consensus] ⚠️  Verschlüsselte Key-Datei konnte nicht geschrieben werden: {e}");
                    return key;
                }
                // Klartext-Datei sicher löschen (überschreiben + löschen)
                let zeros = [0u8; 32];
                let _ = std::fs::write(&plain_path, &zeros);
                let _ = std::fs::remove_file(&plain_path);
                println!(
                    "[consensus] 🔄 Validator-Key migriert: Klartext → AES-256-GCM verschlüsselt"
                );
                println!(
                    "[consensus] 🗑️  Klartext-Datei '{}' sicher gelöscht",
                    plain_path
                );
            } else {
                eprintln!(
                    "[consensus] ⚠️  Validator-Key liegt UNVERSCHLÜSSELT auf Disk: {}",
                    plain_path
                );
                eprintln!(
                    "[consensus]    Setze STONE_VALIDATOR_PASSPHRASE für automatische Verschlüsselung."
                );
            }
            return key;
        }
    }

    // ── Fall 3: Kein Key vorhanden → Neu generieren ──────────────────────
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);

    if let Some(ref pass) = passphrase {
        let encrypted = encrypt_validator_key(&seed, pass);
        let _ = std::fs::write(&enc_path, &encrypted);
        println!(
            "[consensus] 🔐 Neuer Validator-Schlüssel erstellt (AES-256-GCM verschlüsselt): {}",
            enc_path
        );
    } else {
        let _ = std::fs::write(&plain_path, key.to_bytes());
        eprintln!(
            "[consensus] ⚠️  Neuer Validator-Schlüssel UNVERSCHLÜSSELT gespeichert: {}",
            plain_path
        );
        eprintln!(
            "[consensus]    Empfehlung: Setze STONE_VALIDATOR_PASSPHRASE für verschlüsselte Speicherung."
        );
    }
    key
}

/// Public Key dieser Node als Hex
pub fn local_validator_pubkey_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}
