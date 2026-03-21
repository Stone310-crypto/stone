//! Chat-Policy Module: Self-Destruct, Reporting & Stake-Gate
//!
//! ## 1. Self-Destruct (TTL)
//! Nachrichten haben eine konfigurierbare Lebensdauer (30 oder 90 Tage).
//! Nach Ablauf wird der verschlüsselte Inhalt gelöscht, der Hash bleibt
//! als Beweis auf der Chain. Kryptografisch sauber: Daten = unlesbar,
//! Beweis = unveränderbar.
//!
//! ## 2. Report-System
//! - **Mutual Report**: Beide Parteien melden → sofortiges Content-Löschen
//! - **Single Report**: Reporter liefert Decryption-Key, Nodes stimmen ab
//!   Bei Mehrheit → Content gelöscht, bei Missbrauch → Reporter-Slash

use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::blockchain::data_dir;

// ═══════════════════════════════════════════════════════════════════════════════
// Konstanten
// ═══════════════════════════════════════════════════════════════════════════════

/// Minimum-Stake um den Messenger nutzen zu dürfen (in STONE)

/// Standard-TTL für Nachrichten (30 Tage in Sekunden)
pub const TTL_30_DAYS: i64 = 30 * 24 * 3600;

/// Lange TTL (90 Tage in Sekunden)
pub const TTL_90_DAYS: i64 = 90 * 24 * 3600;

/// Standard-TTL wenn keiner gesetzt wird (30 Tage)
pub const DEFAULT_TTL_SECS: i64 = TTL_30_DAYS;

/// Maximale TTL (90 Tage)
pub const MAX_TTL_SECS: i64 = TTL_90_DAYS;

/// Mindest-Votes für eine Report-Entscheidung (bei wenigen Nodes: 1)
pub const REPORT_MIN_VOTES: u32 = 1;

/// Quorum für Report-Voting: Anteil der aktiven Validatoren die zustimmen müssen (>50%)
pub const REPORT_QUORUM_PCT: u32 = 51;

/// Slash-Prozentsatz bei erfolgreichem Report gegen den Verursacher
pub const REPORT_SLASH_PCT: u32 = 20;

/// Maximale Dauer einer Report-Voting-Runde (24 Stunden)
pub const REPORT_VOTING_TIMEOUT_SECS: i64 = 24 * 3600;

/// Platzhalter für gelöschten Content
pub const REDACTED_CONTENT: &str = "[REDACTED — self-destruct or reported]";

// ═══════════════════════════════════════════════════════════════════════════════
// Self-Destruct TTL
// ═══════════════════════════════════════════════════════════════════════════════

/// TTL-Policy einer Nachricht.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageTtl {
    /// 30 Tage
    Days30,
    /// 90 Tage
    Days90,
}

impl MessageTtl {
    pub fn to_secs(&self) -> i64 {
        match self {
            MessageTtl::Days30 => TTL_30_DAYS,
            MessageTtl::Days90 => TTL_90_DAYS,
        }
    }

    /// Parse aus String ("30" oder "90"), default = 30
    pub fn from_str_or_default(s: &str) -> Self {
        match s {
            "90" | "days90" | "Days90" => MessageTtl::Days90,
            _ => MessageTtl::Days30,
        }
    }
}

impl Default for MessageTtl {
    fn default() -> Self {
        MessageTtl::Days30
    }
}

impl std::fmt::Display for MessageTtl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageTtl::Days30 => write!(f, "30d"),
            MessageTtl::Days90 => write!(f, "90d"),
        }
    }
}

/// Tracking-Eintrag für eine Nachricht mit TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageTtlEntry {
    /// Nachrichten-ID (msg_id aus Chat-Memo)
    pub msg_id: String,
    /// TX-ID in der Blockchain
    pub tx_id: String,
    /// Konversations-Key (walletA:walletB)
    pub conv_key: String,
    /// Sender Wallet
    pub from_wallet: String,
    /// Empfänger Wallet
    pub to_wallet: String,
    /// TTL-Policy
    pub ttl: MessageTtl,
    /// Timestamp wann die Nachricht erstellt wurde (Unix-Secs)
    pub created_at: i64,
    /// Timestamp wann der Content ablauft (Unix-Secs)
    pub expires_at: i64,
    /// Block-Index in dem die Nachricht geminet wurde
    pub block_index: u64,
    /// Ob der Content bereits gelöscht wurde (Self-Destruct oder Report)
    pub content_purged: bool,
    /// Grund für Löschung
    pub purge_reason: Option<String>,
}

impl MessageTtlEntry {
    /// Ist diese Nachricht abgelaufen?
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.expires_at
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Report-System
// ═══════════════════════════════════════════════════════════════════════════════

/// Status eines Reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Voting läuft
    Pending,
    /// Durch Mutual Report sofort gelöscht
    MutualDelete,
    /// Durch Voting angenommen → Content gelöscht
    Accepted,
    /// Durch Voting abgelehnt (kein Slash)
    Rejected,
    /// Voting-Timeout abgelaufen
    Expired,
}

impl std::fmt::Display for ReportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportStatus::Pending => write!(f, "pending"),
            ReportStatus::MutualDelete => write!(f, "mutual_delete"),
            ReportStatus::Accepted => write!(f, "accepted"),
            ReportStatus::Rejected => write!(f, "rejected"),
            ReportStatus::Expired => write!(f, "expired"),
        }
    }
}

/// Kategorie des Reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportCategory {
    Spam,
    Harassment,
    IllegalContent,
    Scam,
    Other,
}

impl std::fmt::Display for ReportCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportCategory::Spam => write!(f, "spam"),
            ReportCategory::Harassment => write!(f, "harassment"),
            ReportCategory::IllegalContent => write!(f, "illegal_content"),
            ReportCategory::Scam => write!(f, "scam"),
            ReportCategory::Other => write!(f, "other"),
        }
    }
}

/// Ein Report gegen eine Chat-Nachricht.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReport {
    /// Eindeutige Report-ID
    pub report_id: String,
    /// Die gemeldete msg_id
    pub msg_id: String,
    /// TX-ID der gemeldeten Nachricht
    pub tx_id: String,
    /// Konversations-Key
    pub conv_key: String,
    /// Wer hat gemeldet (Wallet)
    pub reporter_wallet: String,
    /// Gegen wen (Wallet des Nachrichtenautors)
    pub reported_wallet: String,
    /// Report-Kategorie
    pub category: ReportCategory,
    /// Freitext-Begründung (optional)
    pub reason: String,
    /// Decryption-Key für die verschlüsselte Nachricht (optional, für Single-Report)
    /// Bei Mutual Report nicht nötig.
    pub decryption_key: Option<String>,
    /// Timestamp
    pub created_at: i64,
    /// Report-Status
    pub status: ReportStatus,
    /// Voting-Ergebnis: Node-ID → stimmt zu (true) / lehnt ab (false)
    pub votes: HashMap<String, bool>,
    /// Gesamtzahl aktiver Validatoren zum Zeitpunkt des Reports
    pub total_validators: u32,
    /// Slash-Betrag der bei Annahme geslasht wurde
    pub slashed_amount: Decimal,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Chat Policy Store
// ═══════════════════════════════════════════════════════════════════════════════

/// Zentrale Verwaltung aller Chat-Policies: TTL-Tracking, Reports, Stake-Gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatPolicyStore {
    /// TTL-Tracking: msg_id → MessageTtlEntry
    pub ttl_entries: HashMap<String, MessageTtlEntry>,
    /// Aktive Reports: report_id → MessageReport
    pub reports: HashMap<String, MessageReport>,
    /// Erledigte Reports (Archiv, begrenzt): report_id → MessageReport
    pub report_archive: Vec<MessageReport>,
    /// Statistik
    pub total_messages_tracked: u64,
    pub total_content_purged: u64,
    pub total_reports_filed: u64,
    pub total_reports_accepted: u64,
    pub total_slashed: Decimal,
}

impl ChatPolicyStore {
    pub fn new() -> Self {
        Self {
            ttl_entries: HashMap::new(),
            reports: HashMap::new(),
            report_archive: Vec::new(),
            total_messages_tracked: 0,
            total_content_purged: 0,
            total_reports_filed: 0,
            total_reports_accepted: 0,
            total_slashed: Decimal::ZERO,
        }
    }

    // ─── TTL-Management ───────────────────────────────────────────────────

    /// Neue Nachricht mit TTL registrieren.
    pub fn track_message(
        &mut self,
        msg_id: &str,
        tx_id: &str,
        from_wallet: &str,
        to_wallet: &str,
        ttl: MessageTtl,
        created_at: i64,
        block_index: u64,
    ) {
        let expires_at = created_at + ttl.to_secs();
        let conv_key = crate::chat::ChatIndex::conv_key(from_wallet, to_wallet);

        let entry = MessageTtlEntry {
            msg_id: msg_id.to_string(),
            tx_id: tx_id.to_string(),
            conv_key,
            from_wallet: from_wallet.to_string(),
            to_wallet: to_wallet.to_string(),
            ttl,
            created_at,
            expires_at,
            block_index,
            content_purged: false,
            purge_reason: None,
        };

        self.ttl_entries.insert(msg_id.to_string(), entry);
        self.total_messages_tracked += 1;
    }

    /// Abgelaufene Nachrichten ermitteln (Content zum Löschen).
    /// Gibt msg_ids zurück deren Content gelöscht werden soll.
    pub fn collect_expired(&self) -> Vec<String> {
        let now = Utc::now().timestamp();
        self.ttl_entries
            .iter()
            .filter(|(_, e)| !e.content_purged && now >= e.expires_at)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Content einer Nachricht als gelöscht markieren.
    pub fn mark_purged(&mut self, msg_id: &str, reason: &str) {
        if let Some(entry) = self.ttl_entries.get_mut(msg_id) {
            if !entry.content_purged {
                entry.content_purged = true;
                entry.purge_reason = Some(reason.to_string());
                self.total_content_purged += 1;
            }
        }
    }

    /// GC: Bereits gelöschte TTL-Einträge entfernen die älter als `max_age_secs` sind.
    /// Verhindert dass `ttl_entries` unbegrenzt wächst.
    /// Gibt die Anzahl entfernter Einträge zurück.
    pub fn gc_purged_entries(&mut self, max_age_secs: i64) -> usize {
        let cutoff = Utc::now().timestamp() - max_age_secs;
        let before = self.ttl_entries.len();
        self.ttl_entries.retain(|_, e| {
            // Behalten wenn: noch nicht gelöscht, oder gelöscht aber noch jung genug
            !e.content_purged || e.expires_at > cutoff
        });
        let removed = before - self.ttl_entries.len();
        if removed > 0 {
            println!("[chat-policy] 🧹 GC: {} alte TTL-Einträge entfernt, {} verbleibend",
                removed, self.ttl_entries.len());
        }
        removed
    }

    // ─── Report-Management ────────────────────────────────────────────────

    /// Neuen Report erstellen.
    ///
    /// Prüft automatisch ob ein Mutual Report vorliegt (beide Seiten melden).
    /// Gibt `(report_id, is_mutual)` zurück.
    pub fn file_report(
        &mut self,
        msg_id: &str,
        reporter_wallet: &str,
        reported_wallet: &str,
        category: ReportCategory,
        reason: String,
        decryption_key: Option<String>,
        total_validators: u32,
    ) -> Result<(String, bool), String> {
        // Prüfe ob die Nachricht existiert und clone nötige Daten
        let (tx_id, conv_key, from_wallet, to_wallet, already_purged) = {
            let ttl_entry = self.ttl_entries.get(msg_id)
                .ok_or_else(|| "Nachricht nicht im TTL-Tracking gefunden".to_string())?;
            (
                ttl_entry.tx_id.clone(),
                ttl_entry.conv_key.clone(),
                ttl_entry.from_wallet.clone(),
                ttl_entry.to_wallet.clone(),
                ttl_entry.content_purged,
            )
        };

        // Prüfe ob Reporter an der Konversation beteiligt ist
        if reporter_wallet != from_wallet && reporter_wallet != to_wallet {
            return Err("Du bist nicht Teil dieser Konversation".to_string());
        }

        // Prüfe ob bereits Content gelöscht
        if already_purged {
            return Err("Nachricht wurde bereits gelöscht".to_string());
        }

        // Prüfe ob Reporter selbst der Autor ist (darf nicht eigene Nachrichten melden)
        if reporter_wallet == reported_wallet {
            return Err("Du kannst deine eigenen Nachrichten nicht melden".to_string());
        }

        // Prüfe ob es bereits einen aktiven Report vom anderen Teilnehmer gibt → Mutual
        let other_report = self.reports.values().find(|r| {
            r.msg_id == msg_id
                && r.reporter_wallet == reported_wallet
                && r.status == ReportStatus::Pending
        });

        if let Some(existing) = other_report {
            // Mutual Report! Beide Seiten melden → sofortige Löschung
            let existing_id = existing.report_id.clone();

            // Bestehenden Report auf MutualDelete setzen
            if let Some(r) = self.reports.get_mut(&existing_id) {
                r.status = ReportStatus::MutualDelete;
            }

            // Content löschen
            self.mark_purged(msg_id, "mutual_report");

            // Neuen Report auch als MutualDelete erstellen (für Audit)
            let report_id = uuid::Uuid::new_v4().to_string();
            let report = MessageReport {
                report_id: report_id.clone(),
                msg_id: msg_id.to_string(),
                tx_id: tx_id.clone(),
                conv_key: conv_key.clone(),
                reporter_wallet: reporter_wallet.to_string(),
                reported_wallet: reported_wallet.to_string(),
                category,
                reason,
                decryption_key: None,
                created_at: Utc::now().timestamp(),
                status: ReportStatus::MutualDelete,
                votes: HashMap::new(),
                total_validators,
                slashed_amount: Decimal::ZERO,
            };
            self.reports.insert(report_id.clone(), report);
            self.total_reports_filed += 1;

            return Ok((report_id, true));
        }

        // Single Report → Voting startet
        if decryption_key.is_none() {
            return Err("Für einen Single-Report muss der Decryption-Key mitgeliefert werden".to_string());
        }

        let report_id = uuid::Uuid::new_v4().to_string();
        let report = MessageReport {
            report_id: report_id.clone(),
            msg_id: msg_id.to_string(),
            tx_id: tx_id.clone(),
            conv_key: conv_key.clone(),
            reporter_wallet: reporter_wallet.to_string(),
            reported_wallet: reported_wallet.to_string(),
            category,
            reason,
            decryption_key,
            created_at: Utc::now().timestamp(),
            status: ReportStatus::Pending,
            votes: HashMap::new(),
            total_validators,
            slashed_amount: Decimal::ZERO,
        };

        self.reports.insert(report_id.clone(), report);
        self.total_reports_filed += 1;

        Ok((report_id, false))
    }

    /// Vote auf einen Report abgeben (Node/Validator-Stimulus).
    ///
    /// `voter_wallet` ist die Wallet-Adresse des Voters (statt node_id).
    /// Wird zusammen mit `voter_id` (node_id) gespeichert.
    pub fn cast_vote(&mut self, report_id: &str, voter_id: &str, approve: bool) -> Result<(), String> {
        let report = self.reports.get_mut(report_id)
            .ok_or_else(|| "Report nicht gefunden".to_string())?;

        if report.status != ReportStatus::Pending {
            return Err(format!("Report ist nicht mehr ausstehend (Status: {})", report.status));
        }

        report.votes.insert(voter_id.to_string(), approve);
        Ok(())
    }

    /// Report-Ergebnis berechnen und ggf. finalisieren.
    ///
    /// `stake_weights`: Optionale Stake-Gewichte (wallet/node_id → STONE-Betrag).
    /// Wenn vorhanden, wird stake-gewichtet abgestimmt.
    /// Wenn `None`, wird klassisch pro Stimme gezählt (Legacy).
    ///
    /// Gibt `Some((accepted, msg_id, reported_wallet))` zurück wenn finalisiert.
    pub fn try_finalize_report_weighted(
        &mut self,
        report_id: &str,
        stake_weights: Option<&HashMap<String, Decimal>>,
    ) -> Option<(bool, String, String)> {
        // Phase 1: Nur lesen, Ergebnis bestimmen
        let (total, votes_cast, created_at, msg_id, reported_wallet, is_pending, votes_clone) = {
            let report = self.reports.get(report_id)?;
            if report.status != ReportStatus::Pending {
                return None;
            }
            (
                report.total_validators.max(1),
                report.votes.len() as u32,
                report.created_at,
                report.msg_id.clone(),
                report.reported_wallet.clone(),
                true,
                report.votes.clone(),
            )
        };

        if !is_pending {
            return None;
        }

        // Timeout prüfen
        let now = Utc::now().timestamp();
        if now - created_at > REPORT_VOTING_TIMEOUT_SECS {
            let report = self.reports.get_mut(report_id).unwrap();
            report.status = ReportStatus::Expired;
            let archived = report.clone();
            self.report_archive.push(archived);
            return None;
        }

        // Genug Votes?
        if votes_cast < REPORT_MIN_VOTES {
            return None;
        }

        let accepted = if let Some(weights) = stake_weights {
            // Stake-gewichtetes Voting
            let mut total_weight = Decimal::ZERO;
            let mut approve_weight = Decimal::ZERO;

            for (voter, &approved) in &votes_clone {
                let w = weights.get(voter).copied().unwrap_or(Decimal::ONE);
                total_weight += w;
                if approved {
                    approve_weight += w;
                }
            }

            if total_weight == Decimal::ZERO {
                return None;
            }

            // Quorum: Mindestens 51% des gewichteten Potentials müssen gestimmt haben
            let total_potential: Decimal = weights.values().sum();
            if total_potential > Decimal::ZERO {
                let quorum_met = total_weight * Decimal::from(100) >= total_potential * Decimal::from(REPORT_QUORUM_PCT);
                if !quorum_met && votes_cast < total {
                    return None;
                }
            }

            // Mehrheit: >50% der gewichteten Stimmen
            approve_weight * Decimal::from(2) > total_weight
        } else {
            // Legacy: Ungewichtetes Voting (1 Vote = 1 Stimme)
            let approve_count = votes_clone.values().filter(|&&v| v).count() as u32;
            let quorum_met = (votes_cast * 100) >= (total * REPORT_QUORUM_PCT);
            if !quorum_met && votes_cast < total {
                return None;
            }
            (approve_count * 100) > (votes_cast * 50)
        };

        // Phase 2: Mutieren
        if accepted {
            self.mark_purged(&msg_id, &format!("report_accepted:{}", report_id));
            self.total_reports_accepted += 1;
        }

        // Dann Report-Status setzen
        let report = self.reports.get_mut(report_id).unwrap();
        report.status = if accepted { ReportStatus::Accepted } else { ReportStatus::Rejected };
        let archived = report.clone();
        self.report_archive.push(archived);

        // Archiv begrenzen (max 1000 Einträge)
        if self.report_archive.len() > 1000 {
            self.report_archive.drain(0..100);
        }

        // Finalisierten Report aus der aktiven Map entfernen (nur Archiv behalten)
        self.reports.remove(report_id);

        Some((accepted, msg_id, reported_wallet))
    }

    /// Alle Pending Reports durchgehen und finalisieren wo möglich.
    /// `stake_weights`: Optionale Stake-Gewichte für gewichtetes Voting.
    /// Gibt eine Liste von `(report_id, accepted, msg_id, reported_wallet)` zurück.
    pub fn finalize_all_pending(&mut self, stake_weights: Option<&HashMap<String, Decimal>>) -> Vec<(String, bool, String, String)> {
        let pending_ids: Vec<String> = self.reports
            .iter()
            .filter(|(_, r)| r.status == ReportStatus::Pending)
            .map(|(id, _)| id.clone())
            .collect();

        let mut results = Vec::new();
        for id in pending_ids {
            if let Some((accepted, msg_id, reported_wallet)) = self.try_finalize_report_weighted(&id, stake_weights) {
                results.push((id, accepted, msg_id, reported_wallet));
            }
        }
        results
    }

    /// Legacy-Wrapper: Finalisiert ohne Stake-Gewichtung.
    pub fn try_finalize_report(&mut self, report_id: &str) -> Option<(bool, String, String)> {
        self.try_finalize_report_weighted(report_id, None)
    }

    /// Record Slash nach einem akzeptierten Report.
    pub fn record_slash(&mut self, report_id: &str, amount: Decimal) {
        // Prüfe sowohl aktive Reports als auch Archiv
        if let Some(report) = self.reports.get_mut(report_id) {
            report.slashed_amount = amount;
            self.total_slashed += amount;
        } else if let Some(report) = self.report_archive.iter_mut().rev().find(|r| r.report_id == report_id) {
            report.slashed_amount = amount;
            self.total_slashed += amount;
        }
    }

    // ─── Stake-Gate ───────────────────────────────────────────────────────

    /// Prüft ob ein Wallet den Messenger nutzen darf (Minimum-Stake erforderlich).
    ///
    /// Gibt `Ok(staked_amount)` zurück wenn der Stake ausreicht,
    /// sonst `Err(fehlender_betrag)`.

    // ─── Query-Methoden ───────────────────────────────────────────────────

    /// TTL-Info zu einer bestimmten Nachricht.
    pub fn message_ttl_info(&self, msg_id: &str) -> Option<&MessageTtlEntry> {
        self.ttl_entries.get(msg_id)
    }

    /// Alle aktiven Reports auflisten.
    pub fn active_reports(&self) -> Vec<&MessageReport> {
        self.reports.values()
            .filter(|r| r.status == ReportStatus::Pending)
            .collect()
    }

    /// Report-Info.
    pub fn report_info(&self, report_id: &str) -> Option<&MessageReport> {
        self.reports.get(report_id)
    }

    /// Zusammenfassung für API/Dashboard.
    pub fn summary(&self) -> ChatPolicySummary {
        let expired_pending = self.collect_expired().len();
        let active_reports = self.reports.values()
            .filter(|r| r.status == ReportStatus::Pending)
            .count();

        ChatPolicySummary {
            total_messages_tracked: self.total_messages_tracked,
            total_content_purged: self.total_content_purged,
            pending_expirations: expired_pending as u64,
            total_reports_filed: self.total_reports_filed,
            total_reports_accepted: self.total_reports_accepted,
            active_reports: active_reports as u64,
            total_slashed: self.total_slashed,

        }
    }

    // ─── Persistierung ────────────────────────────────────────────────────

    pub fn persist(&self) -> Result<(), String> {
        let db_path = format!("{}/token_db", data_dir());
        let db = rocksdb::DB::open_default(&db_path)
            .map_err(|e| format!("ChatPolicy DB open: {e}"))?;

        let json = serde_json::to_string(self)
            .map_err(|e| format!("ChatPolicy serialize: {e}"))?;

        db.put(b"chat_policy_store", json.as_bytes())
            .map_err(|e| format!("ChatPolicy put: {e}"))?;

        Ok(())
    }

    pub fn load() -> Self {
        let db_path = format!("{}/token_db", data_dir());
        let db = match rocksdb::DB::open_default(&db_path) {
            Ok(db) => db,
            Err(_) => return ChatPolicyStore::new(),
        };

        match db.get(b"chat_policy_store") {
            Ok(Some(bytes)) => {
                match serde_json::from_slice::<ChatPolicyStore>(&bytes) {
                    Ok(store) => {
                        println!(
                            "[chat-policy] 📂 Store geladen: {} Nachrichten getrackt, {} gelöscht, {} Reports",
                            store.total_messages_tracked,
                            store.total_content_purged,
                            store.total_reports_filed,
                        );
                        store
                    }
                    Err(e) => {
                        eprintln!("[chat-policy] ⚠️ Deserialisierung fehlgeschlagen: {e}");
                        ChatPolicyStore::new()
                    }
                }
            }
            _ => ChatPolicyStore::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// API-Typen
// ═══════════════════════════════════════════════════════════════════════════════

/// Dashboard-Zusammenfassung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatPolicySummary {
    pub total_messages_tracked: u64,
    pub total_content_purged: u64,
    pub pending_expirations: u64,
    pub total_reports_filed: u64,
    pub total_reports_accepted: u64,
    pub active_reports: u64,
    pub total_slashed: Decimal,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Chat-Index: Content Purge Integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Löscht den verschlüsselten Content einer Nachricht im ChatIndex.
/// Der Eintrag bleibt bestehen (Hash + Metadaten), aber encrypted_content
/// und nonce werden ersetzt mit REDACTED.
pub fn purge_message_content(
    index: &mut crate::chat::ChatIndex,
    msg_id: &str,
) -> bool {
    let mut found = false;
    for messages in index.conversations.values_mut() {
        for msg in messages.iter_mut() {
            if msg.msg_id == msg_id {
                msg.encrypted_content = REDACTED_CONTENT.to_string();
                msg.nonce = String::new();
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
    found
}

// ═══════════════════════════════════════════════════════════════════════════════
// Post-Block Garbage Collection
// ═══════════════════════════════════════════════════════════════════════════════

/// Garbage Collector: Löscht abgelaufene Nachrichten-Contents.
///
/// Wird nach jedem Block aufgerufen. Sammelt expired Messages,
/// purged den Content im ChatIndex, und markiert die Einträge
/// im TTL-Store als gelöscht.
///
/// Gibt die Anzahl gelöschter Nachrichten zurück.
pub fn gc_expired_messages(
    policy: &mut ChatPolicyStore,
    chat_index: &mut crate::chat::ChatIndex,
) -> u32 {
    let expired = policy.collect_expired();
    if expired.is_empty() {
        return 0;
    }

    let mut purged = 0u32;
    for msg_id in &expired {
        if purge_message_content(chat_index, msg_id) {
            policy.mark_purged(msg_id, "ttl_expired");
            purged += 1;
        }
    }

    if purged > 0 {
        println!(
            "[chat-policy] 🗑️  Self-Destruct: {} Nachrichten-Content gelöscht (TTL abgelaufen)",
            purged
        );
    }

    // Periodisch alte gepurgte Einträge aufräumen (behalte 7 Tage nach Ablauf)
    policy.gc_purged_entries(7 * 24 * 3600);

    purged
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_defaults() {
        assert_eq!(MessageTtl::default(), MessageTtl::Days30);
        assert_eq!(MessageTtl::Days30.to_secs(), 30 * 24 * 3600);
        assert_eq!(MessageTtl::Days90.to_secs(), 90 * 24 * 3600);
    }

    #[test]
    fn test_ttl_parse() {
        assert_eq!(MessageTtl::from_str_or_default("90"), MessageTtl::Days90);
        assert_eq!(MessageTtl::from_str_or_default("30"), MessageTtl::Days30);
        assert_eq!(MessageTtl::from_str_or_default("foo"), MessageTtl::Days30);
    }

    #[test]
    fn test_track_and_expire() {
        let mut store = ChatPolicyStore::new();

        store.track_message(
            "msg-1",
            "tx-1",
            "wallet_a",
            "wallet_b",
            MessageTtl::Days30,
            Utc::now().timestamp() - TTL_30_DAYS - 100, // Created 30 days + 100 secs ago
            10,
        );

        store.track_message(
            "msg-2",
            "tx-2",
            "wallet_a",
            "wallet_b",
            MessageTtl::Days90,
            Utc::now().timestamp(), // Created now
            11,
        );

        let expired = store.collect_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "msg-1");
    }

    #[test]
    fn test_report_mutual() {
        let mut store = ChatPolicyStore::new();

        // Track message
        store.track_message("msg-x", "tx-x", "alice", "bob", MessageTtl::Days30, Utc::now().timestamp(), 5);

        // Bob meldet
        let (r1, mutual) = store.file_report("msg-x", "bob", "alice", ReportCategory::Spam, "spam!".into(), Some("key123".into()), 3).unwrap();
        assert!(!mutual);

        // Alice meldet auch → Mutual!
        let (_, mutual2) = store.file_report("msg-x", "alice", "bob", ReportCategory::Spam, "agree".into(), None, 3).unwrap();
        assert!(mutual2);

        // Content sollte gelöscht sein
        let entry = store.ttl_entries.get("msg-x").unwrap();
        assert!(entry.content_purged);
    }
}
