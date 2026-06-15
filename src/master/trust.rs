//! Web-of-Trust – Peer-Vertrauensmanagement und Abstimmungen

use chrono::Utc;

use super::MasterNodeState;
use super::types::{NodeEvent, TrustStatus, TrustEntry, TrustVote, TrustSummary};

impl MasterNodeState {
    // ─── Web-of-Trust Methoden ────────────────────────────────────────────────

    /// Join-Anfrage eintragen (falls peer_id noch nicht bekannt)
    pub fn trust_request(
        &self,
        peer_id: String,
        public_key_hex: String,
        name: Option<String>,
    ) -> Result<(), String> {
        let mut reg = self.trust_registry.write().unwrap_or_else(|e| e.into_inner());
        if reg.iter().any(|e| e.peer_id == peer_id) {
            return Err(format!("peer_id '{peer_id}' bereits in der Trust-Registry"));
        }
        reg.push(TrustEntry::new(peer_id.clone(), public_key_hex, name.clone()));
        drop(reg);
        self.events.publish(NodeEvent::TrustJoinRequested {
            peer_id,
            name,
            timestamp: Utc::now().timestamp(),
        });
        Ok(())
    }

    /// Abstimmung: approve=true → Zustimmung, false → Ablehnung.
    ///
    /// SECURITY:
    /// - Stimme ist nur gültig wenn `voter_peer_id` ein aktiver Validator ist.
    /// - Zusätzlich muss der übergebene `voter_pubkey_hex` zur Validator-Identität passen.
    /// - Gezählt wird per kanonischer Konsensidentität (validator public_key_hex),
    ///   nicht per freiem node_id-String.
    pub fn trust_vote(
        &self,
        voter_peer_id: &str,
        voter_pubkey_hex: &str,
        target_peer_id: &str,
        approve: bool,
    ) -> Result<TrustStatus, String> {
        if voter_pubkey_hex.trim().is_empty() {
            return Err("voter_pubkey_hex fehlt".to_string());
        }

        // Nur aktive Validatoren mit passender Konsensidentität dürfen voten.
        let canonical_voter_id = {
            let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
            let v = vs
                .validators
                .iter()
                .find(|v| v.node_id == voter_peer_id)
                .ok_or_else(|| format!("voter '{}' ist kein bekannter Validator", voter_peer_id))?;
            if !v.active {
                return Err(format!("voter '{}' ist kein aktiver Validator", voter_peer_id));
            }
            if v.public_key_hex != voter_pubkey_hex {
                return Err(format!(
                    "voter '{}' PubKey passt nicht zur Validator-Identität",
                    voter_peer_id
                ));
            }
            v.public_key_hex.clone()
        };

        // Abstimmung ins History-Log schreiben
        {
            let mut history = self.trust_history.lock().unwrap_or_else(|e| e.into_inner());
            history.push(TrustVote {
                voter_peer_id: voter_peer_id.to_string(),
                target_peer_id: target_peer_id.to_string(),
                approve,
                timestamp: Utc::now().timestamp(),
            });
        }

        let mut reg = self.trust_registry.write().unwrap_or_else(|e| e.into_inner());
        let entry = reg
            .iter_mut()
            .find(|e| e.peer_id == target_peer_id)
            .ok_or_else(|| format!("peer_id '{target_peer_id}' nicht gefunden"))?;

        if entry.status == TrustStatus::Active && approve {
            // bereits aktiv – keine Änderung nötig
            return Ok(TrustStatus::Active);
        }

        // Doppelabstimmung derselben Konsensidentität verhindern.
        // Legacy-Kompatibilität: alte node_id-basierte Votes ebenfalls entfernen.
        entry.votes_approve.retain(|v| v != voter_peer_id && v != &canonical_voter_id);
        entry.votes_reject.retain(|v| v != voter_peer_id && v != &canonical_voter_id);

        if approve {
            entry.votes_approve.push(canonical_voter_id);
        } else {
            entry.votes_reject.push(canonical_voter_id);
        }

        // Quorum: Anzahl aktiver Validators als Referenz (min 1)
        let active_validators = {
            let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
            vs.validators.iter().filter(|v| v.active).count().max(1)
        };
        let threshold = (active_validators / 2) + 1;

        if entry.votes_approve.len() >= threshold {
            entry.status = TrustStatus::Active;
            entry.decided_at = Some(Utc::now().timestamp());
        } else if entry.votes_reject.len() >= threshold {
            entry.status = TrustStatus::Revoked;
            entry.decided_at = Some(Utc::now().timestamp());
        }

        let new_status = entry.status.clone();
        let votes_for = entry.votes_approve.len();
        let votes_against = entry.votes_reject.len();
        drop(reg);

        // WS-Event emittieren
        let now = Utc::now().timestamp();
        match new_status {
            TrustStatus::Active => {
                self.events.publish(NodeEvent::TrustApproved {
                    peer_id: target_peer_id.to_string(),
                    voter: voter_peer_id.to_string(),
                    votes_for,
                    timestamp: now,
                });
            }
            TrustStatus::Revoked => {
                self.events.publish(NodeEvent::TrustRevoked {
                    peer_id: target_peer_id.to_string(),
                    voter: voter_peer_id.to_string(),
                    votes_against,
                    timestamp: now,
                });
            }
            TrustStatus::Pending => {
                self.events.publish(NodeEvent::TrustVoteCast {
                    peer_id: target_peer_id.to_string(),
                    voter: voter_peer_id.to_string(),
                    approve,
                    votes_for,
                    votes_against,
                    needed: threshold,
                    timestamp: now,
                });
            }
        }

        Ok(new_status)
    }

    /// Zusammenfassung für NodeStatusResponse
    pub fn trust_summary(&self) -> TrustSummary {
        let reg = self.trust_registry.read().unwrap_or_else(|e| e.into_inner());
        TrustSummary {
            active: reg.iter().filter(|e| e.status == TrustStatus::Active).count(),
            pending: reg.iter().filter(|e| e.status == TrustStatus::Pending).count(),
            revoked: reg.iter().filter(|e| e.status == TrustStatus::Revoked).count(),
        }
    }

    /// Gibt alle Pending-Einträge zurück
    pub fn trust_pending(&self) -> Vec<TrustEntry> {
        self.trust_registry
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.status == TrustStatus::Pending)
            .cloned()
            .collect()
    }

    /// Gibt die Abstimmungshistorie zurück
    pub fn trust_history_snapshot(&self) -> Vec<TrustVote> {
        self.trust_history.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Prüft ob eine peer_id aktiv vertrauenswürdig ist
    pub fn is_trusted(&self, peer_id: &str) -> bool {
        self.trust_registry
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|e| e.peer_id == peer_id && e.status == TrustStatus::Active)
    }
}
