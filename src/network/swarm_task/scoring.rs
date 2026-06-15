// ─── Peer-Scoring & Banning ──────────────────────────────────────────────────
//
// add_peer_penalty(): Penalty-Punkte vergeben + bei Threshold bannen
// is_peer_banned():   Ban-Status prüfen (mit Decay)

use libp2p::PeerId;
use std::time::{Duration, Instant};

use super::*;

impl SwarmTask {
    fn is_strong_evidence_reason(reason: &str) -> bool {
        let r = reason.to_ascii_lowercase();
        r.contains("invalid hash")
            || r.contains("invalid merkle root")
            || r.contains("invalid validator signature")
            || r.contains("invalid tx signature")
            || r.contains("invalid argon2id pow")
            || r.contains("genesis mismatch")
            || r.contains("incompatible protocol version")
            || r.contains("equivocation")
    }

    fn should_soften_bootstrap_penalty(reason: &str) -> bool {
        let r = reason.to_ascii_lowercase();
        r.contains("rate limit")
            || r.contains("malformed")
            || r.contains("payload too short")
            || r.contains("stale timestamp")
    }

    fn effective_ban_threshold(&self, peer: &PeerId) -> u32 {
        if self.bootstrap_peer_ids.contains(peer) {
            BAN_THRESHOLD_BOOTSTRAP
        } else {
            BAN_THRESHOLD
        }
    }

    /// Fügt einem Peer Penalty-Punkte hinzu. Bei Überschreitung des Schwellwerts
    /// wird der Peer gebannt (Verbindung getrennt).
    pub(super) fn add_peer_penalty(&mut self, peer: &PeerId, points: u32, reason: &str) {
        let is_bootstrap = self.bootstrap_peer_ids.contains(peer);
        let ban_threshold = if is_bootstrap {
            BAN_THRESHOLD_BOOTSTRAP
        } else {
            BAN_THRESHOLD
        };
        let mut effective_points = points;
        if is_bootstrap && Self::should_soften_bootstrap_penalty(reason) {
            // Bootstrap-Peers bei Soft-Offenses weniger aggressiv bestrafen
            // (mindestens 1 Punkt, sonst würde der Event komplett ignoriert).
            effective_points = (points / 4).max(1);
        }

        let entry = self.peer_penalties.entry(*peer).or_insert_with(|| PeerPenalty {
            score: 0,
            last_offense: Instant::now(),
            reasons: Vec::new(),
            ban_count: 0,
            strong_evidence_count: 0,
        });

        // Penalty-Verfall: wenn letzte Offense > PENALTY_DECAY_MINS her → Score halbieren
        if entry.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60) {
            entry.score /= 2;
            entry.reasons.clear();
        }

        entry.score += effective_points;
        entry.last_offense = Instant::now();
        entry.reasons.push(reason.to_string());
        if Self::is_strong_evidence_reason(reason) {
            entry.strong_evidence_count = entry.strong_evidence_count.saturating_add(1);
        }

        eprintln!(
            "[p2p] 🚨 Penalty für {peer}: +{} = {} (Grund: {reason}{})",
            effective_points,
            entry.score
            ,if is_bootstrap && effective_points != points {
                ", bootstrap-softened"
            } else {
                ""
            }
        );

        if entry.score >= ban_threshold {
            let required_evidence = if is_bootstrap {
                BAN_MIN_STRONG_EVIDENCE_BOOTSTRAP
            } else {
                BAN_MIN_STRONG_EVIDENCE
            };

            if entry.strong_evidence_count < required_evidence {
                // Quarantäne statt sofortigem Ban: verhindert Ban-Kaskaden bei
                // vorübergehenden Inkonsistenzen ohne starke Beweise.
                eprintln!(
                    "[p2p] 🧪 Quarantine statt Ban für {peer}: score={} threshold={} evidence={}/{} (reason={reason})",
                    entry.score,
                    ban_threshold,
                    entry.strong_evidence_count,
                    required_evidence,
                );
                entry.score = ban_threshold.saturating_sub(1);
                let _ = self.swarm.disconnect_peer_id(*peer);
                if let Some(info) = self.peers.get_mut(peer) {
                    info.connected = false;
                }
                return;
            }

            entry.ban_count += 1;
            eprintln!(
                "[p2p] 🔨 BANNED: {peer} (Score: {}, Threshold: {}, Evidence: {}, Ban #{}, Gründe: {:?})",
                entry.score,
                ban_threshold,
                entry.strong_evidence_count,
                entry.ban_count,
                entry.reasons,
            );
            // Verbindung trennen
            let _ = self.swarm.disconnect_peer_id(*peer);
            // Aus Peer-Liste entfernen
            if let Some(info) = self.peers.get_mut(peer) {
                info.connected = false;
            }
            // Ban-Liste persistieren (mit Peer-Metadaten)
            save_banned_peers_with_context(&self.peer_penalties, &self.peers);
        }
    }

    /// Prüft ob ein Peer gebannt ist.
    pub(super) fn is_peer_banned(&self, peer: &PeerId) -> bool {
        let threshold = self.effective_ban_threshold(peer);
        self.peer_penalties
            .get(peer)
            .map(|p| {
                // Ban verfällt nach dem doppelten Decay-Zeitraum
                if p.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60 * 2) {
                    false
                } else {
                    p.score >= threshold
                }
            })
            .unwrap_or(false)
    }
}
