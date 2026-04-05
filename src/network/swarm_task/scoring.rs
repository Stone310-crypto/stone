// ─── Peer-Scoring & Banning ──────────────────────────────────────────────────
//
// add_peer_penalty(): Penalty-Punkte vergeben + bei Threshold bannen
// is_peer_banned():   Ban-Status prüfen (mit Decay)

use libp2p::PeerId;
use std::time::{Duration, Instant};

use super::*;

impl SwarmTask {
    /// Fügt einem Peer Penalty-Punkte hinzu. Bei Überschreitung des Schwellwerts
    /// wird der Peer gebannt (Verbindung getrennt).
    pub(super) fn add_peer_penalty(&mut self, peer: &PeerId, points: u32, reason: &str) {
        let entry = self.peer_penalties.entry(*peer).or_insert_with(|| PeerPenalty {
            score: 0,
            last_offense: Instant::now(),
            reasons: Vec::new(),
            ban_count: 0,
        });

        // Penalty-Verfall: wenn letzte Offense > PENALTY_DECAY_MINS her → Score halbieren
        if entry.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60) {
            entry.score /= 2;
            entry.reasons.clear();
        }

        entry.score += points;
        entry.last_offense = Instant::now();
        entry.reasons.push(reason.to_string());

        eprintln!(
            "[p2p] 🚨 Penalty für {peer}: +{points} = {} (Grund: {reason})",
            entry.score
        );

        if entry.score >= BAN_THRESHOLD {
            entry.ban_count += 1;
            eprintln!(
                "[p2p] 🔨 BANNED: {peer} (Score: {}, Ban #{}, Gründe: {:?})",
                entry.score,
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
        self.peer_penalties
            .get(peer)
            .map(|p| {
                // Ban verfällt nach dem doppelten Decay-Zeitraum
                if p.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60 * 2) {
                    false
                } else {
                    p.score >= BAN_THRESHOLD
                }
            })
            .unwrap_or(false)
    }
}
