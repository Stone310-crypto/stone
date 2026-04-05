// ─── Periodisches Cleanup & Keepalive ────────────────────────────────────────
//
// periodic_cleanup():         Aufräumen verwaister Rate-Limiter, Penalties, Peers
// keepalive_ping_peers():     NAT-Warmhalte-Pings an alle verbundenen Peers
// handle_keepalive_response(): Latenz-Recording + last_seen-Update

use libp2p::PeerId;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use super::*;
use super::super::*;

impl SwarmTask {
    /// Maximale Latenz-Samples pro Peer (Rolling Window)
    const LATENCY_WINDOW: usize = 10;

    /// Sendet Keepalive-Pings an alle verbundenen Peers um NAT-Mappings warm
    /// zu halten und Latenz-Statistiken zu sammeln.
    pub(super) fn keepalive_ping_peers(&mut self) {
        let connected: Vec<PeerId> = self.swarm.connected_peers().cloned().collect();
        if connected.is_empty() {
            return;
        }
        let mut sent = 0u32;
        for peer_id in &connected {
            let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                peer_id,
                BlockRequest { block_index: BLOCK_REQUEST_PING, block_index_end: None },
            );
            self.keepalive_pings.insert(req_id, (*peer_id, Instant::now()));
            sent += 1;
        }
        if sent > 0 {
            println!("[p2p] 💓 Keepalive: {sent} Ping(s) gesendet");
        }
    }

    /// Verarbeitet eine Keepalive-Ping-Antwort: zeichnet die Latenz auf und
    /// aktualisiert `last_seen`. Gibt `true` zurück wenn es ein Keepalive-Ping war.
    pub(super) fn handle_keepalive_response(&mut self, request_id: &libp2p::request_response::OutboundRequestId) -> bool {
        if let Some((peer_id, start)) = self.keepalive_pings.remove(request_id) {
            let ms = start.elapsed().as_millis() as u64;
            // Latenz in Rolling-Window aufnehmen
            let window = self.peer_latencies.entry(peer_id).or_insert_with(VecDeque::new);
            if window.len() >= Self::LATENCY_WINDOW {
                window.pop_front();
            }
            window.push_back(ms);
            // last_seen aktualisieren
            if let Some(entry) = self.peers.get_mut(&peer_id) {
                entry.last_seen = chrono::Utc::now().timestamp();
            }
            true
        } else {
            false
        }
    }

    /// Räumt verwaiste Einträge in Rate-Limitern, Penalty-Map und Storage-Announcements auf.
    /// Wird alle 5 Minuten vom Cleanup-Ticker aufgerufen.
    pub(super) fn periodic_cleanup(&mut self) {
        let connected: HashSet<PeerId> = self.swarm.connected_peers().cloned().collect();

        // 1. Rate-Limiter: Einträge für Peers entfernen die seit >10 Minuten nicht verbunden sind
        let stale_limiters: Vec<PeerId> = self.peer_rate_limiters.keys()
            .filter(|pid| !connected.contains(pid))
            .cloned()
            .collect();
        if !stale_limiters.is_empty() {
            for pid in &stale_limiters {
                self.peer_rate_limiters.remove(pid);
            }
            println!("[p2p] 🧹 {} verwaiste Rate-Limiter aufgeräumt", stale_limiters.len());
        }

        // 2. Penalties: abgelaufene Penalties (Score halbiert auf <5) entfernen
        let expired_penalties: Vec<PeerId> = self.peer_penalties.iter()
            .filter(|(_, p)| {
                p.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60 * 2)
                    && p.score < BAN_THRESHOLD
            })
            .map(|(pid, _)| *pid)
            .collect();
        if !expired_penalties.is_empty() {
            for pid in &expired_penalties {
                self.peer_penalties.remove(pid);
            }
            println!("[p2p] 🧹 {} abgelaufene Penalties aufgeräumt", expired_penalties.len());
        }

        // 3. Storage-Announcements: Einträge älter als 10 Minuten von nicht-verbundenen Peers entfernen
        let stale_storage: Vec<String> = self.peer_storage.iter()
            .filter(|(peer_id_str, ann)| {
                let age = chrono::Utc::now().timestamp() - ann.timestamp;
                age > 600 && !connected.iter().any(|pid| pid.to_string() == **peer_id_str)
            })
            .map(|(k, _)| k.clone())
            .collect();
        if !stale_storage.is_empty() {
            for k in &stale_storage {
                self.peer_storage.remove(k);
            }
        }

        // 4. Reconnect-Backoff: Einträge für verbundene Peers entfernen
        self.reconnect_backoff.retain(|pid, _| !connected.contains(pid));

        // 5. Pending-Pings die > 30s alt sind aufräumen (verwaiste oneshot-Sender)
        let stale_pings: Vec<libp2p::request_response::OutboundRequestId> = self.pending_pings.iter()
            .filter(|(_, (_, start, _))| start.elapsed() > Duration::from_secs(30))
            .map(|(rid, _)| *rid)
            .collect();
        for rid in stale_pings {
            if let Some((peer_id_str, _, reply)) = self.pending_pings.remove(&rid) {
                let _ = reply.send(PingResult {
                    peer_id: peer_id_str,
                    reachable: false,
                    latency_ms: None,
                    error: Some("Timeout (cleanup)".to_string()),
                });
            }
        }

        // 6. Pending-Shard-Lists: verwaiste Einträge aufräumen
        {
            let before = self.pending_shard_lists.len();
            self.pending_shard_lists.retain(|_, (_, _reply)| {
                !_reply.is_closed()
            });
            let removed = before - self.pending_shard_lists.len();
            if removed > 0 {
                println!("[p2p] 🧹 {} verwaiste Shard-List-Anfragen aufgeräumt", removed);
            }
        }

        // 7. Inaktive Peers entfernen: Peers die >1h nicht gesehen und disconnected
        {
            let now_ts = chrono::Utc::now().timestamp();
            const INACTIVE_PEER_TIMEOUT_SECS: i64 = 3600; // 1 Stunde
            let stale_peers: Vec<PeerId> = self.peers.iter()
                .filter(|(_, info)| {
                    !info.connected
                        && info.last_seen > 0
                        && (now_ts - info.last_seen) > INACTIVE_PEER_TIMEOUT_SECS
                })
                .map(|(pid, _)| *pid)
                .collect();
            if !stale_peers.is_empty() {
                for pid in &stale_peers {
                    self.peers.remove(pid);
                    self.peer_latencies.remove(pid);
                }
                println!("[p2p] 🧹 {} inaktive Peers entfernt (>1h nicht gesehen)", stale_peers.len());
            }
        }

        // 8. Keepalive-Pings: verwaiste Pings > 30s aufräumen (Fire-and-forget)
        self.keepalive_pings.retain(|_, (_, start)| start.elapsed() < Duration::from_secs(30));

        // 9. Latenz-Daten: Einträge für nicht mehr bekannte Peers entfernen
        self.peer_latencies.retain(|pid, _| self.peers.contains_key(pid));
    }
}
