// ─── Chain-Sync ──────────────────────────────────────────────────────────────
//
// flush_sync_buffer():         Ordnet gepufferte Blöcke und flusht sie
// sync_with_connected_peers(): Periodische ChainInfo-Anfragen an alle Peers
// send_sync_handshake():       Eigene Chain-Länge via Gossipsub broadcasten
// handle_sync_handshake():     Eingehende Handshakes verarbeiten + Sync auslösen

use libp2p::{
    PeerId,
    gossipsub::IdentTopic,
};
use std::collections::HashSet;
use std::time::Duration;

use super::*;
use super::super::*;

impl SwarmTask {
    /// Flusht geordnete Blöcke aus dem Sync-Buffer in den Event-Channel.
    /// Nur zusammenhängende Blöcke ab `sync_expected_next` werden gesendet.
    pub(super) fn flush_sync_buffer(&mut self) {
        // Aktuelle Chain-Höhe aus chain_ref lesen (genauer als sync_expected_next)
        let actual_local = self.chain_ref.as_ref()
            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
            .unwrap_or(self.local_chain_count);

        // sync_expected_next auf Chain-Höhe setzen falls höher
        if actual_local > self.sync_expected_next {
            self.sync_expected_next = actual_local;
        }

        let mut flushed = 0u64;
        loop {
            let next = self.sync_expected_next;
            if let Some((_, (block, from_peer))) = self.sync_buffer.remove_entry(&next) {
                let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                    block: Box::new(block),
                    from_peer,
                });
                self.sync_expected_next = next + 1;
                flushed += 1;
            } else {
                break;
            }
        }
        if flushed > 0 {
            println!("[p2p] 🔄 Sync-Buffer: {flushed} Blöcke geordnet eingefügt (nächster erwartet: #{})", self.sync_expected_next);
        }

        // Aufräumen: Blöcke die unter der aktuellen Chain-Höhe liegen entfernen (veraltet)
        let stale_keys: Vec<u64> = self.sync_buffer.range(..actual_local).map(|(k, _)| *k).collect();
        for k in stale_keys {
            self.sync_buffer.remove(&k);
        }

        // Timeout: Wenn > 30s lang keine neuen Blöcke kamen und Buffer nicht leer
        // → wahrscheinlich Lücke → Buffer leeren und Resync triggern
        if !self.sync_buffer.is_empty() {
            if let Some(last) = self.sync_buffer_last_insert {
                if last.elapsed() > Duration::from_secs(30) {
                    let remaining = self.sync_buffer.len();
                    eprintln!("[p2p] ⚠ Sync-Buffer Timeout: {remaining} Blöcke verwaist (nächster erwartet: #{}, erster im Buffer: #{})" ,
                        self.sync_expected_next,
                        self.sync_buffer.keys().next().unwrap_or(&0),
                    );
                    self.sync_buffer.clear();
                    self.sync_buffer_last_insert = None;
                }
            }
        } else {
            self.sync_buffer_last_insert = None;
        }
    }

    /// Sendet ChainInfo-Anfragen an alle verbundenen Peers per Request/Response.
    /// Zuverlässiger als GossipSub (braucht keinen Mesh).
    pub(super) fn sync_with_connected_peers(&mut self) {
        // ── local_chain_count aus chain_ref aktualisieren ──────────────
        if let Some(arc) = &self.chain_ref {
            if let Ok(chain) = arc.lock() {
                self.local_chain_count = chain.blocks.len() as u64;
            }
        }

        // ── Verwaiste pending_chain_info aufräumen ─────────────────────
        {
            let connected_ids: HashSet<PeerId> = self.peers.iter()
                .filter(|(_, info)| info.connected)
                .map(|(pid, _)| *pid)
                .collect();
            self.pending_chain_info.retain(|_, peer_id| connected_ids.contains(peer_id));
        }

        // Verbundene Peers nach Stake-Level sortieren (höchster Stake zuerst).
        let mut connected: Vec<(PeerId, u64)> = self.peers.iter()
            .filter(|(_, info)| info.connected)
            .map(|(pid, info)| (*pid, info.stake_level))
            .collect();
        connected.sort_by(|a, b| b.1.cmp(&a.1));

        if connected.is_empty() {
            return;
        }

        // Auch GossipSub-Handshake senden für Peers die hinter UNS sind
        self.send_sync_handshake();

        for (peer_id, _stake) in connected {
            // Nicht doppelt anfragen wenn schon eine Anfrage läuft
            if self.pending_chain_info.values().any(|p| *p == peer_id) {
                continue;
            }
            let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                &peer_id,
                BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
            );
            self.pending_chain_info.insert(req_id, peer_id);
        }
    }

    /// Sendet unsere Chain-Länge an alle Peers (Gossipsub).
    /// Peers die mehr Blöcke haben werden uns antworten.
    pub(super) fn send_sync_handshake(&mut self) {
        // Genesis-Hash aus chain_ref lesen
        let genesis_hash = self.chain_ref.as_ref().and_then(|arc| {
            arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
        });
        // Aktuelle Höhe aus chain_ref
        let actual_count = self.chain_ref.as_ref()
            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
            .unwrap_or(self.local_chain_count);
        let msg = SyncHandshake {
            block_count: actual_count,
            peer_id: self.swarm.local_peer_id().to_string(),
            genesis_hash,
            protocol_version: Some(STONE_PROTOCOL_VERSION.to_string()),
            stake_level: self.local_stake_level,
        };
        if let Ok(data) = serde_json::to_vec(&msg) {
            let topic = IdentTopic::new(TOPIC_SYNC_HANDSHAKE);
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                // InsufficientPeers ist kein Fehler beim Start
                if !e.to_string().contains("InsufficientPeers") {
                    eprintln!("[p2p] Sync-Handshake fehlgeschlagen: {e}");
                }
            }
        }
    }

    /// Empfängt einen Sync-Handshake von einem Peer.
    /// Falls der Peer mehr Blöcke hat → fehlende per Request/Response abrufen.
    pub(super) fn handle_sync_handshake(&mut self, data: Vec<u8>, source: PeerId) {
        let Ok(msg) = serde_json::from_slice::<SyncHandshake>(&data) else {
            return;
        };

        if msg.peer_id == self.swarm.local_peer_id().to_string() {
            return; // eigene Nachricht
        }

        // Stake-Level des Peers aktualisieren (Relay-Priorität)
        if let Some(peer) = self.peers.get_mut(&source) {
            peer.stake_level = msg.stake_level;
        }

        // ── Protokoll-Version prüfen ──────────────────────────────────────
        if let Some(ref remote_ver) = msg.protocol_version {
            let local_major = STONE_PROTOCOL_VERSION.split('.').next().unwrap_or("");
            let remote_major = remote_ver.split('.').next().unwrap_or("");
            if local_major != remote_major {
                eprintln!(
                    "[p2p] ⚠ Peer {source} hat inkompatible Protokoll-Version: {remote_ver} (wir: {STONE_PROTOCOL_VERSION}) – Verbindung trennen"
                );
                self.add_peer_penalty(&source, 200, "incompatible protocol version");
                let _ = self.swarm.disconnect_peer_id(source);
                return;
            }
        }

        // ── Genesis-Hash prüfen ───────────────────────────────────────────
        if let Some(ref remote_genesis) = msg.genesis_hash {
            let our_genesis = self.chain_ref.as_ref().and_then(|arc| {
                arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
            });
            if let Some(ref our_gen) = our_genesis {
                if our_gen != remote_genesis {
                    eprintln!(
                        "[p2p] ⛔ Genesis-Mismatch mit {source}: lokal={}… remote={}… – Peer getrennt",
                        &our_gen[..12.min(our_gen.len())],
                        &remote_genesis[..12.min(remote_genesis.len())],
                    );
                    self.add_peer_penalty(&source, 200, "genesis mismatch");
                    let _ = self.swarm.disconnect_peer_id(source);
                    return;
                }
            }
        }

        // Aktuelle lokale Höhe aus chain_ref lesen (genauer als local_chain_count)
        let actual_local = self.chain_ref.as_ref()
            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
            .unwrap_or(self.local_chain_count);

        if msg.block_count > actual_local {
            println!(
                "[p2p] 🔄 Sync: Peer {source} hat {} Blöcke, wir haben {actual_local}",
                msg.block_count,
            );

            let sync_from = if actual_local <= 50 { 1u64 } else { actual_local };
            if !self.sync_buffer.is_empty() {
                let buf_min = self.sync_buffer.keys().next().copied().unwrap_or(0);
                if buf_min < sync_from {
                    self.sync_buffer.clear();
                }
            }

            let _ = self.event_tx.send(NetworkEvent::SyncStarted {
                peer_id: source.to_string(),
                local_count: actual_local,
                remote_count: msg.block_count,
            });

            self.sync_expected_next = sync_from;

            // Fehlende Blöcke per Range-Requests abrufen
            let mut idx = sync_from;
            while idx < msg.block_count {
                let end = (idx + MAX_BLOCKS_PER_RANGE - 1).min(msg.block_count - 1);
                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                    &source,
                    BlockRequest { block_index: idx, block_index_end: Some(end) },
                );
                idx = end + 1;
            }
        } else if msg.block_count < actual_local {
            // Wir haben mehr Blöcke → eigenen Handshake senden damit der Peer synct
            self.send_sync_handshake();
        }
    }
}
