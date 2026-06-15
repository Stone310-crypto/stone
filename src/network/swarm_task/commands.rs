// ─── Externe Befehle ─────────────────────────────────────────────────────────
//
// handle_command(): Verarbeitung von NetworkCommand-Varianten
// (Broadcast, Dial, Sync, GetPeers, GetStatus, Shard-Ops, Shutdown, …)

use libp2p::{
    PeerId,
    gossipsub::{self, IdentTopic},
};
use std::collections::HashSet;

use super::*;
use super::super::*;

impl SwarmTask {
    pub(super) fn handle_command(&mut self, cmd: NetworkCommand) -> bool {
        match cmd {
            NetworkCommand::BroadcastBlock(block) => {
                let hash = block.hash.clone();

                // Eigenen Block sofort als "gesehen" markieren (kein Re-Broadcast)
                if !self.is_duplicate(&hash) {
                    // Duplicate-Filter hat ihn gerade neu eingetragen → gut
                }

                match super::encode_gossip(&*block) {
                    Ok(data) => {
                        let data_len = data.len() as u64;
                        let topic = IdentTopic::new(TOPIC_BLOCKS.as_str());
                        match self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            Ok(_) => {
                                println!("[p2p] 📡 Block #{} gebroadcastet (hash={}...)", block.index, &hash[..8.min(hash.len())]);
                                // Metriken
                                self.net_metrics.bytes_out += data_len;
                                self.net_metrics.messages_out += 1;
                                self.net_metrics.blocks_sent += 1;
                                // Chain-Count aktualisieren
                                if block.index + 1 > self.local_chain_count {
                                    self.local_chain_count = block.index + 1;
                                }
                            }
                            Err(gossipsub::PublishError::InsufficientPeers) => {
                                // Kein Peer verbunden – kein Fehler, nur Info
                                println!("[p2p] Block #{} – keine Peers verbunden, Broadcast übersprungen", block.index);
                            }
                            Err(e) => eprintln!("[p2p] Broadcast-Fehler: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[p2p] Block-Serialisierung: {e}"),
                }
                false
            }

            NetworkCommand::BroadcastTx(tx) => {
                let tx_id = tx.tx_id.clone();

                // Deduplizierung: eigene TX sofort als gesehen markieren
                if !self.is_duplicate(&format!("tx:{tx_id}")) {
                    // hat gerade eingetragen → gut
                }

                match super::encode_gossip(&*tx) {
                    Ok(data) => {
                        let data_len = data.len() as u64;
                        let topic = IdentTopic::new(TOPIC_MEMPOOL.as_str());
                        match self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            Ok(_) => {
                                println!("[p2p] 💸 TX {tx_id} gebroadcastet");
                                self.net_metrics.bytes_out += data_len;
                                self.net_metrics.messages_out += 1;
                                self.net_metrics.txs_sent += 1;
                            }
                            Err(gossipsub::PublishError::InsufficientPeers) => {
                                // Kein Peer – kein Fehler
                            }
                            Err(e) => eprintln!("[p2p] TX-Broadcast-Fehler: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[p2p] TX-Serialisierung: {e}"),
                }
                false
            }

            NetworkCommand::DialPeer(addr) => {
                println!("[p2p] Manueller Dial: {addr}");
                if let Err(e) = self.swarm.dial(addr) {
                    eprintln!("[p2p] Dial fehlgeschlagen: {e}");
                }
                false
            }

            NetworkCommand::SyncWithPeer { peer_id, our_block_count } => {
                // ChainInfo anfragen → Antwort löst automatisch Range-Sync aus
                let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                    &peer_id,
                    BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
                );
                self.pending_chain_info.insert(req_id, peer_id);
                let _ = our_block_count;
                false
            }

            NetworkCommand::SetLocalChainCount(count) => {
                if count > self.local_chain_count {
                    self.mark_sync_progress("set local chain count");
                }
                self.local_chain_count = count;
                false
            }

            NetworkCommand::SetChainRef(chain_arc) => {
                // Beim Setzen der Chain-Referenz Genesis-Hash und initiale Höhe
                // einmal unter Lock lesen und cachen. Danach werden Hot-Path-
                // Reads (gossip.rs, sync.rs) ausschließlich gegen den Cache
                // bzw. `local_chain_count` ausgeführt – kein Lock-Contention
                // mit dem Commit-Pfad mehr.
                if let Ok(chain) = chain_arc.lock() {
                    if let Some(genesis) = chain.blocks.first() {
                        self.genesis_hash_cache = Some(std::sync::Arc::new(genesis.hash.clone()));
                    }
                    let height = chain.blocks.len() as u64;
                    if height > self.local_chain_count {
                        self.local_chain_count = height;
                    }
                }
                println!(
                    "[p2p] Chain-Referenz gesetzt (genesis={}, height={})",
                    self.genesis_hash_cache.as_deref()
                        .map(|s| &s[..12.min(s.len())])
                        .unwrap_or("?"),
                    self.local_chain_count,
                );
                self.chain_ref = Some(chain_arc);
                false
            }

            NetworkCommand::GetPeers(tx) => {
                let list: Vec<PeerInfo> = self.peers.values().cloned().collect();
                let _ = tx.send(list);
                false
            }

            NetworkCommand::Ping { peer_id, reply } => {
                let connected = self.peers.get(&peer_id).map(|p| p.connected).unwrap_or(false);
                if !connected {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id.to_string(),
                        reachable: false,
                        latency_ms: None,
                        error: Some("Peer nicht verbunden".to_string()),
                    });
                    return false;
                }
                // Ping-Marker: block_index = u64::MAX
                let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                    &peer_id,
                    BlockRequest { block_index: BLOCK_REQUEST_PING, block_index_end: None },
                );
                self.pending_pings.insert(req_id, (peer_id.to_string(), std::time::Instant::now(), reply));
                false
            }

            NetworkCommand::GetStatus(reply) => {
                let now = chrono::Utc::now().timestamp();
                let mesh_peers: HashSet<String> = self.swarm
                    .behaviour()
                    .gossipsub
                    .mesh_peers(&gossipsub::TopicHash::from_raw(TOPIC_BLOCKS.as_str()))
                    .map(|p| p.to_string())
                    .collect();

                // Direkt aus dem Swarm die verbundenen Peers holen
                let swarm_connected: HashSet<String> = self.swarm
                    .connected_peers()
                    .map(|p| p.to_string())
                    .collect();

                // peers-Map mit Swarm-Status synchronisieren
                for (peer_id, info) in self.peers.iter_mut() {
                    info.connected = swarm_connected.contains(&peer_id.to_string());
                }
                // Peers die im Swarm verbunden sind aber noch nicht in unserer Map
                for peer_str in &swarm_connected {
                    if let Ok(peer_id) = peer_str.parse::<libp2p::PeerId>() {
                        self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
                            peer_id: peer_str.clone(),
                            addresses: vec![],
                            agent_version: String::new(),
                            connected: true,
                            last_seen: now,
                            blocks_received: 0,
                            stake_level: 0,
                        });
                    }
                }

                let peers: Vec<PeerStatus> = self.peers.iter().map(|(pid, p)| PeerStatus {
                    peer_id: p.peer_id.clone(),
                    addresses: p.addresses.clone(),
                    agent_version: p.agent_version.clone(),
                    connected: p.connected,
                    last_seen: p.last_seen,
                    last_seen_ago_secs: now - p.last_seen,
                    blocks_received: p.blocks_received,
                    in_gossipsub_mesh: mesh_peers.contains(&p.peer_id),
                    avg_latency_ms: self.avg_latency_ms(pid),
                }).collect();

                let connected = swarm_connected.len();

                // Metriken mit Uptime & Durchschnittswerten berechnen
                let uptime = self.started_at.elapsed().as_secs().max(1);
                let mut metrics = self.net_metrics.clone();
                metrics.uptime_secs = uptime;
                metrics.avg_bytes_in_per_sec = metrics.bytes_in as f64 / uptime as f64;
                metrics.avg_bytes_out_per_sec = metrics.bytes_out as f64 / uptime as f64;

                let _ = reply.send(NetworkStatus {
                    local_peer_id: self.swarm.local_peer_id().to_string(),
                    connected_peers: connected,
                    total_known_peers: self.peers.len(),
                    gossipsub_mesh_size: mesh_peers.len(),
                    chain_block_count: self.local_chain_count,
                    peers,
                    metrics,
                    peer_storage: self.peer_storage.values().cloned().collect(),
                    sync_recovery: SyncRecoveryStatus {
                        stage: self.sync_recovery_stage.as_str().to_string(),
                        attempts: self.sync_recovery_attempts,
                        seconds_since_progress: self.sync_last_progress_at.elapsed().as_secs(),
                        target_peer: self.sync_target_peer.map(|p| p.to_string()),
                        last_reason: self.sync_last_recovery_reason.clone(),
                    },
                    health_controller: HealthControllerStatus {
                        state: self.health_state.as_str().to_string(),
                        failure: self.health_failure.map(|f| f.as_str()).unwrap_or("none").to_string(),
                        recovery_level: self.health_recovery_level.as_str().to_string(),
                        seconds_since_transition: self.health_last_transition.elapsed().as_secs(),
                        cooldown_remaining_secs: self.health_cooldown_until
                            .map(|until| until.saturating_duration_since(std::time::Instant::now()).as_secs())
                            .unwrap_or(0),
                        last_reason: self.health_last_reason.clone(),
                    },
                });
                false
            }

            NetworkCommand::Shutdown => {
                println!("[p2p] Shutdown.");
                true
            }

            // ── Shard-Befehle ─────────────────────────────────────────────────

            NetworkCommand::RequestShard { peer_id, chunk_hash, shard_index } => {
                if self.is_protocol_mismatch_quarantined(&peer_id) {
                    return false;
                }
                println!("[p2p] → Shard anfordern: {chunk_hash}[{shard_index}] von {peer_id}");
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::GetShard { chunk_hash, shard_index },
                );
                false
            }

            NetworkCommand::StoreShard { peer_id, chunk_hash, shard_index, shard_hash, data } => {
                if self.is_protocol_mismatch_quarantined(&peer_id) {
                    return false;
                }
                let data_len = data.len() as u64;
                println!("[p2p] → Shard senden: {chunk_hash}[{shard_index}] an {peer_id} ({} bytes)", data.len());
                self.net_metrics.bytes_out += data_len;
                self.net_metrics.messages_out += 1;
                self.net_metrics.shard_bytes_out += data_len;
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::StoreShard { chunk_hash, shard_index, shard_hash, data },
                );
                false
            }

            NetworkCommand::ListPeerShards { peer_id, chunk_hash, reply } => {
                if self.is_protocol_mismatch_quarantined(&peer_id) {
                    let _ = reply.send(vec![]);
                    return false;
                }
                println!("[p2p] → Shard-Liste anfordern: {chunk_hash} von {peer_id}");
                let req_id = self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::ListShards { chunk_hash: chunk_hash.clone() },
                );
                self.pending_shard_lists.insert(req_id, (chunk_hash, reply));
                false
            }

            NetworkCommand::PublishGossip { topic, data } => {
                let data_len = data.len() as u64;
                match self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                    Ok(_) => {
                        println!("[p2p] 📡 Gossip auf Topic {topic} gesendet");
                        self.net_metrics.bytes_out += data_len;
                        self.net_metrics.messages_out += 1;
                    }
                    Err(gossipsub::PublishError::InsufficientPeers) => {
                        println!("[p2p] Gossip {topic} – keine Peers, übersprungen");
                    }
                    Err(e) => {
                        eprintln!("[p2p] Gossip-Fehler auf {topic}: {e}");
                    }
                }
                false
            }

            NetworkCommand::ReportPenalty { peer_id_str, points, reason } => {
                if let Ok(peer_id) = peer_id_str.parse::<PeerId>() {
                    self.add_peer_penalty(&peer_id, points, &reason);
                } else {
                    eprintln!("[p2p] ReportPenalty: ungültige PeerId '{peer_id_str}'");
                }
                false
            }

            NetworkCommand::SetStakeLevel(level) => {
                self.local_stake_level = level;
                false
            }
        }
    }
}
