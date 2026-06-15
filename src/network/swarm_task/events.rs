// ─── Behaviour-Event-Handling ─────────────────────────────────────────────────
//
// Verarbeitung aller libp2p-Behaviour-Events:
// Identify, mDNS, Gossipsub, Kademlia, Request/Response, Relay, DCUtR,
// AutoNAT, UPnP, Shard-Exchange.

use libp2p::{
    Multiaddr,
    autonat,
    dcutr,
    gossipsub,
    identify,
    kad,
    relay,
    request_response,
    upnp,
};

use super::*;
use super::super::*;

impl SwarmTask {
    // ── Behaviour-Events ─────────────────────────────────────────────────────

    pub(super) fn handle_behaviour_event(&mut self, event: StoneBehaviourEvent) {
        match event {
            // ── Identify ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                let addrs: Vec<String> = info.listen_addrs.iter().map(|a| a.to_string()).collect();
                println!(
                    "[p2p] Identify: {peer_id} – agent={} protocol={}",
                    info.agent_version,
                    info.protocol_version,
                );

                // SECURITY: Protokoll-Version prüfen. Peers mit inkompatibler
                // Major-Version werden getrennt um Chain-Korruption zu verhindern.
                {
                    let our_major = STONE_PROTOCOL_VERSION.split('/').nth(1)
                        .and_then(|v| v.split('.').next());
                    let peer_major = if info.protocol_version.starts_with("stone/") {
                        info.protocol_version.strip_prefix("stone/")
                            .and_then(|v| v.split('.').next())
                    } else {
                        None
                    };
                    if let (Some(ours), Some(theirs)) = (our_major, peer_major) {
                        if ours != theirs {
                            eprintln!(
                                "[p2p] ⚠ Peer {peer_id} hat inkompatible Protokoll-Version {} (wir: {}) – Verbindung getrennt",
                                info.protocol_version, STONE_PROTOCOL_VERSION,
                            );
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            return;
                        }
                    }
                }

                // Nur routable Adressen in Kademlia eintragen:
                // - Öffentliche IPs (nicht 127.x, nicht 10.x, nicht 192.168.x, nicht 100.64-127.x CGNAT)
                // - Relay-Circuit-Adressen (/p2p-circuit)
                // Private/Tailscale-Adressen führen zu sinnlosen Dial-Versuchen auf anderen Nodes.
                for addr in &info.listen_addrs {
                    let is_circuit = addr.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit));
                    let is_routable = addr.iter().any(|p| {
                        match p {
                            libp2p::multiaddr::Protocol::Ip4(ip) => {
                                !ip.is_loopback()
                                    && !ip.is_unspecified()
                                    && !ip.is_private()
                                    // CGNAT range 100.64.0.0/10 (Tailscale etc.)
                                    && !(ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127)
                            }
                            libp2p::multiaddr::Protocol::Ip6(ip) => {
                                !ip.is_loopback()
                                    && !ip.is_unspecified()
                                    // Link-Local (fe80::/10) und ULA (fc00::/7) sind nicht global routbar
                                    && !is_ipv6_non_global(&ip)
                            }
                            _ => false,
                        }
                    });
                    if is_circuit || is_routable {
                        self.swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }
                }

                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.agent_version = info.agent_version.clone();
                    entry.addresses = addrs.clone();
                }

                let _ = self.event_tx.send(NetworkEvent::PeerIdentified {
                    peer_id: peer_id.to_string(),
                    agent: info.agent_version.clone(),
                    addresses: addrs,
                });

                // ── Auto-Relay: Wenn wir hinter NAT sind und ein neuer Stone-Peer
                //    sich verbindet, versuche ihn als Relay zu nutzen.
                //    Stone-Nodes sind standardmäßig Relay-Server.
                if self.nat_status == NatStatus::Private
                    && info.agent_version.contains("stone")
                    && !self.active_relays.contains(&peer_id)
                    && self.active_relays.len() < 3
                {
                    // Öffentliche Adresse des Peers als Relay-Basis nutzen
                    if let Some(relay_addr) = info.listen_addrs.iter().find(|a| {
                        a.iter().any(|p| {
                            matches!(p,
                                libp2p::multiaddr::Protocol::Ip4(ip) if !ip.is_private() && !ip.is_loopback()
                            ) || matches!(p,
                                libp2p::multiaddr::Protocol::Ip6(ip) if !ip.is_loopback() && !is_ipv6_non_global(&ip)
                            )
                        })
                    }) {
                        // Erst /p2p entfernen falls vorhanden, dann sauber aufbauen
                        let stripped = strip_p2p_suffix(relay_addr.clone());
                        let circuit_addr = stripped
                            .with(libp2p::multiaddr::Protocol::P2p(peer_id))
                            .with(libp2p::multiaddr::Protocol::P2pCircuit);
                        if let Ok(_) = self.swarm.listen_on(circuit_addr.clone()) {
                            println!(
                                "[p2p] 🔍 Auto-Relay: Neuer Stone-Peer {peer_id} als Relay-Kandidat"
                            );
                        }
                    }
                }
            }

            // ── mDNS ──────────────────────────────────────────────────────────
            StoneBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                let local_peer = *self.swarm.local_peer_id();

                // Adressen je Peer sammeln (Original-Addrs inkl. /p2p-Suffix behalten)
                let mut by_peer: std::collections::HashMap<
                    libp2p::PeerId,
                    Vec<libp2p::Multiaddr>,
                > = std::collections::HashMap::new();

                for (peer_id, addr) in list {
                    if peer_id == local_peer {
                        continue; // Selbst-Dial verhindern
                    }
                    println!("[p2p] mDNS entdeckt: {peer_id} @ {addr}");
                    // Kademlia bekommt die Adresse OHNE /p2p-Suffix
                    let addr_bare = strip_p2p_suffix(addr.clone());
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr_bare);
                    // Dial-Liste behält die Original-Adresse (mit /p2p wenn vorhanden)
                    by_peer.entry(peer_id).or_default().push(addr);
                }

                for (peer_id, addrs) in by_peer {
                    // Bereits verbunden (laut Swarm-State) → kein erneuter Dial
                    if self.swarm.is_connected(&peer_id) {
                        continue;
                    }
                    // Bereits verbunden (laut unserer Peer-Map) → überspringen
                    if self.peers.get(&peer_id).map(|p| p.connected).unwrap_or(false) {
                        continue;
                    }

                    // Bevorzuge LAN-Adressen (10.x / 192.168.x / 172.x)
                    fn is_lan(addr: &libp2p::Multiaddr) -> bool {
                        use libp2p::multiaddr::Protocol;
                        addr.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_private() && !ip.is_loopback()))
                    }

                    // Adressen sortieren: LAN-Adressen zuerst, dann Rest
                    let mut sorted_addrs = addrs.clone();
                    sorted_addrs.sort_by_key(|a| if is_lan(a) { 0u8 } else { 1u8 });

                    // Beste Adresse für das Log
                    let best_addr = sorted_addrs.first().cloned();

                    // DialOpts mit allen Adressen + NotDialing-Condition:
                    use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
                    let opts = DialOpts::peer_id(peer_id)
                        .addresses(sorted_addrs)
                        .condition(PeerCondition::NotDialing)
                        .build();

                    match self.swarm.dial(opts) {
                        Ok(_) => {
                            if let Some(a) = best_addr {
                                println!("[p2p] mDNS-Dial → {a}");
                            }
                        }
                        Err(e) => {
                            let s = e.to_string();
                            // Alle bekannten Race-Conditions stumm schalten
                            if !s.contains("condition")
                                && !s.contains("Already")
                                && !s.contains("connected")
                                && !s.contains("Pending")
                            {
                                eprintln!("[p2p] mDNS-Dial {peer_id}: {e}");
                            }
                        }
                    }
                }
            }

            StoneBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, addr) in list {
                    println!("[p2p] mDNS abgelaufen: {peer_id} @ {addr}");
                }
            }

            // ── Gossipsub ─────────────────────────────────────────────────────
            StoneBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                propagation_source,
                message_id,
                ..
            }) => {
                let topic = message.topic.as_str().to_string();
                let msg_len = message.data.len() as u64;

                // Metriken: eingehende Gossipsub-Nachricht
                self.net_metrics.bytes_in += msg_len;
                self.net_metrics.messages_in += 1;

                // Manuelle Validierung (Gossipsub `validate_messages` aktiv).
                // Jede Topic-Branch liefert ein `MessageAcceptance` zurück, das
                // anschließend an Gossipsub gemeldet wird:
                //   - Accept  → Mesh-Propagation + positives Peer-Score
                //   - Reject  → KEINE Propagation + P4-Penalty (Mesh-Prune)
                //   - Ignore  → KEINE Propagation, neutrales Score
                let acceptance = if topic == *TOPIC_BLOCKS {
                    self.handle_gossip_block(message.data, propagation_source)
                } else if topic == *TOPIC_SYNC_HANDSHAKE {
                    self.handle_sync_handshake(message.data, propagation_source)
                } else if topic == *TOPIC_MEMPOOL {
                    self.handle_gossip_tx(message.data, propagation_source)
                } else if topic == *crate::updater::TOPIC_UPDATES {
                    println!("[p2p] 🆕 Update-Manifest von {propagation_source} empfangen");
                    let _ = self.event_tx.send(NetworkEvent::UpdateManifestReceived {
                        manifest_json: message.data,
                        from_peer: propagation_source.to_string(),
                    });
                    gossipsub::MessageAcceptance::Accept
                } else if topic == *TOPIC_STORAGE {
                    match serde_json::from_slice::<StorageAnnouncement>(&message.data) {
                        Ok(ann) => {
                            println!(
                                "[p2p] 💾 Storage-Announcement von {} – {} GB angeboten, {} bytes belegt",
                                &ann.peer_id[..12.min(ann.peer_id.len())], ann.offered_gb, ann.used_bytes
                            );
                            self.peer_storage.insert(ann.peer_id.clone(), ann.clone());
                            let _ = self.event_tx.send(NetworkEvent::StorageAnnouncementReceived {
                                announcement: ann,
                                from_peer: propagation_source.to_string(),
                            });
                            gossipsub::MessageAcceptance::Accept
                        }
                        Err(_) => {
                            self.add_peer_penalty(&propagation_source, 10, "malformed storage ann");
                            gossipsub::MessageAcceptance::Reject
                        }
                    }
                } else if topic == *TOPIC_CHAT {
                    match serde_json::from_slice::<crate::message_pool::PooledMessage>(&message.data) {
                        Ok(msg) => {
                            let _ = self.event_tx.send(NetworkEvent::ChatMessageReceived {
                                message: msg,
                                from_peer: propagation_source.to_string(),
                            });
                            gossipsub::MessageAcceptance::Accept
                        }
                        Err(_) => {
                            self.add_peer_penalty(&propagation_source, 10, "malformed chat msg");
                            gossipsub::MessageAcceptance::Reject
                        }
                    }
                } else if topic == *TOPIC_CHAT_CONTENT {
                    match serde_json::from_slice::<crate::chat::ChatContentSync>(&message.data) {
                        Ok(content) => {
                            let _ = self.event_tx.send(NetworkEvent::ChatContentReceived {
                                content,
                                from_peer: propagation_source.to_string(),
                            });
                            gossipsub::MessageAcceptance::Accept
                        }
                        Err(_) => {
                            self.add_peer_penalty(&propagation_source, 10, "malformed chat content");
                            gossipsub::MessageAcceptance::Reject
                        }
                    }
                } else if topic == *crate::network::TOPIC_MINERS {
                    // Payload-Format: 1 Byte kind-Tag (0=connect, 1=heartbeat) + JSON
                    if message.data.len() < 2 {
                        self.add_peer_penalty(&propagation_source, 5, "miner payload too short");
                        gossipsub::MessageAcceptance::Reject
                    } else {
                        let kind = match message.data[0] {
                            0 => "connect",
                            1 => "heartbeat",
                            _ => "unknown",
                        }.to_string();
                        let payload = message.data[1..].to_vec();
                        let _ = self.event_tx.send(NetworkEvent::MinerGossipReceived {
                            kind,
                            payload,
                            from_peer: propagation_source.to_string(),
                        });
                        gossipsub::MessageAcceptance::Accept
                    }
                } else {
                    // Unbekanntes Topic – nicht weiterleiten, kein Penalty
                    gossipsub::MessageAcceptance::Ignore
                };

                // Validierungs-Ergebnis an Gossipsub melden (Pflicht bei
                // `validate_messages` Modus, sonst wird der Peer P3-gepenaltet).
                let _ = self.swarm.behaviour_mut().gossipsub
                    .report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        acceptance,
                    );
            }

            StoneBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                println!("[p2p] {peer_id} hat '{topic}' abonniert");
            }

            StoneBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { peer_id }) => {
                eprintln!("[p2p] Gossipsub nicht unterstützt von: {peer_id}");
            }

            // ── Kademlia ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. }) => {
                println!("[p2p] Kademlia Routing: {peer}");
            }
            StoneBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })),
                ..
            }) => {
                if num_remaining == 0 {
                    println!("[p2p] ✓ Kademlia Bootstrap abgeschlossen");
                }
            }

            // ── Request/Response (Block-Sync + Ping) ──────────────────────
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::Message { peer, message, .. }
            ) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    // ── Pings brauchen kein Rate-Limit-Token ──────────────
                    if request.block_index == BLOCK_REQUEST_PING {
                        println!("[p2p] 🏓 Ping von {peer} – antworte");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                        return;
                    }

                    // ── Rate-Limit prüfen ──────────────────────────────────
                    let limiter = self.peer_rate_limiters
                        .entry(peer)
                        .or_insert_with(PeerRateLimiter::new);
                    if !limiter.requests.try_consume() {
                        // Grace-Zähler: erst nach RATE_LIMIT_GRACE aufeinanderfolgenden
                        // Verletzungen eine Penalty vergeben (Sync-Bursts tolerieren)
                        let grace = self.rate_limit_grace.entry(peer).or_insert(0);
                        *grace += 1;
                        let grace_limit = if self.bootstrap_peer_ids.contains(&peer) {
                            RATE_LIMIT_GRACE_BOOTSTRAP
                        } else {
                            RATE_LIMIT_GRACE
                        };
                        if *grace > grace_limit {
                            self.add_peer_penalty(&peer, 5, "request rate limit");
                        }
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                        return;
                    }
                    // Erfolgreicher Request → Grace-Zähler zurücksetzen
                    self.rate_limit_grace.remove(&peer);

                    if request.block_index == BLOCK_REQUEST_CHAIN_INFO {
                        // Chain-Info zurückgeben: Höhe & Genesis aus dem Cache
                        // (kein Lock), `latest_hash` braucht weiterhin den Lock.
                        let height = self.local_chain_count;
                        let genesis = self.genesis_hash_cache.as_deref().map(|s| s.to_string());
                        let latest = self.chain_ref.as_ref().and_then(|arc| {
                            arc.lock().ok().and_then(|c| c.blocks.last().map(|b| b.hash.clone()))
                        });
                        println!("[p2p] 📊 ChainInfo-Anfrage von {peer} → height={height}");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: Some(height), genesis_hash: genesis, latest_hash: latest,
                            },
                        );
                    } else if let Some(end) = request.block_index_end {
                        // Range-Request: block_index..=end (max MAX_BLOCKS_PER_RANGE)
                        let start = request.block_index;
                        let clamped_end = end.min(start + MAX_BLOCKS_PER_RANGE - 1);
                        println!("[p2p] 📦 Block-Range {start}..={clamped_end} von {peer}");
                        let mut blocks = Vec::new();
                        if let Some(ref chain_arc) = self.chain_ref {
                            if let Ok(chain) = chain_arc.lock() {
                                for idx in start..=clamped_end {
                                    if let Some(b) = chain.blocks.get(idx as usize) {
                                        blocks.push(b.clone());
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks,
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                    } else {
                        // Einzelner Block
                        let idx = request.block_index;
                        println!("[p2p] 📦 Block #{idx} angefragt von {peer}");
                        let block = if let Some(ref chain_arc) = self.chain_ref {
                            if let Ok(chain) = chain_arc.lock() {
                                chain.blocks.get(idx as usize).cloned()
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if block.is_none() {
                            eprintln!("[p2p] Block #{idx} nicht verfügbar (chain_ref={})" , self.chain_ref.is_some());
                        }
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block, blocks: vec![],
                                chain_height: None, genesis_hash: None, latest_hash: None,
                            },
                        );
                    }
                }
                request_response::Message::Response { request_id, response, .. } => {
                    // Keepalive-Ping-Antwort? (Fire-and-forget, nur Latenz aufzeichnen)
                    if self.handle_keepalive_response(&request_id) {
                        // Keepalive verarbeitet – fertig
                    }
                    // Manueller Ping-Antwort?
                    else if let Some((peer_id_str, start, reply)) = self.pending_pings.remove(&request_id) {
                        let ms = start.elapsed().as_millis() as u64;
                        println!("[p2p] 🏓 Pong von {peer_id_str} – {ms}ms");
                        let _ = reply.send(PingResult {
                            peer_id: peer_id_str,
                            reachable: true,
                            latency_ms: Some(ms),
                            error: None,
                        });
                    } else if !response.blocks.is_empty() {
                        // Range-Response → validiere jeden Block vor Weitergabe
                        let peer_str = peer.to_string();
                        let mut invalid = false;
                        for blk in &response.blocks {
                            if blk.index == 0
                                || blk.hash.is_empty()
                                || blk.previous_hash.is_empty()
                            {
                                eprintln!(
                                    "[p2p] ❌ Invalider Range-Sync-Block von {peer_str}: \
                                     index={}, hash_len={}, prev_hash_len={}",
                                    blk.index,
                                    blk.hash.len(),
                                    blk.previous_hash.len(),
                                );
                                invalid = true;
                                break;
                            }
                        }
                        if invalid {
                            eprintln!("[p2p] 🔨 Range-Sync von {peer_str} abgebrochen – invalider Block");
                            let _ = self.event_tx.send(NetworkEvent::Error {
                                message: format!("Invalider Range-Sync-Block von {peer_str}"),
                            });
                            let _ = self.swarm.disconnect_peer_id(peer);
                        } else {
                            let block_count = response.blocks.len();
                            println!("[p2p] ← {block_count} Blöcke via Range-Sync von {peer}");
                            self.mark_sync_progress("range response received");

                            if let Some(entry) = self.peers.get_mut(&peer) {
                                entry.blocks_received += block_count as u64;
                            }
                            let _ = self.event_tx.send(NetworkEvent::RangeSyncReceived {
                                blocks: response.blocks,
                                from_peer: peer_str,
                            });
                        }
                    } else if let Some(block) = response.block {
                        // Einzelner Block-Sync
                        let hash = block.hash.clone();
                        if !self.is_duplicate(&hash) {
                            println!("[p2p] ← Block #{} via Sync von {peer}", block.index);
                            if let Some(entry) = self.peers.get_mut(&peer) {
                                entry.blocks_received += 1;
                            }
                            let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                                block: Box::new(block),
                                from_peer: peer.to_string(),
                            });
                        }
                    } else if response.chain_height.is_some() {
                        // ChainInfo-Antwort → prüfe ob wir Blöcke nachholen müssen
                        let remote_height = response.chain_height.unwrap_or(0);
                        println!(
                            "[p2p] 📊 ChainInfo von {peer}: height={remote_height}, genesis={:?}, lokal={}",
                            response.genesis_hash.as_deref().map(|h| &h[..12.min(h.len())]),
                            self.local_chain_count,
                        );

                        // Genesis-Prüfung falls beide Seiten eine Chain haben
                        if let Some(ref remote_genesis) = response.genesis_hash {
                            if let Some(our_gen) = self.genesis_hash_cache.as_deref() {
                                if our_gen != remote_genesis {
                                    eprintln!(
                                        "[p2p] ⛔ Genesis-Mismatch mit {peer}: lokal={}… remote={}…",
                                        &our_gen[..12.min(our_gen.len())],
                                        &remote_genesis[..12.min(remote_genesis.len())],
                                    );
                                    // Nicht syncen bei Genesis-Mismatch
                                    self.pending_chain_info.remove(&request_id);
                                    return;
                                }
                            }
                        }

                        // Aktuelle lokale Höhe lock-free aus `local_chain_count`
                        let actual_local = self.local_chain_count;

                        if remote_height > actual_local {
                            println!(
                                "[p2p] 🔄 Sync: Peer {peer} hat {remote_height} Blöcke, wir haben {actual_local} → hole {} fehlende",
                                remote_height - actual_local
                            );

                            let sync_from = if actual_local <= 50 { 1u64 } else { actual_local };

                            if !self.sync_buffer.is_empty() {
                                let buf_min = self.sync_buffer.keys().next().copied().unwrap_or(0);
                                if buf_min < sync_from {
                                    self.sync_buffer.clear();
                                }
                            }

                            let _ = self.event_tx.send(NetworkEvent::SyncStarted {
                                peer_id: peer.to_string(),
                                local_count: actual_local,
                                remote_count: remote_height,
                            });

                            self.sync_expected_next = sync_from;
                            self.start_sync_session(peer, "chain info indicates remote ahead");

                            // Range-Requests für fehlende Blöcke
                            let mut idx = sync_from;
                            while idx < remote_height {
                                let end = (idx + MAX_BLOCKS_PER_RANGE - 1).min(remote_height - 1);
                                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                                    &peer,
                                    BlockRequest { block_index: idx, block_index_end: Some(end) },
                                );
                                idx = end + 1;
                            }
                        }
                        if remote_height <= actual_local {
                            self.sync_target_peer = None;
                        }
                        self.pending_chain_info.remove(&request_id);
                    }
                }
            },

            // Request-Fehler (Timeout, Verbindungsabbruch)
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                let err_str = error.to_string();
                if err_str.contains("supports none of the requested protocols") {
                    let until = std::time::Instant::now() + std::time::Duration::from_secs(120);
                    let should_log = self.protocol_mismatch_cooldown
                        .get(&peer)
                        .map(|t| *t <= std::time::Instant::now())
                        .unwrap_or(true);
                    self.protocol_mismatch_cooldown.insert(peer, until);
                    if should_log {
                        eprintln!(
                            "[p2p] ⚠ Peer {peer} protokoll-inkompatibel – 120s Quarantäne aktiviert"
                        );
                    }
                }

                if let Some((peer_id_str, _, reply)) = self.pending_pings.remove(&request_id) {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id_str,
                        reachable: false,
                        latency_ms: None,
                        error: Some(err_str.clone()),
                    });
                } else {
                    // pending_chain_info aufräumen bei Fehler (verhindert Memory-Leak + Sync-Blockade)
                    self.pending_chain_info.remove(&request_id);
                    if Some(peer) == self.sync_target_peer {
                        self.sync_last_recovery_reason = format!("request failure to target peer: {err_str}");
                    }
                    if !err_str.contains("supports none of the requested protocols") {
                        eprintln!("[p2p] Request-Fehler zu {peer}: {err_str}");
                    }
                }
            }

            // ── Relay-Client Events ──────────────────────────────────────────────

            StoneBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                ..
            }) => {
                self.active_relays.insert(relay_peer_id);
                println!("[p2p] ✅ Relay-Reservation akzeptiert von {relay_peer_id} ({} aktive Relays)", self.active_relays.len());

                // ── Relay-Circuit-Adresse als externe Adresse bekanntgeben ──
                if let Some(info) = self.peers.get(&relay_peer_id) {
                    for addr_str in &info.addresses {
                        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                            let is_public = addr.iter().any(|p| {
                                matches!(p,
                                    libp2p::multiaddr::Protocol::Ip4(ip)
                                        if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified()
                                ) || matches!(p,
                                    libp2p::multiaddr::Protocol::Ip6(ip)
                                        if !ip.is_loopback() && !ip.is_unspecified() && !is_ipv6_non_global(&ip)
                                )
                            });
                            if is_public {
                                let circuit_addr = strip_p2p_suffix(addr)
                                    .with(libp2p::multiaddr::Protocol::P2p(relay_peer_id))
                                    .with(libp2p::multiaddr::Protocol::P2pCircuit);
                                let local_peer = *self.swarm.local_peer_id();
                                let full_circuit = circuit_addr.clone()
                                    .with(libp2p::multiaddr::Protocol::P2p(local_peer));
                                self.swarm.add_external_address(full_circuit.clone());
                                println!("[p2p] 🌍 Relay-Circuit als externe Adresse: {full_circuit}");
                            }
                        }
                    }
                }
            }

            StoneBehaviourEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished {
                limit, ..
            }) => {
                println!("[p2p] 🔗 Ausgehender Relay-Circuit hergestellt (limit: {limit:?})");
            }

            StoneBehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
                src_peer_id,
                limit,
            }) => {
                println!("[p2p] 🔗 Eingehender Relay-Circuit von {src_peer_id} (limit: {limit:?})");
            }

            // ── DCUtR (Direct Connection Upgrade / Hole-Punching) ────────────────

            StoneBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => {
                match result {
                    Ok(_) => {
                        println!("[p2p] 🕳️  Hole-Punch erfolgreich zu {remote_peer_id}!");
                    }
                    Err(e) => {
                        eprintln!("[p2p] ⚠ Hole-Punch fehlgeschlagen zu {remote_peer_id}: {e:?}");
                    }
                }
            }

            // ── AutoNAT (NAT-Erkennung) ──────────────────────────────────────────

            StoneBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new }) => {
                println!("[p2p] 🌐 NAT-Status: {old:?} → {new:?}");
                match new {
                    autonat::NatStatus::Public(_addr) => {
                        self.nat_status = NatStatus::Public;
                        println!("[p2p] ✅ NAT-Status: Öffentlich erreichbar");
                    }
                    autonat::NatStatus::Private => {
                        self.nat_status = NatStatus::Private;
                        println!("[p2p] 🔒 NAT-Status: Privat – nutze Relay für Erreichbarkeit");
                        // Bei privatem NAT automatisch Relay-Reservierungen herstellen
                        self.establish_relay_reservations();
                        // Zusätzlich: Alle bereits verbundenen Peers als potentielle Relays nutzen
                        self.auto_discover_relays();
                    }
                    autonat::NatStatus::Unknown => {
                        self.nat_status = NatStatus::Unknown;
                    }
                }
            }

            StoneBehaviourEvent::Autonat(_) => {}

            // ── UPnP (Automatische Port-Weiterleitung) ──────────────────────────

            StoneBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr)) => {
                println!("[p2p] 🔌 UPnP: Externe Adresse hinzugefügt: {addr}");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::GatewayNotFound) => {
                println!("[p2p] ℹ️  UPnP: Kein Gateway gefunden – Relay wird genutzt");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::NonRoutableGateway) => {
                println!("[p2p] ℹ️  UPnP: Gateway ist nicht routbar");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr(addr)) => {
                println!("[p2p] ⏰ UPnP: Externe Adresse abgelaufen: {addr}");
            }

            // ── Relay-Server Events (wir leiten Traffic für andere weiter) ───────

            #[allow(deprecated)]
            StoneBehaviourEvent::RelayServer(relay::Event::ReservationReqAccepted {
                src_peer_id,
                ..
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} akzeptiert (wir sind Relay für diesen Node)");
            }

            StoneBehaviourEvent::RelayServer(relay::Event::ReservationReqDenied {
                src_peer_id,
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} abgelehnt (Limit erreicht)");
            }

            StoneBehaviourEvent::RelayServer(relay::Event::ReservationTimedOut {
                src_peer_id,
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} abgelaufen");
            }

            StoneBehaviourEvent::RelayServer(_) => {}

            // ── Shard-Exchange (Request/Response) ────────────────────────────
            StoneBehaviourEvent::ShardExchange(
                request_response::Event::Message { peer, message, .. }
            ) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    match request {
                        ShardRequest::GetShard { chunk_hash, shard_index } => {
                            println!("[p2p] 📦 Shard-Anfrage: {chunk_hash}[{shard_index}] von {peer}");
                            let data = self.shard_store.read_shard(&chunk_hash, shard_index).ok();
                            let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                channel,
                                ShardResponse::ShardData { chunk_hash, shard_index, data },
                            );
                        }
                        ShardRequest::StoreShard { chunk_hash, shard_index, shard_hash, data } => {
                            let incoming_len = data.len() as u64;
                            println!("[p2p] 💾 Shard-Store: {chunk_hash}[{shard_index}] von {peer} ({} bytes)", data.len());
                            self.net_metrics.bytes_in += incoming_len;
                            self.net_metrics.messages_in += 1;
                            self.net_metrics.shard_bytes_in += incoming_len;
                            match self.shard_store.write_shard(&chunk_hash, shard_index, &data) {
                                Ok(written_hash) => {
                                    let ok = written_hash == shard_hash;
                                    if !ok {
                                        eprintln!("[p2p] ⚠ Shard-Hash Mismatch: erwartet {shard_hash}, got {written_hash}");
                                    }
                                    if ok {
                                        let _ = self.event_tx.send(NetworkEvent::ShardReceived {
                                            chunk_hash: chunk_hash.clone(),
                                            shard_index,
                                            data,
                                            from_peer: peer.to_string(),
                                        });
                                    }
                                    let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                        channel,
                                        ShardResponse::StoreResult {
                                            chunk_hash,
                                            shard_index,
                                            success: ok,
                                            error: if ok { None } else { Some("Hash mismatch".into()) },
                                        },
                                    );
                                }
                                Err(e) => {
                                    eprintln!("[p2p] ❌ Shard-Store Fehler: {e}");
                                    let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                        channel,
                                        ShardResponse::StoreResult {
                                            chunk_hash,
                                            shard_index,
                                            success: false,
                                            error: Some(e.to_string()),
                                        },
                                    );
                                }
                            }
                        }
                        ShardRequest::ListShards { chunk_hash } => {
                            let indices = self.shard_store.local_shard_indices(&chunk_hash);
                            println!("[p2p] 📋 Shard-Liste für {chunk_hash}: {:?} (an {peer})", indices);
                            let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                channel,
                                ShardResponse::ShardList { chunk_hash, indices },
                            );
                        }
                    }
                }
                request_response::Message::Response { request_id, response, .. } => {
                    match response {
                        ShardResponse::ShardData { chunk_hash, shard_index, data } => {
                            if let Some(data) = data {
                                let recv_len = data.len() as u64;
                                println!("[p2p] ← Shard empfangen: {chunk_hash}[{shard_index}] ({} bytes) von {peer}", data.len());
                                self.net_metrics.bytes_in += recv_len;
                                self.net_metrics.messages_in += 1;
                                self.net_metrics.shard_bytes_in += recv_len;
                                let _ = self.event_tx.send(NetworkEvent::ShardReceived {
                                    chunk_hash,
                                    shard_index,
                                    data,
                                    from_peer: peer.to_string(),
                                });
                            } else {
                                println!("[p2p] ← Shard nicht gefunden: {chunk_hash}[{shard_index}] bei {peer}");
                                let _ = self.event_tx.send(NetworkEvent::ShardRequestFailed {
                                    chunk_hash,
                                    shard_index,
                                    peer_id: peer.to_string(),
                                    error: "Shard nicht vorhanden".into(),
                                });
                            }
                        }
                        ShardResponse::StoreResult { chunk_hash, shard_index, success, error } => {
                            println!("[p2p] ← Shard-Store Ergebnis: {chunk_hash}[{shard_index}] bei {peer} → {success}");
                            let _ = self.event_tx.send(NetworkEvent::ShardStored {
                                chunk_hash,
                                shard_index,
                                peer_id: peer.to_string(),
                                success,
                                error,
                            });
                        }
                        ShardResponse::ShardList { chunk_hash, indices } => {
                            // Antwort auf ListPeerShards
                            if let Some((_, reply)) = self.pending_shard_lists.remove(&request_id) {
                                let _ = reply.send(indices);
                            } else {
                                println!("[p2p] Shard-Liste von {peer}: {chunk_hash} → {indices:?}");
                            }
                        }
                    }
                }
            },

            StoneBehaviourEvent::ShardExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                let err_str = error.to_string();
                if err_str.contains("supports none of the requested protocols") {
                    let until = std::time::Instant::now() + std::time::Duration::from_secs(120);
                    let should_log = self.protocol_mismatch_cooldown
                        .get(&peer)
                        .map(|t| *t <= std::time::Instant::now())
                        .unwrap_or(true);
                    self.protocol_mismatch_cooldown.insert(peer, until);
                    if should_log {
                        eprintln!(
                            "[p2p] ⚠ Peer {peer} protokoll-inkompatibel – 120s Quarantäne aktiviert"
                        );
                    }
                }

                if let Some((_chunk_hash, reply)) = self.pending_shard_lists.remove(&request_id) {
                    if !err_str.contains("supports none of the requested protocols") {
                        eprintln!("[p2p] Shard-Liste Fehler zu {peer}: {err_str}");
                    }
                    let _ = reply.send(vec![]);
                } else {
                    if !err_str.contains("supports none of the requested protocols") {
                        eprintln!("[p2p] Shard-Request Fehler zu {peer}: {err_str}");
                    }
                }
            }

            StoneBehaviourEvent::ShardExchange(_) => {}

            _ => {}
        }
    }
}
