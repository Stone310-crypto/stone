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
    pub(crate) fn is_protocol_mismatch_quarantined(&self, peer: &PeerId) -> bool {
        self.protocol_mismatch_cooldown
            .get(peer)
            .map(|until| Instant::now() < *until)
            .unwrap_or(false)
    }

    fn sync_session_active(&self) -> bool {
        // Only consider sync "active" if we're actually behind a peer OR have blocks to process.
        // pending_chain_info is NOT a sync indicator — it's just I/O-in-flight tracking.
        self.sync_target_peer.is_some() || !self.sync_buffer.is_empty()
    }

    fn connected_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.connected).count()
    }

    fn connected_bootstrap_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|(pid, info)| info.connected && self.bootstrap_peer_ids.contains(pid))
            .count()
    }

    fn has_penalty_reason(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        self.peer_penalties.values().any(|p| {
            p.reasons
                .iter()
                .rev()
                .take(10)
                .any(|r| r.to_ascii_lowercase().contains(&needle))
        })
    }

    fn has_partition_signal(&self) -> bool {
        self.has_penalty_reason("genesis mismatch")
            || self.has_penalty_reason("incompatible protocol version")
    }

    fn has_peer_poisoning_signal(&self) -> bool {
        self.has_penalty_reason("invalid hash")
            || self.has_penalty_reason("invalid merkle root")
            || self.has_penalty_reason("invalid validator signature")
            || self.has_penalty_reason("invalid tx signature")
    }

    fn has_database_inconsistency_signal(&self) -> bool {
        let r = self.sync_last_recovery_reason.to_ascii_lowercase();
        r.contains("db") || r.contains("database") || r.contains("index mismatch")
    }

    fn evaluate_network_health(&self) -> (NetworkHealthState, Option<FailureClass>, String) {
        let connected = self.connected_peer_count();
        let bootstrap_connected = self.connected_bootstrap_count();
        let total_known = self.peers.len();

        let avg_latency = {
            let mut vals: Vec<u64> = Vec::new();
            for pid in self.peers.iter().filter_map(|(pid, info)| if info.connected { Some(*pid) } else { None }) {
                if let Some(ms) = self.avg_latency_ms(&pid) {
                    vals.push(ms);
                }
            }
            if vals.is_empty() {
                None
            } else {
                Some(vals.iter().sum::<u64>() / vals.len() as u64)
            }
        };

        let sync_active = self.sync_session_active();
        let stalled = sync_active
            && self.sync_stall_timeout_secs > 0
            && self.sync_last_progress_at.elapsed() > Duration::from_secs(self.sync_stall_timeout_secs);

        let partition_signal = self.has_partition_signal();
        let poisoning_signal = self.has_peer_poisoning_signal();
        let relay_collapse = self.nat_status == NatStatus::Private
            && !self.relay_addrs.is_empty()
            && self.active_relays.is_empty();
        let high_churn = connected <= 1 && total_known >= 6;
        let db_inconsistency = self.has_database_inconsistency_signal();

        let failure = if db_inconsistency {
            Some(FailureClass::DatabaseInconsistency)
        } else if partition_signal {
            Some(FailureClass::NetworkPartition)
        } else if stalled {
            Some(FailureClass::SyncDivergence)
        } else if connected == 0 {
            Some(FailureClass::DiscoveryFailure)
        } else if !self.bootstrap_peer_ids.is_empty() && bootstrap_connected == 0 && connected == 0 {
            Some(FailureClass::BootstrapFailure)
        } else if poisoning_signal {
            Some(FailureClass::PeerPoisoning)
        } else if relay_collapse {
            Some(FailureClass::RelayCollapse)
        } else if high_churn {
            Some(FailureClass::HighChurn)
        } else {
            None
        };

        let state = if db_inconsistency {
            NetworkHealthState::Critical
        } else if self.sync_recovery_stage == SyncRecoveryStage::Stage4SnapshotEscalation {
            NetworkHealthState::SnapshotRecovery
        } else if matches!(
            self.sync_recovery_stage,
            SyncRecoveryStage::Stage1SoftReset
                | SyncRecoveryStage::Stage2PeerSwitch
                | SyncRecoveryStage::Stage3RebuildNetwork
        ) {
            NetworkHealthState::Recovering
        } else if partition_signal {
            NetworkHealthState::Partitioned
        } else if connected == 0 {
            NetworkHealthState::Isolated
        } else if sync_active {
            NetworkHealthState::Syncing
        } else if connected <= 1
            || avg_latency.map(|ms| ms > 900).unwrap_or(false)
            || (!self.bootstrap_peer_ids.is_empty() && bootstrap_connected == 0)
        {
            NetworkHealthState::Degraded
        } else {
            NetworkHealthState::Healthy
        };

        let reason = format!(
            "connected={} bootstrap_connected={} known={} sync_active={} stalled={} avg_latency_ms={}",
            connected,
            bootstrap_connected,
            total_known,
            sync_active,
            stalled,
            avg_latency
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );

        (state, failure, reason)
    }

    fn refresh_peer_table_non_bootstrap(&mut self) -> usize {
        let before = self.peers.len();
        let now_ts = chrono::Utc::now().timestamp();
        self.peers.retain(|pid, info| {
            if self.bootstrap_peer_ids.contains(pid) {
                return true;
            }
            if info.connected {
                return true;
            }
            // sehr alte oder nie gesunde Einträge verwerfen
            !(info.last_seen == 0 || now_ts.saturating_sub(info.last_seen) > 900)
        });
        before.saturating_sub(self.peers.len())
    }

    fn isolate_high_penalty_non_bootstrap_peers(&mut self) -> usize {
        let to_disconnect: Vec<PeerId> = self
            .peer_penalties
            .iter()
            .filter(|(pid, p)| !self.bootstrap_peer_ids.contains(pid) && p.score >= (BAN_THRESHOLD / 2))
            .map(|(pid, _)| *pid)
            .collect();
        let mut n = 0usize;
        for pid in to_disconnect {
            if self.swarm.disconnect_peer_id(pid).is_ok() {
                n += 1;
            }
            if let Some(info) = self.peers.get_mut(&pid) {
                info.connected = false;
            }
        }
        n
    }

    pub(super) fn run_health_controller(&mut self) {
        let (state, failure, reason) = self.evaluate_network_health();
        let transition = self.health_state != state || self.health_failure != failure;
        if transition {
            println!(
                "[health] {} -> {} failure={} level={} reason={}",
                self.health_state.as_str(),
                state.as_str(),
                failure.map(|f| f.as_str()).unwrap_or("none"),
                self.health_recovery_level.as_str(),
                reason
            );
            self.health_last_transition = Instant::now();
        }
        self.health_state = state;
        self.health_failure = failure;
        self.health_last_reason = reason;

        if self.sync_recovery_stage == SyncRecoveryStage::Stage4SnapshotEscalation {
            self.health_recovery_level = RecoveryLevel::Level5SnapshotSync;
        }

        if let Some(until) = self.health_cooldown_until {
            if Instant::now() < until {
                return;
            }
        }

        match failure {
            Some(FailureClass::DiscoveryFailure) => {
                self.reconnect_bootstrap_nodes();
                if self.config.kad_enabled {
                    let _ = self.swarm.behaviour_mut().kad.bootstrap();
                }
                self.send_sync_handshake();
                self.health_recovery_level = RecoveryLevel::Level1SoftReconnect;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(20));
            }
            Some(FailureClass::BootstrapFailure) => {
                let removed = self.refresh_peer_table_non_bootstrap();
                self.reconnect_bootstrap_nodes();
                self.send_sync_handshake();
                println!("[health] Level2 Peer-Table-Refresh removed={removed}");
                self.health_recovery_level = RecoveryLevel::Level2PeerTableRefresh;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(30));
            }
            Some(FailureClass::HighChurn) => {
                self.keepalive_ping_peers();
                self.reconnect_bootstrap_nodes();
                self.health_recovery_level = RecoveryLevel::Level1SoftReconnect;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(25));
            }
            Some(FailureClass::RelayCollapse) => {
                self.establish_relay_reservations();
                self.health_recovery_level = RecoveryLevel::Level3KadBootstrapReset;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(45));
            }
            Some(FailureClass::PeerPoisoning) => {
                let disconnected = self.isolate_high_penalty_non_bootstrap_peers();
                println!("[health] Level4 Peer-Cache-Invalidation disconnected={disconnected}");
                self.health_recovery_level = RecoveryLevel::Level4PeerCacheInvalidation;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(45));
            }
            Some(FailureClass::SyncDivergence) => {
                self.maybe_recover_sync_stall();
                self.health_recovery_level = RecoveryLevel::Level3KadBootstrapReset;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(20));
            }
            Some(FailureClass::NetworkPartition) => {
                // Deterministisch: zuerst Peer-Switch, dann Rebuild über bestehende WS-C-Mechanik.
                if self.sync_recovery_stage == SyncRecoveryStage::Idle {
                    self.trigger_stage2_peer_switch("health controller: network partition");
                } else {
                    self.maybe_recover_sync_stall();
                }
                self.health_recovery_level = RecoveryLevel::Level4PeerCacheInvalidation;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(40));
            }
            Some(FailureClass::DatabaseInconsistency) => {
                self.trigger_stage4_snapshot_escalation("health controller: database inconsistency");
                self.health_recovery_level = RecoveryLevel::Level6CriticalIsolation;
                self.health_cooldown_until = Some(Instant::now() + Duration::from_secs(120));
            }
            None => {
                self.health_recovery_level = RecoveryLevel::None;
                self.health_cooldown_until = None;
            }
        }
    }

    pub(super) fn mark_sync_progress(&mut self, reason: &str) {
        self.sync_last_progress_at = std::time::Instant::now();
        self.sync_last_progress_height = self.local_chain_count;
        if self.sync_recovery_stage != SyncRecoveryStage::Idle {
            println!(
                "[p2p] 🛠️ WS-C Recovery abgeschlossen ({} -> idle): {reason}",
                self.sync_recovery_stage.as_str(),
            );
        }
        self.sync_recovery_stage = SyncRecoveryStage::Idle;
        self.sync_last_recovery_reason.clear();
        self.sync_recovery_cooldown_until = None;
    }

    pub(super) fn start_sync_session(&mut self, peer_id: PeerId, reason: &str) {
        self.sync_target_peer = Some(peer_id);
        self.sync_last_progress_at = std::time::Instant::now();
        self.sync_last_recovery_reason = reason.to_string();
    }

    fn best_sync_peer(&self, avoid: Option<PeerId>) -> Option<PeerId> {
        let mut best: Option<(PeerId, i64)> = None;
        for (pid, info) in &self.peers {
            if !info.connected {
                continue;
            }
            if Some(*pid) == avoid {
                continue;
            }

            let latency_score = self.avg_latency_ms(pid)
                .map(|ms| (1000_i64 - (ms as i64).min(1000)).max(0))
                .unwrap_or(200);
            let score = (info.stake_level as i64 * 10)
                + (info.blocks_received as i64)
                + latency_score;

            match best {
                Some((_, best_score)) if best_score >= score => {}
                _ => best = Some((*pid, score)),
            }
        }
        best.map(|(pid, _)| pid)
    }

    fn trigger_stage1_soft_reset(&mut self, reason: &str) {
        self.sync_recovery_stage = SyncRecoveryStage::Stage1SoftReset;
        self.sync_recovery_attempts = self.sync_recovery_attempts.saturating_add(1);
        self.sync_last_recovery_reason = reason.to_string();

        let pending_before = self.pending_chain_info.len();
        let buffered_before = self.sync_buffer.len();
        self.pending_chain_info.clear();
        self.sync_buffer.clear();
        self.sync_buffer_last_insert = None;
        self.sync_expected_next = self.local_chain_count;

        let target = self.best_sync_peer(None).or(self.sync_target_peer);
        if let Some(peer) = target {
            let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                &peer,
                BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
            );
            self.pending_chain_info.insert(req_id, peer);
            self.sync_target_peer = Some(peer);
            println!(
                "[p2p] 🛠️ WS-C Stage1: Soft-Reset (pending={} buffer={}) -> ChainInfo an {} ({reason})",
                pending_before,
                buffered_before,
                peer,
            );
        } else {
            self.sync_target_peer = None;
            println!(
                "[p2p] 🛠️ WS-C Stage1: Soft-Reset ohne verfügbaren Peer ({reason})",
            );
            self.send_sync_handshake();
        }

        self.sync_recovery_cooldown_until = Some(
            std::time::Instant::now() + Duration::from_secs(self.sync_recovery_cooldown_secs),
        );
        self.sync_last_progress_at = std::time::Instant::now();
    }

    fn trigger_stage2_peer_switch(&mut self, reason: &str) {
        self.sync_recovery_stage = SyncRecoveryStage::Stage2PeerSwitch;
        self.sync_recovery_attempts = self.sync_recovery_attempts.saturating_add(1);
        self.sync_last_recovery_reason = reason.to_string();

        let prev_target = self.sync_target_peer;
        let target = self.best_sync_peer(prev_target).or(self.best_sync_peer(None));
        self.pending_chain_info.clear();
        self.sync_buffer.clear();
        self.sync_buffer_last_insert = None;
        self.sync_expected_next = self.local_chain_count;

        if let Some(peer) = target {
            let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                &peer,
                BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
            );
            self.pending_chain_info.insert(req_id, peer);
            self.sync_target_peer = Some(peer);
            println!(
                "[p2p] 🛠️ WS-C Stage2: Peer-Switch {} -> {} ({reason})",
                prev_target.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
                peer,
            );
        } else {
            self.sync_target_peer = None;
            println!("[p2p] 🛠️ WS-C Stage2: kein alternativer Peer verfügbar ({reason})");
            self.send_sync_handshake();
        }

        self.sync_recovery_cooldown_until = Some(
            std::time::Instant::now() + Duration::from_secs(self.sync_recovery_cooldown_secs),
        );
        self.sync_last_progress_at = std::time::Instant::now();
    }

    fn trigger_stage3_rebuild_network(&mut self, reason: &str) {
        self.sync_recovery_stage = SyncRecoveryStage::Stage3RebuildNetwork;
        self.sync_recovery_attempts = self.sync_recovery_attempts.saturating_add(1);
        self.sync_last_recovery_reason = reason.to_string();

        let connected: Vec<PeerId> = self.swarm.connected_peers().cloned().collect();
        let mut disconnected = 0u32;
        for pid in connected {
            if self.swarm.disconnect_peer_id(pid).is_ok() {
                disconnected += 1;
            }
        }

        self.pending_chain_info.clear();
        self.sync_buffer.clear();
        self.sync_buffer_last_insert = None;
        self.sync_expected_next = self.local_chain_count;
        self.sync_target_peer = None;

        let mut dialed = 0u32;
        for addr_str in self.bootstrap_addrs.clone() {
            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                if self.swarm.dial(addr).is_ok() {
                    dialed += 1;
                }
            }
        }

        if self.config.kad_enabled {
            let _ = self.swarm.behaviour_mut().kad.bootstrap();
        }
        self.send_sync_handshake();

        println!(
            "[p2p] 🛠️ WS-C Stage3: Netzwerk-Rebuild (disconnected={}, redial_bootstrap={}) ({reason})",
            disconnected,
            dialed,
        );

        self.sync_recovery_cooldown_until = Some(
            std::time::Instant::now() + Duration::from_secs(self.sync_recovery_cooldown_secs),
        );
        self.sync_last_progress_at = std::time::Instant::now();
    }

    fn trigger_stage4_snapshot_escalation(&mut self, reason: &str) {
        self.sync_recovery_stage = SyncRecoveryStage::Stage4SnapshotEscalation;
        self.sync_recovery_attempts = self.sync_recovery_attempts.saturating_add(1);
        self.sync_last_recovery_reason = reason.to_string();
        self.sync_target_peer = None;

        let msg = format!(
            "WS-C Stage4: Snapshot-Eskalation empfohlen ({reason}). "
        );
        eprintln!(
            "[p2p] 🚨 {}Führe verifizierten Snapshot-Sync aus und starte den Node neu.",
            msg
        );
        let _ = self.event_tx.send(NetworkEvent::Error {
            message: format!(
                "{msg}Nutze Snapshot-Recovery (verified_download_snapshot) und danach Reboot."
            ),
        });

        self.sync_recovery_cooldown_until = Some(
            std::time::Instant::now()
                + Duration::from_secs(self.sync_snapshot_escalation_cooldown_secs),
        );
        self.sync_last_progress_at = std::time::Instant::now();
    }

    pub(super) fn maybe_recover_sync_stall(&mut self) {
        if self.sync_stall_timeout_secs == 0 {
            return;
        }

        // Recovery nur wenn tatsächlich ein Sync aktiv oder erwartet ist.
        let sync_active = self.sync_target_peer.is_some()
            || !self.sync_buffer.is_empty()
            || !self.pending_chain_info.is_empty();
        if !sync_active {
            return;
        }

        if let Some(until) = self.sync_recovery_cooldown_until {
            if std::time::Instant::now() < until {
                return;
            }
        }

        let stalled_for = self.sync_last_progress_at.elapsed();
        if stalled_for < Duration::from_secs(self.sync_stall_timeout_secs) {
            return;
        }

        let reason = format!(
            "kein Sync-Fortschritt seit {}s (target={}, pending={}, buffer={})",
            stalled_for.as_secs(),
            self.sync_target_peer
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.pending_chain_info.len(),
            self.sync_buffer.len(),
        );

        match self.sync_recovery_stage {
            SyncRecoveryStage::Idle => {
                if self.sync_recovery_stage1_enabled {
                    self.trigger_stage1_soft_reset(&reason);
                    return;
                }
                if self.sync_recovery_stage2_enabled {
                    self.trigger_stage2_peer_switch(&reason);
                    return;
                }
                if self.sync_recovery_stage3_enabled {
                    self.trigger_stage3_rebuild_network(&reason);
                    return;
                }
                if self.sync_recovery_stage4_enabled {
                    self.trigger_stage4_snapshot_escalation(&reason);
                    return;
                }
            }
            SyncRecoveryStage::Stage1SoftReset => {
                if self.sync_recovery_stage2_enabled {
                    self.trigger_stage2_peer_switch(&reason);
                    return;
                }
                if self.sync_recovery_stage3_enabled {
                    self.trigger_stage3_rebuild_network(&reason);
                    return;
                }
                if self.sync_recovery_stage4_enabled {
                    self.trigger_stage4_snapshot_escalation(&reason);
                    return;
                }
            }
            SyncRecoveryStage::Stage2PeerSwitch => {
                if self.sync_recovery_stage3_enabled {
                    self.trigger_stage3_rebuild_network(&reason);
                    return;
                }
                if self.sync_recovery_stage4_enabled {
                    self.trigger_stage4_snapshot_escalation(&reason);
                    return;
                }
            }
            SyncRecoveryStage::Stage3RebuildNetwork => {
                if self.sync_recovery_stage4_enabled {
                    self.trigger_stage4_snapshot_escalation(&reason);
                    return;
                }
            }
            SyncRecoveryStage::Stage4SnapshotEscalation => {
                // Bereits höchstes Level erreicht – nur eskalierten Zustand halten.
                return;
            }
        }

        // Fallback wenn Stage-Flags deaktiviert sind: nur Handshake neu senden.
        self.sync_last_recovery_reason = reason.clone();
        println!("[p2p] WS-C Fallback: sende Sync-Handshake erneut ({reason})");
        self.send_sync_handshake();
        self.sync_recovery_cooldown_until = Some(
            std::time::Instant::now() + Duration::from_secs(self.sync_recovery_cooldown_secs),
        );
        self.sync_last_progress_at = std::time::Instant::now();
    }

    /// Flusht geordnete Blöcke aus dem Sync-Buffer in den Event-Channel.
    /// Nur zusammenhängende Blöcke ab `sync_expected_next` werden gesendet.
    pub(super) fn flush_sync_buffer(&mut self) {
        // Aktuelle Chain-Höhe ohne Lock (lock-free, via `local_chain_count` der
        // periodisch vom Master-Pfad via `SetLocalChainCount` aktualisiert wird).
        let actual_local = self.local_chain_count;

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
            self.mark_sync_progress("flush_sync_buffer");
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
            if self.pending_chain_info.is_empty() {
                self.sync_target_peer = None;
            }
        }
    }

    /// Sendet ChainInfo-Anfragen an alle verbundenen Peers per Request/Response.
    /// Zuverlässiger als GossipSub (braucht keinen Mesh).
    pub(super) fn sync_with_connected_peers(&mut self) {
        // ── local_chain_count wird außerhalb via SetLocalChainCount aktualisiert.
        //    Kein Lock auf chain_ref nötig hier (Hot-Path).

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

        if self.local_chain_count > self.sync_last_progress_height {
            self.mark_sync_progress("local chain count advanced");
        }

        self.maybe_recover_sync_stall();

        // Auch GossipSub-Handshake senden für Peers die hinter UNS sind
        self.send_sync_handshake();

        for (peer_id, _stake) in connected {
            if self.is_protocol_mismatch_quarantined(&peer_id) {
                continue;
            }
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
        // Genesis-Hash aus dem Cache (kein Lock)
        let genesis_hash = self.genesis_hash_cache.as_deref().map(|s| s.to_string());
        // Aktuelle Höhe ohne Lock
        let actual_count = self.local_chain_count;
        let msg = SyncHandshake {
            block_count: actual_count,
            peer_id: self.swarm.local_peer_id().to_string(),
            genesis_hash,
            protocol_version: Some(STONE_PROTOCOL_VERSION.to_string()),
            stake_level: self.local_stake_level,
        };
        if let Ok(data) = super::encode_gossip(&msg) {
            let topic = IdentTopic::new(TOPIC_SYNC_HANDSHAKE.as_str());
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
    pub(super) fn handle_sync_handshake(
        &mut self,
        data: Vec<u8>,
        source: PeerId,
    ) -> libp2p::gossipsub::MessageAcceptance {
        use libp2p::gossipsub::MessageAcceptance;
        let Ok(msg) = super::decode_gossip::<SyncHandshake>(&data) else {
            self.add_peer_penalty(&source, 10, "malformed sync handshake");
            return MessageAcceptance::Reject;
        };

        if msg.peer_id == self.swarm.local_peer_id().to_string() {
            return MessageAcceptance::Ignore; // eigene Nachricht
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
                return MessageAcceptance::Reject;
            }
        }

        // ── Genesis-Hash prüfen (aus Cache, kein Lock) ───────────────────
        if let Some(ref remote_genesis) = msg.genesis_hash {
            if let Some(our_gen) = self.genesis_hash_cache.as_deref() {
                if our_gen != remote_genesis {
                    eprintln!(
                        "[p2p] ⛔ Genesis-Mismatch mit {source}: lokal={}… remote={}… – Peer getrennt",
                        &our_gen[..12.min(our_gen.len())],
                        &remote_genesis[..12.min(remote_genesis.len())],
                    );
                    self.add_peer_penalty(&source, 200, "genesis mismatch");
                    let _ = self.swarm.disconnect_peer_id(source);
                    return MessageAcceptance::Reject;
                }
            }
        }

        // Aktuelle lokale Höhe lock-free aus `local_chain_count`
        let actual_local = self.local_chain_count;

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
            self.start_sync_session(source, "sync handshake indicates remote ahead");

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
        MessageAcceptance::Accept
    }
}
