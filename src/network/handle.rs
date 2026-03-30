// ─── Öffentliche API ──────────────────────────────────────────────────────────

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use tokio::sync::{broadcast, mpsc};

use super::*;
use super::swarm_task::SwarmTask;

/// Handle für den laufenden P2P-Swarm-Task.
///
/// Wird als `AppState.network` gehalten. Alle Methoden sind `async` und
/// kommunizieren über den `mpsc`-Kanal mit dem Swarm-Task.
#[derive(Clone)]
pub struct NetworkHandle {
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    pub event_rx: broadcast::Sender<NetworkEvent>,
    pub local_peer_id: String,
}

impl NetworkHandle {
    /// Broadcastet einen Block per Gossipsub an alle Peers.
    pub async fn broadcast_block(&self, block: Block) {
        let _ = self.cmd_tx.send(NetworkCommand::BroadcastBlock(Box::new(block))).await;
    }

    /// Broadcastet eine Token-TX per Gossipsub an alle Peers.
    pub async fn broadcast_tx(&self, tx: crate::token::TokenTx) {
        let _ = self.cmd_tx.send(NetworkCommand::BroadcastTx(Box::new(tx))).await;
    }

    /// Publiziert eine generische Nachricht auf einem Gossipsub-Topic.
    pub async fn publish_gossip(&self, topic: &str, data: Vec<u8>) {
        let topic_hash = IdentTopic::new(topic).hash();
        let _ = self.cmd_tx.send(NetworkCommand::PublishGossip { topic: topic_hash, data }).await;
    }

    /// Wählt einen Peer manuell an.
    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::DialPeer(addr)).await;
    }

    /// Teilt dem Swarm unsere aktuelle Chain-Länge mit (z.B. nach jedem neuen Block).
    pub async fn set_chain_count(&self, count: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SetLocalChainCount(count)).await;
    }

    /// Setzt die Chain-Referenz, damit der SwarmTask Blöcke direkt servieren kann.
    pub async fn set_chain_ref(&self, chain: std::sync::Arc<std::sync::Mutex<crate::blockchain::StoneChain>>) {
        let _ = self.cmd_tx.send(NetworkCommand::SetChainRef(chain)).await;
    }

    /// Startet einen expliziten Chain-Sync mit einem bestimmten Peer.
    pub async fn sync_with(&self, peer_id: PeerId, our_block_count: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SyncWithPeer { peer_id, our_block_count }).await;
    }

    /// Gibt die aktuelle Peer-Liste zurück.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd_tx.send(NetworkCommand::GetPeers(tx)).await;
        rx.await.unwrap_or_default()
    }

    /// Gibt alle verbundenen Peers zurück.
    pub async fn connected_peers(&self) -> Vec<PeerInfo> {
        self.get_peers().await.into_iter().filter(|p| p.connected).collect()
    }

    /// Subscribt auf Network-Events (broadcast channel).
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_rx.subscribe()
    }

    /// Pingt einen Peer via Request/Response und misst die Latenz.
    /// Timeout: 5 Sekunden. Gibt `PingResult.reachable = false` bei Fehler zurück.
    pub async fn ping(&self, peer_id: PeerId) -> PingResult {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(NetworkCommand::Ping { peer_id: peer_id.clone(), reply: tx }).await.is_err() {
            return PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("P2P-Task nicht erreichbar".to_string()),
            };
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Interner Fehler".to_string()),
            },
            Err(_) => PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Timeout (5s)".to_string()),
            },
        }
    }

    /// Gibt den vollständigen Netzwerkstatus zurück (alle Peers, Mesh, Chain-Count).
    pub async fn get_status(&self) -> Option<NetworkStatus> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx.send(NetworkCommand::GetStatus(tx)).await.ok()?;
        tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await.ok()?.ok()
    }

    /// Gibt nur die Netzwerk-Metriken zurück.
    pub async fn get_metrics(&self) -> Option<NetworkMetrics> {
        self.get_status().await.map(|s| s.metrics)
    }

    /// Beendet den Swarm-Task.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
    }

    // ── Shard-API ─────────────────────────────────────────────────────────────

    /// Fordert einen bestimmten Shard von einem Peer an.
    /// Die Antwort kommt asynchron als `NetworkEvent::ShardReceived`.
    pub async fn request_shard(&self, peer_id: PeerId, chunk_hash: String, shard_index: u8) {
        let _ = self.cmd_tx.send(NetworkCommand::RequestShard {
            peer_id,
            chunk_hash,
            shard_index,
        }).await;
    }

    /// Sendet einen Shard an einen Peer zum Speichern.
    /// Die Bestätigung kommt als `NetworkEvent::ShardStored`.
    pub async fn store_shard_on_peer(
        &self,
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    ) {
        let _ = self.cmd_tx.send(NetworkCommand::StoreShard {
            peer_id,
            chunk_hash,
            shard_index,
            shard_hash,
            data,
        }).await;
    }

    /// Fragt ab welche Shards ein Peer für einen bestimmten Chunk hat.
    /// Timeout: 5 Sekunden.
    pub async fn list_peer_shards(&self, peer_id: PeerId, chunk_hash: String) -> Vec<u8> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(NetworkCommand::ListPeerShards {
            peer_id,
            chunk_hash,
            reply: tx,
        }).await.is_err() {
            return vec![];
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(indices)) => indices,
            _ => vec![],
        }
    }

    /// Meldet Fehlverhalten eines Peers (aus Handlern/Binaries heraus).
    pub async fn report_penalty(&self, peer_id_str: &str, points: u32, reason: &str) {
        let _ = self.cmd_tx.send(NetworkCommand::ReportPenalty {
            peer_id_str: peer_id_str.to_string(),
            points,
            reason: reason.to_string(),
        }).await;
    }

    /// Eigenen Stake-Level setzen (Relay-Priorität).
    /// Peers bevorzugen höher-gestakte Nodes als Sync-Quelle.
    pub async fn set_stake_level(&self, level: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SetStakeLevel(level)).await;
    }
}

// ─── start_network ────────────────────────────────────────────────────────────

/// Startet den P2P-Swarm-Task und gibt ein `NetworkHandle` zurück.
pub async fn start_network(
    config_override: Option<P2pConfig>,
) -> Result<NetworkHandle, Box<dyn std::error::Error>> {
    let config = match config_override {
        Some(c) => c, // Caller hat schon konfiguriert – merge_env() nicht nochmal aufrufen
        None => {
            let mut c = P2pConfig::load_or_default();
            c.merge_env();
            c
        }
    };

    let keypair = load_or_create_keypair();
    let local_peer_id = PeerId::from_public_key(&keypair.public()).to_string();

    println!("[p2p] Stone P2P-Netzwerk startet");
    println!("[p2p] PeerId: {local_peer_id}");
    println!("[p2p] Listen: {}", config.listen_addr);
    if config.bootstrap_nodes.is_empty() {
        println!("[p2p] Keine Bootstrap-Nodes – nur mDNS/lokale Discovery");
    } else {
        for b in &config.bootstrap_nodes {
            println!("[p2p] Bootstrap: {b}");
        }
    }

    // NAT-Traversal Konfiguration loggen
    println!("[p2p] NAT-Traversal:");
    println!("[p2p]   QUIC:     ✅ (UDP, native TLS 1.3)");
    println!("[p2p]   AutoNAT:  {}", if config.autonat_enabled { "✅" } else { "❌" });
    println!("[p2p]   UPnP:     {}", if config.upnp_enabled { "✅" } else { "❌" });
    println!("[p2p]   DCUtR:    {}", if config.dcutr_enabled { "✅" } else { "❌" });
    println!("[p2p]   Relay:    ✅ (Auto-Discovery + Server)");
    if !config.relay_nodes.is_empty() {
        for r in &config.relay_nodes {
            println!("[p2p]   Relay:    {r}");
        }
    }

    let mut swarm = build_swarm(keypair, &config)?;

    // Gossipsub: alle Topics abonnieren
    super::swarm_task::subscribe_all_topics(&mut swarm.behaviour_mut().gossipsub)
        .map_err(|e| format!("Gossipsub-Subscribe: {e}"))?;

    let (event_tx, _) = broadcast::channel(4096);
    let (cmd_tx, cmd_rx) = mpsc::channel(128);

    let bootstrap_addrs = config.bootstrap_nodes.clone();

    let relay_addrs = config.relay_nodes.clone();

    let task = SwarmTask {
        swarm,
        event_tx: event_tx.clone(),
        cmd_rx,
        peers: HashMap::new(),
        seen_hashes: HashSet::new(),
        seen_order: VecDeque::new(),
        local_chain_count: 0,
        bootstrap_addrs,
        last_reconnect: Instant::now(),
        config,
        pending_pings: HashMap::new(),
        nat_status: super::swarm_task::NatStatus::Unknown,
        active_relays: HashSet::new(),
        relay_addrs,
        peer_penalties: super::swarm_task::load_banned_peers(),
        shard_store: crate::shard::ShardStore::new().expect("ShardStore erstellen"),
        pending_shard_lists: HashMap::new(),
        net_metrics: NetworkMetrics::default(),
        started_at: Instant::now(),
        peer_storage: HashMap::new(),
        peer_rate_limiters: HashMap::new(),
        chain_ref: None,
        pending_chain_info: HashMap::new(),
        sync_buffer: std::collections::BTreeMap::new(),
        sync_buffer_last_insert: None,
        sync_expected_next: 0,
        local_stake_level: 0,
        reconnect_backoff: HashMap::new(),
        keepalive_pings: HashMap::new(),
        peer_latencies: HashMap::new(),
        rate_limit_grace: HashMap::new(),
    };

    tokio::spawn(task.run());

    Ok(NetworkHandle {
        cmd_tx,
        event_rx: event_tx,
        local_peer_id,
    })
}

// ─── Hilfsfunktionen für die REST-API ─────────────────────────────────────────

/// Parst eine Multiaddr aus einem String.
pub fn parse_multiaddr(s: &str) -> Result<Multiaddr, String> {
    s.parse::<Multiaddr>().map_err(|e| format!("Ungültige Multiaddr: {e}"))
}

/// Gibt die vollständige eigene P2P-Adresse zurück (für Bootstrap-Konfiguration anderer Nodes).
pub fn local_p2p_addr(port: u16) -> Option<String> {
    let peer_id = read_peer_id()?;
    let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Some(format!("/ip4/{ip}/tcp/{port}/p2p/{peer_id}"))
}

/// Gibt die QUIC-Adresse zurück (UDP-basiert, für NAT-Traversal).
pub fn local_quic_addr(port: u16) -> Option<String> {
    let peer_id = read_peer_id()?;
    let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Some(format!("/ip4/{ip}/udp/{port}/quic-v1/p2p/{peer_id}"))
}

fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}
